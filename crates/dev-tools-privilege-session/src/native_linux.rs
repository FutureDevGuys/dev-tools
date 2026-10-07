//! Retained Linux cgroup-v2 mechanics for a trusted, single-owner coordinator.
//!
//! This module neither grants privilege nor contains an unrestricted root
//! process. The product must arrange an independent deadline/coordinator-death
//! guardian outside the payload domain (for example, a separately supervised
//! systemd owner), restrict capabilities, control sockets and mount/PID/cgroup
//! visibility, and reject helpers that can escape or disable those restrictions.
//! The calling thread must remain outside every domain it creates. Root custody
//! is observed in the coordinator's namespaces; authenticating those namespaces
//! and excluding other privileged writers is the product's responsibility.
//!
//! A domain owns only a freshly created leaf beneath an explicitly supplied,
//! root-custodied boundary. It never adopts a named existing domain. Commands are
//! trusted coordinator-built commands: prior `pre_exec` callbacks must perform
//! no payload work or forks, and `Command::uid`/`gid` cannot drop the permission
//! needed to enter the domain. Apply payload sandboxing in a reviewed launcher
//! after the gate, before executing its approved helper. Every inherited cgroup
//! and gate descriptor is close-on-exec. No uncontrolled payload is released
//! until the coordinator explicitly releases its token.
//!
//! Admission/deadline validation and `release_child` must be serialized by the
//! product. All cleanup operations retain retry state; only `terminate` can
//! produce positive cleanup evidence. `Drop`, signals, leader exit, and manager
//! stop replies are never such evidence. These primitives are not native
//! platform acceptance or an independent crash backstop.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustix::fs::{AtFlags, FileType, Mode, OFlags};

const CGROUP2_MAGIC: u64 = 0x6367_7270;
const CONTROL_LIMIT: usize = 4096;
const MEMBERSHIP_LIMIT: usize = 256 * 1024;
const MAX_CHILDREN: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 64;
static NEXT_DOMAIN_INSTANCE: AtomicU64 = AtomicU64::new(1);
const MAX_WAIT: Duration = Duration::from_secs(300);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const RELEASE: u8 = 0xa5;

/// Fixed, value-free failures. OS errors retain only the numeric errno/category.
#[derive(Debug)]
#[non_exhaustive]
pub enum NativeError {
    Io(io::Error),
    InvalidPath,
    NotCgroupV2,
    UnsafeCustody,
    IdentityChanged,
    UnsupportedDomain,
    InvalidKernelEvidence,
    InvalidTimeout,
    TimedOut,
    AdmissionClosed,
    ChildLimit,
    UnknownChild,
    ChildNotGated,
    ChildSpawnFailed,
    WorkerFailed,
    PeerMismatch,
    PeerExited,
    CleanupNotComplete,
}

impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io(_) => "native cgroup operation failed",
            Self::InvalidPath => "native cgroup path is invalid",
            Self::NotCgroupV2 => "native evidence requires the kernel cgroup-v2 filesystem",
            Self::UnsafeCustody => "native cgroup custody is unsafe",
            Self::IdentityChanged => "native cgroup identity changed",
            Self::UnsupportedDomain => "native cgroup is not a supported nondelegated domain",
            Self::InvalidKernelEvidence => "native kernel evidence is invalid or exceeds bounds",
            Self::InvalidTimeout => "native observation timeout is outside its bounds",
            Self::TimedOut => "native cgroup observation timed out",
            Self::AdmissionClosed => "native domain admission is closed",
            Self::ChildLimit => "native retained child limit was reached",
            Self::UnknownChild => "native child token belongs to a different domain",
            Self::ChildNotGated => "native child is not waiting at its gate",
            Self::ChildSpawnFailed => "native child did not complete spawn",
            Self::WorkerFailed => "native child spawn owner failed",
            Self::PeerMismatch => "native peer does not belong to the retained domain and owner",
            Self::PeerExited => "native peer is no longer alive",
            Self::CleanupNotComplete => "native domain cleanup is not positively complete",
        };
        f.write_str(message)
    }
}

impl std::error::Error for NativeError {}
impl From<io::Error> for NativeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<rustix::io::Errno> for NativeError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

type Result<T> = std::result::Result<T, NativeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl Identity {
    fn from_stat(stat: &rustix::fs::Stat) -> Self {
        Self {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode: stat.st_mode,
            uid: stat.st_uid,
            gid: stat.st_gid,
        }
    }

    fn require_custody(self, kind: FileType) -> Result<()> {
        if FileType::from_raw_mode(self.mode) != kind
            || self.uid != 0
            || self.gid != 0
            || self.mode & 0o022 != 0
        {
            return Err(NativeError::UnsafeCustody);
        }
        Ok(())
    }
}

struct HeldDirectory {
    fd: OwnedFd,
    identity: Identity,
    parent: Option<Arc<HeldDirectory>>,
    name: OsString,
    path: PathBuf,
}

impl HeldDirectory {
    fn open_absolute(path: &Path) -> Result<Arc<Self>> {
        // Reject lexical aliases too: Path::components normalizes repeated '/'
        // and '.', which must not silently turn an input into authority.
        if !path.is_absolute()
            || path.as_os_str().as_bytes().contains(&0)
            || path.as_os_str().as_bytes().len() > 4096
            || path.components().count() > MAX_PATH_COMPONENTS
            || path
                .components()
                .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        {
            return Err(NativeError::InvalidPath);
        }
        let reconstructed: PathBuf = path.components().collect();
        if reconstructed.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
            return Err(NativeError::InvalidPath);
        }
        let fd = rustix::fs::open("/", directory_flags(), Mode::empty())?;
        let identity = Identity::from_stat(&rustix::fs::fstat(&fd)?);
        identity.require_custody(FileType::Directory)?;
        let mut current = Arc::new(Self {
            fd,
            identity,
            parent: None,
            name: OsString::from("/"),
            path: PathBuf::from("/"),
        });
        for component in path.components().skip(1) {
            let Component::Normal(name) = component else {
                return Err(NativeError::InvalidPath);
            };
            current = Self::open_child(current, name)?;
        }
        current.validate()?;
        Ok(current)
    }

    fn open_child(parent: Arc<Self>, name: &OsStr) -> Result<Arc<Self>> {
        require_leaf(name)?;
        parent.validate()?;
        let fd = rustix::fs::openat(&parent.fd, name, directory_flags(), Mode::empty())?;
        let identity = Identity::from_stat(&rustix::fs::fstat(&fd)?);
        identity.require_custody(FileType::Directory)?;
        let result = Arc::new(Self {
            fd,
            identity,
            path: parent.path.join(name),
            parent: Some(parent),
            name: name.to_owned(),
        });
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        let held = Identity::from_stat(&rustix::fs::fstat(&self.fd)?);
        held.require_custody(FileType::Directory)?;
        if held != self.identity {
            return Err(NativeError::IdentityChanged);
        }
        let named = if let Some(parent) = &self.parent {
            parent.validate()?;
            rustix::fs::statat(&parent.fd, &self.name, AtFlags::SYMLINK_NOFOLLOW)?
        } else {
            rustix::fs::statat(rustix::fs::CWD, "/", AtFlags::SYMLINK_NOFOLLOW)?
        };
        if Identity::from_stat(&named) != self.identity {
            return Err(NativeError::IdentityChanged);
        }
        Ok(())
    }

    fn require_kernel(&self) -> Result<()> {
        self.validate()?;
        require_cgroup_filesystem(&self.fd)
    }
}

struct ControlFile {
    file: File,
    identity: Identity,
    directory: Arc<HeldDirectory>,
    name: &'static str,
}

impl ControlFile {
    fn open(directory: Arc<HeldDirectory>, name: &'static str, access: OFlags) -> Result<Self> {
        directory.require_kernel()?;
        let fd = rustix::fs::openat(
            &directory.fd,
            name,
            access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        let identity = Identity::from_stat(&rustix::fs::fstat(&fd)?);
        let result = Self {
            file: fd.into(),
            identity,
            directory,
            name,
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        self.directory.require_kernel()?;
        let held = Identity::from_stat(&rustix::fs::fstat(&self.file)?);
        held.require_custody(FileType::RegularFile)?;
        require_cgroup_filesystem(&self.file)?;
        let named = rustix::fs::statat(&self.directory.fd, self.name, AtFlags::SYMLINK_NOFOLLOW)?;
        if held != self.identity || Identity::from_stat(&named) != self.identity {
            return Err(NativeError::IdentityChanged);
        }
        Ok(())
    }

    fn read(&self, limit: usize) -> Result<Vec<u8>> {
        self.validate()?;
        // Independent descriptor offsets make concurrent read-only observations
        // harmless. The new descriptor must still name the retained inode.
        let fresh = Self::open(self.directory.clone(), self.name, OFlags::RDONLY)?;
        if fresh.identity != self.identity {
            return Err(NativeError::IdentityChanged);
        }
        let mut bytes = Vec::new();
        (&fresh.file)
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(NativeError::InvalidKernelEvidence);
        }
        fresh.validate()?;
        self.validate()?;
        Ok(bytes)
    }

    fn write(&self, bytes: &[u8]) -> Result<()> {
        self.validate()?;
        // A kernfs command is one write; a short write is not retried as a
        // separate partially interpreted command.
        if rustix::io::write(&self.file, bytes)? != bytes.len() {
            return Err(NativeError::InvalidKernelEvidence);
        }
        self.validate()
    }
}

/// A held, root-owned, nondelegated cgroup-v2 parent selected by the product.
/// Opening it is read-only. No arbitrary existing child can be adopted.
pub struct ValidatedCgroupBoundary {
    directory: Arc<HeldDirectory>,
}

impl ValidatedCgroupBoundary {
    pub fn open(path: &Path) -> Result<Self> {
        let result = Self {
            directory: HeldDirectory::open_absolute(path)?,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        require_domain(&self.directory)
    }

    /// Creates one absent leaf. Existing names, delegation, missing cgroup.kill,
    /// and unsafe custody fail closed. The caller must have native root authority.
    pub fn create_domain(&self, name: &OsStr) -> Result<RetainedCgroupDomain> {
        require_leaf(name)?;
        self.validate()?;
        if !rustix::process::geteuid().is_root() {
            return Err(NativeError::UnsafeCustody);
        }
        let instance = NEXT_DOMAIN_INSTANCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| NativeError::ChildLimit)?;
        rustix::fs::mkdirat(&self.directory.fd, name, Mode::from_raw_mode(0o700))?;
        // On an unexpected post-mkdir failure, leave the empty name in place.
        // Adopting or deleting an unverified replacement would be less safe.
        let directory = HeldDirectory::open_child(self.directory.clone(), name)?;
        require_domain(&directory)?;
        let events = ControlFile::open(directory.clone(), "cgroup.events", OFlags::RDONLY)?;
        let members = ControlFile::open(directory.clone(), "cgroup.procs", OFlags::RDONLY)?;
        let kill = ControlFile::open(directory.clone(), "cgroup.kill", OFlags::WRONLY)?;
        if population(&events.read(CONTROL_LIMIT)?)? {
            return Err(NativeError::InvalidKernelEvidence);
        }
        Ok(RetainedCgroupDomain {
            instance,
            directory,
            events,
            members,
            kill,
            children: Vec::new(),
            admission_closed: false,
            cleanup_complete: false,
            cleanup_failed: false,
            removed: false,
        })
    }
}

/// An unforgeable-in-safe-Rust selector, not a credential or transferable grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildToken {
    instance: u64,
    device: u64,
    inode: u64,
    index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildStatus {
    Gated,
    Running,
    Exited(ExitStatus),
    SpawnFailed,
}

/// Stream handles may be drained by the product without surrendering the child
/// or pidfd join owner. They cannot keep the independent cleanup loop blocked.
pub struct ChildStreams {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
}

struct ChildRecord {
    gate: UnixStream,
    worker: Option<JoinHandle<io::Result<Child>>>,
    child: Option<Child>,
    pidfd: Option<OwnedFd>,
    pid: Option<u32>,
    released: bool,
    exit: Option<ExitStatus>,
    spawn_failed: bool,
    worker_failed: bool,
}

impl ChildRecord {
    fn collect(&mut self) -> Result<()> {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            match self.worker.take().expect("checked worker").join() {
                Ok(Ok(child)) => {
                    if self.pid.is_some_and(|pid| child.id() != pid) {
                        // Retain this actual owned child for cleanup as well.
                        self.worker_failed = true;
                    }
                    self.child = Some(child);
                }
                Ok(Err(_)) => self.spawn_failed = true,
                Err(_) => self.worker_failed = true,
            }
        }
        if self.exit.is_none() {
            if let Some(child) = &mut self.child {
                self.exit = child.try_wait()?;
            }
        }
        Ok(())
    }

    fn joined(&self) -> Result<bool> {
        if self.worker_failed {
            return Err(NativeError::WorkerFailed);
        }
        if self.worker.is_some() || (!self.spawn_failed && self.exit.is_none()) {
            return Ok(false);
        }
        if let Some(pidfd) = &self.pidfd {
            if pidfd_alive(pidfd)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Owns the exact created kernel domain, startup gates, pidfds and direct-child
/// joins. Keep this value and retry after failures until the product guardian
/// has independently established terminal cleanup.
pub struct RetainedCgroupDomain {
    instance: u64,
    directory: Arc<HeldDirectory>,
    events: ControlFile,
    members: ControlFile,
    kill: ControlFile,
    children: Vec<ChildRecord>,
    admission_closed: bool,
    cleanup_complete: bool,
    cleanup_failed: bool,
    removed: bool,
}

impl RetainedCgroupDomain {
    /// Observational path only; it is never sufficient evidence of ownership.
    pub fn path(&self) -> &Path {
        &self.directory.path
    }

    pub fn validate(&self) -> Result<()> {
        require_domain(&self.directory)?;
        self.events.validate()?;
        self.members.validate()?;
        self.kill.validate()
    }

    pub fn populated(&self) -> Result<bool> {
        self.validate()?;
        population(&self.events.read(CONTROL_LIMIT)?)
    }

    /// Starts a trusted prepared Command only as far as its containment gate.
    /// Timeout/error leaves any started child owned here; call `terminate`.
    /// The child writes itself into the exact held cgroup.procs before reporting
    /// readiness. No helper exec occurs until `release_child`.
    pub fn spawn_gated(&mut self, mut command: Command, timeout: Duration) -> Result<ChildToken> {
        if self.admission_closed {
            return Err(NativeError::AdmissionClosed);
        }
        let deadline = deadline(timeout)?;
        self.validate()?;
        if self.children.len() >= MAX_CHILDREN {
            return Err(NativeError::ChildLimit);
        }
        let membership = ControlFile::open(self.directory.clone(), "cgroup.procs", OFlags::WRONLY)?;
        // Keep all gate operands above the standard-stream slots. Command's
        // child-side stdio setup must not overwrite a retained operand when the
        // coordinator happened to start with fd 0, 1, or 2 closed.
        let membership_fd = rustix::io::fcntl_dupfd_cloexec(&membership.file, 3)?;
        drop(membership);
        let (original_gate, original_child_gate) = UnixStream::pair()?;
        let gate = UnixStream::from(rustix::io::fcntl_dupfd_cloexec(&original_gate, 3)?);
        let child_gate =
            UnixStream::from(rustix::io::fcntl_dupfd_cloexec(&original_child_gate, 3)?);
        drop((original_gate, original_child_gate));
        let parent_fd = gate.as_raw_fd();
        // SAFETY: the closure performs only async-signal-safe native descriptor
        // operations with stack values. Captured descriptors remain owned until
        // spawn returns. close(parent_fd) affects only the forked child's copy.
        unsafe {
            command.pre_exec(move || {
                libc::close(parent_fd);
                enter_child_gate(membership_fd.as_raw_fd(), child_gate.as_raw_fd())
            });
        }
        let worker = thread::Builder::new()
            .name("contained-spawn".into())
            .spawn(move || command.spawn())?;
        let index = self.children.len();
        self.children.push(ChildRecord {
            gate,
            worker: Some(worker),
            child: None,
            pidfd: None,
            pid: None,
            released: false,
            exit: None,
            spawn_failed: false,
            worker_failed: false,
        });
        let result = self.await_gate(index, deadline);
        if result.is_err() {
            self.admission_closed = true;
            let _ = self.children[index].gate.shutdown(Shutdown::Write);
        }
        result?;
        Ok(ChildToken {
            instance: self.instance,
            device: self.directory.identity.device,
            inode: self.directory.identity.inode,
            index,
        })
    }

    fn await_gate(&mut self, index: usize, deadline: Duration) -> Result<()> {
        let mut bytes = [0u8; 4];
        let mut offset = 0;
        self.children[index].gate.set_nonblocking(true)?;
        while offset != bytes.len() {
            if boottime() >= deadline {
                return Err(NativeError::TimedOut);
            }
            match self.children[index].gate.read(&mut bytes[offset..]) {
                Ok(0) => return Err(NativeError::ChildSpawnFailed),
                Ok(count) => offset += count,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(POLL_INTERVAL)
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        let pid = u32::from_ne_bytes(bytes);
        let native_pid = rustix::process::Pid::from_raw(
            i32::try_from(pid).map_err(|_| NativeError::InvalidKernelEvidence)?,
        )
        .ok_or(NativeError::InvalidKernelEvidence)?;
        let pidfd = rustix::process::pidfd_open(native_pid, rustix::process::PidfdFlags::empty())?;
        self.require_member(pid, &pidfd)?;
        let record = &mut self.children[index];
        record.pid = Some(pid);
        record.pidfd = Some(pidfd);
        record.collect()?;
        if record.worker.is_none() {
            return Err(NativeError::ChildSpawnFailed);
        }
        Ok(())
    }

    /// The product must atomically validate/consume lease admission versus stop
    /// before calling this method. A released use is never automatically retried.
    pub fn release_child(&mut self, token: ChildToken) -> Result<()> {
        if self.admission_closed {
            return Err(NativeError::AdmissionClosed);
        }
        let index = self.index(token)?;
        self.validate()?;
        let record = &self.children[index];
        if record.released || record.spawn_failed || record.worker_failed {
            return Err(NativeError::ChildNotGated);
        }
        self.require_member(
            record.pid.ok_or(NativeError::ChildNotGated)?,
            record.pidfd.as_ref().ok_or(NativeError::ChildNotGated)?,
        )?;
        // The only write is one byte to a fresh socket. The nonblocking parent
        // end cannot wait behind child I/O or an unresponsive payload.
        self.children[index].gate.write_all(&[RELEASE])?;
        self.children[index].released = true;
        Ok(())
    }

    pub fn child_status(&mut self, token: ChildToken) -> Result<ChildStatus> {
        let index = self.index(token)?;
        let record = &mut self.children[index];
        record.collect()?;
        if record.worker_failed {
            return Err(NativeError::WorkerFailed);
        }
        if record.spawn_failed {
            return Ok(ChildStatus::SpawnFailed);
        }
        if let Some(status) = record.exit {
            return Ok(ChildStatus::Exited(status));
        }
        Ok(if record.released {
            ChildStatus::Running
        } else {
            ChildStatus::Gated
        })
    }

    /// Returns None while the exec handshake is pending. A returned set may
    /// contain no handles when the command selected inherited or closed streams.
    pub fn take_child_streams(&mut self, token: ChildToken) -> Result<Option<ChildStreams>> {
        let index = self.index(token)?;
        let record = &mut self.children[index];
        record.collect()?;
        if record.worker_failed {
            return Err(NativeError::WorkerFailed);
        }
        if record.spawn_failed {
            return Err(NativeError::ChildSpawnFailed);
        }
        Ok(record.child.as_mut().map(|child| ChildStreams {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
        }))
    }

    /// Uses both SO_PEERCRED and SO_PEERPIDFD from this connected Unix socket.
    /// Caller-supplied PIDs, cgroup strings and environment hints are not inputs.
    /// Exact leaf membership is intentional: this nondelegated payload domain
    /// does not authorize caller-created descendant cgroups.
    pub fn authenticate_peer(&self, stream: &UnixStream, uid: u32, gid: u32) -> Result<KernelPeer> {
        if self.admission_closed {
            return Err(NativeError::AdmissionClosed);
        }
        let peer = KernelPeer::from_socket(stream)?;
        if peer.uid != uid || peer.gid != gid {
            return Err(NativeError::PeerMismatch);
        }
        self.require_member(peer.pid, &peer.pidfd)?;
        Ok(peer)
    }

    /// Recheck a retained peer immediately before serialized admission.
    pub fn revalidate_peer(&self, peer: &KernelPeer) -> Result<()> {
        if self.admission_closed {
            return Err(NativeError::AdmissionClosed);
        }
        self.require_member(peer.pid, &peer.pidfd)
    }

    fn require_member(&self, pid: u32, pidfd: &OwnedFd) -> Result<()> {
        self.validate()?;
        if !pidfd_alive(pidfd)? {
            return Err(NativeError::PeerExited);
        }
        if !contains_pid(&self.members.read(MEMBERSHIP_LIMIT)?, pid)? {
            return Err(NativeError::PeerMismatch);
        }
        if !pidfd_alive(pidfd)? {
            return Err(NativeError::PeerExited);
        }
        self.validate()
    }

    fn index(&self, token: ChildToken) -> Result<usize> {
        if token.instance != self.instance
            || token.device != self.directory.identity.device
            || token.inode != self.directory.identity.inode
            || token.index >= self.children.len()
        {
            return Err(NativeError::UnknownChild);
        }
        Ok(token.index)
    }

    /// Closes admission permanently, rejects all unreleased gates, writes the
    /// retained kernel cgroup.kill, then requires populated=0 AND every retained
    /// spawn owner/direct child joined AND every retained pidfd terminal.
    /// CLOCK_BOOTTIME bounds observation across suspend. Failure retains owners
    /// for retry and is recorded in every later successful proof.
    pub fn terminate(&mut self, timeout: Duration) -> Result<CleanupProof> {
        self.admission_closed = true;
        let result = self.terminate_inner(timeout);
        if result.is_err() {
            self.cleanup_failed = true;
        }
        result
    }

    fn terminate_inner(&mut self, timeout: Duration) -> Result<CleanupProof> {
        let deadline = deadline(timeout)?;
        for child in &self.children {
            let _ = child.gate.shutdown(Shutdown::Write);
        }
        self.validate()?;
        self.kill.write(b"1\n")?;
        loop {
            let mut joined = true;
            for child in &mut self.children {
                child.collect()?;
                joined &= child.joined()?;
            }
            if !self.populated()? && joined {
                self.validate()?;
                if !self.populated()? {
                    self.cleanup_complete = true;
                    return Ok(CleanupProof {
                        joined_children: self.children.len(),
                        had_failure: self.cleanup_failed,
                    });
                }
            }
            if boottime() >= deadline {
                return Err(NativeError::TimedOut);
            }
            thread::sleep(POLL_INTERVAL);
        }
    }

    /// Remove only this still-held empty leaf, after successful termination.
    /// Nonempty child directories and stale/replaced names are errors. Failure
    /// leaves this object available; no recursive deletion is attempted.
    pub fn remove(&mut self) -> Result<()> {
        if !self.cleanup_complete || !self.admission_closed {
            return Err(NativeError::CleanupNotComplete);
        }
        self.validate()?;
        if self.populated()? {
            return Err(NativeError::CleanupNotComplete);
        }
        for child in &mut self.children {
            child.collect()?;
            if !child.joined()? {
                return Err(NativeError::CleanupNotComplete);
            }
        }
        let parent = self
            .directory
            .parent
            .as_ref()
            .ok_or(NativeError::InvalidPath)?;
        rustix::fs::unlinkat(&parent.fd, &self.directory.name, AtFlags::REMOVEDIR)?;
        parent.validate()?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for RetainedCgroupDomain {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        self.admission_closed = true;
        for child in &self.children {
            let _ = child.gate.shutdown(Shutdown::Write);
        }
        // Best effort only. Destruction cannot return cleanup evidence and must
        // not pretend to replace the independent native crash/deadline owner.
        let _ = self.kill.write(b"1\n");
    }
}

/// Produced only by positive retained-domain population and join observations.
/// It does not attest endpoint/unit removal or the product's guardian contract.
#[derive(Debug)]
pub struct CleanupProof {
    joined_children: usize,
    had_failure: bool,
}

impl CleanupProof {
    pub fn joined_children(&self) -> usize {
        self.joined_children
    }
    pub fn had_prior_failure(&self) -> bool {
        self.had_failure
    }
}

/// Retained kernel socket identity. Cannot be built from a claimed PID.
pub struct KernelPeer {
    pid: u32,
    uid: u32,
    gid: u32,
    pidfd: OwnedFd,
}

impl KernelPeer {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn uid(&self) -> u32 {
        self.uid
    }
    pub fn gid(&self) -> u32 {
        self.gid
    }
    pub fn is_alive(&self) -> Result<bool> {
        pidfd_alive(&self.pidfd)
    }

    fn from_socket(stream: &UnixStream) -> Result<Self> {
        let mut credentials = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: initialized correctly sized native output buffers; stream
        // remains borrowed and the kernel owns the returned credential values.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(credentials).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if length as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0 {
            return Err(NativeError::InvalidKernelEvidence);
        }
        let mut raw_pidfd: libc::c_int = -1;
        let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: a successful SO_PEERPIDFD call creates one descriptor owned by
        // this caller, never an integer PID opened after an identity race.
        let result = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                std::ptr::addr_of_mut!(raw_pidfd).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if raw_pidfd < 0 {
            return Err(NativeError::InvalidKernelEvidence);
        }
        // SAFETY: the successful getsockopt transferred a new owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
        if length as usize != std::mem::size_of::<libc::c_int>() {
            return Err(NativeError::InvalidKernelEvidence);
        }
        rustix::io::fcntl_setfd(&pidfd, rustix::io::FdFlags::CLOEXEC)?;
        if !pidfd_alive(&pidfd)? {
            return Err(NativeError::PeerExited);
        }
        Ok(Self {
            pid: credentials.pid as u32,
            uid: credentials.uid,
            gid: credentials.gid,
            pidfd,
        })
    }
}

fn require_cgroup_filesystem(fd: impl AsFd) -> Result<()> {
    if rustix::fs::fstatfs(fd)?.f_type as u64 != CGROUP2_MAGIC {
        return Err(NativeError::NotCgroupV2);
    }
    Ok(())
}

fn directory_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
}

fn require_leaf(name: &OsStr) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 255
        || bytes.contains(&0)
        || bytes.contains(&b'/')
        || bytes == b"."
        || bytes == b".."
    {
        return Err(NativeError::InvalidPath);
    }
    Ok(())
}

fn require_domain(directory: &Arc<HeldDirectory>) -> Result<()> {
    directory.require_kernel()?;
    let kind = ControlFile::open(directory.clone(), "cgroup.type", OFlags::RDONLY)?;
    if kind.read(CONTROL_LIMIT)? != b"domain\n" {
        return Err(NativeError::UnsupportedDomain);
    }
    // These are the delegation-sensitive knobs documented by cgroup v2. A
    // directory alone being root-owned does not make a delegated domain safe.
    for name in ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control"] {
        ControlFile::open(directory.clone(), name, OFlags::RDONLY)?.validate()?;
    }
    directory.require_kernel()
}

fn population(bytes: &[u8]) -> Result<bool> {
    if bytes.is_empty() || bytes.len() > CONTROL_LIMIT {
        return Err(NativeError::InvalidKernelEvidence);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NativeError::InvalidKernelEvidence)?;
    let mut seen = BTreeSet::new();
    let mut populated = None;
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        let key = words.next().ok_or(NativeError::InvalidKernelEvidence)?;
        let value = words.next().ok_or(NativeError::InvalidKernelEvidence)?;
        if words.next().is_some()
            || !seen.insert(key)
            || value.is_empty()
            || !value.bytes().all(|b| b.is_ascii_digit())
            || value.parse::<u64>().is_err()
        {
            return Err(NativeError::InvalidKernelEvidence);
        }
        if key == "populated" {
            populated = Some(match value {
                "0" => false,
                "1" => true,
                _ => return Err(NativeError::InvalidKernelEvidence),
            });
        }
    }
    populated.ok_or(NativeError::InvalidKernelEvidence)
}

fn contains_pid(bytes: &[u8], pid: u32) -> Result<bool> {
    if bytes.len() > MEMBERSHIP_LIMIT || pid == 0 {
        return Err(NativeError::InvalidKernelEvidence);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| NativeError::InvalidKernelEvidence)?;
    let mut found = false;
    for line in text.lines() {
        if line.is_empty() || !line.bytes().all(|b| b.is_ascii_digit()) {
            return Err(NativeError::InvalidKernelEvidence);
        }
        let observed = line
            .parse::<u32>()
            .map_err(|_| NativeError::InvalidKernelEvidence)?;
        if observed == 0 || observed > i32::MAX as u32 {
            return Err(NativeError::InvalidKernelEvidence);
        }
        found |= observed == pid;
    }
    Ok(found)
}

fn pidfd_alive(pidfd: &OwnedFd) -> Result<bool> {
    use rustix::event::{poll, PollFd, PollFlags, Timespec};
    let mut descriptors = [PollFd::new(pidfd, PollFlags::IN)];
    match poll(
        &mut descriptors,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    ) {
        Ok(0) => Ok(true),
        Ok(_)
            if descriptors[0]
                .revents()
                .intersects(PollFlags::IN | PollFlags::HUP) =>
        {
            Ok(false)
        }
        Ok(_) => Err(NativeError::InvalidKernelEvidence),
        Err(error) => Err(error.into()),
    }
}

fn boottime() -> Duration {
    let value = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    Duration::new(value.tv_sec as u64, value.tv_nsec as u32)
}

fn deadline(timeout: Duration) -> Result<Duration> {
    if timeout.is_zero() || timeout > MAX_WAIT {
        return Err(NativeError::InvalidTimeout);
    }
    boottime()
        .checked_add(timeout)
        .ok_or(NativeError::InvalidTimeout)
}

// This runs after fork, before exec: do not allocate, lock, format, panic, or
// access coordinator state. EINTR is retried, never a partial cgroup command.
unsafe fn enter_child_gate(membership: libc::c_int, socket: libc::c_int) -> io::Result<()> {
    loop {
        // SAFETY: the closure owns a writable retained cgroup.procs descriptor;
        // this constant buffer is valid for the complete one-byte command.
        let count = unsafe { libc::write(membership, b"0".as_ptr().cast(), 1) };
        if count == 1 {
            break;
        }
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::from_raw_os_error(libc::EIO));
    }
    // SAFETY: getpid has no memory preconditions and is async-signal-safe.
    let bytes = (unsafe { libc::getpid() } as u32).to_ne_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: valid connected descriptor and the indicated live stack span.
        let count = unsafe {
            libc::send(
                socket,
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::from_raw_os_error(libc::EPIPE));
    }
    let mut release = 0u8;
    loop {
        // SAFETY: valid gate descriptor and a writable one-byte stack buffer.
        let count = unsafe { libc::recv(socket, std::ptr::addr_of_mut!(release).cast(), 1, 0) };
        if count == 1 && release == RELEASE {
            return Ok(());
        }
        if count < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::from_raw_os_error(libc::ECANCELED));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forged_empty_events_fail_the_kernel_filesystem_check_independently_of_custody() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("cgroup.events");
        std::fs::write(&path, b"populated 0\n").unwrap();
        assert!(!population(&std::fs::read(&path).unwrap()).unwrap());
        let file = File::open(path).unwrap();
        assert!(matches!(
            require_cgroup_filesystem(file),
            Err(NativeError::NotCgroupV2)
        ));
        let directory = File::open(fixture.path()).unwrap();
        assert!(matches!(
            require_cgroup_filesystem(directory),
            Err(NativeError::NotCgroupV2)
        ));
    }

    #[test]
    fn population_requires_one_bounded_explicit_boolean() {
        assert!(!population(b"populated 0\nfrozen 0\n").unwrap());
        assert!(population(b"populated 1\nfuture_counter 12\n").unwrap());
        for bytes in [
            b"".as_slice(),
            b"frozen 0\n",
            b"populated 2\n",
            b"populated 00\n",
            b"populated 0\npopulated 1\n",
            b"populated 0 trailing\n",
            b"populated 0\nx -1\n",
            b"populated 0\nx 18446744073709551616\n",
        ] {
            assert!(population(bytes).is_err());
        }
        assert!(population(&vec![b' '; CONTROL_LIMIT + 1]).is_err());
    }

    #[test]
    fn membership_is_exact_numeric_and_bounded() {
        assert!(contains_pid(b"12\n123\n", 12).unwrap());
        assert!(!contains_pid(b"123\n", 12).unwrap());
        assert!(!contains_pid(b"", 12).unwrap());
        for bytes in [
            b"0\n".as_slice(),
            b"-1\n",
            b"12 extra\n",
            b"12\n\n",
            b"2147483648\n",
        ] {
            assert!(contains_pid(bytes, 12).is_err());
        }
        assert!(contains_pid(&vec![b'1'; MEMBERSHIP_LIMIT + 1], 12).is_err());
    }

    #[test]
    fn safe_leaf_is_exactly_one_native_component() {
        assert!(require_leaf(OsStr::new("synthetic-123.scope")).is_ok());
        for name in ["", ".", "..", "a/b", "/root", "embedded\0nul"] {
            assert!(require_leaf(OsStr::new(name)).is_err());
        }
        assert!(require_leaf(OsStr::from_bytes(&[b'a'; 256])).is_err());
    }

    #[test]
    fn observation_deadline_is_bounded_and_uses_boottime() {
        assert!(deadline(Duration::ZERO).is_err());
        assert!(deadline(MAX_WAIT + Duration::from_nanos(1)).is_err());
        assert!(deadline(Duration::from_secs(1)).unwrap() > boottime());
    }
}
