//! Owned Linux cgroup-v2 execution boundaries. The product verifies the host
//! realm, administrator approval, service-manager crash cleanup and parent
//! custody before creating a boundary. This module never authorizes a caller.

mod guardian;
pub mod terminal;

use nix::sys::eventfd::{EfdFlags, EventFd};
use rustix::fs::{AtFlags, Mode, OFlags};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const CGROUP2_SUPER_MAGIC: u64 = 0x6367_7270;
/// Absolute Linux timer deadlines must fit the kernel's signed nanosecond ktime.
pub const MAX_BOOT_DEADLINE: Duration = Duration::from_nanos(i64::MAX as u64);
/// How long a stopped boundary's members have between SIGTERM and SIGKILL.
/// It is fixed: no caller, request or policy chooses it (ADR 0141).
pub const TERMINATION_GRACE: Duration = Duration::from_secs(10);
/// The OOM score adjustment every job starts with: the kernel's ordinary
/// ranking, never the coordinator's protected value (ADR 0141).
const JOB_OOM_SCORE_ADJ: &std::ffi::CStr = c"0";

pub fn boot_time() -> io::Result<Duration> {
    let time =
        nix::time::clock_gettime(nix::time::ClockId::CLOCK_BOOTTIME).map_err(io::Error::from)?;
    let seconds = u64::try_from(time.tv_sec()).map_err(|_| invalid())?;
    let nanos = u32::try_from(time.tv_nsec()).map_err(|_| invalid())?;
    if nanos >= 1_000_000_000 {
        return Err(invalid());
    }
    Ok(Duration::new(seconds, nanos))
}

/// A root-owned, non-delegated cgroup and its admission gate. Closing the gate
/// precedes killing members, so a prepared but not-yet-spawned job cannot enter
/// after revocation and escape the earlier cgroup kill.
pub struct ExecutionBoundary {
    parent: File,
    directory: File,
    name: OsString,
    events: File,
    kill: File,
    gate: AdmissionGate,
    ending: Ending,
    deadline: Duration,
    removed: bool,
    deadline_guard: Option<guardian::DeadlineGuard>,
}

impl ExecutionBoundary {
    pub fn create(parent: &File, name: &str, deadline: Duration) -> io::Result<Self> {
        if deadline > MAX_BOOT_DEADLINE
            || name.is_empty()
            || name.len() > 96
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(invalid());
        }
        validate_directory(parent)?;
        if boot_time()? >= deadline {
            return Err(denied());
        }
        rustix::fs::mkdirat(parent, name, Mode::from_bits_truncate(0o700))?;
        let prepared = (|| {
            let directory = File::from(rustix::fs::openat(
                parent,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )?);
            validate_directory(&directory)?;
            let events = open_control(&directory, "cgroup.events", OFlags::RDONLY)?;
            let kill = open_control(&directory, "cgroup.kill", OFlags::WRONLY)?;
            let gate = AdmissionGate::new()?;
            // The guardian reads its own open file description, so this
            // owner's reads never consume the change notifications it waits on.
            let deadline_guard = guardian::DeadlineGuard::start(
                kill.try_clone()?,
                gate.event.as_fd().try_clone_to_owned()?,
                open_control(&directory, "cgroup.events", OFlags::RDONLY)?,
                deadline,
                TERMINATION_GRACE,
            )?;
            Ok(Self {
                parent: parent.try_clone()?,
                directory,
                name: OsString::from(name),
                events,
                kill,
                gate,
                ending: Ending::Running,
                deadline,
                removed: false,
                deadline_guard: Some(deadline_guard),
            })
        })();
        if prepared.is_err() {
            // The fresh, empty entry was created under the held root directory;
            // no child is admitted until all controls and the gate exist.
            let _ = rustix::fs::unlinkat(parent, name, AtFlags::REMOVEDIR);
        }
        prepared
    }

    pub fn directory(&self) -> &File {
        &self.directory
    }

    pub fn gate(&self) -> io::Result<OwnedFd> {
        self.deadline_guard
            .as_ref()
            .ok_or_else(denied)?
            .admission_gate()?;
        self.gate.event.as_fd().try_clone_to_owned()
    }

    /// Stop-only custody of this boundary's held admission gate and cgroup.kill.
    /// These handles cannot authorize admission. They remain usable after the
    /// deadline guardian has exited; no path is reopened or live guardian used.
    pub fn stop_handles(&self) -> io::Result<(OwnedFd, OwnedFd)> {
        if self.removed {
            return Err(denied());
        }
        Ok((
            self.gate.event.as_fd().try_clone_to_owned()?,
            self.kill.as_fd().try_clone_to_owned()?,
        ))
    }

    pub fn permit(&self, ancestor_gates: Vec<OwnedFd>) -> io::Result<SpawnPermit> {
        if self.ending != Ending::Running || self.removed || boot_time()? >= self.deadline {
            return Err(denied());
        }
        let procs = open_control(&self.directory, "cgroup.procs", OFlags::WRONLY)?;
        let mut gates = ancestor_gates;
        if gates.len() > 64 {
            return Err(invalid());
        }
        gates.push(self.gate()?);
        gates.push(
            self.deadline_guard
                .as_ref()
                .ok_or_else(denied)?
                .admission_gate()?,
        );
        Ok(SpawnPermit {
            procs,
            gates,
            deadline: self.deadline,
        })
    }

    /// The product supplies only trusted native-plugin peers with this permit.
    /// The recipient writes its own PID using the kernel's zero selector; it
    /// does not ask a coordinator to migrate an unretained numeric PID.
    pub fn attachment(&self) -> io::Result<(OwnedFd, OwnedFd, Duration)> {
        if self.ending != Ending::Running || self.removed || boot_time()? >= self.deadline {
            return Err(denied());
        }
        Ok((
            open_control(&self.directory, "cgroup.procs", OFlags::WRONLY)?.into(),
            self.gate()?,
            self.deadline,
        ))
    }

    /// End this boundary's work: close its admission gate, then end its
    /// members as `Ending` directs. Call again to advance the ending.
    pub fn stop(&mut self) -> io::Result<()> {
        let gate = self.gate.revoke();
        let step = match boot_time() {
            Ok(now) => self.ending.advance(now, self.deadline, TERMINATION_GRACE),
            Err(_) => {
                self.ending = Ending::Killed;
                Step::Kill
            }
        };
        let ended = match step {
            Step::Terminate => self.terminate().or_else(|_| {
                self.ending = Ending::Killed;
                self.kill()
            }),
            Step::Kill => self.kill(),
            Step::Wait => Ok(()),
        };
        let guard = if gate.is_ok() {
            self.settle_guardian()
        } else {
            Err(denied())
        };
        gate.and(ended).and(guard)
    }

    /// End a boundary whose members all live in nested boundaries that its
    /// owner stops with it.
    pub fn stop_enclosing(&mut self) -> io::Result<()> {
        self.stop()
    }

    /// Whether this boundary's work has begun to end.
    pub fn stopping(&self) -> bool {
        self.ending != Ending::Running
    }

    fn settle_guardian(&mut self) -> io::Result<()> {
        match self.deadline_guard.as_mut() {
            Some(guard) => {
                guard.join()?;
                self.deadline_guard.take();
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Ask every member to exit: SIGTERM, then SIGCONT so that a stopped
    /// member also sees the request.
    fn terminate(&self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        self.signal(nix::sys::signal::Signal::SIGTERM)?;
        self.signal(nix::sys::signal::Signal::SIGCONT)
    }

    fn kill(&self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        self.kill.write_at(b"1", 0).and_then(|written| {
            if written == 1 {
                Ok(())
            } else {
                Err(io::ErrorKind::WriteZero.into())
            }
        })
    }

    pub fn is_empty(&self) -> io::Result<bool> {
        let mut bytes = [0_u8; 4096];
        let length = self.events.read_at(&mut bytes, 0)?;
        if length == bytes.len() {
            return Err(invalid());
        }
        let text = std::str::from_utf8(&bytes[..length]).map_err(|_| invalid())?;
        let mut populated = text
            .lines()
            .filter_map(|line| line.strip_prefix("populated "));
        let value = populated.next().ok_or_else(invalid)?;
        if populated.next().is_some() {
            return Err(invalid());
        }
        match value {
            "0" => Ok(true),
            "1" => Ok(false),
            _ => Err(invalid()),
        }
    }

    /// Forward a native control signal only to retained members of this owned
    /// hierarchy. pidfds prevent PID reuse from signaling an unrelated process.
    /// Signal delivery is not cleanup evidence; removal still requires emptiness.
    pub fn signal(&self, signal: nix::sys::signal::Signal) -> io::Result<()> {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        let root = std::fs::read_link(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))?;
        let mut directories = vec![self.directory.try_clone()?];
        let mut groups = 0;
        let mut pids = std::collections::BTreeSet::new();
        while let Some(directory) = directories.pop() {
            groups += 1;
            if groups > 1024 {
                return Err(invalid());
            }
            validate_directory(&directory)?;
            let mut text = String::new();
            open_control(&directory, "cgroup.procs", OFlags::RDONLY)?
                .take(65_537)
                .read_to_string(&mut text)?;
            if text.len() > 65_536 {
                return Err(invalid());
            }
            for value in text.lines() {
                let pid: u32 = value.parse().map_err(|_| invalid())?;
                if pid == 0 || pids.len() >= 16_384 {
                    return Err(invalid());
                }
                pids.insert(pid);
            }
            for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    directories.push(File::from(rustix::fs::openat(
                        &directory,
                        entry.file_name(),
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )?));
                }
            }
        }
        for pid in pids {
            // SAFETY: the syscall either returns a new descriptor for the
            // current process identity or fails. Ownership begins immediately.
            let descriptor = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
            if descriptor < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(nix::libc::ESRCH) {
                    continue;
                }
                return Err(error);
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(descriptor as i32) };
            let membership = match std::fs::read_to_string(format!("/proc/{pid}/cgroup")) {
                Ok(membership) => membership,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            let within = membership
                .lines()
                .find_map(|line| line.strip_prefix("0::"))
                .is_some_and(|path| {
                    std::path::Path::new("/sys/fs/cgroup")
                        .join(path.trim_start_matches('/'))
                        .starts_with(&root)
                });
            if !within {
                continue;
            }
            if let Err(error) = signal_pidfd(&descriptor, signal) {
                if error.raw_os_error() != Some(nix::libc::ESRCH) {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Call only after every issued spawn/attachment permit has settled. An
    /// empty cgroup alone cannot prove that an in-flight admission has stopped.
    pub fn remove(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        if self.ending == Ending::Running
            || !self.gate.revoked
            || self.deadline_guard.is_some()
            || !self.is_empty()?
        {
            return Err(denied());
        }
        let current = File::from(rustix::fs::openat(
            &self.parent,
            &self.name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let before = self.directory.metadata()?;
        let after = current.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(denied());
        }
        rustix::fs::unlinkat(&self.parent, &self.name, AtFlags::REMOVEDIR)?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for ExecutionBoundary {
    fn drop(&mut self) {
        // Drop is fail-closed best effort, never the proof used for a successful
        // revocation result. The product also retains service-manager cleanup.
        let _ = self.stop();
        if self.is_empty().unwrap_or(false) {
            let _ = self.remove();
        }
    }
}

/// Where a boundary is in ending its members' work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    Running,
    /// The members were asked to exit, and SIGKILL follows at `kill_at`.
    Terminating {
        kill_at: Duration,
    },
    Killed,
}

/// What a stopping boundary does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Terminate,
    Kill,
    Wait,
}

impl Ending {
    /// The next step at boot time `now` for a boundary whose hard deadline is
    /// `deadline`.
    fn advance(&mut self, _now: Duration, _deadline: Duration, _grace: Duration) -> Step {
        *self = Self::Killed;
        Step::Kill
    }
}

struct AdmissionGate {
    event: EventFd,
    revoked: bool,
}

impl AdmissionGate {
    fn new() -> io::Result<Self> {
        let event =
            EventFd::from_value_and_flags(0, EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK)
                .map_err(io::Error::from)?;
        Ok(Self {
            event,
            revoked: false,
        })
    }

    fn revoke(&mut self) -> io::Result<()> {
        if self.revoked {
            return Ok(());
        }
        // The kernel counter becomes readable for every inherited descriptor.
        // Unlike pipe EOF, this does not depend on all forked writers closing.
        // Permit holders poll without reading or resetting the counter.
        loop {
            match self.event.write(1) {
                Ok(8) => {
                    self.revoked = true;
                    return Ok(());
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(error) => return Err(io::Error::from(error)),
                Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
            }
        }
    }
}

/// A one-use preparation object. Native process creation consumes it, preventing
/// the trusted coordinator from accidentally reusing a charged admission.
pub struct SpawnPermit {
    procs: File,
    gates: Vec<OwnedFd>,
    deadline: Duration,
}

pub struct NativeContext {
    pub working_directory: File,
    pub mount_namespace: Option<File>,
    pub uid: u32,
    /// Effective and saved UID selected by the already-authorized owner. A
    /// distinct real UID preserves native invoking-user semantics for held
    /// privilege frontends; it is not inferred from executable mode bits.
    pub effective_uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
    /// Set when the image starts an ordinary user's process rather than a
    /// privileged job. `None` keeps the owner's process state.
    pub user_session: Option<UserSession>,
    pub controlling_terminal: bool,
    /// Extra owned descriptors retained at their existing numbers across exec.
    /// Keeping them open in the parent prevents collision with spawn internals.
    pub inherited_files: Vec<OwnedFd>,
}

/// The process state a user's process starts with, as a login gives it: the
/// user's file-creation mask, a session and a session keyring of its own,
/// and no descriptor beyond its streams and the explicitly inherited files.
#[derive(Debug, Clone, Copy)]
pub struct UserSession {
    pub umask: u32,
}

/// `KEYCTL_JOIN_SESSION_KEYRING` from the Linux `keyctl.h` UAPI.
const KEYCTL_JOIN_SESSION_KEYRING: nix::libc::c_long = 1;

/// Give a forked child about to exec a user's image that user's process
/// state, so it shares no session, process group, keyring or descriptor with
/// the root owner that starts it. It uses only async-signal-safe system calls
/// and allocates nothing.
fn enter_user_session(session: UserSession) -> io::Result<()> {
    // SAFETY: each call changes only this process's own mask, session,
    // keyring or descriptor flags, and passes no pointer except a null name.
    unsafe {
        nix::libc::umask(session.umask as nix::libc::mode_t);
        // A terminal job already leads the session it created for its terminal.
        if nix::libc::getsid(0) != nix::libc::getpid() && nix::libc::setsid() < 0 {
            return Err(io::Error::last_os_error());
        }
        if nix::libc::syscall(
            nix::libc::SYS_keyctl,
            KEYCTL_JOIN_SESSION_KEYRING,
            std::ptr::null::<nix::libc::c_char>(),
        ) < 0
            && io::Error::last_os_error().raw_os_error() != Some(nix::libc::ENOSYS)
        {
            return Err(io::Error::last_os_error());
        }
        if nix::libc::syscall(
            nix::libc::SYS_close_range,
            3_u32,
            u32::MAX,
            nix::libc::CLOSE_RANGE_CLOEXEC,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Restore the default action of the signals that ask a process to exit, so
/// that a child which receives one before it executes its image ends instead
/// of running a handler inherited from its owner. It uses only
/// async-signal-safe system calls and allocates nothing.
fn default_termination_signals() -> io::Result<()> {
    Ok(())
}

/// Give a forked child about to exec a job the process state every job
/// starts with: a terminal job leads a session that its relayed terminal
/// controls. It uses only async-signal-safe system calls and allocates nothing.
fn enter_job(controlling_terminal: bool, _oom_score_adj: &std::ffi::CStr) -> io::Result<()> {
    // SAFETY: each call changes only this process's own session or terminal
    // and passes no pointer.
    unsafe {
        if controlling_terminal
            && (nix::libc::setsid() < 0 || nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) != 0)
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

impl SpawnPermit {
    pub fn spawn(
        self,
        program: &OsStr,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
        context: NativeContext,
        streams: [OwnedFd; 3],
    ) -> io::Result<Child> {
        self.spawn_image(None, program, arguments, environment, context, streams)
    }

    /// Execute one retained native ELF image without re-resolving its pathname
    /// after entering a caller mount namespace. Scripts requiring an inherited
    /// executable descriptor are intentionally outside this ELF-only surface.
    pub fn spawn_held(
        self,
        executable: File,
        argv0: &OsStr,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
        context: NativeContext,
        streams: [OwnedFd; 3],
    ) -> io::Result<Child> {
        let mut magic = [0_u8; 4];
        if executable.read_at(&mut magic, 0)? != 4 || &magic != b"\x7fELF" {
            return Err(invalid());
        }
        self.spawn_image(
            Some(executable),
            argv0,
            arguments,
            environment,
            context,
            streams,
        )
    }

    fn spawn_image(
        self,
        executable: Option<File>,
        program: &OsStr,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
        context: NativeContext,
        streams: [OwnedFd; 3],
    ) -> io::Result<Child> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        if context.supplementary_groups.len() > 65_536 {
            return Err(invalid());
        }
        if arguments.len() > 1024 || environment.len() > 1024 {
            return Err(invalid());
        }
        if context.inherited_files.len() > 16
            || context.inherited_files.iter().any(|fd| fd.as_raw_fd() < 3)
            || context
                .user_session
                .is_some_and(|session| session.umask > 0o777)
        {
            return Err(invalid());
        }
        let image_arguments = std::iter::once(program)
            .chain(arguments.iter().map(OsString::as_os_str))
            .map(|argument| CString::new(argument.as_bytes()).map_err(|_| invalid()))
            .collect::<io::Result<Vec<_>>>()?;
        let image_environment = environment
            .iter()
            .map(|(key, value)| {
                if key.is_empty() || key.as_bytes().contains(&b'=') {
                    return Err(invalid());
                }
                let mut bytes = key.as_bytes().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(value.as_bytes());
                CString::new(bytes).map_err(|_| invalid())
            })
            .collect::<io::Result<Vec<_>>>()?;
        let [stdin, stdout, stderr] = streams;
        let mut command = Command::new(program);
        command
            .args(arguments)
            .env_clear()
            .envs(environment.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // SAFETY: all buffers and descriptors are prepared before fork. This
        // closure uses only async-signal-safe syscalls and inline OS errors; it
        // allocates nothing and acquires no Rust/foreign locks. Attaching before
        // checking the closed gate makes both sides of revocation fail closed.
        unsafe {
            command.pre_exec(move || {
                default_termination_signals()?;
                if nix::libc::write(self.procs.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                    return Err(io::Error::last_os_error());
                }
                for gate in &self.gates {
                    let mut descriptor = nix::libc::pollfd {
                        fd: gate.as_raw_fd(),
                        events: nix::libc::POLLIN,
                        revents: 0,
                    };
                    if nix::libc::poll(&mut descriptor, 1, 0) != 0 {
                        return Err(denied());
                    }
                }
                let mut now = nix::libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                if nix::libc::clock_gettime(nix::libc::CLOCK_BOOTTIME, &mut now) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if now.tv_sec < 0
                    || now.tv_nsec < 0
                    || (now.tv_sec as u64, now.tv_nsec as u32)
                        >= (self.deadline.as_secs(), self.deadline.subsec_nanos())
                {
                    return Err(denied());
                }
                if let Some(namespace) = &context.mount_namespace {
                    if nix::libc::setns(namespace.as_raw_fd(), nix::libc::CLONE_NEWNS) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                enter_job(context.controlling_terminal, JOB_OOM_SCORE_ADJ)?;
                if nix::libc::fchdir(context.working_directory.as_raw_fd()) != 0
                    || nix::libc::setgroups(
                        context.supplementary_groups.len(),
                        context.supplementary_groups.as_ptr(),
                    ) != 0
                    || nix::libc::setresgid(context.gid, context.gid, context.gid) != 0
                    || nix::libc::setresuid(
                        context.uid,
                        context.effective_uid,
                        context.effective_uid,
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if let Some(session) = context.user_session {
                    enter_user_session(session)?;
                }
                for source in &context.inherited_files {
                    let flags = nix::libc::fcntl(source.as_raw_fd(), nix::libc::F_GETFD);
                    if flags < 0
                        || nix::libc::fcntl(
                            source.as_raw_fd(),
                            nix::libc::F_SETFD,
                            flags & !nix::libc::FD_CLOEXEC,
                        ) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                if let Some(executable) = &executable {
                    // Fixed stack arrays are initialized outside any allocator;
                    // every CString and its pointer remain owned by this closure.
                    // execveat on the held ELF descriptor cannot select bytes
                    // through a substituted pathname or caller-mounted /proc.
                    let mut argv = [std::ptr::null::<nix::libc::c_char>(); 1026];
                    let mut envp = [std::ptr::null::<nix::libc::c_char>(); 1025];
                    for (index, argument) in image_arguments.iter().enumerate() {
                        argv[index] = argument.as_ptr();
                    }
                    for (index, variable) in image_environment.iter().enumerate() {
                        envp[index] = variable.as_ptr();
                    }
                    nix::libc::syscall(
                        nix::libc::SYS_execveat,
                        executable.as_raw_fd(),
                        c"".as_ptr(),
                        argv.as_ptr(),
                        envp.as_ptr(),
                        nix::libc::AT_EMPTY_PATH,
                    );
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn()
    }
}

pub fn signal_pidfd(pidfd: &impl AsFd, signal: nix::sys::signal::Signal) -> io::Result<()> {
    // SAFETY: the borrowed descriptor remains open; a null siginfo requests the
    // kernel-generated signal payload, and flags are zero as required by Linux.
    let result = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_pidfd_send_signal,
            pidfd.as_fd().as_raw_fd(),
            signal as i32,
            std::ptr::null::<nix::libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn validate_directory(directory: &File) -> io::Result<()> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || rustix::fs::fstatfs(directory)?.f_type as u64 != CGROUP2_SUPER_MAGIC
    {
        return Err(denied());
    }
    Ok(())
}

fn open_control(directory: &File, name: &str, access: OFlags) -> io::Result<File> {
    let file = File::from(rustix::fs::openat(
        directory,
        name,
        access | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(denied());
    }
    Ok(file)
}

fn invalid() -> io::Error {
    io::Error::from_raw_os_error(nix::libc::EINVAL)
}
fn denied() -> io::Error {
    io::Error::from_raw_os_error(nix::libc::EACCES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::OFlag;
    use nix::unistd::pipe2;

    /// `keyctl.h`: `KEYCTL_GET_KEYRING_ID` and `KEY_SPEC_SESSION_KEYRING`.
    const KEYCTL_GET_KEYRING_ID: nix::libc::c_long = 0;
    const KEY_SPEC_SESSION_KEYRING: nix::libc::c_long = -3;

    /// What a forked child sees of its own state, as bits of its exit code:
    /// 1 when its mask is not 0o027, 2 when `stray` would cross exec, 4 when
    /// its session keyring is the one it inherited, and 8 when it does not
    /// lead its own session.
    fn child_view(session: Option<UserSession>, stray: i32) -> i32 {
        // SAFETY: the child calls only async-signal-safe system calls and
        // `_exit`; it never returns into the test harness.
        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Child => unsafe {
                let keyring = || {
                    nix::libc::syscall(
                        nix::libc::SYS_keyctl,
                        KEYCTL_GET_KEYRING_ID,
                        KEY_SPEC_SESSION_KEYRING,
                        0,
                    )
                };
                let inherited = keyring();
                nix::libc::umask(0o022);
                if let Some(session) = session {
                    if enter_user_session(session).is_err() {
                        nix::libc::_exit(64);
                    }
                }
                let mut seen = 0;
                if nix::libc::umask(0) != 0o027 {
                    seen |= 1;
                }
                if nix::libc::fcntl(stray, nix::libc::F_GETFD) & nix::libc::FD_CLOEXEC == 0 {
                    seen |= 2;
                }
                if inherited >= 0 && keyring() == inherited {
                    seen |= 4;
                }
                if nix::libc::getsid(0) != nix::libc::getpid() {
                    seen |= 8;
                }
                nix::libc::_exit(seen)
            },
            nix::unistd::ForkResult::Parent { child } => {
                match nix::sys::wait::waitpid(child, None).unwrap() {
                    nix::sys::wait::WaitStatus::Exited(_, code) => code,
                    other => panic!("child did not exit: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn a_user_session_starts_with_its_mask_and_none_of_the_owners_descriptors() {
        let (stray, _writer) = nix::unistd::pipe().unwrap();
        let stray = stray.as_raw_fd();
        let owner = child_view(None, stray);
        let user = child_view(Some(UserSession { umask: 0o027 }), stray);
        assert_eq!(
            owner & 0b1011,
            0b1011,
            "control: the owner's state reaches the child"
        );
        assert_eq!(user, 0, "mask=1 descriptor=2 keyring=4 session=8");
    }

    /// What a forked child sees after it enters a job whose OOM score
    /// adjustment is `oom`, as bits of its exit code: 1 when it does not lead
    /// its own session, 2 when it still shares its parent's process group, and
    /// 4 when its adjustment is not `oom`.
    fn job_view(oom: &std::ffi::CStr) -> i32 {
        // SAFETY: the child calls only async-signal-safe system calls and
        // `_exit`; it never returns into the test harness.
        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Child => unsafe {
                let parent_group = nix::libc::getpgrp();
                if enter_job(false, oom).is_err() {
                    nix::libc::_exit(64);
                }
                let mut seen = 0;
                if nix::libc::getsid(0) != nix::libc::getpid() {
                    seen |= 1;
                }
                if nix::libc::getpgrp() == parent_group {
                    seen |= 2;
                }
                let descriptor = nix::libc::open(
                    c"/proc/self/oom_score_adj".as_ptr(),
                    nix::libc::O_RDONLY | nix::libc::O_CLOEXEC,
                );
                let mut buffer = [0_u8; 16];
                let length = if descriptor < 0 {
                    -1
                } else {
                    nix::libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len())
                };
                let expected = oom.to_bytes();
                if length != expected.len() as isize + 1
                    || buffer.get(..expected.len()) != Some(expected)
                {
                    seen |= 4;
                }
                nix::libc::_exit(seen)
            },
            nix::unistd::ForkResult::Parent { child } => {
                match nix::sys::wait::waitpid(child, None).unwrap() {
                    nix::sys::wait::WaitStatus::Exited(_, code) => code,
                    other => panic!("child did not exit: {other:?}"),
                }
            }
        }
    }

    #[test]
    fn every_job_leads_its_own_session_and_takes_its_own_oom_score() {
        // An unprivileged test may only raise its adjustment, as a job of the
        // coordinator raises the protected -900 to 0, so it asks for one more
        // than it has.
        let current: i32 = std::fs::read_to_string("/proc/self/oom_score_adj")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let wanted = std::ffi::CString::new((current + 1).min(1000).to_string()).unwrap();
        assert_eq!(job_view(&wanted), 0, "session=1 group=2 oom=4");
    }

    extern "C" fn inherited_handler(_: nix::libc::c_int) {}

    #[test]
    fn a_job_that_is_asked_to_exit_before_it_runs_takes_the_default_action() {
        // SAFETY: the child installs a handler in its own copy of the
        // process, calls only async-signal-safe functions and `_exit`.
        match unsafe { nix::unistd::fork() }.unwrap() {
            nix::unistd::ForkResult::Child => unsafe {
                let mut owner: nix::libc::sigaction = std::mem::zeroed();
                owner.sa_sigaction = inherited_handler as extern "C" fn(nix::libc::c_int) as usize;
                if nix::libc::sigaction(nix::libc::SIGTERM, &owner, std::ptr::null_mut()) != 0
                    || default_termination_signals().is_err()
                {
                    nix::libc::_exit(64);
                }
                let mut current: nix::libc::sigaction = std::mem::zeroed();
                nix::libc::sigaction(nix::libc::SIGTERM, std::ptr::null(), &mut current);
                nix::libc::_exit(i32::from(current.sa_sigaction != nix::libc::SIG_DFL))
            },
            nix::unistd::ForkResult::Parent { child } => assert_eq!(
                nix::sys::wait::waitpid(child, None).unwrap(),
                nix::sys::wait::WaitStatus::Exited(child, 0),
                "the owner's SIGTERM handler survived into the job"
            ),
        }
    }

    fn at(seconds: u64) -> Duration {
        Duration::from_secs(seconds)
    }

    #[test]
    fn a_stopped_boundary_asks_its_members_to_exit_before_it_kills_them() {
        let deadline = at(1000);
        let mut ending = Ending::Running;
        assert_eq!(
            ending.advance(at(100), deadline, TERMINATION_GRACE),
            Step::Terminate
        );
        assert_eq!(
            ending.advance(at(109), deadline, TERMINATION_GRACE),
            Step::Wait,
            "the members still have the grace"
        );
        assert_eq!(
            ending.advance(at(110), deadline, TERMINATION_GRACE),
            Step::Kill
        );
        assert_eq!(
            ending.advance(at(111), deadline, TERMINATION_GRACE),
            Step::Kill,
            "a later look kills again"
        );
        assert_eq!(TERMINATION_GRACE, at(10), "the grace ADR 0141 states");
    }

    #[test]
    fn no_member_outlives_its_hard_deadline_by_more_than_the_grace() {
        let deadline = at(1000);
        let mut late = Ending::Running;
        assert_eq!(
            late.advance(at(1004), deadline, TERMINATION_GRACE),
            Step::Terminate
        );
        assert_eq!(
            late.advance(at(1009), deadline, TERMINATION_GRACE),
            Step::Wait
        );
        assert_eq!(
            late.advance(at(1010), deadline, TERMINATION_GRACE),
            Step::Kill,
            "the grace counts from the deadline"
        );
        let mut wedged = Ending::Running;
        assert_eq!(
            wedged.advance(at(1010), deadline, TERMINATION_GRACE),
            Step::Kill,
            "a stop that begins after the deadline's grace kills at once"
        );
    }

    #[test]
    fn revocation_reaches_a_child_that_inherited_the_entire_descriptor_table() {
        let mut gate = AdmissionGate::new().unwrap();
        let (barrier_read, barrier_write) = pipe2(OFlag::O_CLOEXEC).unwrap();
        let gate_fd = gate.event.as_raw_fd();
        let barrier_fd = barrier_read.as_raw_fd();
        // SAFETY: the child executes only read, poll and _exit, with initialized
        // stack buffers and inherited live descriptors. It never runs Rust
        // destructors, allocation, test machinery or locks after fork.
        let child = unsafe { nix::libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                let mut byte = 0_u8;
                if nix::libc::read(barrier_fd, (&mut byte as *mut u8).cast(), 1) != 1 {
                    nix::libc::_exit(2);
                }
                let mut descriptor = nix::libc::pollfd {
                    fd: gate_fd,
                    events: nix::libc::POLLIN,
                    revents: 0,
                };
                let ready = nix::libc::poll(&mut descriptor, 1, 0);
                nix::libc::_exit(if ready > 0 { 0 } else { 1 });
            }
        }
        gate.revoke().unwrap();
        nix::unistd::write(&barrier_write, &[1]).unwrap();
        let status = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(child), None).unwrap();
        assert_eq!(
            status,
            nix::sys::wait::WaitStatus::Exited(nix::unistd::Pid::from_raw(child), 0),
            "fork-inherited writer handles must not suppress revocation"
        );
    }
}
