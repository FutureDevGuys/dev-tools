//! Owned Linux cgroup-v2 execution boundaries. The product verifies the host
//! realm, administrator approval, service-manager crash cleanup and parent
//! custody before creating a boundary. This module never authorizes a caller.

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
    stopping: bool,
    deadline: Duration,
    removed: bool,
    deadline_guard: Option<std::thread::JoinHandle<io::Result<()>>>,
}

impl ExecutionBoundary {
    pub fn create(parent: &File, name: &str, deadline: Duration) -> io::Result<Self> {
        if deadline.as_secs() > i64::MAX as u64
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
            let deadline_guard = start_deadline_guard(
                kill.try_clone()?,
                gate.event.as_fd().try_clone_to_owned()?,
                deadline,
            )?;
            Ok(Self {
                parent: parent.try_clone()?,
                directory,
                name: OsString::from(name),
                events,
                kill,
                gate,
                stopping: false,
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
        self.gate.event.as_fd().try_clone_to_owned()
    }

    pub fn permit(&self, ancestor_gates: Vec<OwnedFd>) -> io::Result<SpawnPermit> {
        if self.stopping || self.removed || boot_time()? >= self.deadline {
            return Err(denied());
        }
        let procs = open_control(&self.directory, "cgroup.procs", OFlags::WRONLY)?;
        let mut gates = ancestor_gates;
        if gates.len() > 64 {
            return Err(invalid());
        }
        gates.push(self.gate()?);
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
        if self.stopping || self.removed || boot_time()? >= self.deadline {
            return Err(denied());
        }
        Ok((
            open_control(&self.directory, "cgroup.procs", OFlags::WRONLY)?.into(),
            self.gate()?,
            self.deadline,
        ))
    }

    pub fn stop(&mut self) -> io::Result<()> {
        self.stopping = true;
        let gate = self.gate.revoke();
        let kill = if self.removed {
            Ok(())
        } else {
            self.kill.write_at(b"1", 0).and_then(|written| {
                if written == 1 {
                    Ok(())
                } else {
                    Err(io::ErrorKind::WriteZero.into())
                }
            })
        };
        let guard = if gate.is_ok() {
            self.deadline_guard.take().map_or(Ok(()), |guard| {
                guard
                    .join()
                    .map_err(|_| io::Error::other("native deadline guard failed"))?
            })
        } else {
            Err(denied())
        };
        gate.and(kill).and(guard)
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
        if !self.stopping
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

/// A small owned OS thread enforces each hard deadline independently of the
/// product actor, policy IO and request futures. The kernel BOOTTIME timer
/// includes suspension. The owner wakes and joins the guard before removal.
fn start_deadline_guard(
    kill: File,
    gate: OwnedFd,
    deadline: Duration,
) -> io::Result<std::thread::JoinHandle<io::Result<()>>> {
    use nix::sys::timerfd::{ClockId, TimerFd, TimerFlags, TimerSetTimeFlags};
    let timer = TimerFd::new(
        ClockId::CLOCK_BOOTTIME,
        TimerFlags::TFD_CLOEXEC | TimerFlags::TFD_NONBLOCK,
    )?;
    timer.set(
        nix::sys::timer::Expiration::OneShot(nix::sys::time::TimeSpec::from_duration(deadline)),
        TimerSetTimeFlags::TFD_TIMER_ABSTIME,
    )?;
    std::thread::Builder::new()
        .name("privilege-deadline".into())
        .stack_size(64 * 1024)
        .spawn(move || {
            let mut descriptors = [
                nix::poll::PollFd::new(gate.as_fd(), nix::poll::PollFlags::POLLIN),
                nix::poll::PollFd::new(timer.as_fd(), nix::poll::PollFlags::POLLIN),
            ];
            while let Err(nix::errno::Errno::EINTR) =
                nix::poll::poll(&mut descriptors, nix::poll::PollTimeout::NONE)
            {}
            // Close admission on timer readiness or a monitoring failure before
            // the kill. An externally revoked gate remains permanently readable.
            let revocation = loop {
                match nix::unistd::write(&gate, &1_u64.to_ne_bytes()) {
                    Ok(8) => break Ok(()),
                    Err(nix::errno::Errno::EINTR) => continue,
                    // A saturated event counter is already nonzero/readable.
                    Err(nix::errno::Errno::EAGAIN) => break Ok(()),
                    Err(error) => break Err(io::Error::from(error)),
                    Ok(_) => break Err(io::ErrorKind::WriteZero.into()),
                }
            };
            let killed = kill.write_at(b"1", 0).and_then(|count| {
                if count == 1 {
                    Ok(())
                } else {
                    Err(io::ErrorKind::WriteZero.into())
                }
            });
            revocation.and(killed)
        })
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
    pub controlling_terminal: bool,
    /// Extra owned descriptors retained at their existing numbers across exec.
    /// Keeping them open in the parent prevents collision with spawn internals.
    pub inherited_files: Vec<OwnedFd>,
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
                if context.controlling_terminal
                    && (nix::libc::setsid() < 0
                        || nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) != 0)
                {
                    return Err(io::Error::last_os_error());
                }
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
