//! A request-owned native PolicyKit agent for interactive processes without a
//! desktop/session agent. Password I/O belongs only to pkttyagent and /dev/tty.

use super::Failure;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::fs::File;
use std::io::IsTerminal;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) struct TtyAgent(Child);

impl TtyAgent {
    pub(super) fn for_request() -> Result<Option<Self>, Failure> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        Self::for_process(std::process::id())
    }

    /// Pipe-mode workloads retain their streams while their authenticated
    /// dispatcher owns the native terminal agent for this exact supervisor.
    pub(crate) fn for_workload_request(
        peer: &crate::linux_admission::LinuxPeerEvidence,
        installed_core: &std::path::Path,
    ) -> Result<Option<Self>, Failure> {
        if !std::io::stdin().is_terminal()
            || (std::io::stdout().is_terminal() && std::io::stderr().is_terminal())
        {
            return Ok(None);
        }
        if !nix::unistd::getuid().is_root() || !nix::unistd::geteuid().is_root() || peer.uid == 0 {
            return Err(Failure::AuthorityDenied);
        }
        let image = File::open(installed_core).map_err(|_| Failure::NativeUnavailable)?;
        validate_workload_subject(peer, &image)?;
        let agent = Self::for_process(peer.pid)?;
        validate_workload_subject(peer, &image)?;
        Ok(agent)
    }

    fn for_process(pid: u32) -> Result<Option<Self>, Failure> {
        let terminal = match File::options()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOCTTY)
            .open("/dev/tty")
        {
            Ok(terminal) => terminal,
            // Inherited terminal stdin does not give a pipe-mode service a
            // controlling TTY. PolicyKit may use its registered native agent.
            Err(error) if error.raw_os_error() == Some(nix::libc::ENXIO) => return Ok(None),
            Err(_) => return Err(Failure::NativeUnavailable),
        };
        if nix::unistd::tcgetpgrp(&terminal).map_err(|_| Failure::NativeUnavailable)?
            != nix::unistd::getpgrp()
        {
            return Err(Failure::NativeUnavailable);
        }
        let program = std::path::Path::new("/usr/bin/pkttyagent");
        crate::setup::validate_root_owned_executable(program, "native PolicyKit terminal agent")
            .map_err(|_| Failure::NativeUnavailable)?;
        let stat =
            super::native::read_bounded(std::path::Path::new(&format!("/proc/{pid}/stat")), 8192)?;
        let start_time = process_start_time(&stat)?;
        let mut command = Command::new(program);
        configure_subject(&mut command, pid, start_time);
        command
            .env_clear()
            .env("LANG", "C.UTF-8")
            .stdin(Stdio::from(
                terminal
                    .try_clone()
                    .map_err(|_| Failure::NativeUnavailable)?,
            ))
            .stdout(Stdio::from(
                terminal
                    .try_clone()
                    .map_err(|_| Failure::NativeUnavailable)?,
            ))
            .stderr(Stdio::from(terminal));
        Self::spawn_ready(command, Duration::from_secs(5)).map(Some)
    }

    fn spawn_ready(mut command: Command, timeout: Duration) -> Result<Self, Failure> {
        let (read, write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)
            .map_err(|_| Failure::NativeUnavailable)?;
        // Keep the source away from fixed child FD 3, regardless of parent FD
        // allocation. Only the child copy survives exec, until native readiness.
        let notify = nix::fcntl::fcntl(&write, nix::fcntl::FcntlArg::F_DUPFD_CLOEXEC(4))
            .map_err(|_| Failure::NativeUnavailable)?;
        use std::os::fd::FromRawFd;
        // SAFETY: successful F_DUPFD_CLOEXEC created one new owned descriptor.
        let notify = unsafe { OwnedFd::from_raw_fd(notify) };
        drop(write);
        let parent = nix::unistd::getpid().as_raw();
        let notify_fd = notify.as_raw_fd();
        // SAFETY: only async-signal-safe raw syscalls run between fork and exec.
        // The parent owns notify through spawn; FD 3 is the child's sole handoff.
        unsafe {
            command.pre_exec(move || {
                if nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) != 0
                    || nix::libc::dup2(notify_fd, 3) != 3
                {
                    return Err(std::io::Error::last_os_error());
                }
                if nix::libc::getppid() != parent {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                Ok(())
            });
        }
        let mut agent = Self(command.spawn().map_err(|_| Failure::NativeUnavailable)?);
        drop(notify);
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(Failure::NativeUnavailable)?;
            let mut descriptor = [PollFd::new(read.as_fd(), PollFlags::POLLIN)];
            match poll(
                &mut descriptor,
                PollTimeout::try_from(remaining).map_err(|_| Failure::NativeUnavailable)?,
            ) {
                Err(nix::errno::Errno::EINTR) => continue,
                Ok(ready) if ready > 0 => {
                    let mut byte = [0_u8];
                    if nix::unistd::read(&read, &mut byte)
                        .map_err(|_| Failure::NativeUnavailable)?
                        == 0
                        && agent
                            .0
                            .try_wait()
                            .map_err(|_| Failure::NativeUnavailable)?
                            .is_none()
                    {
                        return Ok(agent);
                    }
                    return Err(Failure::NativeUnavailable);
                }
                _ => return Err(Failure::NativeUnavailable),
            }
        }
    }
}

fn configure_subject(command: &mut Command, pid: u32, start_time: u64) {
    // PolicyKit's fallback lookup exits before selecting a process fallback
    // when no login session exists. Register for this exact process instead;
    // this neither replaces nor modifies another process/session's agent.
    command.args([
        "--process",
        &format!("{pid},{start_time}"),
        "--notify-fd",
        "3",
    ]);
}

impl Drop for TtyAgent {
    fn drop(&mut self) {
        // This is our directly owned native UI process. Killing
        // it neither grants authority nor affects another agent. Reap before
        // returning; PDEATHSIG handles abrupt request-process termination.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn validate_workload_subject(
    peer: &crate::linux_admission::LinuxPeerEvidence,
    expected_image: &File,
) -> Result<(), Failure> {
    if peer.pid == 0
        || !super::native::alive(peer.peer_pidfd())
        || crate::linux_admission::read_unified_cgroup(peer.pid)
            .map_err(|_| Failure::AuthorityDenied)?
            != peer.unified_cgroup
    {
        return Err(Failure::AuthorityDenied);
    }
    let image =
        File::open(format!("/proc/{}/exe", peer.pid)).map_err(|_| Failure::AuthorityDenied)?;
    if !super::native::same_file(&image, expected_image)?
        || !super::native::alive(peer.peer_pidfd())
    {
        return Err(Failure::AuthorityDenied);
    }
    Ok(())
}

fn process_start_time(stat: &[u8]) -> Result<u64, Failure> {
    let end = stat
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or(Failure::NativeUnavailable)?;
    std::str::from_utf8(&stat[end + 1..])
        .ok()
        .and_then(|tail| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or(Failure::NativeUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_is_process_scoped_and_usable_without_a_login_session() {
        let mut command = Command::new("/usr/bin/pkttyagent");
        configure_subject(&mut command, 42, 9876);
        let arguments: Vec<_> = command.get_args().collect();
        assert_eq!(arguments, ["--process", "42,9876", "--notify-fd", "3"]);
    }

    #[test]
    fn process_subject_uses_start_time_despite_parentheses_in_command_name() {
        let stat = format!("42 (name with ) characters) S {} 9876 0", "0 ".repeat(18));
        assert_eq!(process_start_time(stat.as_bytes()), Ok(9876));
        assert!(process_start_time(b"42 (truncated)").is_err());
    }

    #[test]
    fn terminal_input_without_controlling_tty_defers_and_subject_custody_is_retained() {
        use std::os::fd::FromRawFd;
        use std::os::unix::net::{UnixListener, UnixStream};

        const SUBJECT_SOCKET: &str = "DEV_AUTH_TTY_AGENT_SUBJECT_FIXTURE";
        const TEST: &str = "privilege::grants::tty_agent::tests::terminal_input_without_controlling_tty_defers_and_subject_custody_is_retained";
        if let Some(path) = std::env::var_os(SUBJECT_SOCKET) {
            assert!(std::io::stdin().is_terminal());
            assert!(!std::io::stdout().is_terminal());
            assert!(TtyAgent::for_request().unwrap().is_none());
            let mut stream = UnixStream::connect(path).unwrap();
            let _ = std::io::Read::read_exact(&mut stream, &mut [0_u8]);
            return;
        }

        struct Subject(Child);
        impl Drop for Subject {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("subject.sock");
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty initializes these two descriptor outputs, and every
        // optional terminal/name pointer is null. No terminal data is captured.
        assert_eq!(
            unsafe {
                nix::libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: successful openpty created two new, exclusively owned FDs.
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
        for descriptor in [&master, &slave] {
            nix::fcntl::fcntl(
                descriptor,
                nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
            )
            .unwrap();
        }
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST])
            .env(SUBJECT_SOCKET, &path)
            .stdin(Stdio::from(slave))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: this isolated child only changes its native session before
        // exec. The already open terminal stdin cannot become its controlling TTY.
        unsafe {
            command.pre_exec(|| {
                if nix::libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut subject = Subject(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "native terminal fallback did not finish"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept native subject: {error}"),
            }
        };
        let peer = crate::linux_admission::peer_evidence(&stream).unwrap();
        let image = File::open("/proc/self/exe").unwrap();
        validate_workload_subject(&peer, &image).unwrap();
        let foreign_image = File::open("/usr/bin/true").unwrap();
        assert_eq!(
            validate_workload_subject(&peer, &foreign_image),
            Err(Failure::AuthorityDenied)
        );
        subject.0.kill().unwrap();
        subject.0.wait().unwrap();
        assert_eq!(
            validate_workload_subject(&peer, &image),
            Err(Failure::AuthorityDenied)
        );
    }

    #[test]
    fn native_agent_readiness_and_owned_shutdown_are_bounded() {
        let mut ready = Command::new("/usr/bin/sh");
        ready
            .args(["-c", "exec 3>&-; exec /usr/bin/sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let agent = TtyAgent::spawn_ready(ready, Duration::from_secs(2)).unwrap();
        let pid = nix::unistd::Pid::from_raw(agent.0.id() as i32);
        drop(agent);
        assert_eq!(
            nix::sys::wait::waitpid(pid, Some(nix::sys::wait::WaitPidFlag::WNOHANG)),
            Err(nix::errno::Errno::ECHILD)
        );
        let mut unready = Command::new("/usr/bin/sleep");
        unready
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        assert!(TtyAgent::spawn_ready(unready, Duration::from_millis(20)).is_err());
    }
}
