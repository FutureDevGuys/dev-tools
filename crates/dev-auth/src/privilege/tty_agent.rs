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

pub(super) struct TtyAgent(Child);

impl TtyAgent {
    pub(super) fn for_request() -> Result<Option<Self>, Failure> {
        if !std::io::stdin().is_terminal() {
            return Ok(None);
        }
        let program = std::path::Path::new("/usr/bin/pkttyagent");
        crate::setup::validate_root_owned_executable(program, "native PolicyKit terminal agent")
            .map_err(|_| Failure::NativeUnavailable)?;
        let terminal = File::options()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOCTTY)
            .open("/dev/tty")
            .map_err(|_| Failure::NativeUnavailable)?;
        if nix::unistd::tcgetpgrp(&terminal).map_err(|_| Failure::NativeUnavailable)?
            != nix::unistd::getpgrp()
        {
            return Err(Failure::NativeUnavailable);
        }
        let pid = std::process::id();
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
        // This is our directly owned, nonprivileged native UI process. Killing
        // it neither grants authority nor affects another agent. Reap before
        // returning; PDEATHSIG handles abrupt request-process termination.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
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
