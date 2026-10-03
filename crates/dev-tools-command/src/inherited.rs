//! Native inherited streams in an owned process group. Products retain the
//! outer native containment boundary when hostile descendants are in scope.
use super::OwnedPreparedCommand;
#[cfg(target_os = "linux")]
use super::ProcessDomain;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::process::ExitStatus;

pub struct InheritedCommandOutput {
    pub status: ExitStatus,
    pub cancelled: bool,
}

/// Run prepared native argv/streams in a retained process group. The callback
/// must be local, bounded, and nonblocking; false requests terminal cleanup.
/// This does not authorize the command or contain descendants that deliberately
/// leave the group. The caller owns that outer native containment boundary.
/// The command is consumed so child-only callbacks cannot accumulate on reuse.
/// A returned success proves the retained process group has exited; uncertain
/// descendant cleanup is an error. The callback owns the overall run deadline.
/// Process-directed signal forwarding requires a single-threaded launcher or
/// caller-owned process-wide signal routing; this function changes only its
/// calling thread's mask, never other threads' masks or global dispositions.
/// Caller-selected pipes are rejected after spawn and immediately cleaned up;
/// use inherited, null, or caller-owned file descriptors instead. Job-control
/// suspension requires external continuation before callback deadlines resume.
/// The caller must exclusively own child reaping for this invocation and prevent
/// concurrent SIGCHLD disposition changes. Auto-reaping dispositions are rejected.
///
/// Prepared commands cannot be reused or borrowed mutably:
/// ```compile_fail
/// let command = std::process::Command::new("example");
/// let _ = dev_tools_command::run_prepared_inherited_command(command, || false);
/// let _ = dev_tools_command::run_prepared_inherited_command(command, || false);
/// ```
/// ```compile_fail
/// let mut command = std::process::Command::new("example");
/// let _ = dev_tools_command::run_prepared_inherited_command(&mut command, || false);
/// ```
pub fn run_prepared_inherited_command<'a>(
    command: impl Into<OwnedPreparedCommand<'a>>,
    continue_running: impl FnMut() -> bool,
) -> anyhow::Result<InheritedCommandOutput> {
    #[cfg(target_os = "linux")]
    {
        let mut owned = command.into();
        linux::run(owned.command_mut(), continue_running)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut owned = command.into();
        let _ = (owned.command_mut(), continue_running);
        anyhow::bail!("inherited native execution is unavailable on this platform")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::{bail, Context, Result};
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    use std::process::Child;
    use std::time::{Duration, Instant};

    struct Signals {
        previous: libc::sigset_t,
        input: File,
    }

    impl Signals {
        fn block() -> Result<Self> {
            // SAFETY: sigset_t is a libc POD output object; sigemptyset initializes
            // it before use. pthread_sigmask writes the complete previous mask.
            let (mut mask, mut previous) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
            // SAFETY: both pointers are live sigset_t objects; no pointer is retained.
            unsafe {
                libc::sigemptyset(&mut mask);
                for signal in [
                    libc::SIGINT,
                    libc::SIGTERM,
                    libc::SIGQUIT,
                    libc::SIGHUP,
                    libc::SIGCHLD,
                    libc::SIGTTOU,
                ] {
                    libc::sigaddset(&mut mask, signal);
                }
                let error = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, &mut previous);
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(error).into());
                }
            }
            // SAFETY: mask is initialized and borrowed only during signalfd. A
            // successful call transfers one new descriptor to this owner.
            let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
            if fd < 0 {
                let error = io::Error::last_os_error();
                // SAFETY: previous was initialized by successful pthread_sigmask.
                unsafe {
                    libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                }
                return Err(error.into());
            }
            // SAFETY: fd is a fresh owned descriptor returned above, not aliased
            // by another Rust owner. File closes it exactly once.
            Ok(Self {
                previous,
                input: unsafe { File::from_raw_fd(fd) },
            })
        }

        fn forward(&mut self, child: i32) -> Result<()> {
            let mut bytes = [0u8; std::mem::size_of::<libc::signalfd_siginfo>()];
            for _ in 0..64 {
                match self.input.read(&mut bytes) {
                    Ok(length) if length == bytes.len() => {
                        let signal = u32::from_ne_bytes(
                            bytes[..4]
                                .try_into()
                                .context("invalid native signal field")?,
                        );
                        if matches!(
                            signal as i32,
                            libc::SIGINT | libc::SIGTERM | libc::SIGQUIT | libc::SIGHUP
                        ) {
                            signal_group(child, signal as i32)?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    _ => bail!("native signal observation failed"),
                }
            }
            Ok(())
        }

        fn restore(&mut self) -> Result<()> {
            // SAFETY: previous was initialized by this calling thread's mask exchange.
            let error = unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut())
            };
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error).into());
            }
            Ok(())
        }
    }

    impl Drop for Signals {
        fn drop(&mut self) {
            // SAFETY: previous belongs to this thread's successful mask exchange.
            // Restoration changes no process-wide signal disposition or handler.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
            }
        }
    }

    struct Terminal {
        file: File,
        parent: i32,
        changed: bool,
    }

    impl Terminal {
        fn open() -> Result<Option<Self>> {
            let file = match File::options()
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY)
                .open("/dev/tty")
            {
                Ok(file) => file,
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ENXIO | libc::ENOENT | libc::ENODEV)
                    ) =>
                {
                    return Ok(None)
                }
                Err(error) => return Err(error).context("open inherited controlling terminal"),
            };
            // SAFETY: getpgrp has no pointer arguments or memory preconditions.
            Ok(Some(Self {
                file,
                parent: unsafe { libc::getpgrp() },
                changed: false,
            }))
        }

        fn give_to(&mut self, child: i32) -> Result<()> {
            // SAFETY: file retains a live controlling-terminal descriptor.
            let foreground = unsafe { libc::tcgetpgrp(self.file.as_raw_fd()) };
            if foreground < 0 {
                return Err(io::Error::last_os_error())
                    .context("observe terminal foreground group");
            }
            if foreground == self.parent {
                // SAFETY: this process is in the terminal's session and child is
                // its retained process group. SIGTTOU is blocked on this thread.
                if unsafe { libc::tcsetpgrp(self.file.as_raw_fd(), child) } != 0 {
                    return Err(io::Error::last_os_error())
                        .context("transfer terminal foreground group");
                }
                self.changed = true;
            }
            Ok(())
        }

        fn restore(&mut self) -> Result<()> {
            if self.changed {
                // SAFETY: parent is the original native process group and the
                // retained terminal descriptor remains open. SIGTTOU is blocked.
                if unsafe { libc::tcsetpgrp(self.file.as_raw_fd(), self.parent) } != 0 {
                    return Err(io::Error::last_os_error())
                        .context("restore terminal foreground group");
                }
                self.changed = false;
            }
            Ok(())
        }
    }

    impl Drop for Terminal {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    struct OwnedChild(Option<Child>);

    impl OwnedChild {
        fn finish(&mut self) -> Result<ExitStatus> {
            let Some(mut child) = self.0.take() else {
                bail!("native child already finalized")
            };
            let domain = ProcessDomain::for_child(&child);
            let (status, failures) = super::super::terminate_lingering_domain(&mut child, domain);
            if !failures.is_empty() {
                return Err(super::super::BoundedCommandError::new(
                    super::super::BoundedCommandErrorKind::Cleanup,
                )
                .with_cleanup_failures(failures)
                .into());
            }
            status.context("native child exit status unavailable")
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let domain = ProcessDomain::for_child(&child);
                // Panic/error fallback uses the existing bounded owner cleanup.
                // It never turns an uncertain process-domain result into success.
                let _ = super::super::terminate_process_domain(&mut child, domain);
            }
        }
    }

    fn signal_group(group: i32, signal: i32) -> Result<()> {
        let domain = ProcessDomain {
            group: rustix::process::Pid::from_raw(group),
        };
        // A WNOWAIT observation must still identify our retained direct child.
        // Never signal a bare numeric group after wait ownership was lost.
        super::super::process_exit_observed(domain)
            .context("native child wait ownership unavailable")?;
        // SAFETY: group is a positive unreaped child PID made into its own group
        // before exec; negation selects only that owned native group.
        if unsafe { libc::kill(-group, signal) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error.into());
            }
        }
        Ok(())
    }

    pub(super) fn run(
        command: &mut Command,
        mut continue_running: impl FnMut() -> bool,
    ) -> Result<InheritedCommandOutput> {
        if !continue_running() {
            bail!("native execution was cancelled before admission");
        }
        // SAFETY: query only; sigaction writes the initialized output structure.
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0 {
            return Err(io::Error::last_os_error()).context("query native child disposition");
        }
        if disposition.sa_sigaction == libc::SIG_IGN
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            bail!("native inherited execution rejects automatic child reaping");
        }
        let mut signals = Signals::block()?;
        let mut terminal = Terminal::open()?;
        let original_mask = signals.previous;
        command.process_group(0);
        // SAFETY: the child callback uses only sigprocmask, an async-signal-safe
        // native mask operation; the initialized by-value mask has no pointers or
        // shared Rust state. All prepared descriptor callbacks remain intact.
        unsafe {
            command.pre_exec(move || {
                if libc::sigprocmask(libc::SIG_SETMASK, &original_mask, std::ptr::null_mut()) == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
        let mut child = OwnedChild(Some(
            command.spawn().context("start inherited native command")?,
        ));
        let result = observe(
            &mut child,
            &mut signals,
            &mut terminal,
            &mut continue_running,
        );
        // Errors before leader completion still need bounded termination.
        let cleanup = if let Some(mut pending) = child.0.take() {
            let domain = ProcessDomain::for_child(&pending);
            super::super::terminate_process_domain(&mut pending, domain)
        } else {
            Vec::new()
        };
        let terminal_error = terminal.as_mut().map_or(Ok(()), Terminal::restore).err();
        // Drop may retry restoration; keep SIGTTOU blocked through that attempt.
        drop(terminal.take());
        let signal_error = signals.restore().err();
        if !cleanup.is_empty() || terminal_error.is_some() || signal_error.is_some() {
            return Err(FinalizationError {
                operation: result.err(),
                cleanup,
                terminal: terminal_error,
                signals: signal_error,
            }
            .into());
        }
        result
    }

    #[derive(Debug)]
    struct FinalizationError {
        operation: Option<anyhow::Error>,
        cleanup: Vec<super::super::BoundedCommandCleanupFailure>,
        terminal: Option<anyhow::Error>,
        signals: Option<anyhow::Error>,
    }
    impl std::fmt::Display for FinalizationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let process_failed = !self.cleanup.is_empty()
                || self
                    .operation
                    .as_ref()
                    .and_then(|error| error.downcast_ref::<super::super::BoundedCommandError>())
                    .is_some_and(|error| !error.cleanup_failures().is_empty());
            write!(f, "native finalization incomplete (operation_failed={}, process_cleanup_failed={}, terminal_restore_failed={}, signal_restore_failed={})",
                self.operation.is_some(), process_failed, self.terminal.is_some(), self.signals.is_some())
        }
    }
    impl std::error::Error for FinalizationError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.operation
                .as_ref()
                .or(self.terminal.as_ref())
                .or(self.signals.as_ref())
                .map(|error| error.as_ref() as &(dyn std::error::Error + 'static))
                .or_else(|| {
                    self.cleanup
                        .first()
                        .and_then(|failure| failure.io_error())
                        .map(|error| error as &(dyn std::error::Error + 'static))
                })
        }
    }

    fn observe(
        child: &mut OwnedChild,
        signals: &mut Signals,
        terminal: &mut Option<Terminal>,
        continue_running: &mut impl FnMut() -> bool,
    ) -> Result<InheritedCommandOutput> {
        let retained = child.0.as_ref().context("retained child is absent")?;
        if retained.stdin.is_some() || retained.stdout.is_some() || retained.stderr.is_some() {
            bail!("native inherited execution does not service caller-selected pipes");
        }
        let pid = i32::try_from(retained.id())?;
        if let Some(terminal) = terminal.as_mut() {
            terminal.give_to(pid)?;
        }
        signal_group(pid, libc::SIGCONT)?;
        let mut cancelled_at = None;
        loop {
            signals.forward(pid)?;
            if cancelled_at.is_none() && !continue_running() {
                cancelled_at = Some(Instant::now());
                signal_group(pid, libc::SIGTERM)?;
                signal_group(pid, libc::SIGCONT)?;
            }
            if cancelled_at.is_some_and(|start| start.elapsed() >= Duration::from_millis(100)) {
                signal_group(pid, libc::SIGKILL)?;
                if cancelled_at.is_some_and(|start| start.elapsed() >= Duration::from_secs(2)) {
                    bail!("native cancellation exit observation deadline reached");
                }
            }
            // SAFETY: siginfo_t is a libc output object, initialized before union
            // access. WNOWAIT retains the leader PID until group cleanup completes.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: pid names the retained direct child and info is writable for
            // this call. waitid retains no pointer, and WNOWAIT does not reap it.
            let observed = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as u32,
                    &mut info,
                    libc::WEXITED
                        | libc::WSTOPPED
                        | libc::WCONTINUED
                        | libc::WNOHANG
                        | libc::WNOWAIT,
                )
            };
            if observed != 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("observe retained native child");
            }
            // SAFETY: successful waitid supplies the SIGCHLD layout; zero pid is
            // its documented no-event observation under WNOHANG.
            if unsafe { info.si_pid() } != 0 {
                match info.si_code {
                    libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED => {
                        let status = child.finish()?;
                        return Ok(InheritedCommandOutput {
                            status,
                            cancelled: cancelled_at.is_some(),
                        });
                    }
                    libc::CLD_STOPPED | libc::CLD_CONTINUED => {
                        // SAFETY: the fresh siginfo is a libc output object. Do
                        // not request WEXITED here: a concurrent exit must remain
                        // unreaped until the terminal cleanup branch owns it.
                        let mut consumed: libc::siginfo_t = unsafe { std::mem::zeroed() };
                        // SAFETY: pid is our retained child and consumed is live.
                        if unsafe {
                            libc::waitid(
                                libc::P_PID,
                                pid as u32,
                                &mut consumed,
                                libc::WSTOPPED | libc::WCONTINUED | libc::WNOHANG,
                            )
                        } != 0
                        {
                            return Err(io::Error::last_os_error())
                                .context("consume native child state change");
                        }
                        if consumed.si_code == libc::CLD_STOPPED && cancelled_at.is_none() {
                            if let Some(terminal) = terminal.as_mut() {
                                terminal.restore()?;
                            }
                            // SAFETY: native self-stop has no memory preconditions.
                            // The owning shell/session resumes us through SIGCONT.
                            unsafe {
                                libc::raise(libc::SIGSTOP);
                            }
                            if let Some(terminal) = terminal.as_mut() {
                                terminal.give_to(pid)?;
                            }
                            signal_group(pid, libc::SIGCONT)?;
                        }
                    }
                    _ => {}
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
