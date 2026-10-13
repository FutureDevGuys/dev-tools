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
    run_prepared_inherited_command_after_spawn(command, |_| Ok(()), continue_running)
}

/// Observe a successful final native spawn before entering the supervision
/// loop. The fallible, bounded callback runs in the owning parent; an error
/// terminalizes the owned process group through the existing cleanup path.
/// The callback does not receive child ownership or confer execution authority.
/// Its immutable Child borrow is valid only during the callback; it must not
/// reap, transfer or concurrently wait for that child. Non-reaping native
/// observations preserve the runner's exclusive identity and cleanup custody.
pub fn run_prepared_inherited_command_after_spawn<'a>(
    command: impl Into<OwnedPreparedCommand<'a>>,
    after_spawn: impl FnOnce(&std::process::Child) -> anyhow::Result<()>,
    continue_running: impl FnMut() -> bool,
) -> anyhow::Result<InheritedCommandOutput> {
    #[cfg(target_os = "linux")]
    {
        let mut owned = command.into();
        linux::run(owned.command_mut(), after_spawn, continue_running)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut owned = command.into();
        let _ = (owned.command_mut(), after_spawn, continue_running);
        anyhow::bail!("inherited native execution is unavailable on this platform")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::terminal_custody::{signal_group, Signals, Terminal};
    use anyhow::{bail, Context, Result};
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::Child;
    use std::time::{Duration, Instant};

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

    pub(super) fn run(
        command: &mut Command,
        after_spawn: impl FnOnce(&Child) -> Result<()>,
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
        let result = child
            .0
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native child ownership was lost"))
            .and_then(after_spawn)
            .and_then(|()| {
                observe(
                    &mut child,
                    &mut signals,
                    &mut terminal,
                    &mut continue_running,
                )
            });
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
