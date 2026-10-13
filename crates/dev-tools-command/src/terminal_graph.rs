//! Foreground terminal scheduling for consumed native command graphs.
use crate::{CommandGraphNode, CommandGraphOutput, GraphExitPolicy};

/// Select who prepares the payload's signal mask. This is independent of the
/// temporary calling-thread mask used by the terminal supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalGraphSignalMask {
    /// Append the inherited runner's restoration of the API-entry thread mask.
    RestoreEntry,
    /// Preserve the caller's prepared child-only mask callbacks, in order. The
    /// caller must prepare each payload mask; no shared callback overwrites it.
    PreservePrepared,
}

/// Run a graph through the launcher's current controlling terminal. On Linux,
/// admission requires launcher foreground ownership. Ready pipe components run
/// one at a time in declaration order, each in one retained foreground process
/// group. Pipes, completion dependencies and exit aggregation match the ordinary
/// graph API; unconnected streams and prepared executable callbacks stay intact.
///
/// The caller exclusively owns child reaping and SIGCHLD disposition stability,
/// and provides a single-threaded launcher or process-wide signal routing. The
/// bounded, nonblocking callback owns the overall deadline, including suspension;
/// it is checked immediately after resume before any payload is continued. A
/// stopped launcher needs an independently running owner to enforce deadlines
/// while stopped. This API neither supplies that owner nor contains descendants
/// which deliberately leave a group. Terminal absence/background admission,
/// partial spawn, cancellation, and uncertain group cleanup are errors. No other
/// platform backend is currently supplied.
pub fn run_prepared_terminal_command_graph(
    nodes: Vec<CommandGraphNode<'_>>,
    policy: GraphExitPolicy,
    child_signal_mask: TerminalGraphSignalMask,
    continue_running: impl FnMut() -> bool,
) -> anyhow::Result<CommandGraphOutput> {
    #[cfg(target_os = "linux")]
    {
        linux::run(nodes, policy, child_signal_mask, continue_running)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (nodes, policy, child_signal_mask, continue_running);
        anyhow::bail!("native terminal command graphs are unavailable on this platform")
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::terminal_custody::{signal_group, Signals, Terminal};
    use crate::{BoundedCommandCleanupFailure, BoundedCommandCleanupOperation, ProcessDomain};
    use anyhow::{bail, Context, Result};
    use std::io;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ExitStatus, Stdio};
    use std::time::Instant;

    struct Member {
        index: usize,
        child: Option<Child>,
        exited: bool,
        stopped: bool,
    }

    /// The first retained direct child reserves the component's PGID. No real
    /// group signal is sent after that owner is reaped. Followers remain owned
    /// independently and are reaped before the leader, after all group signals.
    #[derive(Default)]
    struct Component {
        members: Vec<Member>,
    }

    impl Component {
        fn leader(&self) -> Result<&Child> {
            self.members
                .first()
                .and_then(|member| member.child.as_ref())
                .context("terminal component leader custody unavailable")
        }

        fn group(&self) -> Result<i32> {
            let pid = i32::try_from(self.leader()?.id())?;
            if pid <= 0 {
                bail!("terminal component group identity invalid");
            }
            Ok(pid)
        }

        fn reserve_group(&self) -> Result<i32> {
            let child = self.leader()?;
            crate::process_exit_observed(ProcessDomain::for_child(child))
                .context("terminal component wait custody unavailable")?;
            let group = self.group()?;
            // SAFETY: query the positive PID of our unreaped direct child. It
            // cannot be reused while WNOWAIT custody remains exclusively ours.
            if unsafe { libc::getpgid(group) } != group {
                bail!("terminal component leader left its owned process group");
            }
            Ok(group)
        }

        fn signal(&self, signal: i32) -> Result<()> {
            signal_group(self.reserve_group()?, signal)
        }

        fn add(&mut self, index: usize, child: Child) -> Result<()> {
            self.members.push(Member {
                index,
                child: Some(child),
                exited: false,
                stopped: false,
            });
            let group = self.reserve_group()?;
            let member = self.members.last().context("terminal member unavailable")?;
            let child = member
                .child
                .as_ref()
                .context("terminal child unavailable")?;
            crate::process_exit_observed(ProcessDomain::for_child(child))?;
            let pid = i32::try_from(child.id())?;
            // SAFETY: query only our just-spawned unreaped direct child. Prepared
            // callbacks cannot silently substitute another group for this lane.
            if unsafe { libc::getpgid(pid) } != group {
                bail!("terminal graph member did not join its owned process group");
            }
            Ok(())
        }

        fn observe(&mut self) -> Result<bool> {
            let mut stopped = false;
            for member in &mut self.members {
                if member.exited {
                    continue;
                }
                let child = member
                    .child
                    .as_ref()
                    .context("terminal child custody unavailable")?;
                // SAFETY: initialized native output object, and the positive PID
                // is a retained direct child. WNOWAIT preserves exit/PID custody.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let observed = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child.id(),
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
                    return Err(error).context("observe terminal graph child");
                }
                // SAFETY: successful waitid supplied the SIGCHLD layout; zero
                // PID is its documented no-event result under WNOHANG.
                if unsafe { info.si_pid() } == 0 {
                    continue;
                }
                match info.si_code {
                    libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED => member.exited = true,
                    libc::CLD_STOPPED | libc::CLD_CONTINUED => {
                        // Consume only stop/continue events. A concurrent exit
                        // must stay waitable until whole-component cleanup.
                        let mut consumed: libc::siginfo_t = unsafe { std::mem::zeroed() };
                        // SAFETY: the same retained direct child and initialized
                        // output; WEXITED is deliberately absent from this call.
                        if unsafe {
                            libc::waitid(
                                libc::P_PID,
                                child.id(),
                                &mut consumed,
                                libc::WSTOPPED | libc::WCONTINUED | libc::WNOHANG,
                            )
                        } != 0
                        {
                            let error = io::Error::last_os_error();
                            // A retained child can exit between the two waitid
                            // calls. Linux may then return ECHILD to the stop-only
                            // query even though its unreaped exit remains ours.
                            // Accept only a fresh WEXITED|WNOHANG|WNOWAIT proof;
                            // true lost reaping custody or a non-exit still fails.
                            if error.raw_os_error() == Some(libc::ECHILD)
                                && crate::process_exit_observed(ProcessDomain::for_child(child))
                                    .context("recheck terminal child exit custody")?
                            {
                                member.exited = true;
                                member.stopped = false;
                                continue;
                            }
                            return Err(error).context("consume terminal child state");
                        }
                        if consumed.si_code == libc::CLD_STOPPED {
                            member.stopped = true;
                            stopped = true;
                        } else if consumed.si_code == libc::CLD_CONTINUED {
                            member.stopped = false;
                        }
                    }
                    _ => {}
                }
            }
            Ok(stopped)
        }

        fn forward(&self, signals: &mut Signals) -> Result<()> {
            for signal in signals.drain()? {
                if matches!(
                    signal,
                    libc::SIGINT | libc::SIGTERM | libc::SIGQUIT | libc::SIGHUP | libc::SIGTSTP
                ) {
                    self.signal(signal)?;
                }
            }
            Ok(())
        }

        fn suspend(
            &mut self,
            terminal: &mut Terminal,
            signals: &mut Signals,
            continue_running: &mut impl FnMut() -> bool,
        ) -> Result<()> {
            self.signal(libc::SIGSTOP)?;
            // Observe every direct member stopped/exited before stopping this
            // owner. SIGSTOP is uncatchable; the callback/deadline stays live
            // during this bounded observation, rather than assuming a sleep.
            loop {
                self.observe()?;
                if self
                    .members
                    .iter()
                    .all(|member| member.exited || member.stopped)
                {
                    break;
                }
                if !continue_running() {
                    bail!("native terminal graph cancelled while stopping component");
                }
                self.forward(signals)?;
                signals.wait(crate::MONITOR_INTERVAL)?;
            }
            terminal.restore()?;
            if !continue_running() {
                bail!("native terminal graph cancelled before suspension");
            }
            // SAFETY: self-stop has no pointer arguments. The caller's native
            // outer owner resumes this process; no signal disposition changes.
            if unsafe { libc::raise(libc::SIGSTOP) } != 0 {
                return Err(io::Error::last_os_error()).context("stop terminal graph owner");
            }
            // Do not reset the deadline or continue an expired suspended job.
            if !continue_running() {
                bail!("native terminal graph cancelled after suspension");
            }
            terminal.give_to_required(self.reserve_group()?)?;
            self.signal(libc::SIGCONT)?;
            for member in &mut self.members {
                member.stopped = false;
            }
            Ok(())
        }

        fn run(
            &mut self,
            terminal: &mut Terminal,
            signals: &mut Signals,
            continue_running: &mut impl FnMut() -> bool,
        ) -> Result<()> {
            terminal.give_to_required(self.reserve_group()?)?;
            self.signal(libc::SIGCONT)?;
            loop {
                if !continue_running() {
                    bail!("native terminal command graph cancelled");
                }
                self.forward(signals)?;
                let stopped = self.observe()?;
                if self.members.iter().all(|member| member.exited) {
                    return Ok(());
                }
                if stopped {
                    self.suspend(terminal, signals, continue_running)?;
                }
                signals.wait(crate::MONITOR_INTERVAL)?;
            }
        }

        fn finish(&mut self) -> Result<Vec<(usize, ExitStatus)>> {
            if self.members.is_empty() {
                return Ok(Vec::new());
            }
            let mut failures = Vec::new();
            // All real group signals precede every direct-child reap, including
            // normal completion. Exited leaders still reserve the group's ID.
            match self.reserve_group() {
                Ok(group) => {
                    let domain = ProcessDomain {
                        group: rustix::process::Pid::from_raw(group),
                    };
                    crate::signal_process_group(
                        domain,
                        rustix::process::Signal::TERM,
                        &mut failures,
                    );
                    crate::signal_process_group(
                        domain,
                        rustix::process::Signal::KILL,
                        &mut failures,
                    );
                }
                Err(error) => failures.push(BoundedCommandCleanupFailure::io(
                    BoundedCommandCleanupOperation::WaitChild,
                    io::Error::other(error.to_string()),
                )),
            }
            for member in &mut self.members {
                let Some(child) = member.child.as_mut() else {
                    continue;
                };
                match crate::process_exit_observed(ProcessDomain::for_child(child)) {
                    Ok(_) => crate::kill_child_before_reap(child, &mut failures),
                    Err(error) => failures.push(BoundedCommandCleanupFailure::io(
                        BoundedCommandCleanupOperation::WaitChild,
                        error,
                    )),
                }
            }
            let domain = ProcessDomain {
                group: self.group().ok().and_then(rustix::process::Pid::from_raw),
            };
            let deadline = Instant::now() + crate::FORCE_TERMINATION_GRACE;
            let mut statuses = Vec::new();
            // Followers first; the reserved leader is the last reaping boundary.
            for index in (0..self.members.len()).rev() {
                // A failed follower reap must not release the leader's PGID
                // before error/panic cleanup can finish its remaining signals.
                if index == 0
                    && self
                        .members
                        .iter()
                        .skip(1)
                        .any(|member| member.child.is_some())
                {
                    continue;
                }
                let member = &mut self.members[index];
                let Some(child) = member.child.as_mut() else {
                    continue;
                };
                match crate::wait_for_child_reap(child, deadline) {
                    Ok(Some(status)) => {
                        statuses.push((member.index, status));
                        member.child.take();
                    }
                    Ok(None) => failures.push(BoundedCommandCleanupFailure::marker(
                        BoundedCommandCleanupOperation::WaitChild,
                    )),
                    Err(error) => failures.push(BoundedCommandCleanupFailure::io(
                        BoundedCommandCleanupOperation::WaitChild,
                        error,
                    )),
                }
            }
            // Signal zero after reaping cannot affect a reused PGID. Reuse may
            // cause conservative failure; it cannot produce false settlement.
            crate::record_process_group_exit(domain, deadline, &mut failures);
            if !failures.is_empty() {
                return Err(crate::BoundedCommandError::new(
                    crate::BoundedCommandErrorKind::Cleanup,
                )
                .with_cleanup_failures(failures)
                .into());
            }
            Ok(statuses)
        }
    }

    impl Drop for Component {
        fn drop(&mut self) {
            if self.members.iter().any(|member| member.child.is_some()) {
                // Panic/error fallback remains bounded and signals only while
                // the retained leader still proves exclusive native custody.
                let _ = self.finish();
            }
        }
    }

    pub(super) fn run(
        mut nodes: Vec<CommandGraphNode<'_>>,
        policy: GraphExitPolicy,
        child_signal_mask: TerminalGraphSignalMask,
        mut continue_running: impl FnMut() -> bool,
    ) -> Result<CommandGraphOutput> {
        let dependencies: Vec<_> = nodes.iter().map(|node| node.dependencies.clone()).collect();
        let groups = crate::graph::components(&dependencies)?;
        if !continue_running() {
            bail!("native terminal graph cancelled before start");
        }
        // SIGCHLD ownership is the same WNOWAIT/no-auto-reap contract as the
        // inherited runner. We never install a process-global handler.
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: query only, into initialized writable native output storage.
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0 {
            return Err(io::Error::last_os_error())
                .context("query terminal graph child disposition");
        }
        if disposition.sa_sigaction == libc::SIG_IGN
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            bail!("native terminal graph rejects automatic child reaping");
        }
        let mut signals = Signals::block_job_control()?;
        let mut terminal =
            Terminal::open()?.context("native terminal graph requires a controlling terminal")?;
        terminal.require_foreground()?;
        for index in 0..nodes.len() {
            if let Some(source) = nodes[index].dependencies.pipe_from {
                let (reader, writer) = std::io::pipe()?;
                nodes[index]
                    .command
                    .command_mut()
                    .stdin(Stdio::from(reader));
                nodes[source]
                    .command
                    .command_mut()
                    .stdout(Stdio::from(writer));
            }
        }
        let mut commands: Vec<_> = nodes.into_iter().map(|node| Some(node.command)).collect();
        let mut statuses = vec![None; commands.len()];
        let result = (|| -> Result<CommandGraphOutput> {
            while statuses.iter().any(Option::is_none) {
                if !continue_running() {
                    bail!("native terminal graph cancelled before component");
                }
                let first = commands
                    .iter()
                    .enumerate()
                    .find(|(index, command)| {
                        command.is_some()
                            && dependencies
                                .iter()
                                .enumerate()
                                .filter(|(member, _)| groups[*member] == groups[*index])
                                .all(|(_, dependency)| {
                                    dependency
                                        .after
                                        .iter()
                                        .all(|previous| statuses[*previous].is_some())
                                })
                    })
                    .map(|(index, _)| index)
                    .context("terminal graph has no ready component")?;
                let selected = groups[first];
                terminal.require_foreground()?;
                let mut component = Component::default();
                let operation = (|| -> Result<()> {
                    for index in 0..commands.len() {
                        if groups[index] != selected {
                            continue;
                        }
                        if !continue_running() {
                            bail!("native terminal graph cancelled during start");
                        }
                        let mut prepared = commands[index]
                            .take()
                            .context("terminal command already consumed")?;
                        let group = if component.members.is_empty() {
                            0
                        } else {
                            component.reserve_group()?
                        };
                        prepared.command_mut().process_group(group);
                        if child_signal_mask == TerminalGraphSignalMask::RestoreEntry {
                            let original = signals.previous;
                            // SAFETY: only the async-signal-safe native mask call
                            // in the child; copied sigset_t has no borrowed state.
                            unsafe {
                                prepared.command_mut().pre_exec(move || {
                                    if libc::sigprocmask(
                                        libc::SIG_SETMASK,
                                        &original,
                                        std::ptr::null_mut(),
                                    ) == 0
                                    {
                                        Ok(())
                                    } else {
                                        Err(io::Error::last_os_error())
                                    }
                                });
                            }
                        }
                        let child = prepared
                            .command_mut()
                            .spawn()
                            .context("start terminal graph node")?;
                        let undrained = child.stdin.is_some()
                            || child.stdout.is_some()
                            || child.stderr.is_some();
                        component.add(index, child)?;
                        // Immediate endpoint release preserves binary pipe EOF.
                        drop(prepared);
                        if undrained {
                            bail!("terminal graph requires caller-owned streams instead of capture pipes");
                        }
                    }
                    component.run(&mut terminal, &mut signals, &mut continue_running)
                })();
                // Close unstarted endpoints before any cleanup to unblock every
                // already-started pipe member on partial spawn/cancellation.
                if operation.is_err() {
                    commands.clear();
                }
                let cleanup = component.finish();
                let restore = terminal.restore();
                match (operation, cleanup, restore) {
                    (Ok(()), Ok(completed), Ok(())) => {
                        for (index, status) in completed {
                            statuses[index] = Some(status);
                        }
                    }
                    (operation, cleanup, terminal) => {
                        return Err(FinalizationError {
                            operation: operation.err(),
                            cleanup: cleanup.err(),
                            terminal: terminal.err(),
                            signals: None,
                        }
                        .into())
                    }
                }
            }
            let statuses = statuses
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .context("terminal graph completion incomplete")?;
            let last = *statuses.last().context("terminal graph has no status")?;
            let status = match policy {
                GraphExitPolicy::Last => last,
                GraphExitPolicy::All => statuses
                    .iter()
                    .copied()
                    .find(|status| !status.success())
                    .unwrap_or(last),
                GraphExitPolicy::Pipefail => statuses
                    .iter()
                    .rev()
                    .copied()
                    .find(|status| !status.success())
                    .unwrap_or(last),
            };
            Ok(CommandGraphOutput { status, statuses })
        })();
        drop(commands);
        let terminal_error = terminal.restore().err();
        // Retry terminal restoration while SIGTTOU remains blocked.
        drop(terminal);
        let signal_error = signals.restore().err();
        if terminal_error.is_none() && signal_error.is_none() {
            return result;
        }
        Err(FinalizationError {
            operation: result.err(),
            cleanup: None,
            terminal: terminal_error,
            signals: signal_error,
        }
        .into())
    }

    #[derive(Debug)]
    struct FinalizationError {
        operation: Option<anyhow::Error>,
        cleanup: Option<anyhow::Error>,
        terminal: Option<anyhow::Error>,
        signals: Option<anyhow::Error>,
    }
    impl std::fmt::Display for FinalizationError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let process_cleanup_failed = self.cleanup.is_some()
                || self.operation.as_ref().is_some_and(|error| {
                    error
                        .downcast_ref::<FinalizationError>()
                        .is_some_and(|nested| nested.cleanup.is_some())
                        || error
                            .downcast_ref::<crate::BoundedCommandError>()
                            .is_some_and(|error| !error.cleanup_failures().is_empty())
                });
            write!(f, "terminal graph finalization incomplete (operation_failed={}, process_cleanup_failed={}, terminal_restore_failed={}, signal_restore_failed={})",
                self.operation.is_some(), process_cleanup_failed, self.terminal.is_some(), self.signals.is_some())
        }
    }
    impl std::error::Error for FinalizationError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.operation
                .as_ref()
                .or(self.cleanup.as_ref())
                .or(self.terminal.as_ref())
                .or(self.signals.as_ref())
                .map(|error| error.as_ref() as &(dyn std::error::Error + 'static))
        }
    }
}
