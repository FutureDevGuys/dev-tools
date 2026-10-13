//! Consumed native command graphs with direct binary pipes. The caller owns
//! authorization, output custody/limits and any hostile-descendant containment.
use crate::OwnedPreparedCommand;
use anyhow::{bail, Context, Result};
use std::process::ExitStatus;

pub const MAX_GRAPH_NODES: usize = 64;

/// `after` waits for completion, regardless of exit status. A pipe joins its
/// producer and consumer into one concurrent component; dependencies on that
/// component must all complete before any of its processes start.
pub struct CommandGraphNode<'a> {
    pub command: OwnedPreparedCommand<'a>,
    pub dependencies: GraphDependencies,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphDependencies {
    pub after: Vec<usize>,
    pub pipe_from: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphExitPolicy {
    Last,
    All,
    Pipefail,
}

pub struct CommandGraphOutput {
    pub status: ExitStatus,
    /// Native statuses in declaration order, not completion order.
    pub statuses: Vec<ExitStatus>,
}

/// Executes at most 64 consumed prepared commands. Pipes use kernel byte streams
/// without decoding or buffering the graph's payload in this process. A stdout
/// has at most one consumer and a stdin has at most one producer. Unconnected
/// streams retain the caller's prepared descriptors; captured `Stdio::piped()`
/// streams are rejected because nobody would drain them.
///
/// This Linux backend owns one process group per node and keeps each leader
/// unreaped until group cleanup. A false callback cancels every started group.
/// The callback must be bounded/nonblocking and own the overall deadline.
/// A native outer boundary is still required for descendants that deliberately
/// escape a process group. No filesystem, credential or approval policy lives
/// here. Terminal foreground routing is not provided by this graph mode.
pub fn run_prepared_command_graph(
    nodes: Vec<CommandGraphNode<'_>>,
    policy: GraphExitPolicy,
    continue_running: impl FnMut() -> bool,
) -> Result<CommandGraphOutput> {
    #[cfg(target_os = "linux")]
    {
        linux::run(nodes, policy, continue_running)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (nodes, policy, continue_running);
        bail!("native command graphs are unavailable on this platform")
    }
}

pub fn validate_command_graph_dependencies(nodes: &[GraphDependencies]) -> Result<()> {
    components(nodes).map(|_| ())
}

fn components(nodes: &[GraphDependencies]) -> Result<Vec<usize>> {
    let count = nodes.len();
    if count == 0 || count > MAX_GRAPH_NODES {
        bail!("native command graph exceeds its node bound");
    }
    let mut parent: Vec<_> = (0..count).collect();
    let mut consumers = vec![false; count];
    for (index, node) in nodes.iter().enumerate() {
        if node.after.len() > count {
            bail!("native command graph exceeds its dependency bound");
        }
        let mut unique = std::collections::BTreeSet::new();
        for dependency in &node.after {
            if *dependency >= count || *dependency == index || !unique.insert(dependency) {
                bail!("native command graph dependency is invalid");
            }
        }
        if let Some(source) = node.pipe_from {
            if source >= count || source == index || consumers[source] {
                bail!("native command graph pipe is invalid or has multiple consumers");
            }
            consumers[source] = true;
            let a = representative(&parent, index);
            let b = representative(&parent, source);
            if a == b {
                bail!("native command graph contains a pipe cycle");
            }
            parent[a] = b;
        }
    }
    let groups: Vec<_> = (0..count).map(|n| representative(&parent, n)).collect();
    let mut pending: std::collections::BTreeSet<_> = groups.iter().copied().collect();
    let mut done = std::collections::BTreeSet::new();
    while !pending.is_empty() {
        let ready = pending.iter().copied().find(|group| {
            nodes
                .iter()
                .enumerate()
                .filter(|(n, _)| groups[*n] == *group)
                .all(|(_, node)| node.after.iter().all(|n| done.contains(&groups[*n])))
        });
        let group = ready.context("native command graph contains a dependency cycle")?;
        pending.remove(&group);
        done.insert(group);
    }
    Ok(groups)
}

fn representative(parent: &[usize], mut index: usize) -> usize {
    while parent[index] != index {
        index = parent[index];
    }
    index
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::ProcessDomain;
    use std::process::{Child, Stdio};
    use std::time::Duration;

    struct Running(Option<Child>);
    impl Running {
        fn finished(&self) -> Result<bool> {
            let child = self
                .0
                .as_ref()
                .context("graph child was already finalized")?;
            crate::process_exit_observed(ProcessDomain::for_child(child))
                .context("observe native graph child")
        }
        fn finish(&mut self) -> Result<ExitStatus> {
            let mut child = self.0.take().context("graph child was already finalized")?;
            let domain = ProcessDomain::for_child(&child);
            let (status, failures) = crate::terminate_lingering_domain(&mut child, domain);
            if !failures.is_empty() {
                return Err(crate::BoundedCommandError::new(
                    crate::BoundedCommandErrorKind::Cleanup,
                )
                .with_cleanup_failures(failures)
                .into());
            }
            status.context("native graph child status is absent")
        }
        fn cancel(&mut self) -> Result<()> {
            if let Some(mut child) = self.0.take() {
                let domain = ProcessDomain::for_child(&child);
                let failures = crate::terminate_process_domain(&mut child, domain);
                if !failures.is_empty() {
                    return Err(crate::BoundedCommandError::new(
                        crate::BoundedCommandErrorKind::Cleanup,
                    )
                    .with_cleanup_failures(failures)
                    .into());
                }
            }
            Ok(())
        }
    }
    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.cancel();
        }
    }

    fn group_finished(groups: &[usize], statuses: &[Option<ExitStatus>], group: usize) -> bool {
        groups
            .iter()
            .zip(statuses)
            .all(|(&member, status)| member != group || status.is_some())
    }

    pub(super) fn run(
        mut nodes: Vec<CommandGraphNode<'_>>,
        policy: GraphExitPolicy,
        mut continue_running: impl FnMut() -> bool,
    ) -> Result<CommandGraphOutput> {
        let dependencies: Vec<_> = nodes.iter().map(|node| node.dependencies.clone()).collect();
        let groups = components(&dependencies)?;
        if !continue_running() {
            bail!("native command graph cancelled before start");
        }
        // Reuse the owning runner's WNOWAIT custody contract: auto-reaping
        // would release a PID before all process-group signals were issued.
        let mut disposition: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: query only, into a live initialized native output object.
        if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut disposition) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("query graph child wait disposition");
        }
        if disposition.sa_sigaction == libc::SIG_IGN
            || disposition.sa_flags & libc::SA_NOCLDWAIT != 0
        {
            bail!("native command graph rejects automatic child reaping");
        }
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
        let after: Vec<_> = dependencies.into_iter().map(|n| n.after).collect();
        let mut commands: Vec<_> = nodes.into_iter().map(|n| Some(n.command)).collect();
        let mut running: Vec<Option<Running>> = (0..commands.len()).map(|_| None).collect();
        let mut statuses: Vec<Option<ExitStatus>> = vec![None; commands.len()];
        let result = (|| -> Result<CommandGraphOutput> {
            while statuses.iter().any(Option::is_none) {
                if !continue_running() {
                    bail!("native command graph cancelled");
                }
                for index in 0..commands.len() {
                    if commands[index].is_none() {
                        continue;
                    }
                    let group = groups[index];
                    let ready = after
                        .iter()
                        .enumerate()
                        .filter(|(n, _)| groups[*n] == group)
                        .all(|(_, dependencies)| {
                            dependencies
                                .iter()
                                .all(|n| group_finished(&groups, &statuses, groups[*n]))
                        });
                    if !ready {
                        continue;
                    }
                    for node in 0..commands.len() {
                        if groups[node] != group {
                            continue;
                        }
                        let Some(mut prepared) = commands[node].take() else {
                            continue;
                        };
                        if !continue_running() {
                            bail!("native command graph cancelled during start");
                        }
                        crate::configure_process_domain(prepared.command_mut());
                        let child = prepared
                            .command_mut()
                            .spawn()
                            .context("start native graph node")?;
                        let undrained = child.stdin.is_some()
                            || child.stdout.is_some()
                            || child.stderr.is_some();
                        running[node] = Some(Running(Some(child)));
                        // Drop retained parent-side pipe endpoints immediately.
                        drop(prepared);
                        if undrained {
                            bail!("native graph requires caller-owned streams instead of capture pipes");
                        }
                    }
                }
                for (index, child) in running.iter_mut().enumerate() {
                    if let Some(child) = child {
                        if statuses[index].is_none() && child.finished()? {
                            statuses[index] = Some(child.finish()?);
                        }
                    }
                }
                if statuses.iter().any(Option::is_none) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            let statuses = statuses
                .iter()
                .copied()
                .collect::<Option<Vec<_>>>()
                .context("native graph completion is incomplete")?;
            let last = *statuses.last().context("native graph has no status")?;
            let status = match policy {
                GraphExitPolicy::Last => last,
                GraphExitPolicy::All => statuses
                    .iter()
                    .copied()
                    .find(|s| !s.success())
                    .unwrap_or(last),
                GraphExitPolicy::Pipefail => statuses
                    .iter()
                    .rev()
                    .copied()
                    .find(|s| !s.success())
                    .unwrap_or(last),
            };
            Ok(CommandGraphOutput { status, statuses })
        })();
        // Close not-yet-started pipe endpoints before cancelling every owner.
        drop(commands);
        // Signal every reserved group before bounded reaping of any one node.
        // Otherwise one slow domain can leave later graph nodes running after
        // cancellation or a partial spawn failure.
        let mut cleanup_error = None;
        for owner in running.iter().flatten() {
            let Some(child) = owner.0.as_ref() else {
                continue;
            };
            let domain = ProcessDomain::for_child(child);
            let mut failures = Vec::new();
            match crate::process_exit_observed(domain) {
                Ok(_) => {
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
                Err(error) => failures.push(crate::BoundedCommandCleanupFailure::io(
                    crate::BoundedCommandCleanupOperation::WaitChild,
                    error,
                )),
            }
            if !failures.is_empty() {
                cleanup_error.get_or_insert_with(|| {
                    anyhow::Error::from(
                        crate::BoundedCommandError::new(crate::BoundedCommandErrorKind::Cleanup)
                            .with_cleanup_failures(failures),
                    )
                });
            }
        }
        for child in running.iter_mut().flatten() {
            if let Err(error) = child.cancel() {
                cleanup_error.get_or_insert(error);
            }
        }
        if let Some(error) = cleanup_error {
            return Err(error).context("native graph cleanup failed");
        }
        result
    }
}
