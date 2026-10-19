//! Bounded native stdin/stdout graph wiring. Callers own executable authority,
//! inherited streams and descendant containment; this module owns direct children.

#[cfg(not(target_vendor = "apple"))]
use std::process::Stdio;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphFailure {
    Invalid,
    Spawn,
    Wait,
    Cancelled,
    Cleanup,
}

#[derive(Debug)]
pub struct GraphOutput {
    pub statuses: Vec<Option<ExitStatus>>,
    pub failure: Option<GraphFailure>,
}

/// Start at most 64 commands with an acyclic, topologically ordered set of
/// one-to-one binary pipes. Unconnected streams keep the caller's configuration.
/// On failure/cancellation, signal every direct child before bounded reaping.
/// A caller needing containment of detached descendants must provide it outside
/// this process-local owner (for example, a native cgroup or Job Object).
pub fn run_command_graph(
    commands: Vec<Command>,
    pipes: &[(usize, usize)],
    mut continue_permitted: impl FnMut() -> bool,
) -> GraphOutput {
    let count = commands.len();
    if count == 0 || count > 64 || pipes.len() > 63 {
        return GraphOutput {
            statuses: vec![],
            failure: Some(GraphFailure::Invalid),
        };
    }
    let mut output = GraphOutput {
        statuses: vec![None; count],
        failure: None,
    };
    #[cfg(not(target_vendor = "apple"))]
    let mut commands = commands;
    let mut incoming = vec![false; count];
    let mut outgoing = vec![false; count];
    for &(from, to) in pipes {
        if from >= to || to >= count || incoming[to] || outgoing[from] {
            output.failure = Some(GraphFailure::Invalid);
            return output;
        }
        incoming[to] = true;
        outgoing[from] = true;
        #[cfg(target_vendor = "apple")]
        {
            // Darwin has no atomic pipe2(CLOEXEC) API. A pipe followed by
            // F_SETFD can leak an endpoint to a concurrent spawn before the
            // flags are set, so do not claim a protected graph pipe here.
            output.failure = Some(GraphFailure::Spawn);
            return output;
        }
        #[cfg(not(target_vendor = "apple"))]
        let (read, write) = match rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC) {
            Ok(pair) => pair,
            Err(_) => {
                output.failure = Some(GraphFailure::Spawn);
                return output;
            }
        };
        #[cfg(not(target_vendor = "apple"))]
        commands[from].stdout(Stdio::from(write));
        #[cfg(not(target_vendor = "apple"))]
        commands[to].stdin(Stdio::from(read));
    }
    let mut children: Vec<Child> = Vec::with_capacity(count);
    for mut command in commands {
        if !continue_permitted() {
            output.failure = Some(GraphFailure::Cancelled);
            break;
        }
        match command.spawn() {
            Ok(child) => children.push(child),
            Err(_) => {
                output.failure = Some(GraphFailure::Spawn);
                break;
            }
        }
        // Drop the Command after spawn: retaining its pipe endpoints in the
        // parent would prevent EOF from ever reaching a downstream consumer.
    }
    let mut stopping_by = None;
    loop {
        if output.failure.is_none() && !continue_permitted() {
            output.failure = Some(GraphFailure::Cancelled);
        }
        if output.failure.is_some() && stopping_by.is_none() {
            for (child, status) in children.iter_mut().zip(&output.statuses) {
                if status.is_none() {
                    let _ = child.kill();
                }
            }
            stopping_by = Some(Instant::now() + Duration::from_secs(5));
        }
        let mut pending = false;
        for (index, child) in children.iter_mut().enumerate() {
            if output.statuses[index].is_some() {
                continue;
            }
            match child.try_wait() {
                Ok(Some(status)) => output.statuses[index] = Some(status),
                Ok(None) => pending = true,
                Err(_) => {
                    output.failure = Some(GraphFailure::Wait);
                    pending = true;
                }
            }
        }
        if !pending {
            return output;
        }
        if stopping_by.is_some_and(|deadline| Instant::now() >= deadline) {
            output.failure = Some(GraphFailure::Cleanup);
            return output;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_vendor = "apple")]
    #[test]
    fn graph_pipe_fails_closed_without_an_atomic_cloexec_backend() {
        let commands = vec![Command::new("/usr/bin/true"), Command::new("/usr/bin/cat")];
        let result = run_command_graph(commands, &[(0, 1)], || true);
        assert_eq!(result.failure, Some(GraphFailure::Spawn));
        assert_eq!(result.statuses, vec![None, None]);
    }

    #[test]
    fn binary_pipe_closes_and_preserves_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("output");
        let mut producer = Command::new("/usr/bin/printf");
        producer.arg("a\\000b\\377");
        let mut consumer = Command::new("/usr/bin/cat");
        consumer.stdout(std::fs::File::create(&path).unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        let output = run_command_graph(vec![producer, consumer], &[(0, 1)], || {
            Instant::now() < deadline
        });
        assert_eq!(output.failure, None);
        assert!(output
            .statuses
            .iter()
            .all(|status| status.is_some_and(|status| status.success())));
        assert_eq!(std::fs::read(path).unwrap(), b"a\0b\xff");
    }

    #[test]
    fn partial_spawn_failure_reaps_the_started_child() {
        let mut first = Command::new("/usr/bin/sleep");
        first.arg("30");
        let output = run_command_graph(
            vec![first, Command::new("/missing-graph-executable")],
            &[],
            || true,
        );
        assert_eq!(output.failure, Some(GraphFailure::Spawn));
        assert!(output.statuses[0].is_some_and(|status| !status.success()));
        assert!(output.statuses[1].is_none());
    }

    #[test]
    fn malformed_graph_and_pre_cancelled_graph_start_nothing() {
        let output = run_command_graph(vec![Command::new("/usr/bin/true")], &[(0, 0)], || true);
        assert_eq!(output.failure, Some(GraphFailure::Invalid));
        assert!(output.statuses[0].is_none());
        let output = run_command_graph(vec![Command::new("/usr/bin/true")], &[], || false);
        assert_eq!(output.failure, Some(GraphFailure::Cancelled));
        assert!(output.statuses[0].is_none());
    }
}
