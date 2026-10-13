#![cfg(target_os = "linux")]

use dev_tools_command::{
    run_prepared_command_graph, validate_command_graph_dependencies, CommandGraphNode,
    GraphDependencies, GraphExitPolicy, HeldExecutable,
};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::time::{Duration, Instant};

fn node(
    command: Command,
    after: Vec<usize>,
    pipe_from: Option<usize>,
) -> CommandGraphNode<'static> {
    CommandGraphNode {
        command: command.into(),
        dependencies: GraphDependencies { after, pipe_from },
    }
}

fn exit(code: i32) -> Command {
    let mut command = Command::new("/usr/bin/sh");
    command.args(["-c", &format!("exit {code}")]);
    command
}

#[test]
fn binary_pipe_preserves_bytes_and_closes_parent_endpoints() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("output");
    let mut producer = Command::new("/usr/bin/printf");
    producer.arg("a\\000b\\377");
    let mut consumer = Command::new("/usr/bin/cat");
    consumer.stdout(std::fs::File::create(&output).unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    let result = run_prepared_command_graph(
        vec![
            node(producer, vec![], None),
            node(consumer, vec![], Some(0)),
        ],
        GraphExitPolicy::All,
        || Instant::now() < deadline,
    )
    .unwrap();
    assert!(result.status.success());
    assert!(result.statuses.iter().all(|status| status.success()));
    assert_eq!(std::fs::read(output).unwrap(), b"a\0b\xff");
}

#[test]
fn completion_dependency_waits_even_when_predecessor_fails() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("completed");
    let output = directory.path().join("observed");
    let mut predecessor = Command::new("/usr/bin/sh");
    predecessor
        .args(["-c", "printf done > \"$1\"; exit 7", "graph"])
        .arg(&marker);
    let mut successor = Command::new("/usr/bin/cat");
    successor
        .arg(&marker)
        .stdout(std::fs::File::create(&output).unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    // Declaration order need not be a topological execution order.
    let result = run_prepared_command_graph(
        vec![
            node(successor, vec![1], None),
            node(predecessor, vec![], None),
        ],
        GraphExitPolicy::All,
        || Instant::now() < deadline,
    )
    .unwrap();
    assert_eq!(result.statuses[0].code(), Some(0));
    assert_eq!(result.statuses[1].code(), Some(7));
    assert_eq!(result.status.code(), Some(7));
    assert_eq!(std::fs::read(output).unwrap(), b"done");
}

#[test]
fn dependency_on_pipe_component_waits_for_all_members() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("consumed");
    let output = directory.path().join("observed");
    let mut producer = Command::new("/usr/bin/printf");
    producer.arg("payload");
    let mut consumer = Command::new("/usr/bin/sh");
    consumer
        .args([
            "-c",
            "cat > \"$1\"; sleep .1; printf settled >> \"$1\"",
            "graph",
        ])
        .arg(&marker);
    let mut successor = Command::new("/usr/bin/cat");
    successor
        .arg(&marker)
        .stdout(std::fs::File::create(&output).unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    let result = run_prepared_command_graph(
        vec![
            node(producer, vec![], None),
            node(consumer, vec![], Some(0)),
            node(successor, vec![0], None),
        ],
        GraphExitPolicy::All,
        || Instant::now() < deadline,
    )
    .unwrap();
    assert!(result.status.success());
    assert_eq!(std::fs::read(output).unwrap(), b"payloadsettled");
}

#[test]
fn invalid_cycles_and_multiple_consumers_fail_before_execution() {
    let dependency = |after, pipe_from| GraphDependencies { after, pipe_from };
    for graph in [
        vec![],
        vec![dependency(vec![0], None)],
        vec![dependency(vec![1], None), dependency(vec![0], None)],
        vec![dependency(vec![1], None), dependency(vec![], Some(0))],
        vec![
            dependency(vec![], None),
            dependency(vec![], Some(0)),
            dependency(vec![], Some(0)),
        ],
        vec![dependency(vec![], Some(1)), dependency(vec![], Some(0))],
        vec![dependency(vec![1, 1], None), dependency(vec![], None)],
    ] {
        assert!(validate_command_graph_dependencies(&graph).is_err());
    }
}

#[test]
fn exit_selection_uses_declaration_order() {
    for (policy, expected) in [
        (GraphExitPolicy::Last, 0),
        (GraphExitPolicy::All, 2),
        (GraphExitPolicy::Pipefail, 3),
    ] {
        let deadline = Instant::now() + Duration::from_secs(3);
        let result = run_prepared_command_graph(
            vec![
                node(exit(2), vec![], None),
                node(exit(3), vec![], None),
                node(exit(0), vec![], None),
            ],
            policy,
            || Instant::now() < deadline,
        )
        .unwrap();
        assert_eq!(result.status.code(), Some(expected));
    }
}

#[test]
fn native_signal_status_is_distinct_from_numeric_exit() {
    let mut signaled = Command::new("/usr/bin/sh");
    signaled.args(["-c", "kill -TERM \"$$\""]);
    let deadline = Instant::now() + Duration::from_secs(3);
    let result = run_prepared_command_graph(
        vec![node(signaled, vec![], None), node(exit(143), vec![], None)],
        GraphExitPolicy::All,
        || Instant::now() < deadline,
    )
    .unwrap();
    assert_eq!(result.status.signal(), Some(libc::SIGTERM));
    assert_eq!(result.status.code(), None);
    assert_eq!(result.statuses[1].signal(), None);
    assert_eq!(result.statuses[1].code(), Some(143));
}

#[test]
fn consumed_held_command_retains_executable_authority() {
    let held = HeldExecutable::open(std::path::Path::new("/usr/bin/true")).unwrap();
    let command = held.command(std::ffi::OsStr::new("graph-true")).unwrap();
    let result = run_prepared_command_graph(
        vec![CommandGraphNode {
            command: command.into(),
            dependencies: GraphDependencies::default(),
        }],
        GraphExitPolicy::All,
        || true,
    )
    .unwrap();
    assert!(result.status.success());
}

#[test]
fn cancellation_and_partial_spawn_failure_are_bounded() {
    let mut sleep = Command::new("/usr/bin/sleep");
    sleep.arg("30");
    assert!(run_prepared_command_graph(
        vec![node(sleep, vec![], None)],
        GraphExitPolicy::All,
        || false,
    )
    .is_err());
    let mut sleep = Command::new("/usr/bin/sleep");
    sleep.arg("30");
    let start = Instant::now();
    let result = run_prepared_command_graph(
        vec![
            node(sleep, vec![], None),
            node(Command::new("/missing-graph-executable"), vec![], None),
        ],
        GraphExitPolicy::All,
        || start.elapsed() < Duration::from_secs(3),
    );
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
}
