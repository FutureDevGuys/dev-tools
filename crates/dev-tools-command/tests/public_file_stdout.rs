#![cfg(target_os = "linux")]

use dev_tools_command::{BoundedCommandError, BoundedCommandOutput};
use dev_tools_command::{BoundedCommandErrorKind, BoundedCommandStream, HeldExecutable};
use std::process::Command;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

fn shell(script: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command.env_clear().args(["-c", script]);
    command
}

#[test]
fn exact_limit_succeeds_and_either_stream_overflow_fails() {
    let output = capture(shell("printf 12345678; printf abcdefgh >&2"), 8).unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"12345678");
    assert_eq!(output.stderr, b"abcdefgh");
    for (script, stream) in [
        ("printf 123456789", BoundedCommandStream::Stdout),
        ("printf 123456789 >&2", BoundedCommandStream::Stderr),
    ] {
        let error = capture(shell(script), 8).unwrap_err();
        assert_eq!(error.kind(), BoundedCommandErrorKind::OutputLimit(stream));
        assert!(error.cleanup_failures().is_empty());
    }
}

#[test]
fn file_overflow_stops_a_still_running_leader() {
    let started = std::time::Instant::now();
    let error = capture(shell("printf 123456789; exec /bin/sleep 10"), 8).unwrap_err();
    assert_eq!(
        error.kind(),
        BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout)
    );
    assert!(error.cleanup_failures().is_empty());
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn native_arguments_environment_cwd_closed_input_and_status_survive() {
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    let mut command = shell("if read value; then exit 80; fi; [ \"$PWD\" = \"$EXPECTED\" ] || exit 81; printf '%s' \"$1\"; printf '%s' \"$PUBLIC_VALUE\" >&2; exit 23");
    command
        .current_dir(root.path())
        .env("EXPECTED", root.path())
        .env("PUBLIC_VALUE", "public value")
        .env("TMPDIR", "/nonexistent-public-capture-test")
        .arg("argv-zero")
        .arg(std::ffi::OsString::from_vec(vec![b'a', 0xff, b' ', b'*']));
    let output = capture(command, 1024).unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, [b'a', 0xff, b' ', b'*']);
    assert_eq!(output.stderr, b"public value");
}

#[test]
fn invalid_limits_and_precancellation_do_not_spawn() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("spawned");
    for (limit, expected) in [
        (0, BoundedCommandErrorKind::InvalidResourceLimits),
        (1024, BoundedCommandErrorKind::Cancelled),
    ] {
        let mut command = shell("touch \"$1\"");
        command.arg("test").arg(&marker);
        let error = dev_tools_command::run_prepared_bounded_command_with_public_file_stdout_and_cancellation(
            command, Duration::from_secs(1), limit, &AtomicBool::new(true)).unwrap_err();
        assert_eq!(error.kind(), expected);
        assert!(!marker.exists());
    }
}

#[test]
fn held_executable_borrow_is_retained_through_execution() {
    let source = std::fs::canonicalize("/usr/bin/printf").unwrap();
    let held = HeldExecutable::open(&source).unwrap();
    let mut command = held
        .command(std::ffi::OsStr::new("public-observer"))
        .unwrap();
    command.env_clear().args(["%s", "held-output"]);
    let output = dev_tools_command::run_prepared_bounded_command_with_public_file_stdout(
        command,
        Duration::from_secs(2),
        1024,
    )
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"held-output");
    assert!(held.is_cloexec());
}

#[test]
fn timeout_and_spawn_failure_keep_their_typed_causes() {
    let error = dev_tools_command::run_prepared_bounded_command_with_public_file_stdout(
        shell("exec /bin/sleep 10"),
        Duration::from_millis(40),
        1024,
    )
    .unwrap_err();
    assert_eq!(error.kind(), BoundedCommandErrorKind::TimedOut);
    assert!(error.cleanup_failures().is_empty());
    let error = capture(Command::new("/nonexistent-public-observer"), 1024).unwrap_err();
    assert_eq!(error.kind(), BoundedCommandErrorKind::Start);
    assert!(error.io_error().is_some());
}

#[test]
fn parent_limits_and_default_pipe_mode_are_unchanged() {
    let before = rustix::process::getrlimit(rustix::process::Resource::Fsize);
    assert!(capture(shell("printf file"), 4).unwrap().status.success());
    let after = rustix::process::getrlimit(rustix::process::Resource::Fsize);
    assert_eq!(before.current, after.current);
    assert_eq!(before.maximum, after.maximum);
    let mut command = shell("[ -p /proc/self/fd/1 ] && [ -p /proc/self/fd/2 ] && printf pipe");
    let output =
        dev_tools_command::run_prepared_bounded_command(&mut command, Duration::from_secs(1), 4)
            .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"pipe");
}

#[test]
fn inherited_lower_file_limit_is_not_relaxed() {
    const CHILD: &str = "DEV_TOOLS_TEST_LOWER_FILE_LIMIT";
    if std::env::var_os(CHILD).is_some() {
        rustix::process::setrlimit(
            rustix::process::Resource::Fsize,
            rustix::process::Rlimit {
                current: Some(4),
                maximum: Some(4),
            },
        )
        .unwrap();
        let output = capture(shell("printf 12345678"), 1024).unwrap();
        assert!(!output.status.success());
        assert_eq!(output.stdout, b"1234");
        return;
    }
    // Only the isolated test process lowers its limits, never the test harness.
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inherited_lower_file_limit_is_not_relaxed",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

fn capture(command: Command, limit: usize) -> Result<BoundedCommandOutput, BoundedCommandError> {
    dev_tools_command::run_prepared_bounded_command_with_public_file_stdout(
        command,
        Duration::from_secs(5),
        limit,
    )
}

#[test]
fn public_file_stdout_is_regular_and_stderr_remains_a_pipe() {
    let mut command = Command::new("/bin/sh");
    command.env_clear().args([
        "-c",
        "[ -f /proc/self/fd/1 ] && [ -p /proc/self/fd/2 ] && printf regular",
    ]);
    let output = capture(command, 1024).unwrap();
    assert!(
        output.status.success(),
        "stdout was not a regular file with stderr still piped"
    );
    assert_eq!(output.stdout, b"regular");
    assert!(output.stderr.is_empty());
}

#[test]
#[ignore = "requires installed Node.js for public upstream-style truncation acceptance"]
fn public_file_stdout_preserves_node_early_exit_json() {
    let mut command = Command::new("/usr/bin/node");
    command.env_clear().arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/exit_after_stdout.mjs"
    ));
    let output = capture(command, 2 * 1024 * 1024).unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let expected = format!("{{\"payload\":\"{}\"}}", "x".repeat(1024 * 1024));
    assert_eq!(
        output.stdout.len(),
        expected.len(),
        "early exit truncated public JSON"
    );
    assert_eq!(output.stdout, expected.as_bytes());
}
