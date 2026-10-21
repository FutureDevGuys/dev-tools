use super::*;
use crate::test_support::{env_guard, write_executable as write_executable_atomic};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::TempDir;

fn write_executable(path: &Path, content: &str) {
    write_executable_atomic(path, content).unwrap();
}

#[test]
fn storage_failure_classification_uses_full_channels_not_program_name() {
    let error = anyhow!(ProcessExitError {
        program: "/fixture/ENOSPC/provider".to_string(),
        code: "1".to_string(),
        output: Some("ordinary package failure XENOSPCX".to_string()),
        stderr: None,
    });
    assert!(!process_storage_exhausted(&error));
    let error = anyhow!(ProcessExitError {
        program: "provider".to_string(),
        code: "1".to_string(),
        output: Some("ordinary stdout".to_string()),
        stderr: Some(format!(
            "{}\nEDQUOT: disk quota exceeded",
            "padding".repeat(100)
        )),
    });
    assert!(process_storage_exhausted(&error));
    assert!(!storage_exhaustion_output(
        "provider name XENOSPCX is unavailable"
    ));
    assert!(storage_exhaustion_output("ETIMEDOUT followed by ENOSPC"));
}

#[test]
fn cancellation_does_not_replace_an_observed_process_exit() {
    for code in [0, 42] {
        let mut child = Command::new("/bin/sh")
            .args(["-c", &format!("exit {code}")])
            .spawn()
            .unwrap();
        let observed = child.wait().unwrap();
        let result = wait_with_cancel_timeout(
            &mut child,
            CommandDeadline::new(Some(Duration::from_secs(1))),
            Some(Arc::new(|| true)),
            None,
        );
        assert!(matches!(result, Ok(status) if status == observed));
    }
}

#[test]
fn cancellation_drain_keeps_exited_status_and_releases_descendant_pipes() {
    use std::os::unix::process::CommandExt;
    for (code, guard_cleanup) in [(0, false), (42, false), (0, true), (42, true)] {
        let mut child = Command::new("/bin/sh")
            .args(["-c", &format!("/bin/sleep 5 & exit {code}")])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let reader = Some(std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).unwrap();
            bytes
        }));
        let observed = child.wait().unwrap();
        assert_eq!(observed.code(), Some(code));
        assert!(!reader.as_ref().unwrap().is_finished());
        let cancellation: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(|| true);
        let guard = Arc::new(CaptureGuardState::new(CaptureGuard {
            stall_timeout: Duration::ZERO,
            max_line_bytes: 1024,
            max_capture_bytes: 4096,
        }));
        guard.mark_reason(CaptureGuardReason::CaptureLimitExceeded);
        let started = std::time::Instant::now();
        wait_for_pipe_readers(
            &mut child,
            true,
            [&reader, &None],
            None,
            (!guard_cleanup).then_some(&cancellation),
            guard_cleanup.then_some(&guard),
            CommandDeadline::new(Some(Duration::from_secs(1))),
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(child.try_wait().unwrap(), Some(observed));
        assert!(join_pipe_reader(reader.unwrap()).is_empty());
    }
}

#[cfg(unix)]
#[test]
fn successful_capture_keeps_unterminated_stdout_separate_from_stderr() {
    let temp = TempDir::new().unwrap();
    let tool = temp.path().join("capture-fixture");
    write_executable(
        &tool,
        "#!/bin/sh\nprintf 'machine-readable value'\nprintf 'warning: diagnostic' >&2\n",
    );
    let program = tool.to_str().unwrap();
    assert_eq!(
        run_capture(
            program,
            std::iter::empty::<&str>(),
            Some(Duration::from_secs(5))
        )
        .unwrap(),
        "machine-readable value\nwarning: diagnostic"
    );
    assert_eq!(
        run_capture_stdout(
            program,
            std::iter::empty::<&str>(),
            Some(Duration::from_secs(5))
        )
        .unwrap(),
        "machine-readable value"
    );
}

#[cfg(unix)]
#[test]
fn stdout_capture_failure_keeps_both_streams_in_error_context() {
    let temp = TempDir::new().unwrap();
    let tool = temp.path().join("capture-fixture");
    write_executable(
        &tool,
        "#!/bin/sh\nprintf 'partial result'\nprintf 'error: failed' >&2\nexit 7\n",
    );
    let error = run_capture_stdout(
        tool.to_str().unwrap(),
        std::iter::empty::<&str>(),
        Some(Duration::from_secs(5)),
    )
    .unwrap_err();
    let exit_error = error.downcast_ref::<ProcessExitError>().unwrap_or_else(|| {
        let io_error = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>());
        panic!(
            "expected ProcessExitError: error={error:#}; debug={error:?}; raw_os_error={:?}",
            io_error.and_then(std::io::Error::raw_os_error),
        )
    });
    assert_eq!(exit_error.code, "7");
    assert_eq!(
        process_exit_output(&error),
        Some("partial result\nerror: failed")
    );
    assert_eq!(process_error_stderr(&error), Some("error: failed"));
    let detail = error.to_string();
    assert!(detail.contains("output: error: failed"));
    assert!(!detail.contains("partial result"));
}

#[test]
fn capture_timeout_preserves_partial_output_and_settles_owned_io() {
    // The cleanup probe resolves kill through the process-wide PATH.
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let tool = temp.path().join("timeout-fixture");
    write_executable(
        &tool,
        "#!/bin/sh\ntrap '' TERM\nprintf 'observed package progress\\n'\nprintf 'child diagnostic\\n' >&2\nexec /bin/sleep 20\n",
    );
    for use_pty in [false, true] {
        let pid = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let spawned = pid.clone();
        let on_spawn: Arc<dyn Fn(u32) + Send + Sync> =
            Arc::new(move |value| spawned.store(value, Ordering::SeqCst));
        let exited = Arc::new(AtomicBool::new(false));
        let exit_callback = exited.clone();
        let on_exit: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || exit_callback.store(true, Ordering::SeqCst));
        let (sender, receiver) = mpsc::channel();
        let error = if use_pty {
            run_capture_with_pty_options(
                tool.to_str().unwrap(),
                std::iter::empty::<&str>(),
                Some(Duration::from_millis(500)),
                Arc::new(|_, _| {}),
                Arc::new(|| false),
                on_spawn,
                on_exit,
                CaptureGuard {
                    stall_timeout: Duration::ZERO,
                    max_line_bytes: 1024,
                    max_capture_bytes: 4096,
                },
                receiver,
                true,
            )
            .unwrap_err()
        } else {
            run_capture_output_with_options(
                tool.to_str().unwrap(),
                std::iter::empty::<&str>(),
                Some(Duration::from_millis(500)),
                &[],
                false,
                false,
                None,
                None,
                Some(on_spawn),
                Some(on_exit),
                true,
                None,
                Some(receiver),
            )
            .err()
            .expect("runner deadline must remain failure")
        };
        assert!(process_timed_out(&error));
        assert_eq!(
            error.to_string(),
            format!("timeout running {}", tool.display())
        );
        let partial = process_exit_output(&error).unwrap();
        assert!(partial.contains("observed package progress"));
        assert!(partial.contains("child diagnostic"));
        assert_eq!(
            process_error_stderr(&error),
            if use_pty {
                None
            } else {
                Some("child diagnostic")
            }
        );
        assert!(exited.load(Ordering::SeqCst));
        assert!(sender.send("not delivered".to_string()).is_err());
        assert!(!pid_exists(pid.load(Ordering::SeqCst) as i32)
            .expect("launch kill -0 process-existence probe"));
    }
}

#[test]
fn capture_deadline_includes_descendant_pipe_drain_after_leader_exit() {
    let temp = TempDir::new().unwrap();
    let tool = temp.path().join("exited-leader-fixture");
    write_executable(
        &tool,
        "#!/bin/sh\ntrap '' TERM\nprintf 'leader completed\\n'\nprintf 'retained diagnostic\\n' >&2\n/bin/sleep 3 &\nexit 0\n",
    );
    let started = std::time::Instant::now();
    let result = run_capture(
        tool.to_str().unwrap(),
        std::iter::empty::<&str>(),
        Some(Duration::from_millis(250)),
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "descendant output outlived the command deadline: {elapsed:?}"
    );
    let error = result.expect_err("unsettled command output must not be reported as success");
    assert!(process_timed_out(&error), "{error:#}");
    let partial = process_exit_output(&error).unwrap();
    assert!(partial.contains("leader completed"));
    assert!(partial.contains("retained diagnostic"));
}

#[test]
fn capture_deadline_allows_descendant_output_that_settles_in_time() {
    let temp = TempDir::new().unwrap();
    let tool = temp.path().join("settled-descendant-fixture");
    write_executable(
        &tool,
        "#!/bin/sh\n/bin/sh -c '/bin/sleep 0.1; printf \"descendant result\\n\"' &\nexit 0\n",
    );
    assert_eq!(
        run_capture(
            tool.to_str().unwrap(),
            std::iter::empty::<&str>(),
            Some(Duration::from_secs(2)),
        )
        .unwrap(),
        "descendant result\n"
    );
}

struct EnvVarGuard {
    key: &'static str,
    original: Option<OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: impl Into<OsString>) -> Self {
        let original = std::env::var_os(key);
        std::env::set_var(key, value.into());
        Self { key, original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

struct CurrentDirGuard {
    original: PathBuf,
}

impl CurrentDirGuard {
    fn change_to(path: &Path) -> Self {
        let original = std::env::current_dir().expect("current dir");
        std::env::set_current_dir(path).expect("set current dir");
        Self { original }
    }
}

impl Drop for CurrentDirGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.original);
    }
}

fn pid_exists(pid: i32) -> std::io::Result<bool> {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
}

#[test]
fn missing_pid_probe_cannot_report_process_absence() {
    let _lock = env_guard();
    let temp = TempDir::new().expect("empty executable directory");
    let _path_guard = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let pid = i32::try_from(std::process::id()).expect("test process ID fits i32");

    let error =
        pid_exists(pid).expect_err("an unavailable process probe must not report process absence");
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
}

#[test]
fn which_absolutizes_relative_path_entries() {
    let _lock = env_guard();

    let temp = TempDir::new().expect("temp dir");
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).expect("create bin dir");
    let tool = bin.join("reltool");
    write_executable(
        &tool,
        r#"#!/bin/sh
set -eu
printf 'relative-path-tool\n'
"#,
    );

    let _cwd_guard = CurrentDirGuard::change_to(temp.path());
    let _path_guard = EnvVarGuard::set("PATH", "bin");

    let found = which("reltool").expect("tool should resolve from relative PATH entry");
    assert!(found.is_absolute(), "expected absolute path, got {found:?}");
    assert_eq!(found, tool);

    std::env::set_current_dir(std::env::temp_dir()).expect("change cwd after lookup");
    let output = Command::new(found)
        .output()
        .expect("run resolved executable");
    assert!(output.status.success(), "resolved executable should run");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "relative-path-tool\n"
    );
}

#[test]
fn resolve_executable_absolutizes_relative_explicit_programs() {
    let _lock = env_guard();

    let temp = TempDir::new().expect("temp dir");
    let bin = temp.path().join("bin");
    fs::create_dir(&bin).expect("create bin dir");
    let tool = bin.join("explicittool");
    write_executable(
        &tool,
        r#"#!/bin/sh
set -eu
printf 'explicit-path-tool\n'
"#,
    );

    let _cwd_guard = CurrentDirGuard::change_to(temp.path());
    let found = resolve_executable("bin/explicittool");

    assert!(found.is_absolute(), "expected absolute path, got {found:?}");
    assert_eq!(found, tool);

    std::env::set_current_dir(std::env::temp_dir()).expect("change cwd after lookup");
    let output = Command::new(found)
        .output()
        .expect("run resolved executable");
    assert!(output.status.success(), "resolved executable should run");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "explicit-path-tool\n"
    );
}

#[test]
#[ignore = "depends on process-group semantics that vary by environment"]
fn controlled_capture_cancel_terminates_descendants() {
    let _lock = env_guard();
    let temp = TempDir::new().expect("temp dir");
    let script = temp.path().join("spawn-helper.sh");
    let helper_pid_file = temp.path().join("helper.pid");
    write_executable(
        &script,
        r#"#!/bin/sh
set -eu
helper_pid_file="$1"
sh -c 'while :; do sleep 1; done' &
helper_pid="$!"
printf '%s\n' "$helper_pid" > "$helper_pid_file"
while :; do sleep 1; done
"#,
    );

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_for_thread = cancel_flag.clone();
    let script_str = script.to_string_lossy().to_string();
    let helper_pid_file_str = helper_pid_file.to_string_lossy().to_string();

    let runner = std::thread::spawn(move || {
        run_capture_streaming_controlled_stdin_tty_capture(
            &script_str,
            vec![helper_pid_file_str.as_str()],
            Some(Duration::from_secs(30)),
            Arc::new(|_, _| {}),
            Arc::new(move || cancel_for_thread.load(Ordering::SeqCst)),
            Arc::new(|_| {}),
            Arc::new(|| {}),
        )
    });

    let mut helper_pid: Option<i32> = None;
    for _ in 0..200 {
        if let Ok(raw) = fs::read_to_string(&helper_pid_file) {
            if let Ok(pid) = raw.trim().parse::<i32>() {
                helper_pid = Some(pid);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let helper_pid = helper_pid.expect("helper pid to be written");
    assert!(
        pid_exists(helper_pid).expect("launch kill -0 process-existence probe"),
        "expected helper process to be running"
    );

    cancel_flag.store(true, Ordering::SeqCst);
    let result = runner.join().expect("runner thread join");
    let err = result.expect_err("run should be canceled");
    assert!(err.downcast_ref::<Cancelled>().is_some());

    let mut helper_dead = false;
    for _ in 0..200 {
        if !pid_exists(helper_pid).expect("launch kill -0 process-existence probe") {
            helper_dead = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !helper_dead {
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &helper_pid.to_string()])
            .status();
    }
    assert!(helper_dead, "helper subprocess survived cancel");
}

#[test]
fn guarded_capture_stalls_after_initial_output() {
    let _lock = env_guard();

    let temp = TempDir::new().expect("temp dir");
    let script = temp.path().join("output-then-stall.sh");
    write_executable(
        &script,
        r#"#!/bin/sh
set -eu
echo "initial output"
sleep 5
"#,
    );

    let script_str = script.to_string_lossy().to_string();
    let result = run_capture_streaming_stdin_tty_capture_guarded(
        &script_str,
        Vec::<&str>::new(),
        Some(Duration::from_secs(10)),
        Arc::new(|_, _| {}),
        CaptureGuard {
            stall_timeout: Duration::from_millis(300),
            max_line_bytes: 8192,
            max_capture_bytes: 1 << 20,
        },
    );

    let err = result.expect_err("expected guard-triggered stall");
    assert_eq!(
        capture_guard_reason(&err),
        Some(CaptureGuardReason::Stall),
        "expected stall guard reason after initial output"
    );
}

#[test]
fn non_zero_exit_preserves_full_output_for_recovery() {
    let temp = TempDir::new().expect("temp dir");
    let script = temp.path().join("fail-with-output.sh");
    write_executable(
        &script,
        r#"#!/bin/sh
set -eu
i=0
while [ "$i" -lt 120 ]; do
  printf 'prefix '
  i=$((i + 1))
done
printf '\nerror: failed to commit transaction (conflicting files)\n'
printf 'exodus-debug: /usr/lib/debug/.build-id/be/abc.debug exists in filesystem (owned by pinokio-bin-debug)\n'
exit 1
"#,
    );

    let script_str = script.to_string_lossy().to_string();
    let err = run_capture(
        &script_str,
        Vec::<&str>::new(),
        Some(Duration::from_secs(10)),
    )
    .expect_err("expected non-zero exit");

    assert!(
        err.downcast_ref::<ProcessExitError>().is_some(),
        "expected a process exit error, got {err:?}"
    );
    let display = err.to_string();
    assert!(
        display.contains("exited non-zero (code=1); output:"),
        "unexpected process exit diagnostic: {err:?}"
    );
    assert!(display.contains("prefix prefix"), "diagnostic: {display}");
    assert!(
        !display.contains("pinokio-bin-debug"),
        "diagnostic was not bounded: {display}"
    );

    let full = process_exit_output(&err).expect("preserved full output");
    assert!(full.contains("pinokio-bin-debug"));
    assert!(full.contains("failed to commit transaction (conflicting files)"));
}

#[test]
fn pty_capture_surfaces_bash_read_prompt_and_accepts_input() {
    let _lock = env_guard();

    let temp = TempDir::new().expect("temp dir");
    let script = temp.path().join("read-prompt.sh");
    write_executable(
        &script,
        r#"#!/usr/bin/env bash
set -eu
read -rp '-> Select the service(s) to restart: ' selection
printf 'selection=%s\n' "$selection"
"#,
    );

    let lines = Arc::new(std::sync::Mutex::new(Vec::<(StreamKind, String)>::new()));
    let lines_for_cb = lines.clone();
    let (stdin_tx, stdin_rx) = std::sync::mpsc::channel::<String>();
    let input_sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        stdin_tx.send("1 3".to_string()).expect("send selection");
    });
    let script_str = script.to_string_lossy().to_string();
    let result = run_capture_streaming_controlled_stdin_pty_capture_guarded(
        &script_str,
        Vec::<&str>::new(),
        Some(Duration::from_secs(5)),
        Arc::new(move |kind, line| {
            lines_for_cb.lock().expect("line lock").push((kind, line));
        }),
        Arc::new(|| false),
        Arc::new(|_| {}),
        Arc::new(|| {}),
        CaptureGuard {
            stall_timeout: Duration::ZERO,
            max_line_bytes: 8192,
            max_capture_bytes: 1 << 20,
        },
        stdin_rx,
    )
    .expect("pty capture should succeed");
    input_sender.join().expect("input sender join");

    assert!(result.contains("Select the service(s) to restart:"));
    assert!(result.contains("selection=1 3"));
    let captured = lines.lock().expect("lines lock");
    assert!(captured.iter().any(|(kind, line)| {
        *kind == StreamKind::Stdout && line.contains("Select the service(s) to restart:")
    }));
    assert!(captured
        .iter()
        .any(|(kind, line)| { *kind == StreamKind::Stdout && line.contains("selection=1 3") }));
}

struct StreamChunks(std::collections::VecDeque<Vec<u8>>);

impl Read for StreamChunks {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let Some(mut chunk) = self.0.pop_front() else {
            return Ok(0);
        };
        let count = output.len().min(chunk.len());
        let remainder = chunk.split_off(count);
        output[..count].copy_from_slice(&chunk);
        if !remainder.is_empty() {
            self.0.push_front(remainder);
        }
        Ok(count)
    }
}

fn pipe_records(
    kind: StreamKind,
    chunks: Vec<Vec<u8>>,
    guard: Option<Arc<CaptureGuardState>>,
) -> (Vec<u8>, Vec<(StreamKind, String)>) {
    let records = Arc::new(std::sync::Mutex::new(Vec::new()));
    let collected = records.clone();
    let reader = StreamChunks(
        chunks
            .into_iter()
            .filter(|chunk| !chunk.is_empty())
            .collect(),
    );
    let bytes = read_pipe_thread(
        kind,
        reader,
        Some(Arc::new(move |kind, line| {
            collected.lock().unwrap().push((kind, line));
        })),
        guard,
    )
    .join()
    .unwrap();
    let records = records.lock().unwrap().clone();
    (bytes, records)
}

// A regular file makes this reader's 8192-byte read boundaries deterministic.
// The existing real-PTY prompt/input regression still exercises native PTY IO.
fn pty_reader_records(
    input: &[u8],
    guard: Option<Arc<CaptureGuardState>>,
) -> (Vec<u8>, Vec<(StreamKind, String)>) {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("pty-reader-input");
    fs::write(&path, input).unwrap();
    let records = Arc::new(std::sync::Mutex::new(Vec::new()));
    let collected = records.clone();
    let bytes = read_pty_thread(
        File::open(path).unwrap(),
        Some(Arc::new(move |kind, line| {
            collected.lock().unwrap().push((kind, line));
        })),
        guard,
        Arc::new(AtomicBool::new(false)),
    )
    .join()
    .unwrap();
    let records = records.lock().unwrap().clone();
    (bytes, records)
}

fn framing_cases() -> Vec<(&'static [u8], Vec<&'static str>)> {
    vec![
        (b"", vec![]),
        (b"\n", vec![""]),
        (b"\n\n", vec!["", ""]),
        (b"a\n\nb\n", vec!["a", "", "b"]),
        (b"a\n", vec!["a"]),
        (b"a", vec!["a"]),
        (b"\r", vec![""]),
        (b"\r\n", vec![""]),
        (b"a\r\n\r\nb\r\n", vec!["a", "", "b"]),
        (b"a\rb\r", vec!["a", "b"]),
        (b"a\r\r", vec!["a", ""]),
        (b"a\n\rb", vec!["a", "", "b"]),
        (b"\r\r\n", vec!["", ""]),
        (b" \n\t\n", vec![" ", "\t"]),
        (b"\xff\n\n", vec!["\u{fffd}", ""]),
        ("\u{20ac}\n\n".as_bytes(), vec!["\u{20ac}", ""]),
    ]
}

#[test]
fn streaming_pipe_preserves_blank_records_and_line_boundaries() {
    for kind in [StreamKind::Stdout, StreamKind::Stderr] {
        for (input, lines) in framing_cases() {
            let expected: Vec<_> = lines.iter().map(|line| (kind, line.to_string())).collect();
            let mut partitions = vec![vec![input.to_vec()]];
            partitions.push(input.iter().map(|byte| vec![*byte]).collect());
            for split in 0..=input.len() {
                partitions.push(vec![input[..split].to_vec(), input[split..].to_vec()]);
            }
            for chunks in partitions {
                let (bytes, records) = pipe_records(kind, chunks.clone(), None);
                assert_eq!(bytes, input, "captured bytes changed: {chunks:?}");
                assert_eq!(records, expected, "framing changed: {kind:?} {chunks:?}");
            }
        }
    }
}

#[test]
fn streaming_pipe_partial_prompt_terminators_do_not_create_blank_records() {
    let cases: Vec<(Vec<&[u8]>, Vec<&str>)> = vec![
        (vec![b"Password:"], vec!["Password:"]),
        (vec![b"Password:", b"\n"], vec!["Password:"]),
        (vec![b"Password:", b"\r", b"\n"], vec!["Password:"]),
        (vec![b"Password:", b"\n\n"], vec!["Password:", ""]),
        (vec![b"Password:", b"\r", b"\n\r\n"], vec!["Password:", ""]),
        (vec![b"Password:", b"answer\n"], vec!["Password:", "answer"]),
    ];
    for kind in [StreamKind::Stdout, StreamKind::Stderr] {
        for (chunks, lines) in &cases {
            let chunks: Vec<_> = chunks.iter().map(|chunk| chunk.to_vec()).collect();
            let expected: Vec<_> = lines.iter().map(|line| (kind, line.to_string())).collect();
            let input = chunks.concat();
            let (bytes, records) = pipe_records(kind, chunks, None);
            assert_eq!(bytes, input);
            assert_eq!(records, expected);
        }
    }
}

#[test]
fn pty_reader_preserves_blank_records_and_split_crlf() {
    for (input, lines) in framing_cases() {
        let expected: Vec<_> = lines
            .iter()
            .map(|line| (StreamKind::Stdout, line.to_string()))
            .collect();
        let (bytes, records) = pty_reader_records(input, None);
        assert_eq!(bytes, input);
        assert_eq!(records, expected);
    }
    let long = "a".repeat(8191);
    let input = format!("{long}\r\n\r\nb\r\n");
    let (bytes, records) = pty_reader_records(input.as_bytes(), None);
    assert_eq!(bytes, input.as_bytes());
    assert_eq!(
        records,
        vec![
            (StreamKind::Stdout, long),
            (StreamKind::Stdout, String::new()),
            (StreamKind::Stdout, "b".to_string()),
        ]
    );
    let prompt = format!("{}Password:", "a".repeat(8192 - "Password:".len()));
    for ending in ["", "\n", "\r\n", "\r\n\n"] {
        let input = format!("{prompt}{ending}");
        let (bytes, records) = pty_reader_records(input.as_bytes(), None);
        let mut expected = vec![(StreamKind::Stdout, prompt.clone())];
        if ending == "\r\n\n" {
            expected.push((StreamKind::Stdout, String::new()));
        }
        assert_eq!(bytes, input.as_bytes());
        assert_eq!(records, expected);
    }
}

#[test]
fn streaming_readers_do_not_emit_after_capture_guard() {
    for use_pty in [false, true] {
        for (input, line_limit, byte_limit, pre_latched, wanted_reason, expected) in [
            ("abc\n\n", 3, 5, false, None, vec!["abc", ""]),
            (
                "abcd\n\n",
                3,
                64,
                false,
                Some(CaptureGuardReason::LineTooLong),
                vec![],
            ),
            (
                "a\n\n\n",
                64,
                3,
                false,
                Some(CaptureGuardReason::CaptureLimitExceeded),
                vec![],
            ),
            (
                "\n\n",
                64,
                64,
                true,
                Some(CaptureGuardReason::Stall),
                vec![],
            ),
        ] {
            let guard = Arc::new(CaptureGuardState::new(CaptureGuard {
                stall_timeout: Duration::ZERO,
                max_line_bytes: line_limit,
                max_capture_bytes: byte_limit,
            }));
            if pre_latched {
                guard.mark_reason(CaptureGuardReason::Stall);
            }
            let (_, records) = if use_pty {
                pty_reader_records(input.as_bytes(), Some(guard.clone()))
            } else {
                pipe_records(
                    StreamKind::Stdout,
                    vec![input.as_bytes().to_vec()],
                    Some(guard.clone()),
                )
            };
            assert_eq!(guard.reason(), wanted_reason);
            let expected: Vec<_> = expected
                .iter()
                .map(|line| (StreamKind::Stdout, line.to_string()))
                .collect();
            assert_eq!(records, expected, "guard emitted records: pty={use_pty}");
        }
    }
    let guard = Arc::new(CaptureGuardState::new(CaptureGuard {
        stall_timeout: Duration::ZERO,
        max_line_bytes: 64,
        max_capture_bytes: 5,
    }));
    let (bytes, records) = pipe_records(
        StreamKind::Stderr,
        vec![b"ok\n".to_vec(), b"over\n\n".to_vec()],
        Some(guard.clone()),
    );
    assert_eq!(bytes, b"ok\n");
    assert_eq!(records, vec![(StreamKind::Stderr, "ok".to_string())]);
    assert_eq!(
        guard.reason(),
        Some(CaptureGuardReason::CaptureLimitExceeded)
    );
}

#[test]
fn authority_failure_classification_requires_captured_diagnostics_not_names() {
    for diagnostic in [
        "npm error code EACCES",
        "npm ERR! code EPERM",
        "EACCES: permission denied, rename '/fixture'",
        "Permission denied.",
        "Access is denied.",
        "Operation not permitted",
    ] {
        assert!(permission_denied_output(diagnostic), "{diagnostic}");
    }
    for text in [
        "/tmp/EACCES/cache",
        "C:\\EPERM\\cache",
        "npm-cache-eperm",
        "NOT_EACCES XEPERMX EACCES_CACHE",
        "EACCES.log EPERM.txt permission denied.txt",
        "/tmp/permission denied/package",
        "ordinary package failure",
    ] {
        assert!(!permission_denied_output(text), "{text}");
    }
    let error = anyhow!(ProcessExitError {
        program: "/fixture/EACCES/provider".to_string(),
        code: "1".to_string(),
        output: Some("ordinary stdout".to_string()),
        stderr: Some("unrelated failure".to_string()),
    });
    assert!(!process_permission_denied(&error));
    assert!(!process_permission_denied(&anyhow!("EACCES health path")));
    for stdout in [true, false] {
        let diagnostic = format!("{}\nnpm ERR! code EPERM", "padding".repeat(100));
        let error = anyhow!(ProcessExitError {
            program: "provider".to_string(),
            code: "1".to_string(),
            output: Some(if stdout {
                diagnostic.clone()
            } else {
                "ordinary stdout".to_string()
            }),
            stderr: Some(if stdout {
                "unrelated stderr".to_string()
            } else {
                diagnostic
            }),
        });
        assert!(process_permission_denied(&error));
    }
}
