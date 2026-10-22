//! Real process lifecycle acceptance with a compile-time harmless restart backend.
//! This feature never invokes an operating-system restart, even without a marker.
#![cfg(all(unix, feature = "restart-test-backend"))]
// Native PTY acceptance requires owned-descriptor and pre-exec FFI; each call documents safety.
#![allow(unsafe_code)]

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use wait_timeout::ChildExt;

/// Own and reap each process even when a lifecycle assertion panics.
struct TestChild(Child);

impl std::ops::Deref for TestChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for TestChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(Some(_))) {
            return;
        }
        if let Ok(pid) = i32::try_from(self.0.id()) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGINT,
            );
        }
        if !matches!(self.0.wait_timeout(Duration::from_secs(2)), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Fixture {
    home: TempDir,
    marker: PathBuf,
}

impl Fixture {
    fn new(engine: &str, script: &str) -> Self {
        let home = TempDir::new().unwrap();
        let config = home.path().join("config/update-all");
        fs::create_dir_all(config.join("catalog.d/local")).unwrap();
        fs::write(config.join("config.toml"), format!(
            "[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"2\"\n[tasks.tool_update]\nretries=0\ntimeout_secs=15\n"
        )).unwrap();
        let catalog = format!(
            r#"
[tasks."local/restart-fixture"]
label="Harmless restart lifecycle fixture"
category="maintenance"
os=["linux","macos"]
detect_mode="command_available"
command="/bin/sh"
args=["-c", {}]
policy_key="tool_update"
"#,
            serde_json::to_string(script).unwrap()
        );
        fs::write(config.join("catalog.d/local/restart.toml"), catalog).unwrap();
        let marker = home.path().join("restart-requests.jsonl");
        Self { home, marker }
    }

    fn process(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_update-all"));
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join("config"))
            .env("XDG_STATE_HOME", self.home.path().join("state"))
            .env("PATH", "/usr/bin:/bin")
            .env("TERM", "xterm-256color")
            .env("UPDATE_ALL_TEST_RESTART_MARKER", &self.marker)
            .stdin(Stdio::null());
        command
    }

    fn run(&self) -> Command {
        let mut command = self.process();
        command.args([
            "--plain",
            "--completions",
            "off",
            "--only",
            "local/restart-fixture",
        ]);
        command
    }

    fn only_run(&self) -> PathBuf {
        let runs: Vec<_> = fs::read_dir(self.home.path().join("state/update-all/runs"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.join("run-meta.json").is_file())
            .collect();
        assert_eq!(runs.len(), 1);
        runs[0].clone()
    }

    fn assert_no_restart(&self) {
        assert!(
            !self.marker.exists(),
            "unexpected restart request: {:?}",
            fs::read_to_string(&self.marker)
        );
    }
}

fn json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn wait_for(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !path.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited before {}",
            path.display()
        );
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("timed out waiting for {}", path.display());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_child(child: &mut Child) -> std::process::ExitStatus {
    match child.wait_timeout(Duration::from_secs(20)).unwrap() {
        Some(status) => status,
        None => {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("update-all did not settle within fixture deadline");
        }
    }
}

#[test]
fn restart_after_requests_once_only_after_successful_persisted_terminalization() {
    for engine in ["sync", "async"] {
        for flag in ["--restart-after", "--reboot"] {
            let fixture = Fixture::new(engine, "printf 'harmless task complete\\n'");
            let output = fixture.run().arg(flag).output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let lines = fs::read_to_string(&fixture.marker).unwrap();
            let requests: Vec<Value> = lines
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(requests.len(), 1, "restart must be requested exactly once");
            let request = &requests[0];
            assert_eq!(request["run"]["status"], "completed");
            assert_eq!(request["run"]["exit_code"], 0);
            assert_eq!(request["metadata"]["status"], "completed");
            assert_eq!(request["run_completed_count"], 1);
            assert_eq!(request["terminal_raw_mode"], false);
            assert_eq!(request["task_admission_owned"], true);
            assert_eq!(request["run"]["engine_mode"], engine);
            assert_eq!(request["run"], json(fixture.only_run().join("run.json")));
            assert!(!fixture
                .home
                .path()
                .join("state/update-all/runs/.update-all-task-run.lock")
                .exists());
        }
    }
}

#[test]
fn restart_after_is_opt_in_and_read_only_surfaces_never_request_it() {
    let fixture = Fixture::new("sync", "exit 0");
    assert!(fixture.run().output().unwrap().status.success());
    fixture.assert_no_restart();
    for args in [
        vec!["--restart-after", "list"],
        vec!["--restart-after", "build-info", "--json"],
        vec!["--restart-after", "--version"],
        vec!["--restart-after", "--help"],
        vec!["--restart-after", "restore", "--json"],
    ] {
        let output = fixture.process().args(&args).output().unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.assert_no_restart();
    }
}

#[test]
fn restart_after_suppresses_failed_and_invalid_task_runs() {
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(engine, "exit 7");
        let output = fixture.run().arg("--restart-after").output().unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(
            json(fixture.only_run().join("run.json"))["status"],
            "failed"
        );
        fixture.assert_no_restart();

        let fixture = Fixture::new(engine, "exit 0");
        let output = fixture
            .process()
            .args([
                "--plain",
                "--completions",
                "off",
                "--restart-after",
                "--only",
                "local/not-present",
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        fixture.assert_no_restart();
    }
}

#[test]
fn restart_after_suppresses_empty_task_selection() {
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(engine, "exit 0");
        let output = fixture
            .run()
            .args(["--restart-after", "--exclude", "local/restart-fixture"])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        fixture.assert_no_restart();
    }
}

#[test]
fn restart_after_suppresses_canceled_subprocess_runs() {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(engine, "touch \"$HOME/task-started\"; sleep 12");
        let mut child = TestChild(
            fixture
                .run()
                .arg("--restart-after")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(&fixture.home.path().join("task-started"), &mut child);
        kill(
            Pid::from_raw(i32::try_from(child.id()).unwrap()),
            Signal::SIGINT,
        )
        .unwrap();
        assert_eq!(wait_child(&mut child).code(), Some(3));
        assert_eq!(
            json(fixture.only_run().join("run.json"))["status"],
            "canceled"
        );
        fixture.assert_no_restart();
    }
}

#[test]
fn restart_after_suppresses_failed_evidence_persistence() {
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(
            engine,
            "touch \"$HOME/task-started\"; while [ ! -e \"$HOME/release\" ]; do sleep 0.02; done",
        );
        let mut child = TestChild(
            fixture
                .run()
                .arg("--restart-after")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(&fixture.home.path().join("task-started"), &mut child);
        let artifact = fixture.only_run().join("run.json");
        // A directory at the artifact destination forces publication to fail even as root.
        assert!(!artifact.exists());
        fs::create_dir(&artifact).unwrap();
        fs::write(fixture.home.path().join("release"), "continue").unwrap();
        assert!(!wait_child(&mut child).success());
        fixture.assert_no_restart();
        assert_eq!(
            json(fixture.only_run().join("run-meta.json"))["status"],
            "failed"
        );
    }
}

#[test]
fn restart_request_failure_preserves_completed_task_evidence_and_fails_invocation() {
    let fixture = Fixture::new("async", "exit 0");
    let output = fixture
        .run()
        .arg("--restart-after")
        .env("UPDATE_ALL_TEST_RESTART_FAIL", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    fixture.assert_no_restart();
    let run = fixture.only_run();
    assert_eq!(json(run.join("run.json"))["status"], "completed");
    assert_eq!(json(run.join("run.json"))["exit_code"], 0);
    let receipt = json(run.join("restart.json"));
    assert_eq!(receipt["status"], "request_failed_or_uncertain");
    assert_eq!(receipt["automatic_retry_allowed"], false);
    assert!(String::from_utf8_lossy(&output.stderr)
        .to_lowercase()
        .contains("restart"));
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_after_waits_for_dashboard_exit_and_restores_terminal() {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    let fixture = Fixture::new("async", "printf 'dashboard harmless task\\n'");
    let mut master_fd = -1;
    let mut slave_fd = -1;
    let size = libc::winsize {
        ws_row: 40,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty initializes two owned descriptors; all pointer arguments are valid.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        },
        0
    );
    // SAFETY: these distinct successful openpty descriptors are transferred exactly once.
    let mut master = unsafe { fs::File::from_raw_fd(master_fd) };
    let slave = unsafe { fs::File::from_raw_fd(slave_fd) };
    let mut reader = master.try_clone().unwrap();
    let capture = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("read dashboard PTY: {error}"),
            }
        }
        bytes
    });
    let mut command = fixture.process();
    command
        .args([
            "--dashboard",
            "--completions",
            "off",
            "--only",
            "local/restart-fixture",
            "--restart-after",
        ])
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave.try_clone().unwrap());
    // SAFETY: only async-signal-safe native calls occur in this pre-exec closure.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = TestChild(command.spawn().unwrap());
    drop(command);
    drop(slave);
    let deadline = Instant::now() + Duration::from_secs(15);
    let run = loop {
        let root = fixture.home.path().join("state/update-all/runs");
        let ready = fs::read_dir(root)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                fs::read_to_string(path.join("events.jsonl"))
                    .is_ok_and(|events| events.contains("\"kind\":\"tasks_completed\""))
            });
        if let Some(run) = ready {
            break run;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "dashboard exited before tasks completed"
        );
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("dashboard tasks did not complete");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let metadata = json(run.join("run-meta.json"));
    assert!(
        matches!(metadata["status"].as_str(), Some("running" | "finalizing")),
        "dashboard still owns the nonterminal run: {metadata}"
    );
    fixture.assert_no_restart();
    master.write_all(b"q").unwrap();
    assert!(wait_child(&mut child).success());
    drop(master);
    let bytes = capture.join().unwrap();
    let screen = String::from_utf8_lossy(&bytes);
    assert!(
        screen.contains("\x1b[?1049h"),
        "dashboard did not enter alternate screen"
    );
    assert!(
        screen.contains("\x1b[?1049l"),
        "dashboard did not leave alternate screen"
    );
    let requests = fs::read_to_string(&fixture.marker).unwrap();
    assert_eq!(requests.lines().count(), 1);
    let request: Value = serde_json::from_str(requests.trim()).unwrap();
    assert_eq!(request["terminal_raw_mode"], false);
    assert_eq!(request["run"]["ui_mode"], "dashboard");
    assert_eq!(request["metadata"]["status"], "completed");
    assert_eq!(request["run_completed_count"], 1);
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_after_refuses_when_second_run_started_during_dashboard_review() {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    let fixture = Fixture::new("async", "printf 'dashboard harmless task\\n'");
    let mut master_fd = -1;
    let mut slave_fd = -1;
    let size = libc::winsize {
        ws_row: 40,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty initializes two owned descriptors; all pointer arguments are valid.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size,
            )
        },
        0
    );
    // SAFETY: these distinct successful openpty descriptors are transferred exactly once.
    let mut master = unsafe { fs::File::from_raw_fd(master_fd) };
    let slave = unsafe { fs::File::from_raw_fd(slave_fd) };
    let mut reader = master.try_clone().unwrap();
    let capture = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => bytes.extend_from_slice(&buffer[..count]),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("read dashboard PTY: {error}"),
            }
        }
        bytes
    });
    let mut command = fixture.process();
    command
        .args([
            "--dashboard",
            "--completions",
            "off",
            "--only",
            "local/restart-fixture",
            "--restart-after",
        ])
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave.try_clone().unwrap());
    // SAFETY: only async-signal-safe native calls occur in this pre-exec closure.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = TestChild(command.spawn().unwrap());
    drop(command);
    drop(slave);
    let deadline = Instant::now() + Duration::from_secs(15);
    let run = loop {
        let root = fixture.home.path().join("state/update-all/runs");
        let ready = fs::read_dir(root)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                fs::read_to_string(path.join("events.jsonl"))
                    .is_ok_and(|events| events.contains("\"kind\":\"tasks_completed\""))
            });
        if let Some(run) = ready {
            break run;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "dashboard exited before tasks completed"
        );
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("dashboard tasks did not complete");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let metadata = json(run.join("run-meta.json"));
    assert!(
        matches!(metadata["status"].as_str(), Some("running" | "finalizing")),
        "dashboard still owns the nonterminal run: {metadata}"
    );
    fixture.assert_no_restart();
    // The task-completed journal event precedes lock release. Wait for the
    // actual admission boundary rather than racing the first run's final writes.
    let task_lock = fixture
        .home
        .path()
        .join("state/update-all/runs/.update-all-task-run.lock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while task_lock.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "first dashboard exited unexpectedly"
        );
        assert!(
            Instant::now() < deadline,
            "first run did not release task admission"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // The first run released task admission but its dashboard is still open.
    // Start a harmless second writer under the exact same admission root.
    let second_ready = fixture.home.path().join("second-run.ready");
    let release_second = fixture.home.path().join("release-second");
    let script = r#"printf ready > "$HOME/second-run.ready"; while [ ! -f "$HOME/release-second" ]; do sleep 0.01; done"#;
    fs::write(
        fixture
            .home
            .path()
            .join("config/update-all/catalog.d/local/blocker.toml"),
        format!(
            r#"
[tasks."local/restart-blocker"]
label="Harmless second-run writer fixture"
category="maintenance"
os=["linux","macos"]
detect_mode="command_available"
command="/bin/sh"
args=["-c", {}]
policy_key="tool_update"
"#,
            serde_json::to_string(script).unwrap()
        ),
    )
    .unwrap();
    let mut second_command = fixture.process();
    second_command.args([
        "--plain",
        "--completions",
        "off",
        "--only",
        "local/restart-blocker",
    ]);
    let mut second = TestChild(second_command.spawn().unwrap());
    wait_for(&second_ready, &mut second);
    assert!(second.try_wait().unwrap().is_none());
    master.write_all(b"q").unwrap();
    assert_eq!(wait_child(&mut child).code(), Some(1));
    fixture.assert_no_restart();
    assert!(
        second.try_wait().unwrap().is_none(),
        "restart guard must not kill the active updater"
    );
    let lock_payload = fs::read_to_string(&task_lock).unwrap();
    assert!(
        lock_payload
            .lines()
            .any(|line| line == format!("pid={}", second.id())),
        "the second updater must retain admission after restart refusal: {lock_payload}"
    );
    assert_eq!(
        json(run.join("run.json"))["status"],
        "completed",
        "completed first-run task evidence is preserved"
    );
    assert!(
        !run.join("restart.json").exists(),
        "no request is made while another run owns admission"
    );
    fs::write(release_second, "release").unwrap();
    assert!(wait_child(&mut second).success());
    assert!(
        !task_lock.exists(),
        "second updater did not release admission"
    );
    drop(master);
    let bytes = capture.join().unwrap();
    let screen = String::from_utf8_lossy(&bytes);
    assert!(
        screen.contains("\x1b[?1049h"),
        "dashboard did not enter alternate screen"
    );
    assert!(
        screen.contains("\x1b[?1049l"),
        "dashboard did not leave alternate screen"
    );
    assert!(
        screen.contains("restart withheld: cannot establish exclusive Update All task admission"),
        "expected restart admission refusal, not unrelated cancellation: {screen}"
    );
    fixture.assert_no_restart();
}

#[test]
fn restart_after_suppresses_all_skipped_tasks() {
    use std::io::Write;
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(engine, "touch \"$HOME/unexpected-effect\"");
        let config = fixture.home.path().join("config/update-all");
        fs::OpenOptions::new()
            .append(true)
            .open(config.join("config.toml"))
            .unwrap()
            .write_all(b"\n[updaters]\nprivilege_mode=\"skip\"\n")
            .unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(config.join("catalog.d/local/restart.toml"))
            .unwrap()
            .write_all(b"requires_elevation=true\n")
            .unwrap();
        let output = fixture.run().arg("--restart-after").output().unwrap();
        assert!(!output.status.success());
        fixture.assert_no_restart();
        assert!(!fixture.home.path().join("unexpected-effect").exists());
        let run = json(fixture.only_run().join("run.json"));
        assert_eq!(run["tasks"][0]["status"], "skipped");
    }
}

#[test]
fn restart_test_backend_missing_marker_fails_closed_before_task_effects() {
    let fixture = Fixture::new("sync", "touch \"$HOME/unexpected-effect\"");
    let output = fixture
        .run()
        .arg("--restart-after")
        .env_remove("UPDATE_ALL_TEST_RESTART_MARKER")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!fixture.home.path().join("unexpected-effect").exists());
    fixture.assert_no_restart();
    assert!(String::from_utf8_lossy(&output.stderr).contains("test marker"));
}

#[cfg(target_os = "linux")]
#[test]
fn restart_after_suppresses_unsafe_terminal_artifact_leaf() {
    use std::os::unix::fs::symlink;
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(
            engine,
            "touch \"$HOME/task-started\"; while [ ! -e \"$HOME/release\" ]; do sleep 0.02; done",
        );
        let stderr_path = fixture.home.path().join("stderr");
        let mut child = TestChild(
            fixture
                .run()
                .arg("--restart-after")
                .stdout(Stdio::null())
                .stderr(fs::File::create(&stderr_path).unwrap())
                .spawn()
                .unwrap(),
        );
        wait_for(&fixture.home.path().join("task-started"), &mut child);
        let artifact = fixture.only_run().join("run.json");
        assert!(!artifact.exists());
        // Refuse the symlink itself; neither replace it nor open its device target.
        let target_before = fs::metadata("/dev/full").unwrap();
        symlink("/dev/full", &artifact).unwrap();
        fs::write(fixture.home.path().join("release"), "continue").unwrap();
        assert!(!wait_child(&mut child).success());
        fixture.assert_no_restart();
        let stderr = fs::read_to_string(&stderr_path).unwrap();
        assert!(
            stderr.contains("unsafe artifact leaf"),
            "expected leaf refusal: {stderr}"
        );
        assert_eq!(fs::read_link(&artifact).unwrap(), Path::new("/dev/full"));
        use std::os::unix::fs::MetadataExt;
        let target_after = fs::metadata("/dev/full").unwrap();
        assert_eq!(
            (
                target_before.dev(),
                target_before.ino(),
                target_before.mode(),
                target_before.rdev()
            ),
            (
                target_after.dev(),
                target_after.ino(),
                target_after.mode(),
                target_after.rdev()
            )
        );
        assert_eq!(
            json(fixture.only_run().join("run-meta.json"))["status"],
            "failed"
        );
    }
}

#[cfg(target_os = "linux")]
fn compile_restart_sync_failure_shim(directory: &Path) -> PathBuf {
    let shim = directory.join("restart-sync-failure.so");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/enospc.c");
    let output = Command::new("cc")
        .args(["-shared", "-fPIC", "-O2"])
        .arg(&source)
        .args(["-o"])
        .arg(&shim)
        .arg("-ldl")
        .output()
        .expect("compile Linux evidence failure fixture with cc");
    assert!(
        output.status.success(),
        "compile sync failure shim: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    shim
}

#[cfg(target_os = "linux")]
#[test]
fn restart_after_suppresses_failed_pre_request_evidence_sync() {
    let fixture = Fixture::new("async", "printf 'completed before durability gate\\n'");
    let shim = compile_restart_sync_failure_shim(fixture.home.path());
    let output = fixture
        .run()
        .arg("--restart-after")
        .env("LD_PRELOAD", &shim)
        .env("EVIDENCE_SYNC_FAILURE_TARGET", "restart.json")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    fixture.assert_no_restart();
    let run = fixture.only_run();
    let artifact = json(run.join("run.json"));
    assert_eq!(artifact["status"], "completed");
    assert_eq!(artifact["exit_code"], 0);
    assert_eq!(json(run.join("run-meta.json"))["status"], "completed");
    let receipt = json(run.join("restart.json"));
    // Written intent cannot establish a request or authorize replay when fsync fails.
    assert_eq!(receipt["status"], "request_pending");
    assert_eq!(receipt["automatic_retry_allowed"], false);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("os error 28"),
        "expected injected sync ENOSPC: {stderr}"
    );
    assert!(stderr.contains("restart withheld"), "{stderr}");
}
