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
            "[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"2\"\n[ui]\npersist_until_exit=true\n[tasks.tool_update]\nretries=0\ntimeout_secs=15\n"
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
fn restart_after_preserves_failed_deferred_and_warning_task_outcomes() {
    for engine in ["sync", "async"] {
        for (script, protocol, exit_code, status) in [
            ("exit 7", false, 1, "failed"),
            (
                r#"printf '%s\n' 'UPDATE_ALL_RESULT {"outcome":"deferred","detail":"fixture deferred"}'"#,
                true,
                2,
                "failed",
            ),
            (
                "printf 'warning: harmless fixture warning\\n'",
                false,
                0,
                "completed",
            ),
        ] {
            let fixture = Fixture::new(engine, script);
            if protocol {
                use std::io::Write;
                fs::OpenOptions::new()
                    .append(true)
                    .open(
                        fixture
                            .home
                            .path()
                            .join("config/update-all/catalog.d/local/restart.toml"),
                    )
                    .unwrap()
                    .write_all(b"result_protocol=1\n")
                    .unwrap();
            }
            let output = fixture.run().arg("--restart-after").output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(exit_code),
                "{engine}: {output:?}"
            );
            let requests = fs::read_to_string(&fixture.marker).unwrap();
            assert_eq!(requests.lines().count(), 1);
            let request: Value = serde_json::from_str(requests.trim()).unwrap();
            assert_eq!(request["run"]["status"], status);
            assert_eq!(request["run"]["exit_code"], exit_code);
            assert_eq!(request["metadata"]["status"], status);
            assert!(request["run"]["issue_count"].as_u64().unwrap() > 0);
            assert_eq!(request["run_completed_count"], 1);
            assert_eq!(request["terminal_raw_mode"], false);
            assert_eq!(request["task_admission_owned"], true);
            assert_eq!(request["run"], json(fixture.only_run().join("run.json")));
            assert_eq!(
                json(fixture.only_run().join("restart.json"))["status"],
                "request_accepted"
            );
        }
    }
}

#[test]
fn restart_after_suppresses_invalid_task_runs() {
    for engine in ["sync", "async"] {
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
fn restart_after_suppresses_failed_startup_authentication() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(engine, "touch \"$HOME/unexpected-effect\"");
        let bin = fixture.home.path().join("bin");
        fs::create_dir(&bin).unwrap();
        fs::write(bin.join("sudo"), "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(bin.join("sudo"), fs::Permissions::from_mode(0o700)).unwrap();
        let config = fixture.home.path().join("config/update-all");
        for (path, content) in [
            (
                config.join("config.toml"),
                "\n[updaters]\nprivilege_mode=\"required\"\n",
            ),
            (
                config.join("catalog.d/local/restart.toml"),
                "requires_elevation=true\n",
            ),
        ] {
            fs::OpenOptions::new()
                .append(true)
                .open(path)
                .unwrap()
                .write_all(content.as_bytes())
                .unwrap();
        }
        let output = fixture
            .run()
            .arg("--restart-after")
            .env("PATH", bin)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        fixture.assert_no_restart();
        assert!(!fixture.home.path().join("unexpected-effect").exists());
        let run = json(fixture.only_run().join("run.json"));
        assert!(run["tasks"].as_array().unwrap().is_empty());
        assert!(run["reason"]
            .as_str()
            .unwrap()
            .contains("sudo preflight failed"));
    }
}

#[test]
fn restart_after_waits_for_running_siblings_after_failure() {
    for engine in ["sync", "async"] {
        let fixture = Fixture::new(engine, "exit 7");
        let script = r#"touch "$HOME/sibling-started"; while [ ! -e "$HOME/release-sibling" ]; do sleep 0.02; done"#;
        fs::write(
            fixture
                .home
                .path()
                .join("config/update-all/catalog.d/local/sibling.toml"),
            format!(
                r#"
[tasks."local/restart-sibling"]
label="Harmless sibling fixture"
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
        let mut child = TestChild(
            fixture
                .process()
                .args([
                    "--plain",
                    "--only",
                    "local/restart-fixture,local/restart-sibling",
                    "--restart-after",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        wait_for(&fixture.home.path().join("sibling-started"), &mut child);
        fixture.assert_no_restart();
        assert!(child.try_wait().unwrap().is_none());
        fs::write(fixture.home.path().join("release-sibling"), "continue").unwrap();
        assert_eq!(wait_child(&mut child).code(), Some(1));
        let requests = fs::read_to_string(&fixture.marker).unwrap();
        assert_eq!(requests.lines().count(), 1);
        let request: Value = serde_json::from_str(requests.trim()).unwrap();
        assert_eq!(request["run"]["tasks"].as_array().unwrap().len(), 2);
        assert_eq!(request["run"]["failed_task_count"], 1);
        assert_eq!(request["run_completed_count"], 1);
    }
}

#[test]
fn restart_after_requests_after_dependency_and_fail_fast_cancellations() {
    for engine in ["sync", "async"] {
        for fail_fast in [false, true] {
            let fixture = Fixture::new(engine, "exit 7");
            let dependency = if fail_fast {
                ""
            } else {
                "depends_on=[\"local/restart-fixture\"]\n"
            };
            fs::write(
                fixture
                    .home
                    .path()
                    .join("config/update-all/catalog.d/local/pending.toml"),
                format!(
                    r#"
[tasks."local/restart-pending"]
label="Unstarted fixture"
category="maintenance"
os=["linux","macos"]
detect_mode="command_available"
command="/bin/sh"
args=["-c", "touch \"$HOME/unexpected-effect\""]
policy_key="tool_update"
{dependency}"#
                ),
            )
            .unwrap();
            let mut command = fixture.process();
            command.args([
                "--plain",
                "--jobs",
                "1",
                "--only",
                "local/restart-fixture,local/restart-pending",
                "--restart-after",
            ]);
            if fail_fast {
                command.arg("--fail-fast");
            }
            let output = command.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(1),
                "{engine}, fail_fast={fail_fast}: {output:?}"
            );
            assert!(!fixture.home.path().join("unexpected-effect").exists());
            let requests = fs::read_to_string(&fixture.marker).unwrap();
            assert_eq!(requests.lines().count(), 1);
            let request: Value = serde_json::from_str(requests.trim()).unwrap();
            assert_eq!(request["run"]["failed_task_count"], 1);
            assert_eq!(request["run"]["canceled_task_count"], 1);
            assert_eq!(request["run"]["exit_code"], 1);
            assert_eq!(request["run_completed_count"], 1);
        }
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
struct DashboardSession {
    child: Option<TestChild>,
    master: fs::File,
    output: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

#[cfg(all(target_os = "linux", feature = "tui"))]
impl DashboardSession {
    fn start(fixture: &Fixture, args: &[&str]) -> Self {
        use std::io::{Read, Write};
        use std::os::fd::FromRawFd;
        use std::os::unix::process::CommandExt;
        let mut master_fd = -1;
        let mut slave_fd = -1;
        let size = libc::winsize {
            ws_row: 40,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty initializes two distinct owned descriptors and valid output pointers.
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
        // SAFETY: successful openpty descriptors are each transferred exactly once.
        let master = unsafe { fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { fs::File::from_raw_fd(slave_fd) };
        let mut input = master.try_clone().unwrap();
        let mut responder = master.try_clone().unwrap();
        let output = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = output.clone();
        let reader = std::thread::spawn(move || {
            let mut bytes = [0; 8192];
            let mut query_tail = Vec::new();
            loop {
                match input.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(count) => {
                        captured.lock().unwrap().extend_from_slice(&bytes[..count]);
                        query_tail.extend_from_slice(&bytes[..count]);
                        let queries = query_tail
                            .windows(4)
                            .filter(|part| *part == b"\x1b[6n")
                            .count();
                        for _ in 0..queries {
                            let _ = responder.write_all(b"\x1b[1;1R");
                        }
                        let keep = query_tail.len().saturating_sub(3);
                        query_tail.drain(..keep);
                    }
                    Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => panic!("read fixture terminal: {error}"),
                }
            }
        });
        let mut command = fixture.process();
        command
            .args(["--dashboard", "--only", "local/restart-fixture"])
            .args(args)
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin",
                    fixture.home.path().join("bin").display()
                ),
            )
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap());
        // SAFETY: only async-signal-safe native calls run between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = TestChild(command.spawn().unwrap());
        drop(command);
        drop(slave);
        Self {
            child: Some(child),
            master,
            output,
            reader: Some(reader),
        }
    }

    fn wait_for_review(&mut self) {
        self.wait_for_output(b"\x1b[?2004h", 1);
    }

    fn wait_for_output(&mut self, needle: &[u8], count: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if self
                .output
                .lock()
                .unwrap()
                .windows(needle.len())
                .filter(|part| *part == needle)
                .count()
                >= count
            {
                return;
            }
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "dashboard exited before review: {}",
                String::from_utf8_lossy(&self.output.lock().unwrap())
            );
            assert!(Instant::now() < deadline, "review window did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn input(&mut self, bytes: &[u8]) {
        use std::io::Write;
        self.master.write_all(bytes).unwrap();
    }

    fn assert_open_for(&mut self, duration: Duration) {
        let until = Instant::now() + duration;
        while Instant::now() < until {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "dashboard closed during active review"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(mut self, expected: i32) -> Vec<u8> {
        assert_eq!(
            wait_child(self.child.as_mut().unwrap()).code(),
            Some(expected)
        );
        drop(self.child.take());
        self.reader.take().unwrap().join().unwrap();
        self.output.lock().unwrap().clone()
    }
}

#[cfg(all(target_os = "linux", feature = "tui"))]
impl Drop for DashboardSession {
    fn drop(&mut self) {
        drop(self.child.take());
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_after_closes_dashboard_without_input_and_restores_terminal() {
    for engine in ["sync", "async"] {
        for task_exit in [0, 7] {
            let fixture = Fixture::new(
                engine,
                &format!(
                    r#"touch "$HOME/task-started"; while [ ! -e "$HOME/release" ]; do sleep 0.02; done; exit {task_exit}"#
                ),
            );
            let mut session =
                DashboardSession::start(&fixture, &["--restart-after", "--restart-idle-secs", "1"]);
            wait_for(
                &fixture.home.path().join("task-started"),
                session.child.as_mut().unwrap(),
            );
            session.assert_open_for(Duration::from_millis(1100));
            fixture.assert_no_restart();
            fs::write(fixture.home.path().join("release"), "continue").unwrap();
            session.wait_for_review();
            let review_started = Instant::now();
            session.assert_open_for(Duration::from_millis(300));
            let bytes = session.finish(if task_exit == 0 { 0 } else { 1 });
            assert!(review_started.elapsed() >= Duration::from_millis(900));
            assert!(
                bytes.windows(8).any(|part| part == b"\x1b[?2004l"),
                "paste mode was not restored"
            );
            assert!(
                bytes.windows(8).any(|part| part == b"\x1b[?1049l"),
                "alternate screen was not restored"
            );
            let requests = fs::read_to_string(&fixture.marker).unwrap();
            assert_eq!(requests.lines().count(), 1);
            let request: Value = serde_json::from_str(requests.trim()).unwrap();
            assert_eq!(request["terminal_raw_mode"], false);
            assert_eq!(request["task_admission_owned"], true);
            assert_eq!(request["run_completed_count"], 1);
            assert_eq!(
                request["metadata"]["status"],
                if task_exit == 0 {
                    "completed"
                } else {
                    "failed"
                }
            );
            let config: toml::Value = toml::from_str(
                &fs::read_to_string(fixture.home.path().join("config/update-all/config.toml"))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(config["ui"]["persist_until_exit"].as_bool(), Some(true));
            assert!(
                config["ui"].get("restart_idle_secs").is_none(),
                "CLI override must not persist"
            );
        }
    }
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_idle_window_resets_for_keyboard_mouse_and_literal_paste() {
    for input in [
        b"\x1b[B".as_slice(),
        b"\x1b[<64;5;6M",
        b"\x1b[200~q\x03\n\x1b[201~",
    ] {
        let fixture = Fixture::new("async", "exit 0");
        let mut session =
            DashboardSession::start(&fixture, &["--restart-after", "--restart-idle-secs", "2"]);
        session.wait_for_review();
        session.assert_open_for(Duration::from_millis(1100));
        session.input(input);
        session.assert_open_for(Duration::from_millis(1100));
        fixture.assert_no_restart();
        session.finish(0);
        assert_eq!(
            fs::read_to_string(&fixture.marker).unwrap().lines().count(),
            1
        );
    }
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_idle_review_honors_early_quit_and_cancellation() {
    for (input, code) in [(b"q".as_slice(), 0), (b"\x03".as_slice(), 3)] {
        let fixture = Fixture::new("async", "exit 0");
        let mut session =
            DashboardSession::start(&fixture, &["--restart-after", "--restart-idle-secs", "30"]);
        session.wait_for_review();
        session.input(input);
        session.finish(code);
        if code == 3 {
            fixture.assert_no_restart();
        } else {
            assert_eq!(
                fs::read_to_string(&fixture.marker).unwrap().lines().count(),
                1
            );
        }
        assert_eq!(
            json(fixture.only_run().join("run.json"))["status"],
            "completed",
            "review cancellation must preserve completed task evidence"
        );
    }
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_review_config_and_cli_override_preserve_user_preferences() {
    for override_cli in [false, true] {
        let fixture = Fixture::new("async", "exit 0");
        let path = fixture.home.path().join("config/update-all/config.toml");
        let configured = if override_cli { 30 } else { 1 };
        fs::write(
            &path,
            fs::read_to_string(&path).unwrap().replace(
                "persist_until_exit=true",
                &format!("persist_until_exit=false\nrestart_idle_secs={configured}"),
            ),
        )
        .unwrap();
        let args = if override_cli {
            vec!["--restart-after", "--restart-idle-secs", "1"]
        } else {
            vec!["--restart-after"]
        };
        let mut session = DashboardSession::start(&fixture, &args);
        session.wait_for_review();
        let start = Instant::now();
        session.assert_open_for(Duration::from_millis(300));
        session.finish(0);
        assert!(start.elapsed() >= Duration::from_millis(900));
        let config: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(config["ui"]["persist_until_exit"].as_bool(), Some(false));
        assert_eq!(
            config["ui"]["restart_idle_secs"].as_integer(),
            Some(configured)
        );
        assert!(
            json(fixture.only_run().join("run.json"))["ui_wait_ms"]
                .as_u64()
                .unwrap()
                >= 900
        );
    }
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_review_does_not_reset_for_resize() {
    use std::os::fd::AsRawFd;
    let fixture = Fixture::new("async", "exit 0");
    let mut session =
        DashboardSession::start(&fixture, &["--restart-after", "--restart-idle-secs", "2"]);
    session.wait_for_review();
    let start = Instant::now();
    session.assert_open_for(Duration::from_millis(1100));
    let size = libc::winsize {
        ws_row: 41,
        ws_col: 121,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the PTY descriptor is live and size points to a valid winsize.
    assert_eq!(
        unsafe { libc::ioctl(session.master.as_raw_fd(), libc::TIOCSWINSZ, &size) },
        0
    );
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(session.child.as_ref().unwrap().id() as i32),
        nix::sys::signal::Signal::SIGWINCH,
    )
    .unwrap();
    session.wait_for_output(b"\x1b[?2004l", 1);
    assert!(
        start.elapsed() < Duration::from_millis(2900),
        "resize postponed the original deadline: {:?}",
        start.elapsed()
    );
    session.finish(0);
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_review_canceled_task_exits_without_misleading_countdown() {
    let fixture = Fixture::new("async", "touch \"$HOME/task-started\"; sleep 12");
    let mut session =
        DashboardSession::start(&fixture, &["--restart-after", "--restart-idle-secs", "30"]);
    wait_for(
        &fixture.home.path().join("task-started"),
        session.child.as_mut().unwrap(),
    );
    session.wait_for_output(b"Harmless", 1);
    session.input(b"k");
    let output = session.finish(1);
    fixture.assert_no_restart();
    assert!(!output.windows(8).any(|part| part == b"\x1b[?2004h"));
    assert_eq!(
        json(fixture.only_run().join("run.json"))["canceled_task_count"],
        1
    );
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_review_pauses_for_log_viewer_and_resumes_with_full_interval() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new("async", "printf 'reviewable task output\\n'");
    fs::create_dir(fixture.home.path().join("bin")).unwrap();
    let pager = fixture.home.path().join("bin/less");
    fs::write(&pager, "#!/bin/sh\ntouch \"$HOME/pager-started\"\nwhile [ ! -e \"$HOME/release-pager\" ]; do sleep 0.02; done\n").unwrap();
    fs::set_permissions(&pager, fs::Permissions::from_mode(0o700)).unwrap();
    let mut session =
        DashboardSession::start(&fixture, &["--restart-after", "--restart-idle-secs", "1"]);
    session.wait_for_review();
    session.input(b"m");
    wait_for(
        &fixture.home.path().join("pager-started"),
        session.child.as_mut().unwrap(),
    );
    session.assert_open_for(Duration::from_millis(1200));
    fixture.assert_no_restart();
    fs::write(fixture.home.path().join("release-pager"), "continue").unwrap();
    session.wait_for_output(b"\x1b[?2004h", 2);
    let resumed = Instant::now();
    session.assert_open_for(Duration::from_millis(300));
    session.finish(0);
    assert!(resumed.elapsed() >= Duration::from_millis(900));
    assert_eq!(
        fs::read_to_string(&fixture.marker).unwrap().lines().count(),
        1
    );
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn restart_review_preserves_deferred_task_outcome() {
    use std::io::Write;
    let fixture = Fixture::new(
        "async",
        r#"printf '%s\n' 'UPDATE_ALL_RESULT {"outcome":"deferred","detail":"fixture deferred"}'"#,
    );
    fs::OpenOptions::new()
        .append(true)
        .open(
            fixture
                .home
                .path()
                .join("config/update-all/catalog.d/local/restart.toml"),
        )
        .unwrap()
        .write_all(b"result_protocol=1\n")
        .unwrap();
    let mut session =
        DashboardSession::start(&fixture, &["--restart-after", "--restart-idle-secs", "1"]);
    session.wait_for_review();
    session.finish(2);
    let run = json(fixture.only_run().join("run.json"));
    assert_eq!(run["exit_code"], 2);
    assert_eq!(
        fs::read_to_string(&fixture.marker).unwrap().lines().count(),
        1
    );
}

#[cfg(all(target_os = "linux", feature = "tui"))]
#[test]
fn ordinary_dashboard_ignores_restart_timeout_configuration() {
    let fixture = Fixture::new("async", "exit 0");
    let path = fixture.home.path().join("config/update-all/config.toml");
    let content = fs::read_to_string(&path).unwrap().replace(
        "persist_until_exit=true",
        "persist_until_exit=true\nrestart_idle_secs=1",
    );
    fs::write(path, content).unwrap();
    let mut session = DashboardSession::start(&fixture, &[]);
    session.assert_open_for(Duration::from_millis(1600));
    session.input(b"q");
    session.finish(0);
    fixture.assert_no_restart();
}

#[test]
fn restart_idle_cli_and_config_validate_before_task_effects() {
    for args in [
        vec!["--restart-idle-secs", "1"],
        vec!["--restart-after", "--restart-idle-secs", "0"],
    ] {
        let fixture = Fixture::new("async", "touch \"$HOME/unexpected-effect\"");
        let output = fixture.run().args(args).output().unwrap();
        assert!(!output.status.success());
        assert!(!fixture.home.path().join("unexpected-effect").exists());
        fixture.assert_no_restart();
    }
    let fixture = Fixture::new("async", "touch \"$HOME/unexpected-effect\"");
    let path = fixture.home.path().join("config/update-all/config.toml");
    fs::write(
        &path,
        fs::read_to_string(&path).unwrap().replace(
            "persist_until_exit=true",
            "persist_until_exit=true\nrestart_idle_secs=0",
        ),
    )
    .unwrap();
    let output = fixture
        .process()
        .args(["config", "validate", "--strict"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ui.restart_idle_secs"));
    fixture.assert_no_restart();
}

#[test]
fn restart_after_requests_after_all_skipped_tasks() {
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
        assert!(output.status.success(), "{output:?}");
        let requests = fs::read_to_string(&fixture.marker).unwrap();
        assert_eq!(requests.lines().count(), 1);
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
