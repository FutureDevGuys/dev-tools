//! Real standalone CLI outcomes, using native Rust providers and disposable roots.
#![cfg(unix)]
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::TempDir;
use wait_timeout::ChildExt;
fn provider() -> &'static Path {
    static FIXTURE: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    &FIXTURE
        .get_or_init(|| {
            let dir = match std::env::var_os("UPDATE_ALL_OUTCOME_TEST_KEEP_DIR") {
                Some(root) => tempfile::Builder::new()
                    .prefix("provider-")
                    .tempdir_in(root)
                    .unwrap(),
                None => TempDir::new().unwrap(),
            };
            let exe = dir.path().join("provider");
            assert!(Command::new("rustc")
                .args(["--edition=2024", "-C", "debuginfo=0"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/blocked_outcomes.rs"
                ))
                .arg("-o")
                .arg(&exe)
                .status()
                .unwrap()
                .success());
            (dir, exe)
        })
        .1
}
fn executable() -> PathBuf {
    std::env::var_os("UPDATE_ALL_OUTCOME_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")))
}
struct Run {
    _home: Option<TempDir>,
    root: PathBuf,
    run: PathBuf,
    artifact: Value,
    output: Output,
}
impl Run {
    fn task(&self, id: &str) -> &Value {
        self.artifact["tasks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|task| task["task_id"] == id)
            .unwrap()
    }
    fn check(&self, exit: i32, issues: usize) {
        assert_eq!(
            self.output.status.code(),
            Some(exit),
            "{}\n{}\n{}",
            self.root.display(),
            String::from_utf8_lossy(&self.output.stdout),
            String::from_utf8_lossy(&self.output.stderr)
        );
        assert_eq!(self.artifact["exit_code"], exit);
        assert_eq!(self.artifact["issue_count"], issues, "{}", self.artifact);
        let events: Vec<Value> = fs::read_to_string(self.run.join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let completed: Vec<_> = events
            .iter()
            .filter(|event| event["kind"] == "run_completed")
            .collect();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0]["payload"]["exit_code"], exit);
        let tasks = events
            .iter()
            .find(|event| event["kind"] == "tasks_completed")
            .unwrap();
        assert_eq!(tasks["payload"]["success"], exit == 0);
        assert_eq!(tasks["payload"]["had_failures"], exit == 1);
        let history = self
            .command()
            .args([
                "resume",
                self.artifact["run_id"].as_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert!(
            history.status.success(),
            "{}",
            String::from_utf8_lossy(&history.stderr)
        );
        let history: Value = serde_json::from_slice(&history.stdout).unwrap();
        assert_eq!(history["issue_count"], issues);
        assert_eq!(history["exit_code"], exit);
        let plain = self
            .command()
            .args(["resume", self.artifact["run_id"].as_str().unwrap()])
            .output()
            .unwrap();
        assert!(plain.status.success());
        assert!(String::from_utf8_lossy(&plain.stdout).contains(&format!("Issue count: {issues}")));
    }
    fn command(&self) -> Command {
        let mut c = Command::new(executable());
        c.env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("PATH", self.root.join("bin"));
        c
    }
}
fn exercise(
    engine: &str,
    jobs: usize,
    mode: &str,
    privilege: &str,
    selected: &str,
    fail_fast: bool,
    pre: bool,
) -> Run {
    let home = if let Some(dir) = std::env::var_os("UPDATE_ALL_OUTCOME_TEST_KEEP_DIR") {
        tempfile::Builder::new()
            .prefix(&format!("{engine}-{mode}-"))
            .tempdir_in(dir)
            .unwrap()
    } else {
        TempDir::new().unwrap()
    };
    let root = home.path().to_path_buf();
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::hard_link(provider(), bin.join("npm")).unwrap_or_else(|_| {
        fs::copy(provider(), bin.join("npm")).unwrap();
    });
    if mode == "denied" {
        fs::hard_link(provider(), bin.join("sudo")).unwrap_or_else(|_| {
            fs::copy(provider(), bin.join("sudo")).unwrap();
        });
    }
    if mode == "preflight" {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o555)).unwrap();
    }
    fs::create_dir_all(root.join("lib/node_modules/first")).unwrap();
    fs::write(
        root.join("lib/node_modules/first/package.json"),
        "{\"name\":\"first\",\"version\":\"1.0.0\"}",
    )
    .unwrap();
    let config = root.join("config/update-all");
    fs::create_dir_all(config.join("catalog.d/local")).unwrap();
    fs::write(config.join("config.toml"), format!("[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"{jobs}\"\n[updaters]\nprivilege_mode={privilege:?}\n[tasks.npm_install]\nretries=0\nretry_backoff_secs=0\ntimeout_secs=5\n[tasks.tool_update]\nretries=0\ntimeout_secs=5\n")).unwrap();
    let mut catalog = String::new();
    let prerequisite = if selected.contains("local/elevated") {
        "local/elevated"
    } else {
        "builtin/npm"
    };
    for id in [
        "independent",
        "failure",
        "after",
        "health",
        "elevated",
        "deferred",
    ] {
        catalog.push_str(&format!("[tasks.\"local/{id}\"]\nlabel={id:?}\ncategory=\"maintenance\"\nos=[\"linux\",\"macos\"]\ndetect_mode=\"command_available\"\ncommand={:?}\nargs=[{id:?}]\npolicy_key=\"tool_update\"\n", bin.join("npm").to_string_lossy()));
        if id == "after" {
            catalog.push_str(&format!("after=[{prerequisite:?}]\n"));
        }
        if id == "health" {
            catalog.push_str(&format!("depends_on=[{prerequisite:?}]\n"));
        }
        if id == "elevated" {
            catalog.push_str("requires_elevation=true\n");
            if pre {
                catalog.push_str(&format!(
                    "pre_commands=[{{ program={:?}, args=[\"elevated\"] }}]\n",
                    bin.join("npm").to_string_lossy()
                ));
            }
        }
    }
    fs::write(config.join("catalog.d/local/outcomes.toml"), catalog).unwrap();
    let mut command = Command::new(executable());
    command
        .args(["--plain", "--completions", "off", "--only", selected])
        .env("HOME", &root)
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("PATH", &bin)
        .env("OUTCOME_FIXTURE_ROOT", &root)
        .env("OUTCOME_FIXTURE_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if fail_fast {
        command.arg("--fail-fast");
    }
    let mut child = command.spawn().unwrap();
    if child
        .wait_timeout(Duration::from_secs(20))
        .unwrap()
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("fixture timed out");
    }
    let output = child.wait_with_output().unwrap();
    fs::write(root.join("stdout"), &output.stdout).unwrap();
    fs::write(root.join("stderr"), &output.stderr).unwrap();
    let run = fs::read_dir(root.join("state/update-all/runs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.is_dir())
        .unwrap();
    let artifact = serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    let _home = if std::env::var_os("UPDATE_ALL_OUTCOME_TEST_KEEP_DIR").is_some() {
        home.keep();
        None
    } else {
        Some(home)
    };
    Run {
        _home,
        root,
        run,
        artifact,
        output,
    }
}
#[test]
fn blocked_npm_cli_is_incomplete_and_never_invents_poststate() {
    for (engine, jobs) in [("sync", 1), ("async", 1), ("async", 3)] {
        let run = exercise(
            engine,
            jobs,
            "blocked",
            "never",
            "builtin/npm,local/after,local/health,local/independent",
            false,
            false,
        );
        run.check(2, 2);
        assert_eq!(run.task("builtin/npm")["status"], "completed");
        assert_eq!(run.task("local/after")["status"], "completed");
        assert_eq!(run.task("local/health")["status"], "canceled");
        assert!(run.root.join("after").exists() && run.root.join("independent-done").exists());
        assert!(!run.root.join("health").exists());
        let row = &run.task("builtin/npm")["report_sections"][0]["rows"][0];
        assert_eq!(row["status"], "blocked");
        assert!(row["after"].is_null(), "{row}");
        assert!(row["note"].as_str().unwrap().contains("2.0.0"));
        assert_eq!(
            fs::read_to_string(run.root.join("calls"))
                .unwrap()
                .lines()
                .filter(|line| line.starts_with("npm install "))
                .count(),
            1
        );
    }
}
#[test]
fn successful_and_nonblocking_warning_cli_runs_stay_successful() {
    for engine in ["sync", "async"] {
        for mode in ["success", "warning"] {
            let run = exercise(
                engine,
                3,
                mode,
                "never",
                "builtin/npm,local/after,local/health",
                true,
                false,
            );
            run.check(0, usize::from(mode == "warning"));
            assert!(run.root.join("after").exists() && run.root.join("health").exists());
            assert_eq!(
                run.task("builtin/npm")["report_sections"][0]["rows"][0]["after"],
                "2.0.0"
            );
        }
    }
}
#[test]
fn deferred_privilege_and_intentional_skip_counts_match_history() {
    for engine in ["sync", "async"] {
        for (mode, code) in [("auto", 2), ("never", 0)] {
            let run = exercise(
                engine,
                3,
                "success",
                mode,
                "local/elevated,local/independent",
                false,
                false,
            );
            run.check(code, 1);
            assert_eq!(run.task("local/elevated")["status"], "skipped");
            assert!(!run.root.join("elevated").exists());
            assert!(run.root.join("independent-done").exists());
        }
    }
}
#[test]
fn blocked_fail_fast_stops_later_admission_not_running_work() {
    for engine in ["sync", "async"] {
        let run = exercise(
            engine,
            1,
            "blocked",
            "never",
            "builtin/npm,local/after",
            true,
            false,
        );
        run.check(2, 2);
        assert!(!run.root.join("after").exists());
        assert_eq!(run.task("local/after")["status"], "canceled");
    }
    let run = exercise(
        "async",
        2,
        "blocked-concurrent",
        "never",
        "builtin/npm,local/independent,local/after",
        true,
        false,
    );
    run.check(2, 2);
    assert!(run.root.join("independent-done").exists());
    assert_eq!(run.task("local/independent")["status"], "completed");
    assert!(!run.root.join("after").exists());
}
#[test]
fn genuine_failure_precedes_blocked_work_without_losing_success() {
    for engine in ["sync", "async"] {
        let run = exercise(
            engine,
            3,
            "blocked",
            "never",
            "builtin/npm,local/failure,local/independent",
            false,
            false,
        );
        run.check(1, 2);
        assert_eq!(run.task("local/failure")["status"], "failed");
        assert_eq!(run.task("local/independent")["status"], "completed");
    }
}
#[test]
fn attempted_elevation_denial_is_not_an_intentional_skip() {
    for engine in ["sync", "async"] {
        for pre in [false, true] {
            let run = exercise(
                engine,
                1,
                "denied",
                "prompt_tty",
                "local/elevated",
                false,
                pre,
            );
            run.check(2, 1);
            assert!(run.root.join("denied-attempt").exists());
            assert!(!run.root.join("elevated").exists());
            assert_eq!(run.task("local/elevated")["status"], "skipped");
            assert!(run.task("local/elevated")["advisories"]
                .as_array()
                .unwrap()
                .iter()
                .any(|advisory| advisory["code"] == "deferred"
                    && advisory["blocks_dependents"] == true));
        }
    }
}

#[test]
fn deferred_health_gate_stops_fail_fast_before_newly_ready_admission() {
    for engine in ["sync", "async"] {
        let run = exercise(
            engine,
            1,
            "success",
            "never",
            "local/elevated,local/health,local/after",
            true,
            false,
        );
        run.check(2, 3);
        assert!(!run.root.join("after").exists());
        assert!(!run.root.join("health").exists());
        assert_eq!(run.task("local/after")["status"], "canceled");
    }
}

#[test]
fn failed_or_unattempted_npm_install_never_claims_target_as_poststate() {
    for mode in ["preflight", "install-failure", "invalid-manifest"] {
        let run = exercise("sync", 1, mode, "never", "builtin/npm", false, false);
        run.check(if mode == "preflight" { 2 } else { 1 }, 1);
        let row = run.task("builtin/npm")["report_sections"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|section| section["rows"].as_array().unwrap())
            .find(|row| row["name"] == "first")
            .unwrap();
        assert!(
            row["after"].is_null(),
            "unverified installed state: {mode}: {row}"
        );
        assert!(row["note"].as_str().unwrap().contains("2.0.0"));
    }
}

#[test]
fn explicit_info_deferral_counts_as_an_unresolved_issue() {
    for engine in ["sync", "async"] {
        let run = exercise(
            engine,
            1,
            "success",
            "never",
            "local/deferred",
            false,
            false,
        );
        run.check(2, 1);
        assert_eq!(run.task("local/deferred")["status"], "completed");
        assert_eq!(run.task("local/deferred")["completed_with_issues"], true);
        assert_eq!(
            run.task("local/deferred")["advisories"][0]["severity"],
            "info"
        );
    }
}
