use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn command(home: &TempDir) -> Command {
    Command::from_std(fixture_process(home))
}

fn fixture_process(home: &TempDir) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_update-all"));
    command
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("PATH", "/usr/bin:/bin")
        .env_remove("UPDATE_ALL_ROOT_URL")
        .env_remove("UPDATE_ALL_MANIFEST_URL");
    command
}

#[test]
fn help_exposes_current_general_interfaces() {
    let home = TempDir::new().unwrap();
    command(&home)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--only"))
        .stdout(predicate::str::contains("--exclude"));

    command(&home)
        .args(["self", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("install"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("check"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("rollback"))
        .stdout(predicate::str::contains("repair").not());
}

#[test]
fn version_is_one_stable_local_line() {
    let home = TempDir::new().unwrap();
    command(&home)
        .env(
            "DEV_TOOLS_GIT_COMMIT",
            "runtime-value-must-not-replace-build-identity",
        )
        .env(
            "UPDATE_ALL_GIT_COMMIT",
            "runtime-value-must-not-replace-build-identity",
        )
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("update-all {}\n", env!("CARGO_PKG_VERSION")))
        .stderr(predicate::str::is_empty());
}

#[test]
fn standard_build_info_is_local_and_uses_the_common_schema() {
    let home = TempDir::new().unwrap();
    let output = command(&home)
        .args(["build-info", "--json"])
        .output()
        .expect("run standard build-info");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("build-info JSON");
    assert_eq!(payload["schema"], "dev-tools-build-info-v1");
    assert_eq!(payload["product"], "update-all");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    assert!(payload["source_commit"].as_str().is_some());
    assert!(payload["source_state"].as_str().is_some());
    assert!(payload["target"].as_str().is_some());
}

#[test]
fn self_status_is_offline_and_machine_readable() {
    let home = TempDir::new().unwrap();
    command(&home)
        .args(["self", "status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("engine_version"))
        .stdout(predicate::str::contains("managed"));
}

#[test]
fn config_init_and_strict_validate_are_idempotent_read_surfaces() {
    let home = TempDir::new().unwrap();
    let config = home.path().join("update-all.toml");
    command(&home)
        .args(["config", "init", "--path"])
        .arg(&config)
        .assert()
        .success();
    command(&home)
        .args(["config", "validate", "--strict", "--path"])
        .arg(&config)
        .assert()
        .success();
    let before = fs::read(&config).unwrap();
    command(&home)
        .args(["config", "validate", "--strict", "--path"])
        .arg(&config)
        .assert()
        .success();
    assert_eq!(fs::read(&config).unwrap(), before);
}

#[test]
fn external_catalog_namespace_is_loaded_without_a_checkout() {
    let home = TempDir::new().unwrap();
    let config_dir = home.path().join("config/update-all");
    let catalog_dir = config_dir.join("catalog.d/local");
    fs::create_dir_all(&catalog_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[install]\nauto_update = false\n[ui]\nmode = \"plain\"\n",
    )
    .unwrap();
    fs::write(
        catalog_dir.join("demo.toml"),
        r#"
[tasks."local/demo"]
label = "Local Demo"
os = ["linux"]
detect_mode = "command_available"
category = "maintenance"
command = "sh"
args = ["-c", "printf 'demo complete\\n'"]
policy_key = "tool_update"
"#,
    )
    .unwrap();
    command(&home)
        .args(["--plain", "--only", "local/demo"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Local Demo"));
}

#[cfg(unix)]
#[test]
fn command_deadline_settles_descendant_output_and_releases_scheduler_lock() {
    for engine in ["sync", "async"] {
        let home = TempDir::new().unwrap();
        let config_dir = home.path().join("config/update-all");
        let catalog_dir = config_dir.join("catalog.d/local");
        fs::create_dir_all(&catalog_dir).unwrap();
        fs::write(
            config_dir.join("config.toml"),
            format!(
                "[install]\nauto_update=false\n[engine]\nmode=\"{engine}\"\njobs=\"2\"\n[tasks.tool_update]\ntimeout_secs=1\nretries=0\n"
            ),
        )
        .unwrap();
        fs::write(
            catalog_dir.join("deadline.toml"),
            r#"
[tasks."local/a-holder"]
label = "Deadline holder"
os = ["linux", "macos"]
detect_mode = "command_available"
category = "maintenance"
command = "sh"
args = ["-c", "trap '' TERM; printf 'leader result\\n'; printf 'retained evidence\\n' >&2; sleep 4 & exit 0"]
policy_key = "tool_update"
resource_locks = ["fixture-resource"]

[tasks."local/b-follower"]
label = "Deadline follower"
os = ["linux", "macos"]
detect_mode = "command_available"
category = "maintenance"
command = "sh"
args = ["-c", "printf 'follower completed\\n'"]
policy_key = "tool_update"
resource_locks = ["fixture-resource"]
"#,
        )
        .unwrap();
        let started = std::time::Instant::now();
        command(&home)
            .args([
                "--plain",
                "--completions",
                "off",
                "--only",
                "local/a-holder,local/b-follower",
            ])
            .timeout(std::time::Duration::from_secs(8))
            .assert()
            .code(1);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "{engine} retained a task lock beyond its command deadline"
        );
        let run = fs::read_dir(home.path().join("state/update-all/runs"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.join("run.json").is_file())
            .unwrap();
        let artifact: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
        let tasks = artifact["tasks"].as_array().unwrap();
        let holder = tasks
            .iter()
            .find(|task| task["task_id"] == "local/a-holder")
            .unwrap();
        let follower = tasks
            .iter()
            .find(|task| task["task_id"] == "local/b-follower")
            .unwrap();
        assert_eq!(holder["status"], "failed");
        assert!(holder["detail"].as_str().unwrap().contains("timeout"));
        assert_eq!(follower["status"], "completed");
        assert_eq!(artifact["failed_task_count"], 1);
        let logs = fs::read_dir(&run)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
            .filter_map(|path| fs::read_to_string(path).ok())
            .collect::<String>();
        assert!(logs.contains("leader result"));
        assert!(logs.contains("retained evidence"));
        assert!(logs.contains("follower completed"));
    }
}

#[cfg(unix)]
#[test]
fn persisted_runs_identify_the_executing_build_without_caller_values() {
    for engine in ["sync", "async"] {
        for child_exit in [0, 7] {
            let home = TempDir::new().unwrap();
            let config_dir = home.path().join("config/update-all");
            let catalog_dir = config_dir.join("catalog.d/local");
            fs::create_dir_all(&catalog_dir).unwrap();
            fs::write(
                config_dir.join("config.toml"),
                format!("[install]\nauto_update=false\n[engine]\nmode=\"{engine}\"\n"),
            )
            .unwrap();
            fs::write(
                catalog_dir.join("identity.toml"),
                format!(
                    "[tasks.\"local/identity\"]\nlabel=\"Build identity fixture\"\ncategory=\"maintenance\"\nos=[\"linux\",\"macos\"]\ndetect_mode=\"command_available\"\ncommand=\"sh\"\nargs=[\"-c\",\"exit {child_exit}\",\"private-argument-sentinel\"]\npolicy_key=\"tool_update\"\n"
                ),
            )
            .unwrap();
            let build_output = command(&home)
                .args(["build-info", "--json"])
                .output()
                .unwrap();
            assert!(build_output.status.success());
            let expected: serde_json::Value = serde_json::from_slice(&build_output.stdout).unwrap();
            command(&home)
                .env("UPDATE_ALL_GIT_COMMIT", "private-runtime-value-sentinel")
                .args([
                    "--plain",
                    "--completions",
                    "off",
                    "--only",
                    "local/identity",
                ])
                .assert()
                .code(if child_exit == 0 { 0 } else { 1 });
            let run = fs::read_dir(home.path().join("state/update-all/runs"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.join("run.json").is_file())
                .unwrap();
            let artifact: serde_json::Value =
                serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
            assert_eq!(
                artifact["build_info"], expected,
                "{engine}, exit {child_exit}"
            );
            let journal = fs::read_to_string(run.join("events.jsonl")).unwrap();
            let started: serde_json::Value =
                serde_json::from_str(journal.lines().next().unwrap()).unwrap();
            assert_eq!(started["kind"], "run_started");
            assert_eq!(started["payload"]["build_info"], expected);
            assert_eq!(expected.as_object().unwrap().len(), 8);
            let identity = expected.to_string();
            assert!(!identity.contains("private-argument-sentinel"));
            assert!(!identity.contains("private-runtime-value-sentinel"));
            assert!(!identity.contains(&home.path().to_string_lossy().to_string()));
        }
    }
}

#[cfg(unix)]
#[test]
fn controlled_catalog_keeps_late_errors_in_full_logs_and_bounded_summary() {
    let home = TempDir::new().unwrap();
    let config_dir = home.path().join("config/update-all");
    let catalog_dir = config_dir.join("catalog.d/local");
    fs::create_dir_all(&catalog_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[install]\nauto_update=false\n[ui]\nmode=\"plain\"\n[engine]\nmode=\"async\"\njobs=\"1\"\n[logging]\ntimestamps=false\nmax_in_memory_lines=40\n",
    )
    .unwrap();
    fs::write(catalog_dir.join("fidelity.toml"), r#"
[tasks."local/fidelity"]
label = "Output fidelity fixture"
os = ["linux", "macos"]
detect_mode = "command_available"
category = "maintenance"
command = "sh"
args = ["-c", "i=0; while [ $i -lt 64 ]; do printf 'fidelity line %s\\n' \"$i\"; i=$((i+1)); done; printf 'warning: alpha\\n'; printf 'warning: bravo\\n'; printf 'warning: charlie\\n'; printf 'warning: delta\\n'; printf 'warning: echo\\n'; printf 'warning: foxtrot\\n'; printf 'warning: golf\\n'; printf 'warning: hotel\\n'; printf 'warning: india\\n'; printf 'warning: juliet\\n'; printf 'warning: kilo\\n'; printf 'warning: lima\\n'; printf 'warning: stderr evidence\\n' >&2; printf 'multiline first\\n\\nmultiline second\\n'; printf 'error: stdout evidence\\n'; printf 'error: final operation failed\\n' >&2; printf 'final output marker\\n'; exit 1"]
policy_key = "tool_update"
"#).unwrap();
    let captured = command(&home)
        .args([
            "--plain",
            "--completions",
            "off",
            "--only",
            "local/fidelity",
        ])
        .output()
        .unwrap();
    assert_eq!(captured.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&captured.stdout);
    assert!(stdout.contains("error: final operation failed"), "{stdout}");
    assert!(
        stdout.contains("11 diagnostic occurrence(s) omitted"),
        "{stdout}"
    );
    assert!(stdout.contains("complete task log"), "{stdout}");
    let runs = home.path().join("state/update-all/runs");
    let run = fs::read_dir(runs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join("run.json").is_file())
        .unwrap();
    let raw = fs::read_to_string(run.join("task-local%2Ffidelity.raw.log")).unwrap();
    assert_eq!(raw.matches("[local/fidelity] [INFO] [OUT] \n").count(), 1);
    let human = fs::read_to_string(run.join("run.log")).unwrap();
    let events: Vec<serde_json::Value> = fs::read_to_string(run.join("events.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut expected: Vec<(String, &str, &str)> = (0..64)
        .map(|index| (format!("fidelity line {index}"), "OUT", "INFO"))
        .collect();
    for word in [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliet", "kilo", "lima",
    ] {
        expected.push((format!("warning: {word}"), "OUT", "WARN"));
    }
    expected.extend([
        ("warning: stderr evidence".to_string(), "STDERR", "WARN"),
        ("multiline first".to_string(), "OUT", "INFO"),
        ("multiline second".to_string(), "OUT", "INFO"),
        ("error: stdout evidence".to_string(), "OUT", "ERROR"),
        (
            "error: final operation failed".to_string(),
            "STDERR",
            "ERROR",
        ),
        ("final output marker".to_string(), "OUT", "INFO"),
    ]);
    for (line, stream, level) in expected {
        let record = format!("[local/fidelity] [{level}] [{stream}] {line}\n");
        assert_eq!(raw.matches(&record).count(), 1, "{record}");
        assert!(human.lines().any(|entry| entry.ends_with(&line)), "{line}");
        let matching: Vec<_> = events
            .iter()
            .filter(|event| {
                event["kind"] == "log_line"
                    && event["task_id"] == "local/fidelity"
                    && event["payload"]["line"] == line
                    && event["payload"]["stream"] == stream
            })
            .collect();
        assert_eq!(matching.len(), 1, "{line}");
        assert_eq!(matching[0]["payload"]["level"], level);
    }
    for event in &events {
        if event["kind"] == "log_line" {
            let line = event["payload"]["line"].as_str().unwrap();
            assert!(!line.contains(['\n', '\r']));
            if event["payload"]["stream"] == "OUT" || event["payload"]["stream"] == "STDERR" {
                assert!(!line.is_empty());
            }
        }
    }
    let task: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("task-local%2Ffidelity.json")).unwrap()).unwrap();
    let diagnostics = task["report_sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| section["key"] == "command_diagnostics")
        .unwrap();
    assert_eq!(diagnostics["rows"].as_array().unwrap().len(), 5);
    assert_eq!(diagnostics["rows"][0]["name"], "error");
    assert_eq!(diagnostics["rows"][1]["name"], "error");
    assert_eq!(
        diagnostics["rows"][4]["note"],
        "11 diagnostic occurrence(s) omitted from this summary; see the complete task log"
    );
    assert_eq!(task["log_file"], "task-local%2Ffidelity.log");
    let complete: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    assert_eq!(complete["exit_code"], 1);
    assert_eq!(complete["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(complete["tasks"][0]["log_file"], task["log_file"]);
    let final_diagnostics = complete["tasks"][0]["report_sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| section["key"] == "command_diagnostics")
        .unwrap();
    assert_eq!(final_diagnostics, diagnostics);
}

#[cfg(unix)]
#[test]
fn controlled_catalog_failure_summary_keeps_terminal_context() {
    for stream in ["stdout", "stderr"] {
        let home = TempDir::new().unwrap();
        let config_dir = home.path().join("config/update-all");
        let catalog_dir = config_dir.join("catalog.d/local");
        fs::create_dir_all(&catalog_dir).unwrap();
        fs::write(
            config_dir.join("config.toml"),
            "[install]\nauto_update=false\n[engine]\nmode=\"async\"\njobs=\"1\"\n",
        )
        .unwrap();
        let redirect = if stream == "stderr" { " >&2" } else { "" };
        let script = format!(
            "printf 'preparing transaction...\\n'{redirect}; printf 'resource is busy; operation did not start\\n'{redirect}; printf 'The following operations failed: fixture-one,fixture-two\\n'{redirect}; exit 1"
        );
        fs::write(
            catalog_dir.join("failure.toml"),
            format!(
                "[tasks.\"local/failure\"]\nlabel=\"Failure summary fixture\"\ncategory=\"maintenance\"\nos=[\"linux\",\"macos\"]\ndetect_mode=\"command_available\"\ncommand=\"sh\"\nargs=[\"-c\",{}]\npolicy_key=\"tool_update\"\n",
                serde_json::to_string(&script).unwrap()
            ),
        )
        .unwrap();
        command(&home)
            .args(["--plain", "--completions", "off", "--only", "local/failure"])
            .assert()
            .code(1);
        let run = fs::read_dir(home.path().join("state/update-all/runs"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.join("run.json").is_file())
            .unwrap();
        let artifact: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
        assert_eq!(artifact["exit_code"], 1);
        assert_eq!(artifact["tasks"][0]["status"], "failed");
        let detail = artifact["tasks"][0]["detail"].as_str().unwrap();
        assert!(
            detail.contains("The following operations failed"),
            "{stream}: {detail}"
        );
        assert!(
            !detail.contains("preparing transaction"),
            "{stream}: {detail}"
        );
        let raw = fs::read_to_string(run.join("task-local%2Ffailure.raw.log")).unwrap();
        assert!(raw.contains("preparing transaction..."));
        assert!(raw.contains("resource is busy; operation did not start"));
        assert!(raw.contains("The following operations failed"));
    }
}

#[test]
fn invalid_catalog_plan_uses_documented_exit_code_three() {
    let home = TempDir::new().unwrap();
    let config = home.path().join("invalid.toml");
    fs::write(
        &config,
        "[updaters.tasks.\"builtin/npm\"]\ncommand = \"custom-npm\"\n",
    )
    .unwrap();

    command(&home)
        .args(["--config"])
        .arg(config)
        .arg("--plain")
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "invalid updater configuration or plan",
        ));
}

#[test]
fn public_and_legacy_completion_roots_are_mutually_exclusive_before_mutation() {
    let home = TempDir::new().unwrap();
    let managed = home.path().join("managed");
    let legacy = home.path().join("legacy");
    command(&home)
        .args([
            "completions",
            "sync",
            "--providers",
            "path",
            "--managed-root",
        ])
        .arg(&managed)
        .arg("--rc-root")
        .arg(&legacy)
        .assert()
        .failure()
        .stderr(predicate::str::contains("mutually exclusive"));
    assert!(!managed.exists());
    assert!(!legacy.exists());
}

#[test]
fn legacy_audit_requires_exact_executable_before_sync_mutation() {
    let home = TempDir::new().unwrap();
    let legacy = home.path().join("legacy");
    command(&home)
        .args(["completions", "sync", "--providers", "path", "--apply"])
        .arg("--rc-root")
        .arg(&legacy)
        .args(["--shell", "zsh", "--audit", "strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "requires an exact absolute --audit-command",
        ));
    assert!(!legacy.exists());
}

#[test]
fn fresh_public_completion_sync_uses_a_virtual_empty_catalog_and_then_reuses() {
    let home = TempDir::new().unwrap();
    let managed = home.path().join("managed");
    let args = [
        "completions",
        "sync",
        "--providers",
        "path",
        "--managed-root",
    ];
    command(&home)
        .args(args)
        .arg(&managed)
        .args(["--shell", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completion_outcome=published"));
    assert!(!managed.join("cache/managed-tools.json").exists());

    command(&home)
        .args(args)
        .arg(&managed)
        .args(["--shell", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completion_outcome=reused"));
}

#[test]
fn completion_status_reports_retained_snapshot_history_in_json_and_text() {
    let home = TempDir::new().unwrap();
    let managed = home.path().join("managed");
    for shell in ["bash", "fish"] {
        command(&home)
            .args([
                "completions",
                "sync",
                "--providers",
                "path",
                "--managed-root",
            ])
            .arg(&managed)
            .args(["--shell", shell])
            .assert()
            .success();
    }

    command(&home)
        .args(["completions", "status", "--managed-root"])
        .arg(&managed)
        .arg("--json")
        .assert()
        .success()
        .stdout(predicate::str::contains("\"historical_snapshots\""))
        .stdout(predicate::str::contains("\"healthy\": true"));
    command(&home)
        .args(["completions", "status", "--managed-root"])
        .arg(&managed)
        .assert()
        .success()
        .stdout(predicate::str::contains("historical_snapshots=1"))
        .stdout(predicate::str::contains("historical_snapshot="));
}

#[cfg(unix)]
fn admission_fixture(home: &TempDir, engine: &str, extra: &str) -> std::path::PathBuf {
    let config_dir = home.path().join("config/update-all");
    let catalog_dir = config_dir.join("catalog.d/local");
    fs::create_dir_all(&catalog_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        format!("[install]\nauto_update=false\n[engine]\nmode=\"{engine}\"\njobs=\"1\"\n{extra}\n"),
    )
    .unwrap();
    let marker = home.path().join("effect");
    fs::write(
        catalog_dir.join("fixture.toml"),
        format!(
            r#"
[tasks."local/a"]
label="Failing prerequisite"
category="maintenance"
os=["linux","macos"]
detect_mode="command_available"
command="sh"
args=["-c","exit 7"]
policy_key="tool_update"
[tasks."local/b"]
label="Health dependent"
category="maintenance"
os=["linux","macos"]
detect_mode="command_available"
command="sh"
args=["-c","echo dependent >> {}"]
depends_on=["local/a"]
policy_key="tool_update"
[tasks."local/c"]
label="Ordering dependent"
category="maintenance"
os=["linux","macos"]
detect_mode="command_available"
command="sh"
args=["-c","echo ordering >> {}"]
after=["local/a"]
policy_key="tool_update"
"#,
            marker.display(),
            marker.display()
        ),
    )
    .unwrap();
    marker
}

#[cfg(unix)]
fn only_run(home: &TempDir) -> std::path::PathBuf {
    fs::read_dir(home.path().join("state/update-all/runs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.join("run-meta.json").is_file())
        .unwrap()
}

#[cfg(unix)]
#[test]
fn task_run_requires_writable_journal_before_any_effect() {
    let home = TempDir::new().unwrap();
    let occupied = home.path().join("occupied");
    fs::write(&occupied, "not a directory").unwrap();
    let marker = admission_fixture(&home, "sync", &format!("[logging]\nrun_dir={:?}", occupied));
    let output = command(&home)
        .args(["--plain", "--completions", "off", "--only", "local/c"])
        .output()
        .unwrap();
    assert!(!marker.exists(), "task ran without journal admission");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("logging.run_dir") && stderr.contains("XDG_STATE_HOME"),
        "{stderr}"
    );
}

#[cfg(unix)]
#[test]
fn sync_and_async_share_health_dependencies_and_fail_fast() {
    for (engine, jobs) in [("sync", "9"), ("async", "1"), ("async", "3")] {
        for fail_fast in [false, true] {
            let home = TempDir::new().unwrap();
            let marker = admission_fixture(&home, engine, "");
            let mut cmd = command(&home);
            cmd.args([
                "--plain",
                "--completions",
                "off",
                "--only",
                "local/a,local/b,local/c",
                "--jobs",
                jobs,
            ]);
            if fail_fast {
                cmd.arg("--fail-fast");
            }
            let output = cmd.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(1),
                "{engine}, fail_fast={fail_fast}"
            );
            let effects = fs::read_to_string(&marker).unwrap_or_default();
            assert!(
                !effects.contains("dependent"),
                "{engine} bypassed dependency: {effects}"
            );
            assert_eq!(
                effects.contains("ordering"),
                !fail_fast,
                "{engine}, fail_fast={fail_fast}: {effects}"
            );
            let artifact: serde_json::Value =
                serde_json::from_slice(&fs::read(only_run(&home).join("run.json")).unwrap())
                    .unwrap();
            assert_eq!(artifact["engine_mode"], engine);
            assert_eq!(artifact["tasks"].as_array().unwrap().len(), 3);
            let unstarted = artifact["unstarted_tasks"].as_array().unwrap();
            assert!(unstarted.iter().any(|id| id == "local/b"));
            assert_eq!(unstarted.iter().any(|id| id == "local/c"), fail_fast);
        }
    }
}

#[cfg(unix)]
#[test]
fn invalid_selector_and_jobs_terminalize_created_run_once() {
    for args in [
        vec!["--only", "does-not-exist"],
        vec!["--only", "local/a", "--jobs", "nonsense"],
    ] {
        let home = TempDir::new().unwrap();
        let marker = admission_fixture(&home, "async", "");
        let output = command(&home)
            .args(["--plain", "--completions", "off"])
            .args(&args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!marker.exists());
        let run = only_run(&home);
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run-meta.json")).unwrap()).unwrap();
        assert_eq!(metadata["status"], "failed", "{args:?}: {metadata}");
        let artifact: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
        assert_eq!(artifact["exit_code"], output.status.code().unwrap());
        assert_eq!(artifact["status"], "failed");
        assert!(artifact["reason"].as_str().is_some_and(|s| !s.is_empty()));
        let events = fs::read_to_string(run.join("events.jsonl")).unwrap();
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains("\"kind\":\"run_completed\""))
                .count(),
            1
        );
    }
}

#[cfg(unix)]
fn privilege_cli_fixture(
    home: &TempDir,
    mode: &str,
    engine: &str,
    jobs: usize,
) -> std::path::PathBuf {
    let config_dir = home.path().join("config/update-all");
    let catalogs = config_dir.join("catalog.d/local");
    fs::create_dir_all(&catalogs).unwrap();
    fs::create_dir_all(home.path().join("empty-path")).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        format!(
            r#"
[install]
auto_update=false
[engine]
mode="{engine}"
jobs="{jobs}"
[updaters]
privilege_mode="{mode}"
"#
        ),
    )
    .unwrap();
    let marker = home.path().join("effects");
    fs::write(
        catalogs.join("privilege.toml"),
        format!(
            r#"
[tasks."local/a"]
label="Elevated prerequisite"
category="maintenance"
os=["linux"]
detect_mode="command_available"
command="/bin/sh"
args=["-c","echo elevated >> {}"]
requires_elevation=true
policy_key="tool_update"
[tasks."local/b"]
label="Health dependent"
category="maintenance"
os=["linux"]
detect_mode="command_available"
command="/bin/sh"
args=["-c","echo dependent >> {}"]
depends_on=["local/a"]
policy_key="tool_update"
[tasks."local/c"]
label="Ordering dependent"
category="maintenance"
os=["linux"]
detect_mode="command_available"
command="/bin/sh"
args=["-c","echo ordering >> {}"]
after=["local/a"]
policy_key="tool_update"
[tasks."local/d"]
label="Independent task"
category="maintenance"
os=["linux"]
detect_mode="command_available"
command="/bin/sh"
args=["-c","echo independent >> {}"]
policy_key="tool_update"
"#,
            marker.display(),
            marker.display(),
            marker.display(),
            marker.display()
        ),
    )
    .unwrap();
    marker
}

#[cfg(target_os = "linux")]
#[test]
fn auto_privilege_cli_defers_health_gates_and_continues_independent_work() {
    for (engine, jobs) in [("sync", 1), ("async", 1), ("async", 3)] {
        let home = TempDir::new().unwrap();
        let marker = privilege_cli_fixture(&home, "auto", engine, jobs);
        let output = command(&home)
            .env("PATH", home.path().join("empty-path"))
            .args([
                "--plain",
                "--completions",
                "off",
                "--only",
                "local/a,local/b,local/c,local/d",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{engine}/{jobs}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let effects = fs::read_to_string(&marker).unwrap_or_default();
        assert!(!effects.contains("elevated"), "{effects}");
        assert!(
            !effects.lines().any(|line| line == "dependent"),
            "{effects}"
        );
        assert!(
            effects.contains("ordering") && effects.contains("independent"),
            "{effects}"
        );
        let run = only_run(&home);
        let artifact: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
        assert_eq!(artifact["exit_code"], 2);
        let tasks = artifact["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 4);
        let elevated = tasks
            .iter()
            .find(|task| task["task_id"] == "local/a")
            .expect("elevated task result");
        assert_eq!(elevated["status"], "skipped");
        assert!(elevated["advisories"]
            .as_array()
            .unwrap()
            .iter()
            .any(
                |advisory| advisory["code"] == "privilege-missing-executable"
                    && advisory["blocks_dependents"] == true
            ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn required_privilege_cli_is_a_prerequisite_only_for_selected_elevated_work() {
    for engine in ["sync", "async"] {
        let home = TempDir::new().unwrap();
        let marker = privilege_cli_fixture(&home, "required", engine, 3);
        let output = command(&home)
            .env("PATH", home.path().join("empty-path"))
            .args([
                "--plain",
                "--completions",
                "off",
                "--only",
                "local/a,local/d",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{engine}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !marker.exists(),
            "required prerequisite failed after a task had started"
        );
        let run = only_run(&home);
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run-meta.json")).unwrap()).unwrap();
        assert_eq!(metadata["status"], "failed");
        let events = fs::read_to_string(run.join("events.jsonl")).unwrap();
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains("\"kind\":\"run_completed\""))
                .count(),
            1
        );

        let home = TempDir::new().unwrap();
        let marker = privilege_cli_fixture(&home, "required", engine, 3);
        command(&home)
            .env("PATH", home.path().join("empty-path"))
            .args(["--plain", "--completions", "off", "--only", "local/d"])
            .assert()
            .success();
        assert_eq!(fs::read_to_string(marker).unwrap(), "independent\n");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn never_privilege_cli_keeps_clean_exclusions_but_reports_blocked_health_dependents() {
    for (selected, expected) in [("local/a,local/d", 0), ("local/a,local/b,local/d", 2)] {
        let home = TempDir::new().unwrap();
        let marker = privilege_cli_fixture(&home, "never", "sync", 1);
        let output = command(&home)
            .env("PATH", home.path().join("empty-path"))
            .args(["--plain", "--completions", "off", "--only", selected])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{selected}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read_to_string(marker).unwrap(), "independent\n");
    }
}

#[cfg(unix)]
fn wait_fixture_marker(path: &std::path::Path) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !path.is_file() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        path.is_file(),
        "fixture marker did not appear: {}",
        path.display()
    );
}

#[cfg(unix)]
fn blocking_cli_fixture(home: &TempDir, engine: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let config_dir = home.path().join("config/update-all");
    let catalogs = config_dir.join("catalog.d/local");
    fs::create_dir_all(&catalogs).unwrap();
    fs::write(config_dir.join("config.toml"), format!("[install]\nauto_update=false\n[engine]\nmode=\"{engine}\"\njobs=\"1\"\n[tasks.tool_update]\ntimeout_secs=10\n")).unwrap();
    let marker = home.path().join("started");
    let release = home.path().join("release");
    fs::write(catalogs.join("lock.toml"), format!(r#"
[tasks."local/lock"]
label="Blocking harmless fixture"
category="maintenance"
os=["linux","macos"]
detect_mode="command_available"
command="/bin/sh"
args=["-c","echo started >> {}; n=0; while [ ! -e {} ] && [ $n -lt 200 ]; do n=$((n+1)); /bin/sleep 0.02; done"]
policy_key="tool_update"
"#, marker.display(), release.display())).unwrap();
    (marker, release)
}

#[cfg(unix)]
#[test]
fn two_processes_share_mandatory_task_lock_until_owned_execution_settles() {
    let home = TempDir::new().unwrap();
    let (marker, release) = blocking_cli_fixture(&home, "async");
    let mut first_cmd = fixture_process(&home);
    first_cmd.args(["--plain", "--completions", "off", "--only", "local/lock"]);
    let mut first = first_cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    wait_fixture_marker(&marker);
    let second = command(&home)
        .args(["--plain", "--completions", "off", "--only", "local/lock"])
        .output()
        .unwrap();
    assert_eq!(second.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&second.stderr).contains("task lock is held"));
    assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), 1);
    fs::write(&release, "release").unwrap();
    assert!(first.wait().unwrap().success());
    command(&home)
        .args(["--plain", "--completions", "off", "--only", "local/lock"])
        .assert()
        .success();
    assert_eq!(fs::read_to_string(&marker).unwrap().lines().count(), 2);
    let runs = fs::read_dir(home.path().join("state/update-all/runs")).unwrap();
    let mut completed = 0;
    for run in runs
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
    {
        let metadata: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run-meta.json")).unwrap()).unwrap();
        assert_ne!(metadata["status"], "running");
        let artifact: serde_json::Value =
            serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
        if artifact["exit_code"] == 0 {
            completed += 1;
        }
        let events = fs::read_to_string(run.join("events.jsonl")).unwrap();
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains("\"kind\":\"run_completed\""))
                .count(),
            1
        );
    }
    assert_eq!(completed, 2);
}

#[cfg(unix)]
#[test]
fn sync_cancellation_settles_tasks_finalizes_evidence_and_releases_lock() {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    let home = TempDir::new().unwrap();
    let (marker, _release) = blocking_cli_fixture(&home, "sync");
    let mut cmd = fixture_process(&home);
    cmd.args(["--plain", "--completions", "off", "--only", "local/lock"]);
    let mut child = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    wait_fixture_marker(&marker);
    kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGINT,
    )
    .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(3));
    let run = only_run(&home);
    let artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    assert_eq!(artifact["status"], "canceled");
    assert_eq!(artifact["exit_code"], 3);
    assert_eq!(artifact["engine_mode"], "sync");
    assert_eq!(artifact["tasks"][0]["status"], "canceled");
    assert!(!home
        .path()
        .join("state/update-all/runs/.update-all-task-run.lock")
        .exists());
    let events = fs::read_to_string(run.join("events.jsonl")).unwrap();
    assert_eq!(
        events
            .lines()
            .filter(|line| line.contains("\"kind\":\"run_completed\""))
            .count(),
        1
    );
}
