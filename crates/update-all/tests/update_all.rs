use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn command(home: &TempDir) -> Command {
    let mut command = Command::cargo_bin("update-all").expect("compiled update-all binary");
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
