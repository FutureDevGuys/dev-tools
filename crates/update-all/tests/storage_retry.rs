//! Real executable acceptance; all provider effects stay inside disposable fixtures.
#![cfg(unix)]
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::TempDir;
use wait_timeout::ChildExt;

fn provider() -> &'static Path {
    static FIXTURE: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    &FIXTURE
        .get_or_init(|| {
            let temp = TempDir::new().unwrap();
            let binary = temp.path().join("provider");
            assert!(Command::new("rustc")
                .args(["--edition=2024", "-C", "debuginfo=0"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/npm_storage.rs"
                ))
                .arg("-o")
                .arg(&binary)
                .status()
                .unwrap()
                .success());
            (temp, binary)
        })
        .1
}

fn exercise(mode: &str, engine: &str, npm: bool) -> (TempDir, std::process::Output) {
    let home = TempDir::new().unwrap();
    let bin = home.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(home.path().join("lib/node_modules")).unwrap();
    fs::copy(provider(), bin.join("npm")).unwrap();
    let config = home.path().join("config/update-all");
    fs::create_dir_all(config.join("catalog.d/local")).unwrap();
    fs::write(config.join("config.toml"), format!("[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"1\"\n[tasks.npm_install]\nretries=2\nretry_backoff_secs=0\ntimeout_secs=5\n[tasks.tool_update]\nretries=2\nretry_backoff_secs=0\ntimeout_secs=5\n")).unwrap();
    fs::write(config.join("catalog.d/local/storage.toml"), format!("[tasks.\"local/storage\"]\nlabel=\"Storage fixture\"\ncategory=\"maintenance\"\nos=[\"linux\",\"macos\"]\ndetect_mode=\"command_available\"\ncommand={:?}\nargs=[\"generic\"]\npolicy_key=\"tool_update\"\n", bin.join("npm").display().to_string())).unwrap();
    if mode == "guard-storage" {
        use std::io::Write;
        writeln!(
            fs::OpenOptions::new()
                .append(true)
                .open(config.join("catalog.d/local/storage.toml"))
                .unwrap(),
            "interactive=true"
        )
        .unwrap();
        writeln!(fs::OpenOptions::new().append(true).open(config.join("config.toml")).unwrap(), "[runtime.interactive]\nmode=\"auto_fallback\"\nstall_seconds=1\nretry_once=true\nmax_line_bytes=4096\nmax_capture_bytes=16384").unwrap();
    }
    let executable = std::env::var_os("UPDATE_ALL_STORAGE_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")));
    let mut child = Command::new(executable)
        .args([
            "--plain",
            "--completions",
            "off",
            "--only",
            if npm { "builtin/npm" } else { "local/storage" },
        ])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("PATH", &bin)
        .env("STORAGE_FIXTURE_ROOT", home.path())
        .env("STORAGE_FIXTURE_MODE", mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if child
        .wait_timeout(Duration::from_secs(20))
        .unwrap()
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("fixture run timed out");
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        home.path().join("mutation-count").exists(),
        "fixture did not reach mutation: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (home, out)
}

#[test]
fn storage_exhaustion_stops_common_and_npm_retries_without_losing_effects() {
    for engine in ["sync", "async"] {
        for npm in [false, true] {
            for mode in ["storage", "quota", "disk-full", "long-storage"] {
                let (home, out) = exercise(mode, engine, npm);
                assert!(!out.status.success());
                assert_eq!(
                    fs::read_to_string(home.path().join("mutation-count")).unwrap(),
                    "1",
                    "{engine} npm={npm} mode={mode}"
                );
                assert_eq!(
                    fs::read_to_string(home.path().join("partial-effect")).unwrap(),
                    "retained"
                );
                let calls = fs::read_to_string(home.path().join("calls")).unwrap();
                let after_mutation = calls
                    .split_once(if npm { "install " } else { "generic" })
                    .unwrap()
                    .1;
                assert!(
                    !after_mutation.contains("outdated"),
                    "no post-failure repair/probe should claim completion"
                );
                let runs = home.path().join("state/update-all/runs");
                let run = fs::read_dir(runs)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| p.is_dir())
                    .unwrap();
                let artifact: Value =
                    serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
                assert_ne!(artifact["exit_code"], 0);
                if npm {
                    let task = &artifact["tasks"][0];
                    assert_eq!(task["status"], "failed");
                    assert!(task["advisories"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|a| a["code"] == "npm-storage-exhausted"));
                    let rows = task["report_sections"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|s| s["key"] == "npm_packages")
                        .unwrap()["rows"]
                        .as_array()
                        .unwrap();
                    assert_eq!(rows.len(), 2);
                    assert!(rows.iter().all(|row| row["after"].is_null()));
                }
            }
        }
    }
}

#[test]
fn captured_storage_failure_stops_guard_retry() {
    let (home, out) = exercise("guard-storage", "async", false);
    assert!(!out.status.success());
    assert_eq!(
        fs::read_to_string(home.path().join("mutation-count")).unwrap(),
        "1"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("retrying with direct TTY"));
    let run = fs::read_dir(home.path().join("state/update-all/runs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    let artifact: Value = serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    assert!(
        artifact["tasks"][0]["details"]
            .to_string()
            .contains("capture line too long"),
        "{artifact}"
    );
}

#[test]
fn storage_failure_during_individual_or_health_recovery_stops_remaining_roots() {
    for engine in ["sync", "async"] {
        for (mode, expected) in [("late-storage", 4), ("health-storage", 2)] {
            let (home, out) = exercise(mode, engine, true);
            assert!(!out.status.success());
            let count: usize = fs::read_to_string(home.path().join("mutation-count"))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(
                count,
                expected,
                "{engine} {mode}: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let calls = fs::read_to_string(home.path().join("calls")).unwrap();
            assert!(
                calls.lines().last().unwrap().starts_with("install "),
                "no post-failure command: {calls}"
            );
            assert_eq!(
                fs::read_to_string(home.path().join("partial-effect")).unwrap(),
                "retained"
            );
        }
    }
}

#[test]
fn successful_and_recoverable_npm_paths_still_work() {
    for mode in ["success", "recoverable"] {
        let (home, out) = exercise(mode, "async", true);
        assert!(
            out.status.success(),
            "{mode}: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let count: usize = fs::read_to_string(home.path().join("mutation-count"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(count, if mode == "success" { 1 } else { 5 });
    }
}
