//! Real CLI acceptance for a reported authority failure, using only native disposable providers.
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
                    "/tests/fixtures/npm_authority.rs"
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

fn exercise(mode: &str, engine: &str, npm: bool) -> (TempDir, std::process::Output, Value) {
    let home = TempDir::new().unwrap();
    let bin = home.path().join(if mode == "program-path" {
        "EACCES-bin"
    } else {
        "bin"
    });
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(home.path().join("lib/node_modules")).unwrap();
    if mode == "program-path" {
        fs::create_dir_all(home.path().join("bin")).unwrap();
    }
    fs::hard_link(provider(), bin.join("npm")).unwrap();
    let config = home.path().join("config/update-all");
    fs::create_dir_all(config.join("catalog.d/local")).unwrap();
    fs::write(config.join("config.toml"), format!("[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"1\"\n[tasks.npm_install]\nretries=2\nretry_backoff_secs=0\ntimeout_secs=5\n[tasks.tool_update]\nretries=2\nretry_backoff_secs=0\ntimeout_secs=5\n")).unwrap();
    fs::write(config.join("catalog.d/local/authority.toml"), format!("[tasks.\"local/authority\"]\nlabel=\"Authority control\"\ncategory=\"maintenance\"\nos=[\"linux\",\"macos\"]\ndetect_mode=\"command_available\"\ncommand={:?}\nargs=[\"generic\"]\npolicy_key=\"tool_update\"\n", bin.join("npm").display().to_string())).unwrap();
    let binary = std::env::var_os("UPDATE_ALL_AUTHORITY_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")));
    let mut child = Command::new(binary)
        .args([
            "--plain",
            "--completions",
            "off",
            "--only",
            if npm {
                "builtin/npm"
            } else {
                "local/authority"
            },
        ])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("XDG_CACHE_HOME", home.path().join("cache"))
        .env("PATH", &bin)
        .env("AUTHORITY_FIXTURE_ROOT", home.path())
        .env("AUTHORITY_FIXTURE_MODE", mode)
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
        panic!("fixture timeout {mode}");
    }
    let out = child.wait_with_output().unwrap();
    assert!(
        home.path().join("mutation-count").exists(),
        "mutation not reached {mode}: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let run = fs::read_dir(home.path().join("state/update-all/runs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.is_dir())
        .unwrap();
    let artifact = serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    (home, out, artifact)
}

fn count(home: &TempDir) -> u32 {
    fs::read_to_string(home.path().join("mutation-count"))
        .unwrap()
        .parse()
        .unwrap()
}
fn rows(run: &Value) -> Vec<&Value> {
    run["tasks"][0]["report_sections"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["rows"].as_array().unwrap())
        .filter(|r| r["name"] == "first" || r["name"] == "second")
        .collect()
}

#[test]
fn npm_authority_diagnostics_stop_configured_replays_from_complete_channels() {
    for engine in ["sync", "async"] {
        for mode in ["stderr", "stdout", "long", "eperm", "phrase"] {
            let (home, out, run) = exercise(mode, engine, true);
            assert_eq!(count(&home), 1, "{engine} {mode}");
            assert_eq!(out.status.code(), Some(2), "{engine} {mode}: {run}");
            assert_eq!(run["exit_code"], 2);
            assert_eq!(run["tasks"][0]["status"], "completed");
            assert!(rows(&run)
                .iter()
                .all(|r| r["status"] == "blocked" && r["after"].is_null()));
            assert_eq!(rows(&run).len(), 2);
            assert_eq!(
                fs::read_to_string(home.path().join("partial-effect")).unwrap(),
                "retained"
            );
            assert!(fs::read_to_string(home.path().join("calls"))
                .unwrap()
                .lines()
                .last()
                .unwrap()
                .starts_with("install "));
        }
    }
}

#[test]
fn npm_authority_during_individual_and_health_recovery_stops_later_mutation() {
    for engine in ["sync", "async"] {
        for (mode, expected) in [
            ("late-individual", 4),
            ("health-isolated", 2),
            ("health-allow", 3),
            ("lifecycle-isolated", 2),
            ("lifecycle-allow", 3),
            ("health-preserve", 2),
            ("lifecycle-preserve", 2),
            ("individual-preserve", 6),
        ] {
            let (home, out, run) = exercise(mode, engine, true);
            assert_eq!(count(&home), expected, "{engine} {mode}: {run}");
            assert_eq!(out.status.code(), Some(2), "{engine} {mode}: {run}");
            assert_eq!(run["exit_code"], 2);
            assert_eq!(
                fs::read_to_string(home.path().join("partial-effect")).unwrap(),
                "retained"
            );
            let rows = rows(&run);
            assert_eq!(rows.len(), 2, "{run}");
            if mode.ends_with("-preserve") {
                let first = rows.iter().find(|r| r["name"] == "first").unwrap();
                assert_eq!(first["status"], "updated");
                assert_eq!(first["after"], "2.0.0");
                let second = rows.iter().find(|r| r["name"] == "second").unwrap();
                assert_eq!(second["status"], "blocked");
                assert!(second["after"].is_null());
            } else {
                assert!(rows.iter().all(|r| r["after"].is_null()), "{mode}: {run}");
            }
            assert!(fs::read_to_string(home.path().join("calls"))
                .unwrap()
                .lines()
                .last()
                .unwrap()
                .starts_with("install "));
        }
    }
}

#[test]
fn npm_authority_controls_preserve_success_recovery_and_non_npm_retry() {
    for engine in ["sync", "async"] {
        for (mode, expected, npm) in [
            ("success-history", 1, true),
            ("ordinary-retry", 2, true),
            ("recoverable", 5, true),
            ("negative-markers", 5, true),
            ("negative-paths", 5, true),
            ("program-path", 2, true),
            ("generic-authority", 2, false),
        ] {
            let (home, out, run) = exercise(mode, engine, npm);
            assert!(out.status.success(), "{engine} {mode}: {run}");
            assert_eq!(count(&home), expected, "{engine} {mode}");
            assert_eq!(run["exit_code"], 0);
            if npm {
                assert!(
                    rows(&run)
                        .iter()
                        .all(|r| r["status"] == "updated" && r["after"] == "2.0.0"),
                    "{run}"
                );
            }
        }
    }
}
