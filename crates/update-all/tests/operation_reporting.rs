//! Standalone final-report acceptance through a real PTY and disposable native providers.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::TempDir;

#[test]
fn truthful_operation_final_rollup_pty_preserves_outcomes_and_observations() {
    let provider_root = TempDir::new().unwrap();
    let provider = provider_root.path().join("provider");
    assert!(Command::new("rustc")
        .args(["--edition=2024", "-C", "debuginfo=0"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/operation_reporting.rs"
        ))
        .arg("-o")
        .arg(&provider)
        .status()
        .unwrap()
        .success());
    for engine in ["sync", "async"] {
        let home = match std::env::var_os("UPDATE_ALL_REPORT_TEST_KEEP_DIR") {
            Some(root) => tempfile::Builder::new()
                .prefix(engine)
                .tempdir_in(root)
                .unwrap(),
            None => TempDir::new().unwrap(),
        };
        let config = home.path().join("config/update-all");
        fs::create_dir_all(config.join("catalog.d/local")).unwrap();
        fs::write(config.join("config.toml"), format!("[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"1\"\n[ui.dashboard]\nnote_verbosity=\"all\"\n[tasks.tool_update]\nretries=0\ntimeout_secs=5\n")).unwrap();
        let mut catalog = String::new();
        for id in ["noop", "updated", "deferred", "unknown"] {
            catalog.push_str(&format!("[tasks.\"local/{id}\"]\nlabel=\"Fixture {id}\"\ncategory=\"maintenance\"\nos=[\"linux\"]\ndetect_mode=\"command_available\"\ncommand={:?}\nargs=[{id:?}]\npolicy_key=\"tool_update\"\n", provider.to_string_lossy()));
            catalog.push_str(if id == "deferred" {
                "result_protocol=1\n"
            } else {
                "report_parser=\"operation_result\"\n"
            });
        }
        fs::write(config.join("catalog.d/local/reporting.toml"), catalog).unwrap();
        let size = libc::winsize {
            ws_row: 60,
            ws_col: 240,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let (mut master_fd, mut slave_fd) = (-1, -1);
        // SAFETY: all output pointers and the window-size pointer remain valid during openpty.
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
        // SAFETY: successful openpty returned two distinct owned descriptors.
        let (mut master, slave) =
            unsafe { (File::from_raw_fd(master_fd), File::from_raw_fd(slave_fd)) };
        // SAFETY: master remains an open descriptor; F_SETFL updates its nonblocking flag.
        assert_ne!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            -1
        );
        let executable = std::env::var_os("UPDATE_ALL_REPORT_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")));
        let mut child = Command::new(&executable)
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("PATH", provider_root.path())
            .env("TERM", "xterm-256color")
            .env("NO_COLOR", "1")
            .current_dir(home.path())
            .args([
                "--plain",
                "--completions",
                "off",
                "--only",
                "local/noop,local/updated,local/deferred,local/unknown",
            ])
            .stdin(Stdio::null())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut output = Vec::new();
        let status = loop {
            let mut buffer = [0; 8192];
            while let Ok(count) = master.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                output.extend_from_slice(&buffer[..count]);
            }
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "final report fixture timed out: {}",
                    String::from_utf8_lossy(&output)
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let mut buffer = [0; 8192];
        while let Ok(count) = master.read(&mut buffer) {
            if count == 0 {
                break;
            }
            output.extend_from_slice(&buffer[..count]);
        }
        fs::write(home.path().join("pty-output.txt"), &output).unwrap();
        let raw = String::from_utf8_lossy(&output);
        let ansi = regex::Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").unwrap();
        let text = ansi.replace_all(&raw, "");
        assert_eq!(status.code(), Some(2), "{engine}: {text}");
        for expected in [
            "Package Change Rollup",
            "Deferred",
            "Unconfirmed",
            "deferred=1",
            "unconfirmed=1",
            "Command Diagnostics",
            "fixture operation diagnostic",
        ] {
            assert!(
                text.contains(expected),
                "{engine} missing {expected}: {text}"
            );
        }
        let overview = text
            .rsplit("Final Task Overview")
            .next()
            .unwrap()
            .split("Needs Attention")
            .next()
            .unwrap();
        for (task, outcome, count) in [
            ("Fixture deferred", "Deferred", "deferred=1"),
            ("Fixture unknown", "Unconfirmed", "unconfirmed=1"),
        ] {
            let row = overview.lines().find(|line| line.contains(task)).unwrap();
            assert_eq!(row.split('│').nth(3).unwrap().trim(), outcome, "{row}");
            assert!(row.split('│').nth(4).unwrap().contains(count), "{row}");
        }
        assert!(
            !text.contains("emitted") && !text.contains("captured"),
            "{text}"
        );
        let rollup = text.rsplit("Package Change Rollup").next().unwrap();
        let package_rows = rollup.split("Command Diagnostics").next().unwrap();
        assert!(
            !package_rows.contains("fixture operation diagnostic"),
            "{text}"
        );
        let run = fs::read_dir(home.path().join("state/update-all/runs"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir())
            .unwrap();
        let artifact: Value =
            serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
        assert_eq!(artifact["exit_code"], 2);
        assert_eq!(artifact["issue_count"], 3);
        let history = Command::new(&executable)
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_STATE_HOME", home.path().join("state"))
            .args(["resume", artifact["run_id"].as_str().unwrap(), "--json"])
            .output()
            .unwrap();
        assert!(history.status.success());
        let history: Value = serde_json::from_slice(&history.stdout).unwrap();
        assert_eq!(history["run_json_status"], "loaded", "{history}");
        assert_eq!(history["exit_code"], 2, "{history}");
        assert_eq!(history["issue_count"], 3, "{history}");
        let tasks = artifact["tasks"].as_array().unwrap();
        let noop = tasks
            .iter()
            .find(|task| task["task_id"] == "local/noop")
            .unwrap();
        let diagnostic = &noop["report_sections"]
            .as_array()
            .unwrap()
            .iter()
            .find(|section| section["key"] == "command_diagnostics")
            .unwrap()["rows"][0];
        assert_eq!(diagnostic["name"], "warning");
        assert!(diagnostic["before"].is_null() && diagnostic["after"].is_null());
        let row = |id: &str| -> &Value {
            let task = tasks.iter().find(|task| task["task_id"] == id).unwrap();
            assert_eq!(task["status"], "completed");
            &task["report_sections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|section| section["key"] == "operation_results")
                .unwrap()["rows"][0]
        };
        assert!(row("local/noop")["before"].is_null());
        assert_eq!(row("local/noop")["after"], "0.2.0");
        assert_eq!(row("local/updated")["after"], "2.0");
        assert!(row("local/updated")["note"]
            .as_str()
            .unwrap()
            .contains("available: 3.0"));
        assert_eq!(row("local/deferred")["status"], "deferred");
        assert!(row("local/deferred")["after"].is_null());
        assert_eq!(row("local/unknown")["status"], "unconfirmed");
        assert!(row("local/unknown")["after"].is_null());
        if std::env::var_os("UPDATE_ALL_REPORT_TEST_KEEP_DIR").is_some() {
            home.keep();
        }
    }
}
