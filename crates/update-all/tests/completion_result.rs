//! Real completion producer acceptance through the generic task result contract.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::OnceLock;
use std::time::Duration;
use tempfile::TempDir;

fn binary() -> PathBuf {
    std::env::var_os("UPDATE_ALL_COMPLETION_RESULT_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")))
}

fn provider_dir() -> &'static Path {
    static FIXTURE: OnceLock<TempDir> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let root = TempDir::new().unwrap();
            let provider = root.path().join("pipx");
            assert!(std::process::Command::new("rustc")
                .args(["--edition=2021", "-C", "debuginfo=0"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/completion_inventory.rs"
                ))
                .arg("-o")
                .arg(&provider)
                .status()
                .unwrap()
                .success());
            std::os::unix::fs::symlink(&provider, root.path().join("completion-fixture")).unwrap();
            root
        })
        .path()
}

fn command(home: &Path, path: &Path, mode: &str) -> Command {
    let mut command = Command::new(binary());
    command
        .env_clear()
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_STATE_HOME", home.join("state"))
        .env("PATH", path)
        .env("COMPLETION_FIXTURE_MODE", mode)
        .env("NO_COLOR", "1")
        .current_dir(home)
        .timeout(Duration::from_secs(20));
    command
}

fn sync_args(home: &Path, provider: &str, discover: bool) -> Vec<String> {
    let mut args = vec![
        "completions".into(),
        "sync".into(),
        "--providers".into(),
        provider.into(),
        "--managed-root".into(),
        home.join("managed").to_string_lossy().into_owned(),
        "--shell".into(),
        "bash".into(),
    ];
    if discover {
        args.push("--discover".into());
    }
    args
}

fn footer(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<_> = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("UPDATE_ALL_RESULT "))
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(lines[0].len() + "UPDATE_ALL_RESULT ".len() <= 512);
    assert_eq!(
        stdout.lines().last().unwrap(),
        format!("UPDATE_ALL_RESULT {}", lines[0])
    );
    let value: Value = serde_json::from_str(lines[0]).unwrap();
    assert!(
        value.get("current").is_none() && value.get("latest").is_none(),
        "{value}"
    );
    value
}

#[test]
fn completion_sync_emits_scoped_result_after_publication() {
    let home = TempDir::new().unwrap();
    let empty_path = home.path().join("empty-bin");
    let args = sync_args(home.path(), "path", false);
    let initial = command(home.path(), &empty_path, "")
        .args(&args)
        .output()
        .unwrap();
    assert!(initial.status.success());
    let result = footer(&initial);
    assert_eq!(result["outcome"], "updated");
    let detail = result["detail"].as_str().unwrap();
    assert!(
        detail.contains("snapshot=published") && detail.contains("refreshed=0"),
        "{detail}"
    );
    let repeat = command(home.path(), &empty_path, "")
        .args(&args)
        .output()
        .unwrap();
    assert!(repeat.status.success());
    assert_eq!(footer(&repeat)["outcome"], "no_op");
}

#[test]
fn actual_completion_producer_drives_generic_rows_in_both_engines() {
    for engine in ["sync", "async"] {
        for (case, provider, discover, mode, expected_row, expected_exit) in [
            ("initial", "path", false, "", "updated", 0),
            ("repeat", "path", false, "", "passed", 0),
            ("subset", "npm,pipx,uv,go", false, "", "updated", 0),
            ("partial", "pipx", true, "partial", "deferred", 2),
            ("failed", "pipx", true, "failed", "failed", 1),
        ] {
            let home = TempDir::new().unwrap();
            let config = home.path().join("config/update-all");
            fs::create_dir_all(config.join("catalog.d/local")).unwrap();
            fs::write(config.join("config.toml"), format!("[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"1\"\n[tasks.tool_update]\nretries=0\ntimeout_secs=10\n")).unwrap();
            let args = sync_args(home.path(), provider, discover);
            if case == "repeat" {
                assert!(command(home.path(), provider_dir(), mode)
                    .args(&args)
                    .output()
                    .unwrap()
                    .status
                    .success());
            }
            fs::write(config.join("catalog.d/local/completion.toml"), format!(
                "[tasks.\"local/completion\"]\nlabel=\"Completion fixture\"\ncategory=\"maintenance\"\nos=[\"linux\"]\ndetect_mode=\"command_available\"\ncommand={}\nargs={}\npolicy_key=\"tool_update\"\nresult_protocol=1\n",
                serde_json::to_string(&binary()).unwrap(), serde_json::to_string(&args).unwrap())).unwrap();
            let output = command(home.path(), provider_dir(), mode)
                .args([
                    "--plain",
                    "--completions",
                    "off",
                    "--only",
                    "local/completion",
                ])
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(expected_exit),
                "{engine}/{case}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let run = fs::read_dir(home.path().join("state/update-all/runs"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .find(|path| path.is_dir())
                .unwrap();
            let artifact: Value =
                serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
            assert_eq!(artifact["exit_code"], expected_exit);
            let task = &artifact["tasks"][0];
            let section = task["report_sections"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["key"] == "operation_results")
                .unwrap();
            let row = &section["rows"][0];
            assert_eq!(row["status"], expected_row, "{engine}/{case}: {artifact}");
            assert!(row["before"].is_null() && row["after"].is_null());
            if case == "partial" {
                assert_eq!(task["status"], "completed");
                assert!(artifact["issue_count"].as_u64().unwrap() > 0);
            }
        }
    }
}

#[test]
fn failed_audit_never_emits_completion_success_footer() {
    let home = TempDir::new().unwrap();
    let output = command(home.path(), provider_dir(), "")
        .args([
            "completions",
            "sync",
            "--providers",
            "path",
            "--shell",
            "zsh",
            "--apply",
            "--audit",
            "strict",
            "--rc-root",
        ])
        .arg(home.path().join("legacy"))
        .arg("--audit-command")
        .arg(provider_dir().join("pipx"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("UPDATE_ALL_RESULT "), "{stdout}");
    let combined = format!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        combined.contains("audit_failed") || combined.contains("fixture audit rejected"),
        "{combined}"
    );
}

#[test]
fn canceled_final_ambient_probe_never_emits_success_footer() {
    use std::process::Stdio;
    use std::time::Instant;
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let home = TempDir::new().unwrap();
    let log = home.path().join("output");
    fs::write(home.path().join("cancel-mode"), b"enabled").unwrap();
    let output = fs::File::create(&log).unwrap();
    let mut child = OwnedChild(
        std::process::Command::new(binary())
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("PATH", provider_dir())
            .env("COMPLETION_FIXTURE_MODE", "cancel")
            .args(sync_args(home.path(), "pipx", true))
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !home.path().join("probe-started").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "{}",
            fs::read_to_string(&log).unwrap()
        );
        assert!(Instant::now() < deadline, "probe did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    // SAFETY: this retained child has not been reaped, so its PID cannot be reused.
    assert_eq!(
        unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    while child.0.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "cancelled producer did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    let text = fs::read_to_string(&log).unwrap();
    assert!(!text.contains("UPDATE_ALL_RESULT "), "{text}");
}

#[test]
fn legacy_install_only_change_and_other_subcommands_keep_their_scope() {
    let home = TempDir::new().unwrap();
    let empty_path = home.path().join("empty-bin");
    let legacy = home.path().join("legacy");
    let sync = || {
        command(home.path(), &empty_path, "")
            .args([
                "completions",
                "sync",
                "--providers",
                "path",
                "--shell",
                "zsh",
                "--apply",
                "--rc-root",
            ])
            .arg(&legacy)
            .output()
            .unwrap()
    };
    let initial = sync();
    assert!(
        initial.status.success(),
        "{}",
        String::from_utf8_lossy(&initial.stderr)
    );
    assert_eq!(footer(&initial)["outcome"], "updated");
    let repeat = sync();
    assert!(repeat.status.success());
    assert_eq!(footer(&repeat)["outcome"], "no_op");
    fs::remove_file(legacy.join("shell/bootstrap/completions/20-update-all-managed-fpath.zsh"))
        .unwrap();
    let repaired = sync();
    assert!(repaired.status.success());
    let result = footer(&repaired);
    assert_eq!(result["outcome"], "updated");
    let detail = result["detail"].as_str().unwrap();
    assert!(
        detail.contains("install_changed=true") && detail.contains("refreshed=0"),
        "{detail}"
    );

    let public = command(home.path(), &empty_path, "")
        .args(sync_args(home.path(), "path", false))
        .output()
        .unwrap();
    assert!(public.status.success());
    for args in [
        vec![
            "completions".to_string(),
            "status".into(),
            "--managed-root".into(),
            home.path().join("managed").to_string_lossy().into_owned(),
        ],
        vec![
            "completions".to_string(),
            "init".into(),
            "bash".into(),
            "--managed-root".into(),
            home.path().join("managed").to_string_lossy().into_owned(),
        ],
        vec![
            "completions".to_string(),
            "install".into(),
            "--shell".into(),
            "zsh".into(),
            "--rc-root".into(),
            legacy.to_string_lossy().into_owned(),
        ],
    ] {
        let output = command(home.path(), &empty_path, "")
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("UPDATE_ALL_RESULT "));
    }
}
