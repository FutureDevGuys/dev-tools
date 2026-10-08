//! Diagnostic cost and output contracts use isolated synthetic roots only.
use std::fs;
use std::path::Path;
use std::process::Command;

use dev_cache::root::RootHandle;

fn command(home: &Path, root: &RootHandle) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dev-cache"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/nonexistent")
        .current_dir(home)
        .arg("--root")
        .arg(&root.root)
        .args(["--mode", "on", "--json"]);
    for name in ["WSL_DISTRO_NAME", "WSL_INTEROP", "COMPUTERNAME"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}

#[test]
fn default_status_is_explicitly_unaudited_and_full_status_retains_catalog_audit() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
    fs::write(root.control().join("resources/invalid.json"), b"not JSON").unwrap();
    let regular = command(temp.path(), &root).arg("status").output().unwrap();
    assert!(
        regular.status.success(),
        "{}",
        String::from_utf8_lossy(&regular.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&regular.stdout).unwrap();
    assert_eq!(status["maintenance_scope"], "not_observed");
    assert!(status["maintenance"].is_null());
    let implicit = command(temp.path(), &root).output().unwrap();
    let implicit: serde_json::Value = serde_json::from_slice(&implicit.stdout).unwrap();
    assert_eq!(implicit, status);
    let full = command(temp.path(), &root)
        .args(["status", "--full"])
        .output()
        .unwrap();
    assert!(full.status.success());
    let full: serde_json::Value = serde_json::from_slice(&full.stdout).unwrap();
    assert_eq!(full["maintenance_scope"], "full");
    assert_eq!(
        full["maintenance"]["catalog_issues"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let doctor = command(temp.path(), &root).arg("doctor").output().unwrap();
    assert_eq!(doctor.status.code(), Some(1));
    let doctor: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    let maintenance = doctor["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "maintenance")
        .unwrap();
    assert_eq!(maintenance["ok"], false);
    assert_eq!(maintenance["status"], doctor["status"]["maintenance"]);
    assert_eq!(doctor["status"]["maintenance_scope"], "full");
}

#[cfg(unix)]
#[test]
fn lightweight_status_and_path_never_open_an_unrelated_catalog_fifo() {
    use std::time::Duration;
    use wait_timeout::ChildExt;
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
    let fifo = root.control().join("resources/unrelated.json");
    let status = Command::new("mkfifo").arg(&fifo).status().unwrap();
    assert!(status.success());
    for args in [&["status"][..], &["path", "cargo"], &["path", "npm"]] {
        let mut child = command(temp.path(), &root)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let finished = child.wait_timeout(Duration::from_secs(5)).unwrap();
        if finished.is_none() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(
            finished.is_some_and(|status| status.success()),
            "{args:?} inspected an unrelated blocking catalog record"
        );
    }
    assert!(fs::symlink_metadata(fifo).is_ok());
}

#[test]
fn report_has_consistent_categories_one_document_and_stderr_progress() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
    fs::write(root.shared().join("payload"), b"cache").unwrap();
    fs::write(root.repos().join("payload"), b"workspace").unwrap();
    fs::write(root.artifacts().join("payload"), b"artifact").unwrap();
    fs::create_dir_all(root.platform_root.join("artifacts/metadata")).unwrap();
    fs::write(
        root.platform_root.join("artifacts/metadata/payload"),
        b"metadata",
    )
    .unwrap();
    let output = command(temp.path(), &root).arg("report").output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["complete"], true);
    assert_eq!(report["cancelled"], false);
    assert_eq!(report["repos_bytes"], 9);
    assert_eq!(report["shared_bytes"], 5);
    assert_eq!(report["artifacts_bytes"], 8);
    assert_eq!(report["other_bytes"], 8);
    assert_eq!(report["bytes"], 30);
    assert!(String::from_utf8_lossy(&output.stderr).contains("scanning cache sizes"));
}
