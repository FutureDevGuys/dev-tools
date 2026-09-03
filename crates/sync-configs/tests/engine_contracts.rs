use std::fs;
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::time::Duration;

use tempfile::TempDir;

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sync-configs"));
    command
        .arg("--log-style")
        .arg("off")
        .env("HOME", root.join("home"))
        .env("XDG_STATE_HOME", root.join("state"));
    command
}

#[test]
fn regular_file_copy_is_idempotent() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("nested/target.txt");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").unwrap();
    fs::write(
        &manifest,
        format!(
            "default_mode: copy\nentries:\n  - name: example\n    source: {}\n    target: {}\n",
            source.display(),
            target.display()
        ),
    )
    .unwrap();

    let first = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("first convergence");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "desired\n");
    assert!(String::from_utf8_lossy(&first.stdout).contains("1 updated, 0 up-to-date"));

    let before = fs::metadata(&target).unwrap().modified().unwrap();
    let second = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("second convergence");
    assert!(second.status.success());
    assert_eq!(fs::metadata(&target).unwrap().modified().unwrap(), before);
    assert!(String::from_utf8_lossy(&second.stdout).contains("0 updated, 1 up-to-date"));
}

#[test]
fn structured_dry_run_executes_no_hook_or_write() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("target.txt");
    let hook_marker = root.path().join("hook-marker");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").unwrap();
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: example\n    source: {}\n    target: {}\n    mode: copy\n    profiles: [desktop]\n    pre_script: '/usr/bin/touch {}'\n    post_script: '/usr/bin/touch {}'\n",
            source.display(),
            target.display(),
            hook_marker.display(),
            hook_marker.display()
        ),
    )
    .unwrap();

    let output = command(root.path())
        .args([
            "--profile",
            "desktop",
            "--dry-run",
            "--format",
            "json",
            "--config",
        ])
        .arg(&manifest)
        .output()
        .expect("dry run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("one JSON value");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["outcome"], "completed");
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["profiles"], serde_json::json!(["desktop"]));
    assert!(!target.exists());
    assert!(!hook_marker.exists());
}

#[test]
fn profile_map_order_is_preserved_and_deduplicated() {
    let root = TempDir::new().expect("tempdir");
    let manifest = root.path().join("manifest.yaml");
    let profile_map = root.path().join("profiles.yaml");
    fs::write(&manifest, "entries: []\n").unwrap();
    fs::write(
        &profile_map,
        "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
    )
    .unwrap();
    let output = command(root.path())
        .args([
            "--validate",
            "--format",
            "json",
            "--host-profile",
            "workstation",
            "--profile",
            "desktop",
            "--config",
        ])
        .arg(&manifest)
        .arg("--profile-map")
        .arg(&profile_map)
        .output()
        .expect("validate");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["profiles"], serde_json::json!(["linux", "desktop"]));
}

#[test]
fn failed_state_precondition_is_read_only_and_value_conscious() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("target.txt");
    let state = root.path().join("state.json");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").unwrap();
    fs::write(&state, "{}\n").unwrap();
    fs::write(
        &manifest,
        format!(
            "state_preconditions:\n  - type: json_fields\n    path: {}\n    fields:\n      enabled: null\n    remediation: repair state first\nentries:\n  - name: example\n    source: {}\n    target: {}\n    mode: copy\n",
            state.display(),
            source.display(),
            target.display()
        ),
    )
    .unwrap();
    let output = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("precondition");
    assert_eq!(output.status.code(), Some(1));
    assert!(!target.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("repair state first"));
    assert!(!stderr.contains("desired"));
}

#[cfg(unix)]
#[test]
fn concurrent_mutating_runs_never_overlap() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("target.txt");
    let entered = root.path().join("entered");
    let release = root.path().join("release");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").expect("source");
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: serialized\n    source: {}\n    target: {}\n    mode: copy\n    pre_script: 'printf ready > {}; while [ ! -e {} ]; do :; done'\n",
            source.display(),
            target.display(),
            entered.display(),
            release.display(),
        ),
    )
    .expect("manifest");

    let mut first = command(root.path());
    first
        .arg("--config")
        .arg(&manifest)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let first = first.spawn().expect("first convergence");
    for _ in 0..200 {
        if entered.is_file() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !entered.is_file() {
        let _ = fs::write(&release, "continue\n");
        let _ = first.wait_with_output();
        panic!("first run never entered its hook");
    }

    let second = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("overlapping convergence");
    fs::write(&release, "continue\n").expect("release first run");
    let first = first.wait_with_output().expect("first result");

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(second.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&second.stderr)
        .contains("another sync-configs convergence is already running"));
    assert_eq!(fs::read_to_string(&target).expect("target"), "desired\n");
}
