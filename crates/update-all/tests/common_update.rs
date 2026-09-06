#![cfg(target_os = "linux")]

use assert_cmd::Command;
use serde_json::Value;

#[test]
fn common_status_observes_absence_without_initializing() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("PATH", "/nonexistent")
        .args(["update", "status", "--json"])
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["schema"], "dev-tools-operation-result-v2");
    assert_eq!(result["installation_state"], "absent");
    assert_eq!(result["outcome"], "unknown");
    assert_eq!(result["changed"], false);
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn common_status_preserves_external_command_and_emits_one_error_document() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let public = bin.join("update-all");
    std::fs::write(&public, b"external fixture, not executable").unwrap();
    let run = || {
        let mut command = Command::new(assert_cmd::cargo::cargo_bin!("update-all"));
        command
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("PATH", "/nonexistent")
            .args(["update", "status", "--json"])
            .timeout(std::time::Duration::from_secs(5));
        command
    };
    let result: Value =
        serde_json::from_slice(&run().assert().success().get_output().stdout).unwrap();
    assert_eq!(result["outcome"], "external");
    assert_eq!(
        std::fs::read(&public).unwrap(),
        b"external fixture, not executable"
    );
    let product = home.path().join("state/dev-tools/products/update-all");
    std::fs::create_dir_all(&product).unwrap();
    std::fs::set_permissions(&product, std::fs::Permissions::from_mode(0o700)).unwrap();
    let receipt = product.join("installation-receipt-v1.json");
    std::fs::write(&receipt, b"unknown receipt").unwrap();
    let output = run()
        .assert()
        .code(4)
        .stderr("")
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["exit_code"], 4);
    assert_eq!(result["changed"], false);
    assert_eq!(std::fs::read(&receipt).unwrap(), b"unknown receipt");
}

#[test]
fn common_status_missing_home_still_emits_json() {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
        .env_clear()
        .args(["update", "status", "--json"])
        .timeout(std::time::Duration::from_secs(5))
        .assert()
        .code(2)
        .stderr("")
        .get_output()
        .stdout
        .clone();
    let result: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(result["exit_code"], 2);
    assert_eq!(result["changed"], false);
}
