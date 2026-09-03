use std::process::Command;

#[test]
fn sync_configs_has_one_canonical_binary_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_sync-configs"))
        .arg("--version")
        .output()
        .expect("run canonical command name");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("sync-configs 0.2.0"));
}

#[test]
fn build_info_exposes_checkout_independent_build_metadata() {
    let output = Command::new(env!("CARGO_BIN_EXE_sync-configs"))
        .arg("--build-info")
        .output()
        .expect("run build-info");
    assert!(output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("build-info JSON");
    assert!(payload["profile"].as_str().is_some());
    assert!(payload["built_unix"]
        .as_u64()
        .is_some_and(|value| value > 0));
    assert!(payload["git_commit"].as_str().is_some());
    assert!(payload["git_dirty"].as_str().is_some());
    assert!(payload.get("manifest_dir").is_none());
    assert!(payload.get("source_fingerprint").is_none());
}
