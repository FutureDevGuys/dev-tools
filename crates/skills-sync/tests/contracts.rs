use std::process::Command;

#[test]
fn standard_build_info_subcommand_uses_the_common_product_schema() {
    let output = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
        .args(["build-info", "--json"])
        .output()
        .expect("run standard build-info");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("build-info JSON");
    assert_eq!(payload["schema"], "dev-tools-build-info-v1");
    assert_eq!(payload["product"], "skills-sync");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    assert!(payload["source_commit"].as_str().is_some());
    assert!(payload["source_state"].as_str().is_some());
    assert!(payload["target"].as_str().is_some());
    assert!(payload["profile"].as_str().is_some());
    assert!(payload["built_unix"].as_u64().is_some());
}

#[test]
fn legacy_build_info_flag_remains_available_during_the_declared_window() {
    let output = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
        .arg("--build-info")
        .output()
        .expect("run legacy build-info");
    assert!(output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("legacy build-info JSON");
    assert!(payload["git_commit"].as_str().is_some());
}
