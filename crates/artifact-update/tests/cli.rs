use std::fs;
use std::process::Command;

const CONFIG: &str = r#"
schema = "artifact-update-config-v1"

[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "github", owner = "ExampleOrg", repository = "example" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "example-linux-x86_64", os = "linux", architecture = "x86_64" }]
"#;

#[test]
fn list_and_status_are_standalone_structured_and_local_only() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();

    let listed = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["list", "--config", config.to_str().unwrap(), "--json"])
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["schema"], "artifact-update-list-v1");
    assert_eq!(listed["artifacts"][0]["id"], "example");

    let status = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["status", "--config", config.to_str().unwrap(), "--json"])
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["schema"], "artifact-update-status-v1");
    assert_eq!(status["network_accessed"], false);
    assert_eq!(status["artifacts"][0]["outcome"], "unknown");
}

#[test]
fn build_identity_and_help_are_checkout_independent() {
    let version = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        "artifact-update 0.1.0\n"
    );

    let info = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .args(["build-info", "--json"])
        .output()
        .unwrap();
    assert!(info.status.success());
    let info: serde_json::Value = serde_json::from_slice(&info.stdout).unwrap();
    assert_eq!(info["schema"], "dev-tools-build-info-v1");
    assert_eq!(info["product"], "artifact-update");
}

#[cfg(target_os = "linux")]
#[test]
fn fifo_configuration_is_rejected_without_waiting_for_a_writer() {
    use dev_tools_command::run_prepared_bounded_command;
    use std::time::Duration;

    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("config.toml");
    let fixture = run_prepared_bounded_command(
        Command::new("/usr/bin/mkfifo").arg(&fifo),
        Duration::from_secs(5),
        4096,
    )
    .expect("create FIFO fixture");
    assert!(fixture.status.success());
    let output = run_prepared_bounded_command(
        Command::new(env!("CARGO_BIN_EXE_artifact-update"))
            .args(["list", "--config"])
            .arg(&fifo),
        Duration::from_secs(5),
        4096,
    )
    .expect("non-regular configuration must fail without blocking");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}
