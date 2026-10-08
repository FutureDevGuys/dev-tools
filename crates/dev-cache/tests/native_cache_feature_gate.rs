//! Build-time availability only. No real engine or native qualification is used.
use assert_cmd::Command;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

fn command(home: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("dev-cache"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", home.join("absent-path"))
        .current_dir(home)
        .timeout(Duration::from_secs(5));
    command
}

#[test]
fn native_container_cache_is_a_default_off_product_feature() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    assert!(manifest["features"]["default"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        manifest["features"]["experimental-container-cache"]
            .as_array()
            .unwrap(),
        &[toml::Value::String("dep:socket2".into())]
    );
    assert_eq!(
        manifest["target"]["cfg(target_os = \"linux\")"]["dependencies"]["socket2"]["optional"]
            .as_bool(),
        Some(true)
    );
}

#[test]
fn build_info_distinguishes_disabled_from_experimental_unqualified() {
    let home = tempfile::tempdir().unwrap();
    let output = command(home.path())
        .args(["build-info", "--json"])
        .assert()
        .success()
        .stderr("")
        .get_output()
        .stdout
        .clone();
    let value: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schema"], dev_tools_product::BUILD_INFO_SCHEMA);
    assert_eq!(value["product"], "dev-cache");
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        value["native_container_cache"],
        if cfg!(feature = "experimental-container-cache") {
            "experimental-unqualified"
        } else {
            "disabled"
        }
    );
    // The existing observational schema permits product-owned extensions.
    let schema: Value = serde_json::from_str(dev_tools_product::BUILD_INFO_JSON_SCHEMA).unwrap();
    assert_eq!(schema["additionalProperties"], true);
    for field in schema["required"].as_array().unwrap() {
        assert!(value.get(field.as_str().unwrap()).is_some());
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[test]
fn help_and_all_completion_scripts_match_compiled_availability() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["--help"],
        vec!["completion", "bash"],
        vec!["completion", "zsh"],
        vec!["completion", "fish"],
        vec!["completion", "elvish"],
        vec!["completion", "powershell"],
    ] {
        let output = command(home.path())
            .args(&args)
            .assert()
            .success()
            .stderr("")
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(
            text.contains("container-cache"),
            cfg!(feature = "experimental-container-cache"),
            "{args:?} must match the compiled feature"
        );
        if args == ["--help"] && cfg!(feature = "experimental-container-cache") {
            assert!(text.contains("Experimental, unqualified"));
        }
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(not(feature = "experimental-container-cache"))]
#[test]
fn stable_command_rejection_needs_no_configuration_or_provider_setup() {
    let home = tempfile::tempdir().unwrap();
    for provider in ["docker", "podman"] {
        for apply in [false, true] {
            let mut invocation = command(home.path());
            invocation
                .arg("--config")
                .arg(home.path().join("missing-config.toml"))
                .args(["container-cache", provider, "--socket"])
                .arg(home.path().join("missing.sock"))
                .arg("--json");
            if apply {
                invocation.arg("--apply");
            }
            let output = invocation.assert().code(2).get_output().clone();
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("unrecognized subcommand 'container-cache'"));
        }
    }
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(all(target_os = "linux", not(feature = "experimental-container-cache")))]
#[test]
fn stable_preview_and_apply_reject_before_any_provider_connection() {
    use std::io::ErrorKind;
    use std::os::unix::net::UnixListener;

    let home = tempfile::Builder::new()
        .prefix("dc-gate-")
        .tempdir_in("/tmp")
        .unwrap();
    let socket = home.path().join("explicit.sock");
    let ambient_socket = home.path().join("ambient.sock");
    let explicit = UnixListener::bind(&socket).unwrap();
    let ambient = UnixListener::bind(&ambient_socket).unwrap();
    explicit.set_nonblocking(true).unwrap();
    ambient.set_nonblocking(true).unwrap();
    let root = home.path().join("cache-root");
    for provider in ["docker", "podman"] {
        for apply in [false, true] {
            let mut invocation = command(home.path());
            invocation
                .env(
                    "DOCKER_HOST",
                    format!("unix://{}", ambient_socket.display()),
                )
                .env("DOCKER_CONTEXT", "ignored")
                .env("DEV_CACHE_EXPERIMENTAL_CONTAINER_CACHE", "1")
                .env("CARGO_FEATURE_EXPERIMENTAL_CONTAINER_CACHE", "1")
                .arg("--config")
                .arg(home.path().join("missing-config.toml"))
                .arg("--root")
                .arg(&root)
                .args(["container-cache", provider, "--socket"])
                .arg(&socket)
                .arg("--json");
            if apply {
                invocation.args([
                    "--apply",
                    "--engine-id",
                    "fixture-engine",
                    "--storage-root",
                    "/fixture-only-storage",
                    "--privilege-domain",
                    "rootless",
                    "--cache-id",
                    "selected1",
                ]);
            }
            let output = invocation.assert().code(2).get_output().clone();
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("unrecognized subcommand 'container-cache'"));
            for listener in [&explicit, &ambient] {
                assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
            }
            assert!(!root.exists());
            assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 2);
        }
    }
}
