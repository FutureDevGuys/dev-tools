#![cfg(unix)]

use assert_cmd::Command;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::time::Duration;

fn status(root: &Path) -> Command {
    release_status(root, &["self", "status", "--json"])
}

fn release_status(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("update-all"));
    command
        .env_clear()
        .env("HOME", root)
        .env("XDG_STATE_HOME", root.join("state"))
        .env("PATH", "/nonexistent")
        .current_dir(root)
        .args(args)
        .timeout(Duration::from_secs(5));
    command
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_legacy_status_reports_common_failures_without_mutation() {
    use std::os::unix::fs::MetadataExt;

    for (mode, hardlinked) in [(0o644, false), (0o700, false), (0o600, true)] {
        let root = tempfile::tempdir().unwrap();
        let product = root.path().join("state/dev-tools/products/update-all");
        fs::create_dir_all(&product).unwrap();
        fs::set_permissions(&product, fs::Permissions::from_mode(0o700)).unwrap();
        let state = product.join("state.json");
        let bytes = b"{\"accepted_root_generation\":0,\"accepted_generation\":0}";
        fs::write(&state, bytes).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(mode)).unwrap();
        if hardlinked {
            fs::hard_link(&state, root.path().join("private-state-alias")).unwrap();
        }
        let before = fs::symlink_metadata(&state).unwrap();
        for args in [
            &["self", "status", "--json"][..],
            &["self", "status"][..],
            &["product", "status", "update-all", "--json"][..],
            &["product", "status", "update-all"][..],
        ] {
            release_status(root.path(), args)
                .assert()
                .code(4)
                .stdout("")
                .stderr("release status failed; use update-all update status --json for details\n");
            let after = fs::symlink_metadata(&state).unwrap();
            assert_eq!(fs::read(&state).unwrap(), bytes);
            assert_eq!(after.mode(), before.mode());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.nlink(), before.nlink());
            assert_eq!(after.mtime(), before.mtime());
            assert_eq!(after.mtime_nsec(), before.mtime_nsec());
            assert_eq!(fs::read_dir(&product).unwrap().count(), 1);
        }
    }
}

#[test]
fn standalone_legacy_status_preserves_successful_json_shape() {
    let root = tempfile::tempdir().unwrap();
    let product = root.path().join("state/dev-tools/products/update-all");
    let state = product.join("state.json");
    let bytes = br#"{"accepted_root_generation":0,"accepted_generation":0,"active_version":"0.1.14","previous_version":"0.1.13","last_successful_check_unix":42}"#;
    for present in [false, true] {
        if present {
            fs::create_dir_all(&product).unwrap();
            fs::set_permissions(&product, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&state, bytes).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
        }
        for args in [
            &["self", "status", "--json"][..],
            &["product", "status", "update-all", "--json"][..],
        ] {
            let assertion = release_status(root.path(), args)
                .assert()
                .success()
                .stderr("");
            let document: serde_json::Value =
                serde_json::from_slice(&assertion.get_output().stdout).unwrap();
            assert_eq!(
                document,
                serde_json::json!({
                    "product": "update-all",
                    "installed_version": present.then_some("0.1.14"),
                    "engine_version": env!("CARGO_PKG_VERSION"),
                    "previous_version": present.then_some("0.1.13"),
                    "managed": false,
                    "last_successful_check_unix": present.then_some(42),
                })
            );
            if present {
                assert_eq!(fs::read(&state).unwrap(), bytes);
                assert_eq!(fs::read_dir(&product).unwrap().count(), 1);
            } else {
                assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
            }
        }
    }
}

#[test]
fn standalone_status_preserves_absent_and_hostile_release_state() {
    let root = tempfile::tempdir().unwrap();
    status(root.path()).assert().success();
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    let product = root.path().join("state/dev-tools/products/update-all");
    fs::create_dir_all(&product).unwrap();
    fs::set_permissions(&product, fs::Permissions::from_mode(0o700)).unwrap();
    let state = product.join("state.json");
    fs::create_dir(&state).unwrap();
    status(root.path()).assert().failure().stdout("");
    assert!(state.is_dir());
    fs::remove_dir(&state).unwrap();
    let missing = root.path().join("not-created");
    symlink(&missing, &state).unwrap();
    status(root.path()).assert().failure().stdout("");
    assert_eq!(fs::read_link(&state).unwrap(), missing);
    assert!(!missing.exists());
    assert_eq!(fs::read_dir(&product).unwrap().count(), 1);
}

#[test]
fn native_release_writer_excludes_mutations_but_not_status() {
    let root = tempfile::tempdir().unwrap();
    let product = root.path().join("state/dev-tools/products/update-all");
    fs::create_dir_all(&product).unwrap();
    fs::set_permissions(&product, fs::Permissions::from_mode(0o700)).unwrap();
    let held =
        dev_tools_installation::InstallationLock::acquire(&product.join("release-writer-v1.lock"))
            .unwrap();
    for operation in ["check", "install", "update", "rollback"] {
        let assertion = Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path().join("state"))
            .env("PATH", "/nonexistent")
            .current_dir(root.path())
            .args(["self", operation, "--json"])
            .timeout(Duration::from_secs(5))
            .assert()
            .stdout("");
        // ADR 0030's Linux self adapter preserves the common blocked exit.
        // Rollback refuses this absent installation before lease admission;
        // the legacy-product fixture below proves rollback writer exclusion.
        #[cfg(target_os = "linux")]
        assertion.code(3).stderr("");
        #[cfg(not(target_os = "linux"))]
        assertion.failure().stderr(predicates::str::contains(
            "another release mutation is active",
        ));
        assert_eq!(fs::read_dir(&product).unwrap().count(), 1);
    }
    status(root.path()).assert().success();
    assert_eq!(fs::read_dir(&product).unwrap().count(), 1);

    let legacy_product = root.path().join("state/dev-tools/products/dev-cache");
    fs::create_dir_all(&legacy_product).unwrap();
    fs::set_permissions(&legacy_product, fs::Permissions::from_mode(0o700)).unwrap();
    let _legacy_held = dev_tools_installation::InstallationLock::acquire(
        &legacy_product.join("release-writer-v1.lock"),
    )
    .unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("PATH", "/nonexistent")
        .current_dir(root.path())
        .args(["product", "rollback", "dev-cache", "--json"])
        .timeout(Duration::from_secs(5))
        .assert()
        .code(1)
        .stdout("")
        .stderr(predicates::str::contains(
            "another release mutation is active",
        ));
    assert_eq!(fs::read_dir(&legacy_product).unwrap().count(), 1);
    drop(held);
    assert!(dev_tools_installation::InstallationLock::try_acquire(
        &product.join("release-writer-v1.lock")
    )
    .unwrap()
    .is_some());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn standalone_offline_bundle_rejects_tampering_without_online_fallback() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("root.json");
    let manifest = home.path().join("manifest.json");
    let artifact = home.path().join("artifact");
    fs::write(
        &root,
        include_bytes!("../../../release-trust/dev-tools-root.json"),
    )
    .unwrap();
    fs::write(
        &manifest,
        include_bytes!("../../../tests/fixtures/releases/dev-cache-0.1.7-v2.json"),
    )
    .unwrap();
    fs::write(&artifact, b"not the signed artifact").unwrap();
    for path in [&root, &manifest, &artifact] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    for operation in ["install", "update"] {
        Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("PATH", "/nonexistent")
            .env("DEV_TOOLS_ROOT_URL", "invalid-network-sentinel")
            .env("DEV_TOOLS_MANIFEST_URL", "invalid-network-sentinel")
            .env("DEV_TOOLS_RELEASES_URL", "invalid-network-sentinel")
            .current_dir(home.path())
            .args([
                "product",
                operation,
                "dev-cache",
                "--offline",
                "--json",
                "--root-document",
            ])
            .arg(&root)
            .arg("--manifest")
            .arg(&manifest)
            .arg("--artifact")
            .arg(&artifact)
            .timeout(Duration::from_secs(5))
            .assert()
            .code(4)
            .stdout("")
            .stderr(predicates::str::contains(
                "offline release authentication failed",
            ));
    }
    assert!(!home.path().join(".local/bin/dev-cache").exists());
    assert!(!home
        .path()
        .join("state/dev-tools/products/dev-cache/state.json")
        .exists());
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn standalone_offline_bundle_obeys_the_existing_release_writer() {
    let home = tempfile::tempdir().unwrap();
    let product = home.path().join("state/dev-tools/products/dev-cache");
    fs::create_dir_all(&product).unwrap();
    fs::set_permissions(&product, fs::Permissions::from_mode(0o700)).unwrap();
    let _held =
        dev_tools_installation::InstallationLock::acquire(&product.join("release-writer-v1.lock"))
            .unwrap();
    Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
        .env_clear()
        .env("HOME", home.path())
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("PATH", "/nonexistent")
        .current_dir(home.path())
        .args([
            "product",
            "install",
            "dev-cache",
            "--offline",
            "--json",
            "--root-document",
            "/missing-root",
            "--manifest",
            "/missing-manifest",
            "--artifact",
            "/missing-artifact",
        ])
        .timeout(Duration::from_secs(5))
        .assert()
        .failure()
        .stdout("")
        .stderr(predicates::str::contains(
            "another release mutation is active",
        ));
    assert_eq!(fs::read_dir(&product).unwrap().count(), 1);
}
