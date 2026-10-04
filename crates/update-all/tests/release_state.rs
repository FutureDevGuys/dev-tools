#![cfg(unix)]

use assert_cmd::Command;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::time::Duration;

fn status(root: &Path) -> Command {
    let mut command = Command::new(assert_cmd::cargo::cargo_bin!("update-all"));
    command
        .env_clear()
        .env("HOME", root)
        .env("XDG_STATE_HOME", root.join("state"))
        .env("PATH", "/nonexistent")
        .current_dir(root)
        .args(["self", "status", "--json"])
        .timeout(Duration::from_secs(5));
    command
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
        Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
            .env_clear()
            .env("HOME", root.path())
            .env("XDG_STATE_HOME", root.path().join("state"))
            .env("PATH", "/nonexistent")
            .current_dir(root.path())
            .args(["self", operation, "--json"])
            .timeout(Duration::from_secs(5))
            .assert()
            .failure()
            .stdout("")
            .stderr(predicates::str::contains(
                "another release mutation is active",
            ));
    }
    status(root.path()).assert().success();
    assert_eq!(fs::read_dir(&product).unwrap().count(), 1);
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
