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
