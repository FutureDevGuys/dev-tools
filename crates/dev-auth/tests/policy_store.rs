#![cfg(unix)]

use dev_auth::policy_store::{load_user_config_at, load_user_policy_at};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

#[test]
fn policy_loaders_accept_private_regular_documents_and_reject_unsafe_authority() {
    let root = tempfile::tempdir().unwrap();
    let uid = nix::unistd::Uid::current().as_raw();
    let policy = root.path().join("policy.toml");
    let config = root.path().join("config.toml");
    fs::write(
        &policy,
        include_bytes!("../policy-v2-user-only.example.toml"),
    )
    .unwrap();
    fs::write(&config, include_bytes!("../config-v2.example.toml")).unwrap();
    for path in [&policy, &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(load_user_policy_at(&policy, uid).is_ok());
    assert!(load_user_config_at(&config, uid).is_ok());
    assert!(load_user_config_at(&config, uid.wrapping_add(1)).is_err());

    let linked = root.path().join("linked.toml");
    symlink(&config, &linked).unwrap();
    assert!(load_user_config_at(&linked, uid).is_err());
    assert!(load_user_config_at(root.path(), uid).is_err());
    assert!(load_user_config_at(std::path::Path::new("config.toml"), uid).is_err());
    fs::set_permissions(&config, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(load_user_config_at(&config, uid).is_err());
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&config, vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(load_user_config_at(&config, uid).is_err());

    let fifo = root.path().join("fifo.toml");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR).unwrap();
    assert!(load_user_config_at(&fifo, uid).is_err());
}
