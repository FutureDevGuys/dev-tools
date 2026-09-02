#![cfg(unix)]

use dev_auth::credential_input::{
    load_credential_inputs, CredentialInputContext, CredentialInputSource,
};
use dev_auth::deployment::DeploymentMode;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;

#[test]
fn unused_enroll_if_absent_source_is_never_opened() {
    let declared = BTreeSet::from(["automation".to_owned()]);
    let sources = BTreeMap::from([(
        "automation".to_owned(),
        CredentialInputSource::File("/definitely/absent/dev-auth-token".into()),
    )]);
    let mut stdin = std::io::empty();
    let loaded = load_credential_inputs(
        &declared,
        &BTreeSet::new(),
        &sources,
        &CredentialInputContext {
            mode: DeploymentMode::Strong,
            allowed_owner_uids: BTreeSet::from([0]),
        },
        &mut stdin,
    )
    .unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn unused_stdin_source_is_never_read_or_rejected() {
    let declared = BTreeSet::from(["automation".to_owned()]);
    let sources = BTreeMap::from([("automation".to_owned(), CredentialInputSource::Stdin)]);
    let mut stdin = std::io::Cursor::new(b"must-remain-unread\n");
    let loaded = load_credential_inputs(
        &declared,
        &BTreeSet::new(),
        &sources,
        &CredentialInputContext {
            mode: DeploymentMode::Strong,
            allowed_owner_uids: BTreeSet::from([0]),
        },
        &mut stdin,
    )
    .unwrap();
    assert!(loaded.is_empty());
    assert_eq!(stdin.position(), 0);
}

#[test]
fn strong_file_input_requires_private_memory_backed_authority() {
    let root = tempfile::tempdir_in("/dev/shm").unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let token = root.path().join("credential");
    fs::write(&token, b"fixture-service-token\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let declared = BTreeSet::from(["automation".to_owned()]);
    let required = declared.clone();
    let sources = BTreeMap::from([("automation".to_owned(), CredentialInputSource::File(token))]);
    let mut stdin = std::io::empty();
    let loaded = load_credential_inputs(
        &declared,
        &required,
        &sources,
        &CredentialInputContext {
            mode: DeploymentMode::Strong,
            allowed_owner_uids: BTreeSet::from([nix::unistd::Uid::effective().as_raw()]),
        },
        &mut stdin,
    )
    .unwrap();
    assert_eq!(
        loaded.get("automation").unwrap().expose(),
        b"fixture-service-token\n"
    );

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let disk = tempfile::tempdir_in(user.dir).unwrap();
    let token = disk.path().join("credential");
    fs::write(&token, b"fixture-service-token\n").unwrap();
    fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    let sources = BTreeMap::from([("automation".to_owned(), CredentialInputSource::File(token))]);
    assert!(load_credential_inputs(
        &declared,
        &required,
        &sources,
        &CredentialInputContext {
            mode: DeploymentMode::Strong,
            allowed_owner_uids: BTreeSet::from([nix::unistd::Uid::effective().as_raw()]),
        },
        &mut stdin,
    )
    .is_err());
}

#[test]
fn stdin_is_valid_only_for_one_required_slot() {
    let declared = BTreeSet::from(["a".to_owned(), "b".to_owned()]);
    let required = declared.clone();
    let sources = BTreeMap::from([("a".to_owned(), CredentialInputSource::Stdin)]);
    let mut stdin = std::io::Cursor::new(b"secret\n");
    assert!(load_credential_inputs(
        &declared,
        &required,
        &sources,
        &CredentialInputContext {
            mode: DeploymentMode::UserOnly,
            allowed_owner_uids: BTreeSet::from([nix::unistd::Uid::effective().as_raw()]),
        },
        &mut stdin,
    )
    .is_err());
}
