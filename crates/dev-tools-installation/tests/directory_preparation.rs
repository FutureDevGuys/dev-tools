#![cfg(target_os = "linux")]

use dev_tools_installation::{DocumentAuthority, DocumentDirectoryPreparation};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[test]
#[ignore = "requires namespace root with subordinate UID mappings"]
fn native_directory_preparation_assigns_selected_owner_before_publication() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(root.path().metadata().unwrap().uid(), 0);
    let parent = root.path().join("account");
    fs::create_dir(&parent).unwrap();
    rustix::fs::chownat(
        rustix::fs::CWD,
        &parent,
        Some(rustix::fs::Uid::from_raw(1000)),
        None,
        rustix::fs::AtFlags::empty(),
    )
    .unwrap();
    let path = parent.join("first/second");
    let proof = DocumentDirectoryPreparation::observe(&path, 1000, 0o755).unwrap();
    assert!(DocumentDirectoryPreparation::observe(&path, 0, 0o755).is_err());
    assert!(proof.prepare().unwrap().1);
    for path in [parent.join("first"), path] {
        let metadata = path.metadata().unwrap();
        assert_eq!(metadata.uid(), 1000);
        assert_eq!(metadata.mode() & 0o7777, 0o755);
    }
}

#[test]
fn missing_directory_preparation_is_read_only_then_durable_and_conditional() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let path = root.path().join("first/second");
    let proof = DocumentDirectoryPreparation::observe(&path, owner, 0o755).unwrap();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o644,
        limit: 100,
    };
    assert!(proof
        .read(OsStr::new("asset"), &authority)
        .unwrap()
        .is_none());
    assert!(!root.path().join("first").exists());
    let (directory, changed) = proof.prepare().unwrap();
    assert!(changed);
    assert!(proof.verify_observed().is_err());
    for directory in [root.path().join("first"), path.clone()] {
        let metadata = directory.metadata().unwrap();
        assert_eq!(metadata.uid(), owner);
        assert_eq!(metadata.mode() & 0o7777, 0o755);
    }
    assert!(directory
        .write(OsStr::new("asset"), b"selected bytes", &authority, None)
        .unwrap());
    let retry = DocumentDirectoryPreparation::observe(&path, owner, 0o755).unwrap();
    assert!(!retry.prepare().unwrap().1);
    assert_eq!(
        retry
            .read(OsStr::new("asset"), &authority)
            .unwrap()
            .unwrap()
            .bytes,
        b"selected bytes"
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn late_directory_or_unknown_entry_is_not_adopted() {
    for kind in ["directory", "file", "symlink"] {
        let root = tempfile::tempdir().unwrap();
        let owner = root.path().metadata().unwrap().uid();
        let path = root.path().join("selected");
        let proof =
            DocumentDirectoryPreparation::observe(&path.join("child"), owner, 0o755).unwrap();
        match kind {
            "directory" => fs::create_dir(&path).unwrap(),
            "file" => fs::write(&path, b"unknown").unwrap(),
            _ => symlink(root.path(), &path).unwrap(),
        }
        let before = fs::symlink_metadata(&path).unwrap();
        assert!(proof.verify_observed().is_err());
        assert!(proof.prepare().is_err());
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!((before.ino(), before.mode()), (after.ino(), after.mode()));
        assert!(!root.path().join("child").exists());
    }
}

#[test]
fn replaced_ancestor_cannot_redirect_directory_publication() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let path = root.path().join("parent");
    fs::create_dir(&path).unwrap();
    let proof = DocumentDirectoryPreparation::observe(&path.join("child"), owner, 0o755).unwrap();
    fs::rename(&path, root.path().join("displaced")).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(proof.prepare().is_err());
    assert!(!path.join("child").exists());
    assert!(!root.path().join("displaced/child").exists());
}

#[test]
fn unsafe_directory_authority_fails_and_existing_permissions_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let path = root.path().join("parent");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let proof = DocumentDirectoryPreparation::observe(&path, owner, 0o755).unwrap();
    assert!(!proof.prepare().unwrap().1);
    assert_eq!(path.metadata().unwrap().mode() & 0o7777, 0o700);
    assert!(DocumentDirectoryPreparation::observe(&path, owner.wrapping_add(1), 0o755).is_err());
    for mode in [0o777, 0o4755, 0o600] {
        assert!(DocumentDirectoryPreparation::observe(&path, owner, mode).is_err());
    }
    assert!(DocumentDirectoryPreparation::observe(&path.join("../escape"), owner, 0o755).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(DocumentDirectoryPreparation::observe(&path.join("child"), owner, 0o755).is_err());
}
