#![cfg(target_os = "linux")]

use dev_tools_installation::InstallationLock;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn transferred_shared_lease_survives_either_participants_drop() {
    for sender_first in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("lock");
        let owner = root.path().metadata().unwrap().uid();
        let sender = InstallationLock::try_acquire_shared(&path)
            .unwrap()
            .unwrap();
        let receiver = InstallationLock::from_shared_descriptor(
            sender
                .shared_descriptor()
                .unwrap()
                .try_clone_to_owned()
                .unwrap(),
            &path,
            owner,
        )
        .unwrap();
        assert!(InstallationLock::try_acquire(&path).unwrap().is_none());
        let retained = if sender_first {
            drop(sender);
            receiver
        } else {
            drop(receiver);
            sender
        };
        assert!(InstallationLock::try_acquire(&path).unwrap().is_none());
        drop(retained);
        assert!(InstallationLock::try_acquire(&path).unwrap().is_some());
    }
}

#[test]
fn transferred_lease_rejects_wrong_owner_mode_name_and_exclusive_export() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("lock");
    let owner = root.path().metadata().unwrap().uid();
    let sender = InstallationLock::try_acquire_shared(&path)
        .unwrap()
        .unwrap();
    let receive = |uid| {
        InstallationLock::from_shared_descriptor(
            sender
                .shared_descriptor()
                .unwrap()
                .try_clone_to_owned()
                .unwrap(),
            &path,
            uid,
        )
    };
    assert!(receive(owner.wrapping_add(1)).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(receive(owner).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(&path, root.path().join("displaced")).unwrap();
    fs::write(&path, b"independent").unwrap();
    assert!(receive(owner).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let exclusive = InstallationLock::try_acquire(&path).unwrap().unwrap();
    assert!(exclusive.shared_descriptor().is_err());
}
