#![cfg(unix)]

use dev_tools_installation::{
    publish_executable, read_atomic_document, remove_owned_file, remove_owned_installation,
    verify_owned_installation, write_atomic_document, ArtifactIdentity, DocumentAuthority,
    InstallationLock, InstallationReceipt, ReceiptArtifact,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[test]
fn publication_is_atomic_idempotent_and_refuses_symlink_authority() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::write(&source, b"candidate").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let destination = temp.path().join("versions/1.0.0/product");
    let identity = ArtifactIdentity::from_file(&source, 1024).unwrap();

    assert!(publish_executable(&source, &destination, &identity).unwrap());
    assert!(!publish_executable(&source, &destination, &identity).unwrap());

    let escaped = temp.path().join("escaped");
    fs::create_dir(&escaped).unwrap();
    let symlinked_parent = temp.path().join("unsafe");
    symlink(&escaped, &symlinked_parent).unwrap();
    assert!(publish_executable(&source, &symlinked_parent.join("product"), &identity).is_err());
}

#[test]
fn removal_requires_the_exact_recorded_identity() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("owned");
    fs::write(&path, b"owned").unwrap();
    let identity = ArtifactIdentity::from_file(&path, 1024).unwrap();
    fs::write(&path, b"drifted").unwrap();
    assert!(remove_owned_file(&path, &identity).is_err());
    assert!(path.exists());

    fs::write(&path, b"owned").unwrap();
    assert!(remove_owned_file(&path, &identity).unwrap());
    assert!(!path.exists());
    assert!(!remove_owned_file(&path, &identity).unwrap());
}

#[test]
fn hardlinked_sources_and_destinations_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    let linked = temp.path().join("source-link");
    fs::write(&source, b"candidate").unwrap();
    fs::hard_link(&source, &linked).unwrap();
    assert!(ArtifactIdentity::from_file(&source, 1024).is_err());

    fs::remove_file(&linked).unwrap();
    let identity = ArtifactIdentity::from_file(&source, 1024).unwrap();
    let destination = temp.path().join("versions/1.0.0/product");
    assert!(publish_executable(&source, &destination, &identity).unwrap());
    fs::hard_link(&destination, temp.path().join("escaped-copy")).unwrap();
    assert!(publish_executable(&source, &destination, &identity).is_err());
    assert!(remove_owned_file(&destination, &identity).is_err());
}

#[test]
fn receipt_verification_and_uninstall_are_owned_and_all_or_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    fs::write(&first, b"one").unwrap();
    fs::write(&second, b"two").unwrap();
    let receipt = InstallationReceipt {
        schema: "dev-tools-installation-receipt-v1".into(),
        product: "product".into(),
        active_version: "1.2.3".into(),
        previous_version: None,
        artifacts: vec![
            ReceiptArtifact {
                path: first.clone(),
                identity: ArtifactIdentity::from_file(&first, 1024).unwrap(),
            },
            ReceiptArtifact {
                path: second.clone(),
                identity: ArtifactIdentity::from_file(&second, 1024).unwrap(),
            },
        ],
    };
    verify_owned_installation(&receipt).unwrap();

    fs::write(&second, b"user drift").unwrap();
    assert!(remove_owned_installation(&receipt).is_err());
    assert!(first.exists());
    assert!(second.exists());

    fs::write(&second, b"two").unwrap();
    assert_eq!(remove_owned_installation(&receipt).unwrap(), 2);
    assert!(!first.exists());
    assert!(!second.exists());
}

#[test]
fn installation_lock_serializes_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let first = InstallationLock::acquire(&temp.path().join("install.lock")).unwrap();
    assert!(
        InstallationLock::try_acquire(&temp.path().join("install.lock"))
            .unwrap()
            .is_none()
    );
    drop(first);
    assert!(
        InstallationLock::try_acquire(&temp.path().join("install.lock"))
            .unwrap()
            .is_some()
    );
}

#[test]
fn atomic_documents_are_idempotent_compare_and_swap_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("state/release.json");
    let authority = DocumentAuthority {
        owner_uid: fs::metadata(temp.path()).unwrap().uid(),
        mode: 0o600,
        limit: 4096,
    };
    assert!(write_atomic_document(&path, b"one", &authority, None).unwrap());
    assert!(!write_atomic_document(&path, b"one", &authority, None).unwrap());
    let current = read_atomic_document(&path, &authority).unwrap().unwrap();
    assert!(write_atomic_document(&path, b"two", &authority, Some(&current.identity)).unwrap());
    assert_eq!(
        read_atomic_document(&path, &authority)
            .unwrap()
            .unwrap()
            .bytes,
        b"two"
    );
    assert!(write_atomic_document(&path, b"three", &authority, Some(&current.identity)).is_err());
}

#[test]
fn atomic_documents_reject_links_and_unsafe_modes() {
    let temp = tempfile::tempdir().unwrap();
    let authority = DocumentAuthority {
        owner_uid: fs::metadata(temp.path()).unwrap().uid(),
        mode: 0o600,
        limit: 4096,
    };
    let outside = temp.path().join("outside");
    fs::write(&outside, b"outside").unwrap();
    let path = temp.path().join("state");
    symlink(&outside, &path).unwrap();
    assert!(read_atomic_document(&path, &authority).is_err());
    assert!(write_atomic_document(&path, b"new", &authority, None).is_err());

    let real_parent = temp.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let document = real_parent.join("document");
    fs::write(&document, b"document").unwrap();
    fs::set_permissions(&document, fs::Permissions::from_mode(0o600)).unwrap();
    let linked_parent = temp.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    assert!(read_atomic_document(&linked_parent.join("document"), &authority).is_err());
}

#[test]
fn installation_lock_rejects_symlink_and_hardlink_authority() {
    let temp = tempfile::tempdir().unwrap();
    let outside = temp.path().join("outside.lock");
    fs::write(&outside, b"").unwrap();
    fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();
    let symlinked = temp.path().join("symlinked.lock");
    symlink(&outside, &symlinked).unwrap();
    assert!(InstallationLock::acquire(&symlinked).is_err());

    let hardlinked = temp.path().join("hardlinked.lock");
    fs::hard_link(&outside, &hardlinked).unwrap();
    assert!(InstallationLock::acquire(&hardlinked).is_err());
}
