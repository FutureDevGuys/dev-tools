#![cfg(target_os = "linux")]

use dev_tools_installation::{
    read_atomic_document, remove_atomic_document_if_unchanged, write_atomic_document,
    ArtifactIdentity, DocumentAuthority,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[test]
fn removal_requires_exact_content_and_preserves_replacements() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("configuration");
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    write_atomic_document(&path, b"candidate", &authority, None).unwrap();
    let expected = read_atomic_document(&path, &authority)
        .unwrap()
        .unwrap()
        .identity;
    let wrong = ArtifactIdentity {
        length: 9,
        sha256: "0".repeat(64),
    };
    assert!(remove_atomic_document_if_unchanged(&path, &authority, &wrong).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"candidate");
    assert!(remove_atomic_document_if_unchanged(&path, &authority, &expected).unwrap());
    assert!(!path.exists());
    assert!(!remove_atomic_document_if_unchanged(&path, &authority, &expected).unwrap());
    write_atomic_document(&path, b"unrelated", &authority, None).unwrap();
    assert!(remove_atomic_document_if_unchanged(&path, &authority, &expected).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"unrelated");
}

#[test]
fn removal_rejects_links_and_unsafe_custody() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("target");
    let path = root.path().join("configuration");
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    write_atomic_document(&target, b"candidate", &authority, None).unwrap();
    let expected = read_atomic_document(&target, &authority)
        .unwrap()
        .unwrap()
        .identity;
    symlink(&target, &path).unwrap();
    assert!(remove_atomic_document_if_unchanged(&path, &authority, &expected).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"candidate");
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(remove_atomic_document_if_unchanged(&path, &authority, &expected).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&target, &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(remove_atomic_document_if_unchanged(&path, &authority, &expected).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"candidate");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = root.path().join("alias");
    symlink(root.path(), &alias).unwrap();
    assert!(remove_atomic_document_if_unchanged(
        &alias.join("configuration"),
        &authority,
        &expected
    )
    .is_err());
    assert_eq!(fs::read(&path).unwrap(), b"candidate");
}
