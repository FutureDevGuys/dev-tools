#![cfg(target_os = "linux")]

use dev_tools_installation::{
    read_atomic_document, read_atomic_file, DocumentAuthority, DocumentDirectoryPreparation,
    ExistingDocumentDirectory,
};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};

#[test]
fn empty_file_support_does_not_adopt_occupied_new_document_destinations() {
    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(temp.path(), owner).unwrap();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 32,
    };
    let name = OsStr::new("selected-leaf");

    assert!(directory.publish_new(name, b"", &authority).is_err());
    assert!(!temp.path().join(name).exists());
    directory.write_file(name, b"", &authority, None).unwrap();
    let empty = directory.read_file(name, &authority).unwrap().unwrap();
    assert!(directory.publish_new(name, b"owned", &authority).is_err());
    assert_eq!(
        directory.read_file(name, &authority).unwrap().unwrap(),
        empty
    );
    directory
        .remove_file(name, &authority, &empty.identity)
        .unwrap();

    directory.publish_new(name, b"owned", &authority).unwrap();
    let owned = directory.read(name, &authority).unwrap().unwrap();
    assert!(directory.publish_new(name, b"owned", &authority).is_err());
    assert!(directory.publish_new(name, b"changed", &authority).is_err());
    assert_eq!(directory.read(name, &authority).unwrap().unwrap(), owned);
    assert!(!directory
        .write(name, b"owned", &authority, Some(&owned.identity))
        .unwrap());
}

#[test]
fn empty_file_custody_is_explicit_and_does_not_weaken_document_operations() {
    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(temp.path(), owner).unwrap();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 32,
    };
    let name = OsStr::new("empty-config");
    assert!(directory.write_file(name, b"", &authority, None).unwrap());
    let empty = directory.read_file(name, &authority).unwrap().unwrap();
    assert!(empty.bytes.is_empty());
    assert_eq!(empty.identity.length, 0);
    assert_eq!(
        empty.identity.sha256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(directory.read(name, &authority).is_err());
    assert!(directory
        .write(name, b"", &authority, Some(&empty.identity))
        .is_err());
    assert!(directory
        .write(name, b"configured", &authority, Some(&empty.identity))
        .is_err());
    assert!(directory
        .replace(name, b"configured", &authority, &authority, &empty.identity)
        .is_err());
    assert!(!directory
        .write_file(name, b"", &authority, Some(&empty.identity))
        .unwrap());
    assert!(directory
        .replace_file(name, b"configured", &authority, &authority, &empty.identity)
        .unwrap());
    let configured = directory.read_file(name, &authority).unwrap().unwrap();
    assert!(directory
        .replace_file(name, b"", &authority, &authority, &configured.identity)
        .unwrap());
    assert!(directory
        .remove_file(name, &authority, &configured.identity)
        .is_err());
    assert!(directory.remove(name, &authority, &empty.identity).is_err());
    assert!(directory
        .remove_file(name, &authority, &empty.identity)
        .unwrap());
    assert!(!directory
        .remove_file(name, &authority, &empty.identity)
        .unwrap());
    assert!(!temp.path().join(name).exists());
}

#[test]
fn empty_file_reads_remain_bounded_and_document_reads_reject_empty_content() {
    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(temp.path(), owner).unwrap();
    let preparation = DocumentDirectoryPreparation::observe(temp.path(), owner, 0o700).unwrap();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 32,
    };
    let name = OsStr::new("empty-config");
    let path = temp.path().join(name);
    assert!(read_atomic_file(&path, &authority).unwrap().is_none());
    directory.write_file(name, b"", &authority, None).unwrap();
    let empty = directory.read_file(name, &authority).unwrap().unwrap();
    assert_eq!(read_atomic_file(&path, &authority).unwrap().unwrap(), empty);
    assert_eq!(
        preparation.read_file(name, &authority).unwrap().unwrap(),
        empty
    );
    assert!(read_atomic_document(&path, &authority).is_err());
    assert!(preparation.read(name, &authority).is_err());

    let wrong_owner = DocumentAuthority {
        owner_uid: owner.wrapping_add(1),
        ..authority.clone()
    };
    let wrong_mode = DocumentAuthority {
        mode: 0o644,
        ..authority.clone()
    };
    let zero_limit = DocumentAuthority {
        limit: 0,
        ..authority.clone()
    };
    for rejected in [&wrong_owner, &wrong_mode, &zero_limit] {
        assert!(read_atomic_file(&path, rejected).is_err());
        assert!(preparation.read_file(name, rejected).is_err());
    }
    assert!(directory
        .replace_file(name, &[b'x'; 33], &authority, &authority, &empty.identity)
        .is_err());
    assert!(directory
        .replace_file(name, b"", &authority, &wrong_mode, &empty.identity)
        .is_err());
    assert!(directory
        .remove_file(name, &wrong_mode, &empty.identity)
        .is_err());
    assert_eq!(
        directory.read_file(name, &authority).unwrap().unwrap(),
        empty
    );

    let link = temp.path().join("linked-config");
    symlink(&path, &link).unwrap();
    assert!(read_atomic_file(&link, &authority).is_err());
    assert!(preparation
        .read_file(OsStr::new("linked-config"), &authority)
        .is_err());
    fs::remove_file(&link).unwrap();
    fs::hard_link(&path, &link).unwrap();
    assert!(read_atomic_file(&path, &authority).is_err());
    assert!(preparation.read_file(name, &authority).is_err());
    assert!(directory
        .remove_file(name, &authority, &empty.identity)
        .is_err());
    assert!(path.exists());
    assert!(link.exists());
}

#[test]
fn empty_file_directory_observation_preserves_absence_and_rejects_late_parents() {
    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    let parent = temp.path().join("missing/parent");
    let preparation = DocumentDirectoryPreparation::observe(&parent, owner, 0o700).unwrap();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 32,
    };
    assert!(preparation
        .read_file(OsStr::new("empty-config"), &authority)
        .unwrap()
        .is_none());
    assert!(!temp.path().join("missing").exists());
    assert!(preparation
        .read_file(OsStr::new("../empty-config"), &authority)
        .is_err());
    fs::create_dir(temp.path().join("missing")).unwrap();
    assert!(preparation
        .read_file(OsStr::new("empty-config"), &authority)
        .is_err());
    assert!(!parent.exists());
}

#[test]
fn empty_file_replacement_preserves_exact_before_and_after_modes() {
    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(temp.path(), owner).unwrap();
    let private = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 32,
    };
    let public = DocumentAuthority {
        mode: 0o644,
        ..private.clone()
    };
    let name = OsStr::new("empty-config");
    let path = temp.path().join(name);
    directory.write_file(name, b"", &private, None).unwrap();
    let empty = directory.read_file(name, &private).unwrap().unwrap();
    assert!(directory
        .replace_file(name, b"", &public, &private, &empty.identity)
        .unwrap());
    assert_eq!(path.metadata().unwrap().mode() & 0o7777, public.mode);
    assert_eq!(directory.read_file(name, &public).unwrap().unwrap(), empty);
    assert!(directory.read(name, &public).is_err());
    assert!(!directory
        .replace_file(name, b"", &public, &public, &empty.identity)
        .unwrap());
    assert!(directory
        .replace_file(name, b"", &private, &public, &empty.identity)
        .unwrap());
    assert_eq!(path.metadata().unwrap().mode() & 0o7777, private.mode);
    assert_eq!(path.metadata().unwrap().uid(), owner);
}
