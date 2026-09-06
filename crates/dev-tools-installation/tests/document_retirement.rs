#![cfg(target_os = "linux")]

use dev_tools_installation::{retire_atomic_document, write_atomic_document, DocumentAuthority};
use std::fs;
use std::os::unix::fs::MetadataExt;

#[test]
fn retirement_captures_history_and_excludes_an_already_prepared_atomic_writer() {
    let root = tempfile::tempdir().unwrap();
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    let source = root.path().join("state.json");
    write_atomic_document(&source, b"accepted history", &authority, None).unwrap();
    let prepared = root.path().join("legacy-prepared.json");
    write_atomic_document(&prepared, b"stale history", &authority, None).unwrap();
    let (changed, captured) = retire_atomic_document(&source, &authority, false).unwrap();
    assert_eq!(captured.unwrap().bytes, b"accepted history");
    assert!(fs::rename(&prepared, &source).is_err());
    assert!(changed);
    assert!(source.is_dir());
    let (changed, captured) = retire_atomic_document(&source, &authority, false).unwrap();
    assert!(!changed);
    assert_eq!(captured.unwrap().bytes, b"accepted history");
    assert_eq!(fs::read(prepared).unwrap(), b"stale history");
}

#[test]
fn absent_history_is_explicit_and_cannot_satisfy_required_history() {
    let root = tempfile::tempdir().unwrap();
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    let source = root.path().join("state.json");
    assert!(retire_atomic_document(&source, &authority, false).is_err());
    assert!(!source.exists());
    assert_eq!(
        retire_atomic_document(&source, &authority, true).unwrap(),
        (true, None)
    );
    assert_eq!(
        retire_atomic_document(&source, &authority, true).unwrap(),
        (false, None)
    );
    assert!(retire_atomic_document(&source, &authority, false).is_err());
    assert!(source.is_dir());
}

#[test]
fn foreign_directory_is_not_adopted_and_unknown_entries_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    let source = root.path().join("state.json");
    fs::create_dir(&source).unwrap();
    let unknown = source.join("unknown");
    fs::write(&unknown, b"preserve").unwrap();
    assert!(retire_atomic_document(&source, &authority, true).is_err());
    assert_eq!(fs::read(unknown).unwrap(), b"preserve");
}
