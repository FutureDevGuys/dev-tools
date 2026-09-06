#![cfg(target_os = "linux")]

use dev_tools_installation::{
    observe_retired_atomic_document, retire_atomic_document, write_atomic_document,
    DocumentAuthority,
};
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

#[test]
fn read_only_observation_distinguishes_unretired_and_explicit_empty_history() {
    let root = tempfile::tempdir().unwrap();
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    let missing = root.path().join("missing/state.json");
    assert_eq!(
        observe_retired_atomic_document(&missing, &authority).unwrap(),
        None
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    let source = root.path().join("state.json");
    assert_eq!(
        observe_retired_atomic_document(&source, &authority).unwrap(),
        None
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    retire_atomic_document(&source, &authority, true).unwrap();
    let before = inventory(root.path());
    assert!(observe_retired_atomic_document(&source, &authority)
        .unwrap()
        .unwrap()
        .captured
        .is_none());
    assert_eq!(inventory(root.path()), before);
}

#[test]
fn read_only_observation_preserves_captured_bytes_and_does_not_recreate_a_missing_lock() {
    let root = tempfile::tempdir().unwrap();
    let authority = DocumentAuthority {
        owner_uid: root.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    let source = root.path().join("state.json");
    write_atomic_document(&source, b"history", &authority, None).unwrap();
    assert_eq!(
        observe_retired_atomic_document(&source, &authority).unwrap(),
        None
    );
    let (_, captured) = retire_atomic_document(&source, &authority, false).unwrap();
    // Test-owned loss: observation cannot recreate even this coordination file.
    let lock = fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "lock")
        })
        .unwrap();
    fs::remove_file(&lock).unwrap();
    let before = inventory(root.path());
    assert_eq!(
        observe_retired_atomic_document(&source, &authority)
            .unwrap()
            .unwrap()
            .captured,
        captured
    );
    assert!(!lock.exists());
    assert_eq!(inventory(root.path()), before);
}

type InventoryEntry = (std::path::PathBuf, u64, u32, i64, i64, Option<Vec<u8>>);

fn inventory(root: &std::path::Path) -> Vec<InventoryEntry> {
    let mut entries = fs::read_dir(root)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let metadata = path.symlink_metadata().unwrap();
            let bytes = metadata.is_file().then(|| fs::read(&path).unwrap());
            (
                path,
                metadata.ino(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                bytes,
            )
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}
