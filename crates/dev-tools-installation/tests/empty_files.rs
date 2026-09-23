#![cfg(target_os = "linux")]
use dev_tools_installation::{DocumentAuthority, ExistingDocumentDirectory};
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;

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
    assert!(directory.read(name, &authority).is_err());
    assert!(directory
        .write(name, b"", &authority, Some(&empty.identity))
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
