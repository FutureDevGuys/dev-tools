#![cfg(target_os = "linux")]

use dev_tools_installation::{ArtifactIdentity, DocumentAuthority, ExistingDocumentDirectory};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[test]
#[ignore = "requires namespace root with subordinate UID mappings"]
fn explicit_symbolic_link_owner_does_not_relax_directory_or_default_authority() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(root.path().metadata().unwrap().uid(), 0);
    let selected = root.path().join("selected");
    fs::create_dir(&selected).unwrap();
    rustix::fs::chownat(
        rustix::fs::CWD,
        &selected,
        Some(rustix::fs::Uid::from_raw(1000)),
        None,
        rustix::fs::AtFlags::empty(),
    )
    .unwrap();
    let directory = ExistingDocumentDirectory::open(&selected, 1000).unwrap();
    assert!(ExistingDocumentDirectory::open(&selected, 0).is_err());
    let target = root.path().join("target");
    fs::write(&target, b"untouched target").unwrap();
    let target_before = target.metadata().unwrap();
    let name = OsStr::new("legacy");
    symlink(&target, selected.join(name)).unwrap();
    assert!(directory.read_symbolic_link(name).is_err());
    assert!(directory.remove_symbolic_link(name, &target).is_err());
    assert!(directory.read_symbolic_link_with_owner(name, 1000).is_err());
    assert_eq!(
        directory.read_symbolic_link_with_owner(name, 0).unwrap(),
        Some(target.clone())
    );
    assert!(directory
        .remove_symbolic_link_with_owner(name, &target, 1000)
        .is_err());
    assert!(directory
        .remove_symbolic_link_with_owner(name, &root.path().join("wrong"), 0)
        .is_err());
    assert_eq!(fs::symlink_metadata(selected.join(name)).unwrap().uid(), 0);
    assert!(directory
        .remove_symbolic_link_with_owner(name, &target, 0)
        .unwrap());
    assert!(!directory
        .remove_symbolic_link_with_owner(name, &target, 0)
        .unwrap());
    assert_eq!(fs::read(&target).unwrap(), b"untouched target");
    let target_after = target.metadata().unwrap();
    assert_eq!(
        (
            target_before.uid(),
            target_before.mode(),
            target_before.ino()
        ),
        (target_after.uid(), target_after.mode(), target_after.ino())
    );
    symlink(&target, selected.join(name)).unwrap();
    let displaced = root.path().join("displaced");
    fs::rename(&selected, &displaced).unwrap();
    fs::create_dir(&selected).unwrap();
    assert!(directory.read_symbolic_link_with_owner(name, 0).is_err());
    assert!(directory
        .remove_symbolic_link_with_owner(name, &target, 0)
        .is_err());
    assert_eq!(fs::read_link(displaced.join(name)).unwrap(), target);
}

#[test]
fn held_metadata_distinguishes_unowned_entry_types_without_opening_contents() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(root.path(), owner).unwrap();
    let name = OsStr::new("entry");
    let path = root.path().join(name);
    assert!(directory.metadata(name).unwrap().is_none());
    fs::write(&path, b"unrelated bytes").unwrap();
    let metadata = directory
        .metadata(name)
        .unwrap()
        .expect("existing regular file metadata");
    assert!(metadata.is_file());
    assert_eq!(metadata.len(), 15);
    assert_eq!(metadata.uid(), owner);
    fs::remove_file(&path).unwrap();
    symlink(root.path().join("missing target"), &path).unwrap();
    assert!(directory
        .metadata(name)
        .unwrap()
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(&path).unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap();
    let metadata = directory.metadata(name).unwrap().unwrap();
    assert!(!metadata.is_file() && !metadata.is_dir() && !metadata.file_type().is_symlink());
    assert!(directory.metadata(OsStr::new("../entry")).is_err());
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(directory.metadata(name).unwrap().unwrap().is_dir());
    let moved = root.path().with_extension("moved");
    fs::rename(root.path(), &moved).unwrap();
    fs::create_dir(root.path()).unwrap();
    assert!(directory.metadata(name).is_err());
    fs::rename(moved.join(name), root.path().join(name)).unwrap();
    fs::remove_dir(moved).unwrap();
}

#[test]
fn held_symbolic_link_retirement_preserves_targets_and_rejects_parent_redirection() {
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("selected");
    fs::create_dir(&selected).unwrap();
    let owner = fs::metadata(&selected).unwrap().uid();
    let directory = ExistingDocumentDirectory::open(&selected, owner).unwrap();
    let target = root.path().join("unchanged target");
    fs::write(&target, b"unrelated target bytes").unwrap();
    let name = OsStr::new("launcher");
    symlink(&target, selected.join(name)).unwrap();
    assert_eq!(
        directory.read_symbolic_link(name).unwrap(),
        Some(target.clone())
    );
    assert!(directory
        .remove_symbolic_link(name, &root.path().join("wrong target"))
        .is_err());
    assert_eq!(fs::read_link(selected.join(name)).unwrap(), target);
    assert!(directory.remove_symbolic_link(name, &target).unwrap());
    assert!(!directory.remove_symbolic_link(name, &target).unwrap());
    assert!(directory.read_symbolic_link(name).unwrap().is_none());
    assert_eq!(fs::read(&target).unwrap(), b"unrelated target bytes");
    symlink(&target, selected.join(name)).unwrap();
    let retired = root.path().join("retired");
    fs::rename(&selected, &retired).unwrap();
    fs::create_dir(&selected).unwrap();
    symlink(&target, selected.join(name)).unwrap();
    assert!(directory.read_symbolic_link(name).is_err());
    assert!(directory.remove_symbolic_link(name, &target).is_err());
    assert_eq!(fs::read_link(selected.join(name)).unwrap(), target);
    assert_eq!(fs::read_link(retired.join(name)).unwrap(), target);
    assert_eq!(fs::read(&target).unwrap(), b"unrelated target bytes");
}

#[test]
fn held_symbolic_links_require_raw_targets_and_reject_other_object_types() {
    use std::os::unix::ffi::OsStringExt;
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(root.path(), owner).unwrap();
    let name = OsStr::new("launcher");
    let path = root.path().join(name);
    let raw = std::path::PathBuf::from(std::ffi::OsString::from_vec(
        b"../raw//target-\xff".to_vec(),
    ));
    let normalized =
        std::path::PathBuf::from(std::ffi::OsString::from_vec(b"../raw/target-\xff".to_vec()));
    symlink(&raw, &path).unwrap();
    assert_eq!(
        directory
            .read_symbolic_link(name)
            .unwrap()
            .unwrap()
            .as_os_str(),
        raw.as_os_str()
    );
    assert!(directory.remove_symbolic_link(name, &normalized).is_err());
    assert!(directory.remove_symbolic_link(name, &raw).unwrap());
    for kind in ["file", "directory", "fifo", "hardlinked-symlink"] {
        let other = root.path().join("second-link");
        match kind {
            "file" => fs::write(&path, b"unowned document").unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            "fifo" => rustix::fs::mkfifoat(
                rustix::fs::CWD,
                &path,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .unwrap(),
            "hardlinked-symlink" => {
                symlink(&raw, &path).unwrap();
                fs::hard_link(&path, &other).unwrap();
                assert_eq!(fs::symlink_metadata(&path).unwrap().nlink(), 2);
            }
            _ => unreachable!(),
        }
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        assert!(directory.read_symbolic_link(name).is_err(), "{kind}");
        assert!(
            directory.remove_symbolic_link(name, &raw).is_err(),
            "{kind}"
        );
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
        if kind == "directory" {
            fs::remove_dir(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        if kind == "hardlinked-symlink" {
            fs::remove_file(other).unwrap();
        }
    }
    for name in [
        "",
        ".",
        "..",
        "../outside",
        "/absolute",
        "nested/link",
        "trailing/",
    ] {
        assert!(directory.read_symbolic_link(OsStr::new(name)).is_err());
        assert!(directory
            .remove_symbolic_link(OsStr::new(name), &raw)
            .is_err());
    }
    assert!(directory
        .remove_symbolic_link(name, std::path::Path::new(""))
        .is_err());
    assert!(directory
        .remove_symbolic_link(name, std::path::Path::new(&"x".repeat(4097)))
        .is_err());
    assert!(directory
        .remove_symbolic_link(name, std::path::Path::new("with\0nul"))
        .is_err());
}

#[test]
fn a_selected_directory_cannot_redirect_publication_after_replacement() {
    let root = tempfile::tempdir().unwrap();
    let selected = root.path().join("selected");
    fs::create_dir(&selected).unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
    let owner = fs::metadata(&selected).unwrap().uid();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 1024,
    };
    let directory = ExistingDocumentDirectory::open(&selected, owner).unwrap();
    let retired = root.path().join("retired");
    fs::rename(&selected, &retired).unwrap();
    fs::create_dir(&selected).unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(directory
        .write(
            OsStr::new("policy"),
            b"approved public bytes",
            &authority,
            None
        )
        .is_err());
    assert!(!selected.join("policy").exists());
    assert!(!retired.join("policy").exists());
    assert!(directory.read(OsStr::new("policy"), &authority).is_err());
    assert!(directory
        .remove(
            OsStr::new("policy"),
            &authority,
            &ArtifactIdentity {
                length: 1,
                sha256: "a".repeat(64)
            }
        )
        .is_err());
}

#[test]
fn held_publication_replacement_and_removal_require_exact_bounded_authority() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(root.path(), owner).unwrap();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 64,
    };
    let name = OsStr::new("policy with spaces.json");
    assert!(directory.write(name, b"prior", &authority, None).unwrap());
    let prior = directory.read(name, &authority).unwrap().unwrap();
    assert_eq!(prior.bytes, b"prior");
    let inode = fs::metadata(root.path().join(name)).unwrap().ino();
    assert!(!directory.write(name, b"prior", &authority, None).unwrap());
    assert_eq!(fs::metadata(root.path().join(name)).unwrap().ino(), inode);
    assert!(directory
        .write(name, b"candidate", &authority, None)
        .is_err());
    assert_eq!(directory.read(name, &authority).unwrap().unwrap(), prior);
    assert!(directory
        .write(name, b"candidate", &authority, Some(&prior.identity))
        .unwrap());
    let candidate = directory.read(name, &authority).unwrap().unwrap();
    assert_eq!(candidate.bytes, b"candidate");
    assert!(directory.remove(name, &authority, &prior.identity).is_err());
    assert_eq!(
        directory.read(name, &authority).unwrap().unwrap(),
        candidate
    );
    assert!(directory
        .remove(name, &authority, &candidate.identity)
        .unwrap());
    assert!(!directory
        .remove(name, &authority, &candidate.identity)
        .unwrap());
    assert!(directory.read(name, &authority).unwrap().is_none());
    assert!(directory
        .write(name, b"candidate", &authority, Some(&candidate.identity))
        .is_err());
    assert!(fs::read_dir(root.path()).unwrap().next().is_none());
}

#[test]
fn held_operations_reject_unsafe_files_and_names_without_removing_them() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(root.path(), owner).unwrap();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 64,
    };
    let target = root.path().join("target");
    let name = OsStr::new("policy");
    let path = root.path().join(name);
    fs::write(&target, b"unrelated").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let expected = ArtifactIdentity {
        length: 9,
        sha256: "a".repeat(64),
    };
    for name in [
        "",
        ".",
        "..",
        "../outside",
        "/absolute",
        "nested/policy",
        "trailing/",
    ] {
        let name = OsStr::new(name);
        assert!(directory.read(name, &authority).is_err());
        assert!(directory
            .write(name, b"candidate", &authority, None)
            .is_err());
        assert!(directory.remove(name, &authority, &expected).is_err());
    }
    for kind in [
        "symlink",
        "hardlink",
        "directory",
        "fifo",
        "mode",
        "special",
        "empty",
        "bound",
    ] {
        match kind {
            "symlink" => symlink(&target, &path).unwrap(),
            "hardlink" => fs::hard_link(&target, &path).unwrap(),
            "directory" => fs::create_dir(&path).unwrap(),
            "fifo" => rustix::fs::mkfifoat(
                rustix::fs::CWD,
                &path,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .unwrap(),
            _ => {
                fs::write(
                    &path,
                    match kind {
                        "empty" => Vec::new(),
                        "bound" => vec![b'x'; 65],
                        _ => b"unrelated".to_vec(),
                    },
                )
                .unwrap();
                fs::set_permissions(
                    &path,
                    fs::Permissions::from_mode(match kind {
                        "mode" => 0o644,
                        "special" => 0o4600,
                        _ => 0o600,
                    }),
                )
                .unwrap();
            }
        }
        let inode = fs::symlink_metadata(&path).unwrap().ino();
        assert!(directory.read(name, &authority).is_err(), "{kind}");
        assert!(
            directory
                .write(name, b"candidate", &authority, None)
                .is_err(),
            "{kind}"
        );
        assert!(
            directory.remove(name, &authority, &expected).is_err(),
            "{kind}"
        );
        assert_eq!(fs::symlink_metadata(&path).unwrap().ino(), inode);
        if kind == "directory" {
            fs::remove_dir(&path).unwrap();
        } else {
            fs::remove_file(&path).unwrap();
        }
        assert_eq!(fs::read(&target).unwrap(), b"unrelated");
    }
    assert!(directory.write(name, b"", &authority, None).is_err());
    assert!(directory
        .write(name, &[b'x'; 65], &authority, None)
        .is_err());
    for invalid in [
        DocumentAuthority {
            mode: 0o666,
            ..authority.clone()
        },
        DocumentAuthority {
            mode: 0o4600,
            ..authority.clone()
        },
        DocumentAuthority {
            limit: 0,
            ..authority.clone()
        },
    ] {
        assert!(directory.write(name, b"candidate", &invalid, None).is_err());
    }
}

#[test]
fn directory_custody_and_absence_are_not_implicitly_repaired() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let authority = DocumentAuthority {
        owner_uid: owner,
        mode: 0o600,
        limit: 64,
    };
    assert!(ExistingDocumentDirectory::open(&root.path().join("absent/child"), owner).is_err());
    assert!(!root.path().join("absent").exists());
    assert!(ExistingDocumentDirectory::open(root.path(), owner + 1).is_err());
    let alias = root.path().join("alias");
    symlink(root.path(), &alias).unwrap();
    assert!(ExistingDocumentDirectory::open(&alias, owner).is_err());
    let directory = ExistingDocumentDirectory::open(root.path(), owner).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
    assert!(directory
        .write(OsStr::new("policy"), b"candidate", &authority, None)
        .is_err());
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(directory
        .write(OsStr::new("policy"), b"candidate", &authority, None)
        .unwrap());
    let wrong_owner = DocumentAuthority {
        owner_uid: owner + 1,
        ..authority
    };
    assert!(directory.read(OsStr::new("policy"), &wrong_owner).is_err());
}

#[test]
fn exact_replacement_can_restore_prior_permissions_without_changing_owner() {
    let root = tempfile::tempdir().unwrap();
    let owner = root.path().metadata().unwrap().uid();
    let directory = ExistingDocumentDirectory::open(root.path(), owner).unwrap();
    let public = DocumentAuthority {
        owner_uid: owner,
        mode: 0o644,
        limit: 64,
    };
    let private = DocumentAuthority {
        mode: 0o600,
        ..public.clone()
    };
    let name = OsStr::new("receipt");
    directory.write(name, b"candidate", &public, None).unwrap();
    let candidate = directory.read(name, &public).unwrap().unwrap();
    assert!(directory
        .replace(name, b"prior", &private, &public, &candidate.identity)
        .unwrap());
    assert_eq!(
        fs::metadata(root.path().join(name)).unwrap().mode() & 0o7777,
        0o600
    );
    let prior = directory.read(name, &private).unwrap().unwrap();
    assert_eq!(prior.bytes, b"prior");
    assert!(!directory
        .replace(name, b"prior", &private, &private, &prior.identity)
        .unwrap());
    assert!(directory
        .replace(name, b"prior", &public, &private, &prior.identity)
        .unwrap());
    assert_eq!(
        fs::metadata(root.path().join(name)).unwrap().mode() & 0o7777,
        0o644
    );
    assert!(directory
        .replace(name, b"different", &public, &private, &prior.identity)
        .is_err());
    assert_eq!(
        directory.read(name, &public).unwrap().unwrap().bytes,
        b"prior"
    );
}
