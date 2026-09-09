#![cfg(target_os = "linux")]

use dev_tools_command::{HeldComponentKind, HeldExecutable};
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn additional_validation_observes_retained_identity_after_source_replacement() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("program");
    std::fs::write(&source, b"#!/bin/sh\nprintf original").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    let original = std::fs::metadata(&source).unwrap();
    let mut directories = 0;
    let mut executables = 0;
    let held = HeldExecutable::open_with_validation(&source, |descriptor, kind| {
        let metadata = rustix::fs::fstat(descriptor)?;
        match kind {
            HeldComponentKind::Directory => directories += 1,
            HeldComponentKind::Executable => {
                executables += 1;
                std::fs::rename(&source, root.path().join("original"))?;
                std::fs::write(&source, b"replacement")?;
                assert_eq!(metadata.st_ino, original.ino());
                assert_eq!(metadata.st_dev, original.dev());
            }
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(directories, source.components().count() - 1);
    assert_eq!(executables, 1);
    assert_eq!(
        rustix::fs::fstat(held.as_fd()).unwrap().st_ino,
        original.ino()
    );
    let output = held.command(source.as_os_str()).unwrap().output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"original");
}

#[test]
fn additional_validation_can_reject_but_cannot_admit_a_baseline_violation() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("program");
    std::fs::write(&source, b"#!/bin/sh\nexit 0").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(HeldExecutable::open_with_validation(&source, |_, kind| {
        if kind == HeldComponentKind::Executable {
            anyhow::bail!("product rejection");
        }
        Ok(())
    })
    .is_err());
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o777)).unwrap();
    let mut executable_seen = false;
    assert!(HeldExecutable::open_with_validation(&source, |_, kind| {
        executable_seen |= kind == HeldComponentKind::Executable;
        Ok(())
    })
    .is_err());
    assert!(!executable_seen);
}
