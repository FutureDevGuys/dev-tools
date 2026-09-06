#![cfg(target_os = "linux")]

use dev_tools_installation::StagingArea;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;

#[test]
fn reserved_document_publication_rejects_unexpected_targets_and_bounds() {
    use dev_tools_installation::ArtifactIdentity;
    use std::os::unix::fs::{symlink, PermissionsExt};
    for case in [
        "unapproved-existing",
        "missing",
        "linked",
        "symlink",
        "public",
        "directory",
        "zero-limit",
        "large-limit",
        "small-limit",
        "digest",
    ] {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let area = StagingArea::new(
            temp.path().join("stage"),
            temp.path().metadata().unwrap().uid(),
            [8; 32],
        )
        .unwrap();
        area.initialize().unwrap();
        let destination = temp.path().join("document");
        fs::write(&destination, b"existing").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600)).unwrap();
        let expected_current = ArtifactIdentity::from_file(&destination, 1024).unwrap();
        let mut live = area.try_acquire().unwrap().unwrap();
        live.file_mut().write_all(b"replacement").unwrap();
        let mut expected_payload = ArtifactIdentity::from_file(live.path(), 1024).unwrap();
        let mut limit = 1024;
        match case {
            "missing" => fs::remove_file(&destination).unwrap(),
            "linked" => fs::hard_link(&destination, temp.path().join("other-link")).unwrap(),
            "symlink" => {
                fs::rename(&destination, temp.path().join("other")).unwrap();
                symlink(temp.path().join("other"), &destination).unwrap();
            }
            "public" => {
                fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).unwrap()
            }
            "directory" => {
                fs::remove_file(&destination).unwrap();
                fs::create_dir(&destination).unwrap();
            }
            "zero-limit" => limit = 0,
            "large-limit" => limit = 256 * 1024 * 1024 + 1,
            "small-limit" => limit = 3,
            "digest" => expected_payload.sha256 = "0".repeat(64),
            "unapproved-existing" => {}
            _ => unreachable!(),
        }
        let expected = (case != "unapproved-existing").then_some(&expected_current);
        assert!(
            live.publish_private_document(&destination, &expected_payload, expected, limit)
                .is_err(),
            "{case}"
        );
        assert_eq!(
            fs::read(temp.path().join("stage/payload")).unwrap(),
            b"replacement",
            "{case}"
        );
        if !matches!(case, "missing" | "directory") {
            assert_eq!(fs::read(&destination).unwrap(), b"existing", "{case}");
        }
    }
}

#[test]
fn reserved_document_publication_preserves_expected_identity_and_noop() {
    use dev_tools_installation::ArtifactIdentity;
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let area = StagingArea::new(
        temp.path().join("stage"),
        temp.path().metadata().unwrap().uid(),
        [8; 32],
    )
    .unwrap();
    area.initialize().unwrap();
    let destination = temp.path().join("document");
    let mut first = area.try_acquire().unwrap().unwrap();
    first.file_mut().write_all(b"first document").unwrap();
    let first_identity = ArtifactIdentity::from_file(first.path(), 1024).unwrap();
    let first_inode = first.file_mut().metadata().unwrap().ino();
    assert!(first
        .publish_private_document(&destination, &first_identity, None, 1024)
        .unwrap());
    assert_eq!(destination.metadata().unwrap().ino(), first_inode);
    assert!(!temp.path().join("stage/payload").exists());

    let mut next = area.try_acquire().unwrap().unwrap();
    next.file_mut().write_all(b"second document").unwrap();
    let second_identity = ArtifactIdentity::from_file(next.path(), 1024).unwrap();
    assert!(next
        .publish_private_document(&destination, &second_identity, Some(&first_identity), 1024)
        .unwrap());
    let second_inode = destination.metadata().unwrap().ino();
    assert_eq!(fs::read(&destination).unwrap(), b"second document");
    assert_eq!(destination.metadata().unwrap().mode() & 0o7777, 0o600);
    assert_eq!(destination.metadata().unwrap().nlink(), 1);

    let mut same = area.try_acquire().unwrap().unwrap();
    same.file_mut().write_all(b"second document").unwrap();
    assert!(!same
        .publish_private_document(&destination, &second_identity, Some(&first_identity), 1024)
        .unwrap());
    assert_eq!(destination.metadata().unwrap().ino(), second_inode);
    assert!(!temp.path().join("stage/payload").exists());

    let mut stale = area.try_acquire().unwrap().unwrap();
    stale.file_mut().write_all(b"third document").unwrap();
    let third_identity = ArtifactIdentity::from_file(stale.path(), 1024).unwrap();
    assert!(stale
        .publish_private_document(&destination, &third_identity, Some(&first_identity), 1024)
        .is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"second document");
    assert_eq!(
        fs::read(temp.path().join("stage/payload")).unwrap(),
        b"third document"
    );
    area.try_acquire().unwrap().unwrap().cleanup().unwrap();
}

#[test]
fn staging_publication_moves_verified_private_payload_and_preserves_collisions() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let area = StagingArea::new(
        temp.path().join("stage"),
        temp.path().metadata().unwrap().uid(),
        [7; 32],
    )
    .unwrap();
    area.initialize().unwrap();
    let destination = temp.path().join("published");
    let mut live = area.try_acquire().unwrap().unwrap();
    live.file_mut().write_all(b"approved inert bytes").unwrap();
    let identity = dev_tools_installation::ArtifactIdentity::from_file(live.path(), 1024).unwrap();
    let inode = live.file_mut().metadata().unwrap().ino();
    live.publish_private_noclobber(&destination, &identity)
        .unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"approved inert bytes");
    assert_eq!(destination.metadata().unwrap().ino(), inode);
    assert_eq!(destination.metadata().unwrap().nlink(), 1);
    assert_eq!(destination.metadata().unwrap().mode() & 0o7777, 0o600);
    assert!(!temp.path().join("stage/payload").exists());
    let mut next = area.try_acquire().unwrap().unwrap();
    next.file_mut().write_all(b"approved inert bytes").unwrap();
    assert!(next
        .publish_private_noclobber(&destination, &identity)
        .is_err());
    assert_eq!(destination.metadata().unwrap().ino(), inode);
    assert_eq!(
        fs::read(temp.path().join("stage/payload")).unwrap(),
        b"approved inert bytes"
    );
    area.try_acquire().unwrap().unwrap().cleanup().unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"approved inert bytes");
}

#[test]
fn staging_publication_rejects_content_custody_and_destination_drift() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for case in [
        "digest",
        "linked",
        "replaced",
        "public-parent",
        "symlink-parent",
        "internal",
        "relative",
    ] {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let area = StagingArea::new(
            temp.path().join("stage"),
            temp.path().metadata().unwrap().uid(),
            [7; 32],
        )
        .unwrap();
        area.initialize().unwrap();
        let mut live = area.try_acquire().unwrap().unwrap();
        live.file_mut().write_all(b"approved inert bytes").unwrap();
        let mut identity =
            dev_tools_installation::ArtifactIdentity::from_file(live.path(), 1024).unwrap();
        let mut destination = temp.path().join("published");
        match case {
            "digest" => identity.sha256 = "0".repeat(64),
            "linked" => fs::hard_link(live.path(), temp.path().join("other-link")).unwrap(),
            "replaced" => {
                fs::rename(live.path(), temp.path().join("original")).unwrap();
                fs::write(live.path(), b"approved inert bytes").unwrap();
                fs::set_permissions(live.path(), fs::Permissions::from_mode(0o600)).unwrap();
            }
            "public-parent" => {
                fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap()
            }
            "symlink-parent" => {
                symlink(temp.path(), temp.path().join("link")).unwrap();
                destination = temp.path().join("link/published");
            }
            "internal" => destination = temp.path().join("stage/published"),
            "relative" => destination = "relative-publication".into(),
            _ => unreachable!(),
        }
        assert!(
            live.publish_private_noclobber(&destination, &identity)
                .is_err(),
            "{case}"
        );
        assert!(temp.path().join("stage/payload").exists(), "{case}");
        assert!(!temp.path().join("published").exists(), "{case}");
        assert!(!temp.path().join("stage/published").exists(), "{case}");
    }
}

#[test]
fn staging_reservation_excludes_live_work_and_recovers_only_its_payload() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stage");
    let area =
        StagingArea::new(root.clone(), temp.path().metadata().unwrap().uid(), [7; 32]).unwrap();
    assert!(!root.exists());
    assert!(
        area.try_acquire().is_err(),
        "missing reservation is not first-use approval"
    );
    area.initialize().unwrap();
    assert!(
        area.initialize().is_err(),
        "existing reservation cannot be reinitialized"
    );
    let mut live = area.try_acquire().unwrap().unwrap();
    live.file_mut()
        .write_all(b"partial unverified bytes")
        .unwrap();
    let payload = live.path().to_path_buf();
    assert!(area.try_acquire().unwrap().is_none());
    assert_eq!(fs::read(&payload).unwrap(), b"partial unverified bytes");
    drop(live);
    let recovered = area.try_acquire().unwrap().unwrap();
    assert_eq!(recovered.path(), payload);
    assert_eq!(fs::metadata(&payload).unwrap().len(), 0);
    assert_eq!(fs::metadata(&payload).unwrap().mode() & 0o777, 0o600);
    recovered.cleanup().unwrap();
    assert!(!payload.exists());
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        2,
        "reservation and stable lock remain"
    );
}

#[test]
fn staging_unknown_entries_are_rejected_before_any_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stage");
    let area =
        StagingArea::new(root.clone(), temp.path().metadata().unwrap().uid(), [7; 32]).unwrap();
    area.initialize().unwrap();
    fs::write(root.join("unowned"), b"leave untouched").unwrap();
    assert!(area.try_acquire().is_err());
    assert_eq!(fs::read(root.join("unowned")).unwrap(), b"leave untouched");
    assert_eq!(
        fs::read_dir(&root).unwrap().count(),
        2,
        "rejection must not create a lock or payload"
    );
}

#[test]
fn staging_wrong_target_unmarked_roots_and_linked_payloads_are_never_adopted() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    assert!(StagingArea::new("relative".into(), owner, [7; 32]).is_err());
    let root = temp.path().join("stage");
    let area = StagingArea::new(root.clone(), owner, [7; 32]).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(area.initialize().is_err());
    assert!(area.try_acquire().is_err());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
    fs::remove_dir(&root).unwrap();
    area.initialize().unwrap();
    let other = StagingArea::new(root.clone(), owner, [8; 32]).unwrap();
    assert!(other.try_acquire().is_err());
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);

    let live = area.try_acquire().unwrap().unwrap();
    let payload = live.path().to_path_buf();
    drop(live);
    let external = temp.path().join("external");
    fs::write(&external, b"external bytes").unwrap();
    fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&payload).unwrap();
    symlink(&external, &payload).unwrap();
    assert!(area.try_acquire().is_err());
    assert!(fs::symlink_metadata(&payload).unwrap().is_symlink());
    fs::remove_file(&payload).unwrap();
    fs::hard_link(&external, &payload).unwrap();
    assert!(area.try_acquire().is_err());
    assert_eq!(fs::metadata(&external).unwrap().nlink(), 2);
    assert_eq!(fs::read(&external).unwrap(), b"external bytes");
}

#[test]
fn staging_cleanup_refuses_replaced_payload_and_modified_reservation() {
    let temp = tempfile::tempdir().unwrap();
    let area = StagingArea::new(
        temp.path().join("stage"),
        temp.path().metadata().unwrap().uid(),
        [7; 32],
    )
    .unwrap();
    area.initialize().unwrap();
    let live = area.try_acquire().unwrap().unwrap();
    let payload = live.path().to_path_buf();
    fs::rename(&payload, temp.path().join("original")).unwrap();
    fs::write(&payload, b"replacement").unwrap();
    assert!(live.cleanup().is_err());
    assert_eq!(fs::read(&payload).unwrap(), b"replacement");
    fs::remove_file(&payload).unwrap();
    let live = area.try_acquire().unwrap().unwrap();
    fs::write(temp.path().join("stage/staging-reservation-v1.json"), b"{}").unwrap();
    assert!(live.cleanup().is_err());
    assert!(payload.exists());
    assert!(area.try_acquire().is_err());
}

#[test]
fn staging_process_fixture() {
    use std::io::Read;
    let Some(root) = std::env::var_os("DEV_TOOLS_STAGING_TEST_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let area = StagingArea::new(root.clone(), root.metadata().unwrap().uid(), [7; 32]).unwrap();
    let mut live = area.try_acquire().unwrap().unwrap();
    live.file_mut().write_all(b"interrupted download").unwrap();
    live.file_mut().sync_all().unwrap();
    println!("STAGING_READY");
    std::io::stdout().flush().unwrap();
    let mut finish = [0];
    std::io::stdin().read_exact(&mut finish).unwrap();
    live.cleanup().unwrap();
}

#[test]
fn staging_process_death_releases_native_lease_without_destructor_cleanup() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("stage");
    let area =
        StagingArea::new(root.clone(), temp.path().metadata().unwrap().uid(), [7; 32]).unwrap();
    area.initialize().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "staging_process_fixture", "--nocapture"])
        .env("DEV_TOOLS_STAGING_TEST_ROOT", &root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut output = BufReader::new(stdout);
        let mut line = String::new();
        while output.read_line(&mut line)? != 0 {
            if line.contains("STAGING_READY") {
                let _ = sender.send(());
                break;
            }
            line.clear();
        }
        Ok::<_, std::io::Error>(())
    });
    let ready = receiver.recv_timeout(std::time::Duration::from_secs(10));
    // Always terminalize the child before assertions can unwind this test.
    let busy = area.try_acquire();
    let before = fs::read(root.join("payload"));
    let killed = child.kill();
    let terminal = child.wait();
    let reader_result = reader.join();
    ready.unwrap();
    reader_result.unwrap().unwrap();
    killed.unwrap();
    assert!(!terminal.unwrap().success());
    assert!(busy.unwrap().is_none());
    assert_eq!(before.unwrap(), b"interrupted download");
    let recovered = area.try_acquire().unwrap().unwrap();
    assert_eq!(fs::read(recovered.path()).unwrap(), b"");
    recovered.cleanup().unwrap();
}
