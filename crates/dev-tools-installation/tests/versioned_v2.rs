#![cfg(target_os = "linux")]

use dev_tools_installation::{
    apply_versioned_installation, read_versioned_installation_receipt,
    rollback_versioned_installation, uninstall_versioned_installation, versioned_v2,
    ArtifactIdentity, InstallationLock, VersionedInstallRequest, VersionedLayout,
};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

fn request(root: &Path, version: &str) -> VersionedInstallRequest {
    let source = root.join(format!("source-{version}"));
    fs::write(&source, version.as_bytes()).unwrap();
    VersionedInstallRequest {
        layout: VersionedLayout {
            product: "fixture".into(),
            data_root: root.join("data"),
            bin_dir: root.join("bin"),
            artifact_name: "fixture".into(),
            owner_uid: fs::metadata(root).unwrap().uid(),
            directory_mode: 0o700,
            bin_directory_mode: None,
        },
        version: version.into(),
        identity: ArtifactIdentity::from_file(&source, 1024).unwrap(),
        source,
        aliases: vec!["fixture".into()],
    }
}

fn assert_old_mutators_blocked(request: &VersionedInstallRequest) {
    let layout = &request.layout;
    assert!(read_versioned_installation_receipt(layout).is_err());
    assert!(apply_versioned_installation(request, |_| panic!("v1 must not reach health")).is_err());
    assert!(
        rollback_versioned_installation(layout, |_| panic!("v1 must not reach health")).is_err()
    );
    assert!(uninstall_versioned_installation(layout).is_err());
}

#[test]
fn initialized_empty_namespace_excludes_old_first_install_and_supports_new_lifecycle() {
    let root = tempfile::tempdir().unwrap();
    let first = request(root.path(), "1.0.0");
    let layout = &first.layout;
    assert_eq!(
        versioned_v2::initialize(layout, 1024, |prior| {
            assert!(prior.is_none());
            assert!(
                InstallationLock::try_acquire(&layout.data_root.join("installation.lock"))?
                    .is_none()
            );
            Ok(())
        })
        .unwrap(),
        (true, None)
    );
    assert_eq!(versioned_v2::observe(layout, 1024).unwrap(), None);
    assert_old_mutators_blocked(&first);
    assert!(!layout.data_root.join("active").exists());
    let one = versioned_v2::apply_if_unchanged(&first, None, |_| Ok(())).unwrap();
    assert!(one.changed);
    assert!(
        !versioned_v2::apply_if_unchanged(&first, Some(&one.receipt), |_| Ok(()))
            .unwrap()
            .changed
    );
    assert_old_mutators_blocked(&first);
    let second = request(root.path(), "2.0.0");
    assert!(
        versioned_v2::apply_if_unchanged(&second, None, |_| panic!("stale precondition")).is_err()
    );
    assert!(!layout.data_root.join("versions/2.0.0").exists());
    let two = versioned_v2::apply_if_unchanged(&second, Some(&one.receipt), |_| Ok(())).unwrap();
    let rollback = versioned_v2::rollback_if_unchanged(layout, &two.receipt, |candidate| {
        assert_eq!(fs::read(candidate)?, b"1.0.0");
        Ok(())
    })
    .unwrap();
    assert_eq!(rollback.receipt.active_version, "1.0.0");
    assert_eq!(rollback.receipt.previous_version.as_deref(), Some("2.0.0"));
    assert_eq!(
        versioned_v2::observe(layout, 1024).unwrap(),
        Some(rollback.receipt.clone())
    );
    assert_eq!(
        versioned_v2::initialize(layout, 1024, |_| panic!("already initialized")).unwrap(),
        (false, Some(rollback.receipt))
    );
}

#[test]
fn upgrade_preserves_v1_active_and_retained_ownership() {
    let root = tempfile::tempdir().unwrap();
    let first = request(root.path(), "1.0.0");
    apply_versioned_installation(&first, |_| Ok(())).unwrap();
    let second = request(root.path(), "2.0.0");
    let expected = apply_versioned_installation(&second, |_| Ok(()))
        .unwrap()
        .receipt;
    let layout = &first.layout;
    let active = fs::read_link(layout.data_root.join("active")).unwrap();
    let previous = fs::read_link(layout.data_root.join("previous")).unwrap();
    let result = versioned_v2::initialize(layout, 1024, |prior| {
        assert_eq!(prior, Some(&expected));
        Ok(())
    })
    .unwrap();
    assert_eq!(result, (true, Some(expected.clone())));
    assert_old_mutators_blocked(&second);
    assert_eq!(
        fs::read_link(layout.data_root.join("active")).unwrap(),
        active
    );
    assert_eq!(
        fs::read_link(layout.data_root.join("previous")).unwrap(),
        previous
    );
    assert_eq!(versioned_v2::observe(layout, 1024).unwrap(), Some(expected));
}

#[test]
fn failed_product_cutover_stays_fenced_until_explicit_resume() {
    for installed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let request = request(root.path(), "1.0.0");
        let expected = installed.then(|| {
            apply_versioned_installation(&request, |_| Ok(()))
                .unwrap()
                .receipt
        });
        let layout = &request.layout;
        assert!(versioned_v2::initialize(layout, 1024, |_| anyhow::bail!(
            "product cutover interrupted"
        ))
        .is_err());
        let journal = layout.data_root.join("installation-transition-v1.json");
        let before = fs::read(&journal).unwrap();
        // An absent receipt is still absent, but the upgrade journal rejects
        // every v1 mutation before activation. With a receipt, its v1 read is
        // still allowed until the upgrade commits; it grants no write authority.
        assert!(apply_versioned_installation(&request, |_| panic!("fenced")).is_err());
        assert!(rollback_versioned_installation(layout, |_| panic!("fenced")).is_err());
        assert!(uninstall_versioned_installation(layout).is_err());
        assert!(versioned_v2::observe(layout, 1024).is_err());
        assert!(versioned_v2::recover(layout, 1024, |_| panic!(
            "upgrade is not ordinary recovery"
        ))
        .is_err());
        assert!(
            versioned_v2::apply_if_unchanged(&request, expected.as_ref(), |_| panic!("fenced"))
                .is_err()
        );
        assert_eq!(fs::read(&journal).unwrap(), before);
        assert_eq!(
            versioned_v2::initialize(layout, 1024, |prior| {
                assert_eq!(prior, expected.as_ref());
                Ok(())
            })
            .unwrap(),
            (true, expected.clone())
        );
        assert!(!journal.exists());
        assert_eq!(versioned_v2::observe(layout, 1024).unwrap(), expected);
        assert_old_mutators_blocked(&request);
    }
}

#[test]
fn upgrade_resume_after_receipt_commit_repeats_product_acknowledgement() {
    let root = tempfile::tempdir().unwrap();
    let request = request(root.path(), "1.0.0");
    let layout = &request.layout;
    versioned_v2::initialize(layout, 1024, |_| Ok(())).unwrap();
    let journal = layout.data_root.join("installation-transition-v1.json");
    write_json(
        &journal,
        serde_json::json!({
            "schema": "dev-tools-versioned-protocol-upgrade-v2", "layout": layout, "prior": null
        }),
    );
    let called = std::cell::Cell::new(false);
    assert_eq!(
        versioned_v2::initialize(layout, 1024, |_| {
            called.set(true);
            Ok(())
        })
        .unwrap(),
        (true, None)
    );
    assert!(called.get());
    assert!(!journal.exists());
    assert_old_mutators_blocked(&request);
}

#[test]
fn observation_and_failed_admission_do_not_initialize_or_replace_authority() {
    let root = tempfile::tempdir().unwrap();
    let request = request(root.path(), "1.0.0");
    let layout = &request.layout;
    assert!(versioned_v2::observe(layout, 1024).is_err());
    assert!(!layout.data_root.exists());
    assert!(versioned_v2::initialize(layout, 0, |_| panic!("invalid bound")).is_err());
    assert!(!layout.data_root.exists());
    apply_versioned_installation(&request, |_| Ok(())).unwrap();
    let receipt = layout.data_root.join("installation-receipt-v1.json");
    let before = fs::read(&receipt).unwrap();
    assert!(versioned_v2::initialize(layout, 1, |_| panic!("over-bound receipt")).is_err());
    assert_eq!(fs::read(&receipt).unwrap(), before);
    assert!(!layout
        .data_root
        .join("installation-transition-v1.json")
        .exists());
    let journal = layout.data_root.join("installation-transition-v1.json");
    fs::write(&journal, b"unknown owner data").unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(versioned_v2::initialize(layout, 1024, |_| panic!("unknown journal")).is_err());
    assert_eq!(fs::read(&journal).unwrap(), b"unknown owner data");
    assert_eq!(fs::read(&receipt).unwrap(), before);
}

#[test]
fn initialized_empty_retry_does_not_recreate_missing_directories_as_a_noop() {
    for missing_bin in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let request = request(root.path(), "1.0.0");
        let layout = &request.layout;
        versioned_v2::initialize(layout, 1024, |_| Ok(())).unwrap();
        let missing = if missing_bin {
            layout.bin_dir.clone()
        } else {
            layout.data_root.join("versions")
        };
        fs::remove_dir(&missing).unwrap();
        let retried = versioned_v2::initialize(layout, 1024, |_| panic!("already initialized"));
        assert!(
            !missing.exists(),
            "an initialized retry silently repaired a directory"
        );
        if missing_bin {
            assert!(retried.is_err());
        } else {
            assert_eq!(retried.unwrap(), (false, None));
        }
    }
}

fn write_json(path: &Path, value: serde_json::Value) {
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn normal_recovery_authenticates_both_receipts_and_retains_the_protocol_fence() {
    for (empty, committed) in [(true, false), (true, true), (false, false), (false, true)] {
        let root = tempfile::tempdir().unwrap();
        let first = request(root.path(), "1.0.0");
        let layout = &first.layout;
        versioned_v2::initialize(layout, 1024, |_| Ok(())).unwrap();
        let prior = if empty {
            None
        } else {
            Some(
                versioned_v2::apply_if_unchanged(&first, None, |_| Ok(()))
                    .unwrap()
                    .receipt,
            )
        };
        let receipt_path = layout.data_root.join("installation-receipt-v1.json");
        let prior_bytes = fs::read(&receipt_path).unwrap();
        let next_request = request(root.path(), "2.0.0");
        let next = versioned_v2::apply_if_unchanged(&next_request, prior.as_ref(), |_| Ok(()))
            .unwrap()
            .receipt;
        let journal = layout.data_root.join("installation-transition-v1.json");
        write_json(
            &journal,
            serde_json::json!({
                "schema": "dev-tools-versioned-protocol-transition-v2", "layout": layout,
                "transition": { "schema": "dev-tools-versioned-transition-v1", "prior": prior, "next": next }
            }),
        );
        if !committed {
            fs::write(&receipt_path, prior_bytes).unwrap();
        }
        let journal_before = fs::read(&journal).unwrap();
        assert!(versioned_v2::recover(layout, 1024, |_| anyhow::bail!("unauthenticated")).is_err());
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        let mut seen = Vec::new();
        let expected = if committed {
            Some(next.clone())
        } else {
            prior.clone()
        };
        assert_eq!(
            versioned_v2::recover(layout, 1024, |receipt| {
                seen.push(receipt.clone());
                Ok(())
            })
            .unwrap(),
            (true, expected.clone())
        );
        assert!(seen.contains(&next));
        if let Some(prior) = prior {
            assert!(seen.contains(&prior));
        }
        assert_eq!(
            versioned_v2::observe(layout, 1024).unwrap(),
            expected.clone()
        );
        assert_eq!(
            versioned_v2::recover(layout, 1024, |_| Ok(())).unwrap(),
            (false, expected)
        );
        assert_old_mutators_blocked(&next_request);
    }
}

#[test]
fn protocol_upgrade_process_fixture() {
    let Some(root) = std::env::var_os("INSTALLATION_V2_CRASH_FIXTURE") else {
        return;
    };
    let request = request(Path::new(&root), "1.0.0");
    versioned_v2::initialize(&request.layout, 1024, |_| {
        // Exit without unwinding or releasing the native lease through Drop.
        std::process::exit(73);
    })
    .unwrap();
    panic!("the process fixture must terminate inside product cutover");
}

#[test]
fn process_exit_during_product_cutover_retains_the_fence_and_can_resume() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let root = tempfile::tempdir().unwrap();
    let request = request(root.path(), "1.0.0");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env("INSTALLATION_V2_CRASH_FIXTURE", root.path())
        .current_dir(root.path())
        .args(["--exact", "protocol_upgrade_process_fixture", "--nocapture"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            outcome => {
                let _ = child.kill();
                let terminal = child.wait();
                panic!("protocol fixture did not terminate: {outcome:?}; {terminal:?}");
            }
        }
    };
    assert_eq!(status.code(), Some(73));
    assert!(
        apply_versioned_installation(&request, |_| panic!("fence lost after process exit"))
            .is_err()
    );
    assert!(versioned_v2::recover(&request.layout, 1024, |_| Ok(())).is_err());
    assert_eq!(
        versioned_v2::initialize(&request.layout, 1024, |_| Ok(())).unwrap(),
        (true, None)
    );
    assert_old_mutators_blocked(&request);
}
