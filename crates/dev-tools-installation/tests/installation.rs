#![cfg(unix)]

use dev_tools_installation::{
    adopt_versioned_installation, apply_versioned_installation, publish_executable,
    read_atomic_document, remove_owned_file, remove_owned_installation,
    rollback_versioned_installation, uninstall_versioned_installation, verify_owned_installation,
    verify_versioned_installation, write_atomic_document, ArtifactIdentity, DocumentAuthority,
    InstallationLock, InstallationReceipt, ReceiptArtifact, VersionedAdoption,
    VersionedInstallRequest, VersionedLayout,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

#[test]
fn apply_reports_recovery_even_when_requested_version_is_current() {
    assert_noop_reports_journal_recovery("apply");
}

#[test]
fn repair_reports_recovery_even_when_links_need_no_further_repair() {
    assert_noop_reports_journal_recovery("repair");
}

#[test]
fn adoption_reports_recovery_even_when_receipt_already_matches() {
    assert_noop_reports_journal_recovery("adopt");
}

fn assert_noop_reports_journal_recovery(operation: &str) {
    for committed in [true, false] {
        let temp = tempfile::tempdir().unwrap();
        let request = versioned_fixture(temp.path(), "1.0.0", b"first");
        let first = apply_versioned_installation(&request, |_| Ok(()))
            .unwrap()
            .receipt;
        let (prior, next) = if committed {
            (None, first.clone())
        } else {
            let second = versioned_fixture(temp.path(), "2.0.0", b"second");
            let next = apply_versioned_installation(&second, |_| Ok(()))
                .unwrap()
                .receipt;
            // A transition can publish pointers before its receipt. Reconstruct
            // that supported interruption using the exact two owned receipts.
            fs::write(
                request
                    .layout
                    .data_root
                    .join("installation-receipt-v1.json"),
                serde_json::to_vec(&first).unwrap(),
            )
            .unwrap();
            (Some(first.clone()), next)
        };
        let journal = request
            .layout
            .data_root
            .join("installation-transition-v1.json");
        fs::write(
            &journal,
            serde_json::to_vec(&serde_json::json!({
                "schema": "dev-tools-versioned-transition-v1", "prior": prior, "next": next,
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        let run = || match operation {
            "apply" => apply_versioned_installation(&request, |_| Ok(())),
            "repair" => {
                dev_tools_installation::repair_versioned_installation(&request.layout, |_| Ok(()))
            }
            "adopt" => adopt_versioned_installation(
                &VersionedAdoption {
                    layout: request.layout.clone(),
                    version: request.version.clone(),
                    identity: request.identity.clone(),
                    aliases: request.aliases.clone(),
                },
                |_| Ok(()),
            ),
            _ => unreachable!("unknown fixture operation"),
        };
        let report = run().unwrap();
        assert!(!journal.exists(), "fixture did not reach journal recovery");
        assert_eq!(report.receipt, first);
        assert!(
            report.changed,
            "{operation} hid recovery (committed={committed})"
        );
        assert!(
            !run().unwrap().changed,
            "repeat operation must be a clean no-op"
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
fn bounded_artifact_copy_checks_custody_identity_and_writer_completion() {
    use dev_tools_installation::copy_verified_artifact_to_staging;
    use std::io::Write;
    struct Sink {
        bytes: Vec<u8>,
        flushed: bool,
        fail_flush: bool,
    }
    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(bytes.len() <= 64 * 1024, "artifact copy must stream");
            let written = bytes.len().min(997);
            self.bytes.extend_from_slice(&bytes[..written]);
            Ok(written)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushed = true;
            if self.fail_flush {
                Err(std::io::Error::other("fixture"))
            } else {
                Ok(())
            }
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("artifact");
    let bytes = vec![42; 131_073];
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let identity = ArtifactIdentity::from_file(&path, bytes.len() as u64).unwrap();
    let authority = DocumentAuthority {
        owner_uid: temp.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: bytes.len() as u64,
    };
    let mut sink = Sink {
        bytes: Vec::new(),
        flushed: false,
        fail_flush: false,
    };
    copy_verified_artifact_to_staging(&path, &authority, &identity, &mut sink).unwrap();
    assert_eq!(sink.bytes, bytes);
    assert!(sink.flushed);
    sink.fail_flush = true;
    assert!(copy_verified_artifact_to_staging(&path, &authority, &identity, &mut sink).is_err());
    fs::write(&path, vec![43; bytes.len()]).unwrap();
    assert!(
        copy_verified_artifact_to_staging(&path, &authority, &identity, &mut Vec::new()).is_err()
    );
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let mut rejected = Vec::new();
    assert!(
        copy_verified_artifact_to_staging(&path, &authority, &identity, &mut rejected).is_err()
    );
    assert!(rejected.is_empty());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = temp.path().join("linked");
    fs::hard_link(&path, &link).unwrap();
    assert!(
        copy_verified_artifact_to_staging(&path, &authority, &identity, &mut rejected).is_err()
    );
    fs::remove_file(&link).unwrap();
    symlink(&path, &link).unwrap();
    assert!(
        copy_verified_artifact_to_staging(&link, &authority, &identity, &mut rejected).is_err()
    );
    let small = DocumentAuthority {
        limit: identity.length - 1,
        ..authority
    };
    assert!(copy_verified_artifact_to_staging(&path, &small, &identity, &mut rejected).is_err());
    assert!(rejected.is_empty());
}

#[test]
#[cfg(target_os = "linux")]
fn bounded_artifact_copy_never_transfers_growth_beyond_approved_length() {
    use dev_tools_installation::copy_verified_artifact_to_staging;
    use std::io::Write;
    struct GrowingSink {
        source: std::path::PathBuf,
        copied: usize,
    }
    impl Write for GrowingSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.copied == 0 {
                fs::OpenOptions::new()
                    .append(true)
                    .open(&self.source)?
                    .write_all(b"growth")?;
            }
            self.copied += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("artifact");
    fs::write(&path, vec![42; 131_073]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let expected = ArtifactIdentity::from_file(&path, 131_073).unwrap();
    let authority = DocumentAuthority {
        owner_uid: temp.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: expected.length,
    };
    let mut sink = GrowingSink {
        source: path.clone(),
        copied: 0,
    };
    assert!(copy_verified_artifact_to_staging(&path, &authority, &expected, &mut sink).is_err());
    assert_eq!(sink.copied as u64, expected.length);
}

#[test]
#[cfg(target_os = "linux")]
fn exact_recovery_binds_both_receipts_and_transition_direction() {
    use dev_tools_installation::{
        observe_versioned_installation_transition, recover_versioned_installation_transition,
    };
    for committed in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let first = versioned_fixture(temp.path(), "1.0.0", b"first");
        let prior = apply_versioned_installation(&first, |_| Ok(()))
            .unwrap()
            .receipt;
        let second = versioned_fixture(temp.path(), "2.0.0", b"second");
        let next = apply_versioned_installation(&second, |_| Ok(()))
            .unwrap()
            .receipt;
        let receipt_path = first.layout.data_root.join("installation-receipt-v1.json");
        if !committed {
            fs::write(&receipt_path, serde_json::to_vec(&prior).unwrap()).unwrap();
        }
        let journal = first
            .layout
            .data_root
            .join("installation-transition-v1.json");
        let pending = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1", "prior": prior, "next": next,
        }))
        .unwrap();
        fs::write(&journal, &pending).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        let before = fs::read(&receipt_path).unwrap();
        let active = first.layout.data_root.join("active");
        let before_active = fs::read_link(&active).unwrap();
        let observed = observe_versioned_installation_transition(
            &first.layout,
            Some(&prior),
            &next,
            1024,
            |_| Ok(()),
        )
        .unwrap();
        assert!(observed.journal_pending);
        assert_eq!(
            observed.receipt.as_ref(),
            Some(if committed { &next } else { &prior })
        );
        assert_eq!(fs::read(&journal).unwrap(), pending);
        assert_eq!(fs::read(&receipt_path).unwrap(), before);
        assert_eq!(fs::read_link(&active).unwrap(), before_active);
        for (expected_prior, expected_next) in [(None, &next), (Some(&next), &prior)] {
            let mut invoked = false;
            assert!(recover_versioned_installation_transition(
                &first.layout,
                expected_prior,
                expected_next,
                1024,
                |_| {
                    invoked = true;
                    Ok(())
                },
            )
            .is_err());
            assert!(
                !invoked,
                "mismatched journal must reject before verifier or mutation"
            );
            assert_eq!(fs::read(&journal).unwrap(), pending);
            assert_eq!(fs::read(&receipt_path).unwrap(), before);
            assert_eq!(fs::read_link(&active).unwrap(), before_active);
        }
        let expected = if committed { &next } else { &prior };
        let (changed, installed) = recover_versioned_installation_transition(
            &first.layout,
            Some(&prior),
            &next,
            1024,
            |_| Ok(()),
        )
        .unwrap();
        assert!(changed);
        assert_eq!(installed.as_ref(), Some(expected));
        assert!(!journal.exists());
        let (changed, installed) = recover_versioned_installation_transition(
            &first.layout,
            Some(&prior),
            &next,
            1024,
            |_| Ok(()),
        )
        .unwrap();
        assert!(!changed);
        assert_eq!(installed.as_ref(), Some(expected));
        let lock = first.layout.data_root.join("installation.lock");
        fs::remove_file(&lock).unwrap();
        assert!(observe_versioned_installation_transition(
            &first.layout,
            Some(&prior),
            &next,
            1024,
            |_| Ok(()),
        )
        .is_err());
        assert!(
            !lock.exists(),
            "read-only transition admission must not recreate the lock"
        );
    }
}

#[test]
#[cfg(target_os = "linux")]
fn authenticated_recovery_preserves_rejected_transition_and_restores_prior() {
    use dev_tools_installation::recover_versioned_installation_with_verification;
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    let prior = apply_versioned_installation(&first, |_| Ok(()))
        .unwrap()
        .receipt;
    let second = versioned_fixture(temp.path(), "2.0.0", b"second");
    let next = apply_versioned_installation(&second, |_| Ok(()))
        .unwrap()
        .receipt;
    let receipt_path = first.layout.data_root.join("installation-receipt-v1.json");
    let original = serde_json::to_vec(&prior).unwrap();
    fs::write(&receipt_path, &original).unwrap();
    let journal = first
        .layout
        .data_root
        .join("installation-transition-v1.json");
    let pending = serde_json::to_vec(&serde_json::json!({
        "schema": "dev-tools-versioned-transition-v1", "prior": prior, "next": next,
    }))
    .unwrap();
    fs::write(&journal, &pending).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    let active = first.layout.data_root.join("active");
    let before = fs::read_link(&active).unwrap();
    assert!(
        recover_versioned_installation_with_verification(&first.layout, 1024, |_| anyhow::bail!(
            "untrusted"
        ))
        .is_err(),
        "untrusted recovery must fail before restoration"
    );
    assert_eq!(fs::read(&journal).unwrap(), pending);
    assert_eq!(fs::read(&receipt_path).unwrap(), original);
    assert_eq!(fs::read_link(&active).unwrap(), before);
    let mut versions = Vec::new();
    let (changed, receipt) =
        recover_versioned_installation_with_verification(&first.layout, 1024, |receipt| {
            assert!(InstallationLock::try_acquire(
                &first.layout.data_root.join("installation.lock")
            )?
            .is_none());
            versions.push(receipt.active_version.clone());
            Ok(())
        })
        .unwrap();
    assert!(changed);
    assert_eq!(receipt, Some(prior.clone()));
    assert!(versions.contains(&"1.0.0".to_owned()));
    assert!(versions.contains(&"2.0.0".to_owned()));
    assert!(!journal.exists());
    assert_eq!(verify_versioned_installation(&first.layout).unwrap(), prior);
    let (changed, receipt) =
        recover_versioned_installation_with_verification(&first.layout, 1024, |_| Ok(())).unwrap();
    assert!(!changed);
    assert_eq!(receipt, Some(prior));
}

#[test]
#[cfg(target_os = "linux")]
fn authenticated_recovery_handles_committed_and_first_install_journals() {
    use dev_tools_installation::recover_versioned_installation_with_verification;
    for committed in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let request = versioned_fixture(temp.path(), "1.0.0", b"first");
        let next = apply_versioned_installation(&request, |_| Ok(()))
            .unwrap()
            .receipt;
        let receipt = request
            .layout
            .data_root
            .join("installation-receipt-v1.json");
        if !committed {
            fs::remove_file(&receipt).unwrap();
        }
        let journal = request
            .layout
            .data_root
            .join("installation-transition-v1.json");
        let pending = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1", "prior": null, "next": next,
        }))
        .unwrap();
        fs::write(&journal, &pending).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            recover_versioned_installation_with_verification(&request.layout, 4, |_| Ok(()))
                .is_err()
        );
        assert_eq!(fs::read(&journal).unwrap(), pending);
        let active = request.layout.data_root.join("active");
        let before = fs::read_link(&active).unwrap();
        assert!(recover_versioned_installation_with_verification(
            &request.layout,
            1024,
            |_| anyhow::bail!("untrusted")
        )
        .is_err());
        assert_eq!(fs::read_link(&active).unwrap(), before);
        assert_eq!(fs::read(&journal).unwrap(), pending);
        let (changed, recovered) =
            recover_versioned_installation_with_verification(&request.layout, 1024, |_| Ok(()))
                .unwrap();
        assert!(changed);
        assert_eq!(recovered, committed.then_some(next));
        assert!(!journal.exists());
        assert_eq!(fs::symlink_metadata(&active).is_ok(), committed);
        assert_eq!(
            fs::symlink_metadata(request.layout.bin_dir.join("fixture")).is_ok(),
            committed
        );
        let (changed, _) =
            recover_versioned_installation_with_verification(&request.layout, 1024, |_| Ok(()))
                .unwrap();
        assert!(!changed);
    }
}

#[test]
#[cfg(target_os = "linux")]
fn authenticated_recovery_rejects_tampered_bytes_before_link_restoration() {
    use dev_tools_installation::recover_versioned_installation_with_verification;
    let temp = tempfile::tempdir().unwrap();
    let request = versioned_fixture(temp.path(), "1.0.0", b"first");
    let next = apply_versioned_installation(&request, |_| Ok(()))
        .unwrap()
        .receipt;
    let journal = request
        .layout
        .data_root
        .join("installation-transition-v1.json");
    let pending = serde_json::to_vec(&serde_json::json!({
        "schema": "dev-tools-versioned-transition-v1", "prior": null, "next": next,
    }))
    .unwrap();
    fs::write(&journal, &pending).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(
        request
            .layout
            .data_root
            .join("installation-receipt-v1.json"),
    )
    .unwrap();
    let active = request.layout.data_root.join("active");
    let target = fs::read_link(&active).unwrap();
    fs::write(&target, b"wrong").unwrap();
    assert!(
        recover_versioned_installation_with_verification(&request.layout, 1024, |_| Ok(()))
            .is_err()
    );
    assert_eq!(fs::read_link(active).unwrap(), target);
    assert_eq!(fs::read(&journal).unwrap(), pending);
}

#[test]
fn conditional_rollback_rejects_stale_receipt_without_activation() {
    use dev_tools_installation::rollback_versioned_installation_if_unchanged;
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    apply_versioned_installation(&first, |_| Ok(())).unwrap();
    let second = versioned_fixture(temp.path(), "2.0.0", b"second");
    let observed = apply_versioned_installation(&second, |_| Ok(()))
        .unwrap()
        .receipt;
    let third = versioned_fixture(temp.path(), "3.0.0", b"third");
    let current = apply_versioned_installation(&third, |_| Ok(()))
        .unwrap()
        .receipt;
    let mut verified = false;
    let result = rollback_versioned_installation_if_unchanged(&first.layout, &observed, |_| {
        verified = true;
        Ok(())
    });
    assert!(
        result.is_err(),
        "stale rollback authorization must not activate a different retained version"
    );
    assert!(!verified);
    assert_eq!(
        verify_versioned_installation(&first.layout).unwrap(),
        current
    );
}

#[test]
fn conditional_rollback_preserves_journal_and_drift_then_accepts_exact_state() {
    use dev_tools_installation::rollback_versioned_installation_if_unchanged;
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    apply_versioned_installation(&first, |_| Ok(())).unwrap();
    let second = versioned_fixture(temp.path(), "2.0.0", b"second");
    let observed = apply_versioned_installation(&second, |_| Ok(()))
        .unwrap()
        .receipt;
    let receipt_path = first.layout.data_root.join("installation-receipt-v1.json");
    let original = fs::read(&receipt_path).unwrap();
    let journal = first
        .layout
        .data_root
        .join("installation-transition-v1.json");
    let pending = serde_json::to_vec(&serde_json::json!({
        "schema": "dev-tools-versioned-transition-v1", "prior": null, "next": observed,
    }))
    .unwrap();
    fs::write(&journal, &pending).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        rollback_versioned_installation_if_unchanged(&first.layout, &observed, |_| Ok(())).is_err()
    );
    assert_eq!(fs::read(&journal).unwrap(), pending);
    assert_eq!(fs::read(&receipt_path).unwrap(), original);
    fs::remove_file(&journal).unwrap();
    let alias = first.layout.bin_dir.join("fixture");
    fs::remove_file(&alias).unwrap();
    assert!(
        rollback_versioned_installation_if_unchanged(&first.layout, &observed, |_| Ok(())).is_err()
    );
    assert!(fs::symlink_metadata(&alias).is_err());
    assert_eq!(fs::read(&receipt_path).unwrap(), original);
    apply_versioned_installation(&second, |_| Ok(())).unwrap();
    assert!(rollback_versioned_installation_if_unchanged(
        &first.layout,
        &observed,
        |_| anyhow::bail!("reject")
    )
    .is_err());
    assert_eq!(fs::read(&receipt_path).unwrap(), original);
    let result =
        rollback_versioned_installation_if_unchanged(&first.layout, &observed, |candidate| {
            assert_eq!(fs::read(candidate).unwrap(), b"first");
            assert_eq!(fs::read(&receipt_path).unwrap(), original);
            assert!(InstallationLock::try_acquire(
                &first.layout.data_root.join("installation.lock")
            )?
            .is_none());
            Ok(())
        })
        .unwrap();
    assert!(result.changed);
    assert_eq!(result.receipt.active_version, "1.0.0");
    assert_eq!(result.receipt.previous_version.as_deref(), Some("2.0.0"));
    assert_eq!(
        verify_versioned_installation(&first.layout).unwrap(),
        result.receipt
    );
}

#[test]
fn versioned_layout_preserves_exact_build_metadata_and_preflights_without_io() {
    let temp = tempfile::tempdir().unwrap();
    let request = versioned_fixture(temp.path(), "1.2.3+build.1", b"first");
    assert!(request
        .layout
        .validate_candidate(&request.version, &request.identity, &request.aliases)
        .is_ok());
    assert!(!request.layout.data_root.exists());
    let report = apply_versioned_installation(&request, |_| Ok(())).unwrap();
    assert_eq!(report.receipt.active_version, "1.2.3+build.1");
    assert!(request
        .layout
        .data_root
        .join("versions/1.2.3+build.1")
        .is_dir());
    for version in ["../escape", "1/2", ".", "-bad", &"1".repeat(129)] {
        assert!(request
            .layout
            .validate_candidate(version, &request.identity, &request.aliases)
            .is_err());
    }
    assert!(request
        .layout
        .validate_candidate("1.2.3", &request.identity, &["alias+extra".into()])
        .is_err());
}

#[test]
fn conditional_apply_rejects_stale_receipt_before_publishing_candidate() {
    use dev_tools_installation::apply_versioned_installation_if_unchanged;
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    let observed = apply_versioned_installation(&first, |_| Ok(()))
        .unwrap()
        .receipt;
    let newer = versioned_fixture(temp.path(), "3.0.0", b"newer");
    let current = apply_versioned_installation(&newer, |_| Ok(()))
        .unwrap()
        .receipt;
    let stale = versioned_fixture(temp.path(), "2.0.0", b"stale");
    let mut verified = false;
    let result = apply_versioned_installation_if_unchanged(&stale, Some(&observed), |_| {
        verified = true;
        Ok(())
    });
    assert!(
        result.is_err(),
        "a stale policy decision must not replace the current receipt"
    );
    assert!(!verified);
    assert!(!first.layout.data_root.join("versions/2.0.0").exists());
    assert_eq!(
        verify_versioned_installation(&first.layout).unwrap(),
        current
    );
    assert!(apply_versioned_installation_if_unchanged(&stale, None, |_| Ok(())).is_err());
}

#[test]
fn conditional_apply_accepts_exact_state_but_never_repairs_or_recovers() {
    use dev_tools_installation::apply_versioned_installation_if_unchanged;
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    let installed = apply_versioned_installation_if_unchanged(&first, None, |_| Ok(())).unwrap();
    assert!(installed.changed);
    let observed = installed.receipt;
    assert!(
        !apply_versioned_installation_if_unchanged(&first, Some(&observed), |_| Ok(()))
            .unwrap()
            .changed
    );
    let second = versioned_fixture(temp.path(), "2.0.0", b"second");
    let receipt_path = first.layout.data_root.join("installation-receipt-v1.json");
    let original = fs::read(&receipt_path).unwrap();
    let alias = first.layout.bin_dir.join("fixture");
    fs::remove_file(&alias).unwrap();
    assert!(
        apply_versioned_installation_if_unchanged(&second, Some(&observed), |_| Ok(())).is_err()
    );
    assert!(
        fs::symlink_metadata(&alias).is_err(),
        "conditional install must not repair drift"
    );
    assert_eq!(fs::read(&receipt_path).unwrap(), original);
    // Explicit legacy repair restores this fixture before testing the journal boundary.
    apply_versioned_installation(&first, |_| Ok(())).unwrap();
    let journal = first
        .layout
        .data_root
        .join("installation-transition-v1.json");
    let pending = serde_json::to_vec(&serde_json::json!({
        "schema": "dev-tools-versioned-transition-v1",
        "prior": null,
        "next": observed,
    }))
    .unwrap();
    fs::write(&journal, &pending).unwrap();
    fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        apply_versioned_installation_if_unchanged(&second, Some(&observed), |_| Ok(())).is_err()
    );
    assert_eq!(fs::read(&journal).unwrap(), pending);
    assert_eq!(fs::read(&receipt_path).unwrap(), original);
    assert!(!first.layout.data_root.join("versions/2.0.0").exists());
    fs::remove_file(&journal).unwrap();
    let upgraded =
        apply_versioned_installation_if_unchanged(&second, Some(&observed), |candidate| {
            assert_eq!(fs::read(candidate).unwrap(), b"second");
            assert_eq!(fs::read(&receipt_path).unwrap(), original);
            assert!(InstallationLock::try_acquire(
                &first.layout.data_root.join("installation.lock")
            )?
            .is_none());
            Ok(())
        })
        .unwrap();
    assert!(upgraded.changed);
    assert_eq!(upgraded.receipt.active_version, "2.0.0");
    assert_eq!(upgraded.receipt.previous_version.as_deref(), Some("1.0.0"));
}

#[cfg(target_os = "linux")]
#[test]
fn initial_document_directory_publishes_complete_without_replacing_collisions() {
    use dev_tools_installation::publish_new_document_directory;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("new-state");
    let authority = DocumentAuthority {
        owner_uid: temp.path().metadata().unwrap().uid(),
        mode: 0o600,
        limit: 16,
    };
    assert!(publish_new_document_directory(&root, "ledger.json", b"", &authority, 0o700).is_err());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
    publish_new_document_directory(&root, "ledger.json", b"initial", &authority, 0o700).unwrap();
    assert_eq!(
        read_atomic_document(&root.join("ledger.json"), &authority)
            .unwrap()
            .unwrap()
            .bytes,
        b"initial"
    );
    assert_eq!(root.metadata().unwrap().mode() & 0o777, 0o700);
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    assert!(publish_new_document_directory(
        &root,
        "ledger.json",
        b"replacement",
        &authority,
        0o700
    )
    .is_err());
    assert_eq!(fs::read(root.join("ledger.json")).unwrap(), b"initial");
    let linked = temp.path().join("linked");
    symlink(&root, &linked).unwrap();
    assert!(publish_new_document_directory(
        &linked,
        "ledger.json",
        b"replacement",
        &authority,
        0o700
    )
    .is_err());
    assert!(publish_new_document_directory(
        &temp.path().join("escape"),
        "../ledger.json",
        b"initial",
        &authority,
        0o700
    )
    .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn atomic_document_rejects_fifo_without_waiting_for_a_writer() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("document");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &path,
        rustix::fs::Mode::from_raw_mode(0o600),
    )
    .unwrap();
    let authority = DocumentAuthority {
        owner_uid: fs::metadata(temp.path()).unwrap().uid(),
        mode: 0o600,
        limit: 1024,
    };
    let worker_path = path.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let rejected = read_atomic_document(&worker_path, &authority).is_err();
        finished_tx.send(rejected).unwrap();
    });
    started_rx.recv().unwrap();
    let result = finished_rx.recv_timeout(std::time::Duration::from_secs(2));
    // Release the old blocking implementation before asserting the failure.
    // Linux O_RDWR on a FIFO supplies both ends without another peer.
    let unblock = if result.is_err() {
        Some(
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
        )
    } else {
        None
    };
    worker.join().unwrap();
    drop(unblock);
    assert_eq!(
        result.ok(),
        Some(true),
        "non-regular input must reject without a writer"
    );
}

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
fn absent_atomic_document_under_absent_parent_is_empty_state() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("not-installed/yet/release.json");
    let authority = DocumentAuthority {
        owner_uid: fs::metadata(temp.path()).unwrap().uid(),
        mode: 0o600,
        limit: 4096,
    };

    assert!(read_atomic_document(&path, &authority).unwrap().is_none());
    assert!(!temp.path().join("not-installed").exists());
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

fn versioned_fixture(
    root: &std::path::Path,
    version: &str,
    bytes: &[u8],
) -> VersionedInstallRequest {
    let source = root.join(format!("candidate-{version}"));
    fs::write(&source, bytes).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let identity = ArtifactIdentity::from_file(&source, 4096).unwrap();
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
        source,
        identity,
        aliases: vec!["fixture".into(), "fixture-helper".into()],
    }
}

#[cfg(target_os = "linux")]
#[test]
fn read_only_observation_never_creates_a_missing_installation_lock() {
    use dev_tools_installation::observe_versioned_installation;
    let temp = tempfile::tempdir().unwrap();
    let request = versioned_fixture(temp.path(), "1.0.0", b"candidate");
    assert!(observe_versioned_installation(&request.layout, 4096)
        .unwrap()
        .is_none());
    assert!(!request.layout.data_root.exists());
    assert!(!request.layout.bin_dir.exists());
    apply_versioned_installation(&request, |_| Ok(())).unwrap();
    let lock = request.layout.data_root.join("installation.lock");
    fs::remove_file(&lock).unwrap();
    assert!(
        observe_versioned_installation(&request.layout, 4096).is_err(),
        "read-only observation must not recreate missing authority"
    );
    assert!(!lock.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn read_only_observation_is_bounded_and_refuses_busy_recovery_or_drift() {
    use dev_tools_installation::observe_versioned_installation;
    let temp = tempfile::tempdir().unwrap();
    let request = versioned_fixture(temp.path(), "1.0.0", b"candidate");
    let installed = apply_versioned_installation(&request, |_| Ok(())).unwrap();
    let receipt_path = request
        .layout
        .data_root
        .join("installation-receipt-v1.json");
    let lock_path = request.layout.data_root.join("installation.lock");
    let bytes = fs::read(&receipt_path).unwrap();
    let modified = fs::metadata(&receipt_path).unwrap().modified().unwrap();
    let lock_modified = fs::metadata(&lock_path).unwrap().modified().unwrap();
    let count = fs::read_dir(&request.layout.data_root).unwrap().count();
    assert_eq!(
        observe_versioned_installation(&request.layout, 4096).unwrap(),
        Some(installed.receipt)
    );
    assert!(observe_versioned_installation(&request.layout, 1).is_err());
    assert_eq!(fs::read(&receipt_path).unwrap(), bytes);
    assert_eq!(
        fs::metadata(&receipt_path).unwrap().modified().unwrap(),
        modified
    );
    assert_eq!(
        fs::metadata(&lock_path).unwrap().modified().unwrap(),
        lock_modified
    );
    assert_eq!(
        fs::read_dir(&request.layout.data_root).unwrap().count(),
        count
    );

    let held = InstallationLock::acquire(&lock_path).unwrap();
    let layout = request.layout.clone();
    let (sender, receiver) = std::sync::mpsc::channel();
    let observer = std::thread::spawn(move || {
        sender
            .send(observe_versioned_installation(&layout, 4096).is_err())
            .unwrap();
    });
    let completed_while_locked = receiver.recv_timeout(std::time::Duration::from_secs(2));
    drop(held);
    observer.join().unwrap();
    assert_eq!(
        completed_while_locked,
        Ok(true),
        "observer must fail without waiting for the active writer"
    );

    let journal = request
        .layout
        .data_root
        .join("installation-transition-v1.json");
    fs::write(&journal, b"pending recovery must be left untouched").unwrap();
    assert!(observe_versioned_installation(&request.layout, 4096).is_err());
    assert_eq!(
        fs::read(&journal).unwrap(),
        b"pending recovery must be left untouched"
    );
    fs::remove_file(&journal).unwrap();
    let alias = request.layout.bin_dir.join("fixture");
    fs::remove_file(&alias).unwrap();
    assert!(observe_versioned_installation(&request.layout, 4096).is_err());
    assert!(
        !alias.exists(),
        "observation must not repair a missing alias"
    );
    assert_eq!(fs::read(&receipt_path).unwrap(), bytes);
}

#[test]
fn layout_can_keep_private_data_beside_a_public_command_directory() {
    let temp = tempfile::tempdir().unwrap();
    let request = versioned_fixture(temp.path(), "1.0.0", b"candidate");
    let legacy = serde_json::to_value(&request.layout).unwrap();
    assert!(
        legacy.get("bin_directory_mode").is_none(),
        "default layout must preserve the legacy wire document"
    );
    let decoded: VersionedLayout = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
    let mut mixed = legacy;
    mixed["bin_directory_mode"] = serde_json::json!(0o755);
    let parsed = serde_json::from_value::<VersionedLayout>(mixed);
    assert!(
        parsed.is_ok(),
        "explicit separate binary-directory mode must be supported"
    );
    let mut request = request;
    request.layout = parsed.unwrap();
    fs::create_dir(&request.layout.bin_dir).unwrap();
    fs::set_permissions(&request.layout.bin_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        apply_versioned_installation(&request, |_| Ok(()))
            .unwrap()
            .changed
    );
    assert_eq!(
        fs::metadata(&request.layout.data_root).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&request.layout.bin_dir).unwrap().mode() & 0o777,
        0o755
    );
    assert!(
        !apply_versioned_installation(&request, |_| Ok(()))
            .unwrap()
            .changed
    );
    #[cfg(target_os = "linux")]
    assert!(
        dev_tools_installation::observe_versioned_installation(&request.layout, 4096)
            .unwrap()
            .is_some()
    );
    let mut next = versioned_fixture(temp.path(), "2.0.0", b"next-candidate");
    next.layout.bin_directory_mode = Some(0o755);
    assert!(
        apply_versioned_installation(&next, |_| Ok(()))
            .unwrap()
            .changed
    );
    assert_eq!(
        rollback_versioned_installation(&next.layout, |_| Ok(()))
            .unwrap()
            .receipt
            .active_version,
        "1.0.0"
    );
    uninstall_versioned_installation(&next.layout).unwrap();
    assert_eq!(
        fs::metadata(&next.layout.bin_dir).unwrap().mode() & 0o777,
        0o755
    );
}

#[test]
fn separate_binary_directory_mode_cannot_widen_write_authority() {
    for mode in [0o777, 0o775, 0o707, 0o400, 0o1755] {
        let temp = tempfile::tempdir().unwrap();
        let mut request = versioned_fixture(temp.path(), "1.0.0", b"candidate");
        request.layout.bin_directory_mode = Some(mode);
        assert!(apply_versioned_installation(&request, |_| Ok(())).is_err());
        assert!(!request.layout.data_root.exists());
        assert!(!request.layout.bin_dir.exists());
    }
}

#[test]
fn versioned_install_upgrade_rollback_and_uninstall_are_receipt_owned() {
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    let first_report = apply_versioned_installation(&first, |_| Ok(())).unwrap();
    assert!(first_report.changed);
    assert_eq!(first_report.receipt.active_version, "1.0.0");
    assert_eq!(first_report.receipt.previous_version, None);
    assert!(
        !apply_versioned_installation(&first, |_| Ok(()))
            .unwrap()
            .changed
    );
    fs::remove_file(first.layout.bin_dir.join("fixture-helper")).unwrap();
    assert!(
        apply_versioned_installation(&first, |_| Ok(()))
            .unwrap()
            .changed
    );
    assert_eq!(
        fs::read_link(first.layout.bin_dir.join("fixture-helper")).unwrap(),
        first.layout.data_root.join("active")
    );

    let second = versioned_fixture(temp.path(), "1.1.0", b"second");
    let second_report = apply_versioned_installation(&second, |candidate| {
        assert_eq!(fs::read(candidate).unwrap(), b"second");
        Ok(())
    })
    .unwrap();
    assert_eq!(second_report.receipt.active_version, "1.1.0");
    assert_eq!(
        second_report.receipt.previous_version.as_deref(),
        Some("1.0.0")
    );
    for alias in ["fixture", "fixture-helper"] {
        assert_eq!(
            fs::read_link(second.layout.bin_dir.join(alias)).unwrap(),
            second.layout.data_root.join("active")
        );
    }

    let rolled_back = rollback_versioned_installation(&second.layout, |candidate| {
        assert_eq!(fs::read(candidate).unwrap(), b"first");
        Ok(())
    })
    .unwrap();
    assert_eq!(rolled_back.receipt.active_version, "1.0.0");
    assert_eq!(
        rolled_back.receipt.previous_version.as_deref(),
        Some("1.1.0")
    );
    verify_versioned_installation(&second.layout).unwrap();

    let removed = uninstall_versioned_installation(&second.layout).unwrap();
    assert_eq!(removed.removed_versions, 2);
    assert!(!second.layout.data_root.join("active").exists());
    assert!(!second.layout.bin_dir.join("fixture").exists());
    assert!(first.source.exists());
    assert!(second.source.exists());
}

#[test]
fn versioned_install_rejects_unowned_alias_and_drift_without_partial_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    fs::create_dir(&first.layout.bin_dir).unwrap();
    fs::set_permissions(
        &first.layout.bin_dir,
        fs::Permissions::from_mode(first.layout.directory_mode),
    )
    .unwrap();
    fs::write(first.layout.bin_dir.join("fixture"), b"human tool").unwrap();
    assert!(apply_versioned_installation(&first, |_| Ok(())).is_err());
    assert_eq!(
        fs::read(first.layout.bin_dir.join("fixture")).unwrap(),
        b"human tool"
    );
    assert!(!first.layout.data_root.join("active").exists());

    fs::remove_file(first.layout.bin_dir.join("fixture")).unwrap();
    apply_versioned_installation(&first, |_| Ok(())).unwrap();
    let active = first.layout.data_root.join("versions/1.0.0/fixture");
    fs::write(&active, b"drift").unwrap();
    let second = versioned_fixture(temp.path(), "1.1.0", b"second");
    assert!(apply_versioned_installation(&second, |_| Ok(())).is_err());
    assert_eq!(
        fs::read_link(second.layout.data_root.join("active")).unwrap(),
        active
    );
}

#[test]
fn versioned_install_rejects_symlinked_roots_and_hardlinked_candidates() {
    let temp = tempfile::tempdir().unwrap();
    let escaped = temp.path().join("escaped");
    fs::create_dir(&escaped).unwrap();
    let request = versioned_fixture(temp.path(), "1.0.0", b"first");
    symlink(&escaped, &request.layout.data_root).unwrap();
    assert!(apply_versioned_installation(&request, |_| Ok(())).is_err());

    fs::remove_file(&request.layout.data_root).unwrap();
    let hardlink = temp.path().join("candidate-hardlink");
    fs::hard_link(&request.source, &hardlink).unwrap();
    assert!(apply_versioned_installation(&request, |_| Ok(())).is_err());
}

#[test]
fn versioned_receipt_rejects_writable_or_wrong_owner_artifact_authority() {
    let temp = tempfile::tempdir().unwrap();
    let request = versioned_fixture(temp.path(), "1.0.0", b"first");
    apply_versioned_installation(&request, |_| Ok(())).unwrap();
    let artifact = request.layout.data_root.join("versions/1.0.0/fixture");
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(verify_versioned_installation(&request.layout).is_err());
}

#[test]
fn validated_legacy_layout_is_adopted_without_losing_upgrade_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let first = versioned_fixture(temp.path(), "1.0.0", b"first");
    let artifact = first.layout.data_root.join("versions/1.0.0/fixture");
    fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    fs::set_permissions(&first.layout.data_root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(
        first.layout.data_root.join("versions"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        artifact.parent().unwrap(),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::create_dir(&first.layout.bin_dir).unwrap();
    fs::set_permissions(
        &first.layout.bin_dir,
        fs::Permissions::from_mode(first.layout.directory_mode),
    )
    .unwrap();
    fs::copy(&first.source, &artifact).unwrap();
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
    for alias in &first.aliases {
        symlink(&artifact, first.layout.bin_dir.join(alias)).unwrap();
    }

    let adopted = adopt_versioned_installation(
        &VersionedAdoption {
            layout: first.layout.clone(),
            version: first.version.clone(),
            identity: first.identity.clone(),
            aliases: first.aliases.clone(),
        },
        |candidate| {
            assert_eq!(candidate, artifact);
            Ok(())
        },
    )
    .unwrap();
    assert!(adopted.changed);
    assert_eq!(adopted.receipt.active_version, "1.0.0");
    let versions = first.layout.data_root.join("versions");
    for directory in [
        first.layout.data_root.as_path(),
        versions.as_path(),
        artifact.parent().unwrap(),
    ] {
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    for alias in &first.aliases {
        assert_eq!(
            fs::read_link(first.layout.bin_dir.join(alias)).unwrap(),
            first.layout.data_root.join("active")
        );
    }

    let second = versioned_fixture(temp.path(), "1.1.0", b"second");
    let upgraded = apply_versioned_installation(&second, |_| Ok(())).unwrap();
    assert_eq!(upgraded.receipt.active_version, "1.1.0");
    assert_eq!(upgraded.receipt.previous_version.as_deref(), Some("1.0.0"));
}
