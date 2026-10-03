#![cfg(target_os = "linux")]

use dev_tools_installation::{
    apply_versioned_installation, withdraw_versioned_installation_activation, ArtifactIdentity,
    VersionedInstallRequest, VersionedLayout, VersionedReceipt,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

fn fixture(root: &Path) -> (VersionedLayout, VersionedReceipt) {
    let source = root.join("source");
    fs::write(&source, b"retained executable").unwrap();
    let layout = VersionedLayout {
        product: "fixture".into(),
        data_root: root.join("data"),
        bin_dir: root.join("bin"),
        artifact_name: "fixture".into(),
        owner_uid: fs::metadata(root).unwrap().uid(),
        directory_mode: 0o700,
        bin_directory_mode: None,
    };
    let receipt = apply_versioned_installation(
        &VersionedInstallRequest {
            layout: layout.clone(),
            version: "1.0.0".into(),
            identity: ArtifactIdentity::from_file(&source, 1024).unwrap(),
            source,
            aliases: vec!["fixture".into(), "fixture-helper".into()],
        },
        |_| Ok(()),
    )
    .unwrap()
    .receipt;
    (layout, receipt)
}

#[test]
fn withdrawal_retains_recovery_inputs_and_repeats_without_reactivation() {
    for interrupted in ["none", "alias", "active", "receipt"] {
        let root = tempfile::tempdir().unwrap();
        let (layout, receipt) = fixture(root.path());
        let lock = fs::metadata(layout.data_root.join("installation.lock")).unwrap();
        fs::write(
            layout.data_root.join("outer-recovery-authority"),
            b"retained authority",
        )
        .unwrap();
        fs::write(layout.bin_dir.join("unrelated"), b"unrelated user file").unwrap();
        match interrupted {
            "alias" => fs::remove_file(layout.bin_dir.join("fixture")).unwrap(),
            "active" => fs::remove_file(layout.data_root.join("active")).unwrap(),
            "receipt" => {
                fs::remove_file(layout.data_root.join("installation-receipt-v1.json")).unwrap()
            }
            _ => {}
        }
        assert!(withdraw_versioned_installation_activation(&layout, &receipt, 1024).unwrap());
        for path in [
            layout.bin_dir.join("fixture"),
            layout.bin_dir.join("fixture-helper"),
            layout.data_root.join("active"),
            layout.data_root.join("installation-receipt-v1.json"),
        ] {
            assert!(fs::symlink_metadata(path).is_err());
        }
        assert_eq!(
            fs::read(layout.data_root.join("versions/1.0.0/fixture")).unwrap(),
            b"retained executable"
        );
        assert_eq!(
            fs::read(layout.data_root.join("outer-recovery-authority")).unwrap(),
            b"retained authority"
        );
        assert_eq!(
            fs::read(layout.bin_dir.join("unrelated")).unwrap(),
            b"unrelated user file"
        );
        assert_eq!(
            fs::metadata(layout.data_root.join("installation.lock"))
                .unwrap()
                .ino(),
            lock.ino()
        );
        assert!(!withdraw_versioned_installation_activation(&layout, &receipt, 1024).unwrap());
    }
}

#[test]
fn withdrawal_rejects_drift_before_removing_any_other_owned_entry() {
    for drift in [
        "receipt",
        "link",
        "journal",
        "artifact",
        "bound",
        "linked_alias",
        "previous",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (layout, mut expected) = fixture(root.path());
        let mut limit = 1024;
        match drift {
            "receipt" => expected.active_identity.sha256 = "a".repeat(64),
            "link" => {
                fs::remove_file(layout.bin_dir.join("fixture-helper")).unwrap();
                symlink(
                    root.path().join("unrelated"),
                    layout.bin_dir.join("fixture-helper"),
                )
                .unwrap();
            }
            "journal" => {
                let path = layout.data_root.join("installation-transition-v1.json");
                fs::write(&path, b"unrelated pending authority").unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            "artifact" => {
                fs::hard_link(
                    layout.data_root.join("versions/1.0.0/fixture"),
                    root.path().join("hardlink"),
                )
                .unwrap();
            }
            "bound" => limit = 1,
            "linked_alias" => {
                fs::hard_link(
                    layout.bin_dir.join("fixture"),
                    root.path().join("linked-alias"),
                )
                .unwrap();
            }
            "previous" => {
                symlink(
                    layout.data_root.join("versions/1.0.0/fixture"),
                    layout.data_root.join("previous"),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let receipt = fs::read(layout.data_root.join("installation-receipt-v1.json")).unwrap();
        let active = fs::read_link(layout.data_root.join("active")).unwrap();
        let alias = fs::read_link(layout.bin_dir.join("fixture")).unwrap();
        let other_alias = fs::read_link(layout.bin_dir.join("fixture-helper")).unwrap();
        assert!(withdraw_versioned_installation_activation(&layout, &expected, limit).is_err());
        assert_eq!(
            fs::read(layout.data_root.join("installation-receipt-v1.json")).unwrap(),
            receipt
        );
        assert_eq!(
            fs::read_link(layout.data_root.join("active")).unwrap(),
            active
        );
        assert_eq!(
            fs::read_link(layout.bin_dir.join("fixture")).unwrap(),
            alias
        );
        assert_eq!(
            fs::read_link(layout.bin_dir.join("fixture-helper")).unwrap(),
            other_alias
        );
    }
}

#[test]
fn withdrawal_retains_both_artifacts_and_does_not_initialize_missing_roots() {
    let root = tempfile::tempdir().unwrap();
    let (layout, original) = fixture(root.path());
    let source = root.path().join("second-source");
    fs::write(&source, b"second retained executable").unwrap();
    let next = apply_versioned_installation(
        &VersionedInstallRequest {
            layout: layout.clone(),
            version: "2.0.0".into(),
            identity: ArtifactIdentity::from_file(&source, 1024).unwrap(),
            source,
            aliases: original.aliases.clone(),
        },
        |_| Ok(()),
    )
    .unwrap()
    .receipt;
    assert!(withdraw_versioned_installation_activation(&layout, &next, 1024).unwrap());
    assert!(!layout.data_root.join("previous").exists());
    for version in ["1.0.0", "2.0.0"] {
        assert!(layout
            .data_root
            .join("versions")
            .join(version)
            .join("fixture")
            .is_file());
    }
    assert!(!withdraw_versioned_installation_activation(&layout, &next, 1024).unwrap());
    let mut absent = layout.clone();
    absent.data_root = root.path().join("absent-data");
    absent.bin_dir = root.path().join("absent-bin");
    let mut expected = original;
    expected.data_root = absent.data_root.clone();
    expected.bin_dir = absent.bin_dir.clone();
    assert!(withdraw_versioned_installation_activation(&absent, &expected, 1024).is_err());
    assert!(!absent.data_root.exists());
    assert!(!absent.bin_dir.exists());
}
