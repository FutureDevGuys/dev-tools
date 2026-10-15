#![cfg(target_os = "linux")]
use dev_tools_installation::{
    apply_versioned_installation, observe_retained_versioned_installation_repair,
    repair_retained_versioned_installation, ArtifactIdentity, VersionedInstallRequest,
    VersionedLayout, VersionedReceipt,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};

fn fixture(root: &std::path::Path) -> (VersionedLayout, VersionedReceipt) {
    let source = root.join("source");
    fs::write(&source, b"retained candidate").unwrap();
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
            aliases: vec!["first".into(), "last".into()],
        },
        |_| Ok(()),
    )
    .unwrap()
    .receipt;
    (layout, receipt)
}

#[test]
fn retained_repair_reconstructs_missing_receipt_and_links_and_repeats_unchanged() {
    let root = tempfile::tempdir().unwrap();
    let (layout, receipt) = fixture(root.path());
    fs::remove_file(layout.data_root.join("installation-receipt-v1.json")).unwrap();
    fs::remove_file(layout.bin_dir.join("first")).unwrap();
    fs::remove_file(layout.data_root.join("active")).unwrap();
    observe_retained_versioned_installation_repair(&layout, &receipt, 1024).unwrap();
    assert!(!layout.bin_dir.join("first").exists());
    assert!(repair_retained_versioned_installation(&layout, &receipt, 1024).unwrap());
    assert_eq!(
        fs::read_link(layout.bin_dir.join("first")).unwrap(),
        layout.data_root.join("active")
    );
    assert_eq!(
        serde_json::from_slice::<VersionedReceipt>(
            &fs::read(layout.data_root.join("installation-receipt-v1.json")).unwrap()
        )
        .unwrap(),
        receipt
    );
    assert!(!repair_retained_versioned_installation(&layout, &receipt, 1024).unwrap());
}

#[test]
fn retained_repair_observes_all_owned_endpoints_before_reconstructing_one() {
    for drift in ["last_alias", "active", "receipt", "journal"] {
        let root = tempfile::tempdir().unwrap();
        let (layout, receipt) = fixture(root.path());
        fs::remove_file(layout.bin_dir.join("first")).unwrap();
        match drift {
            "last_alias" => {
                fs::remove_file(layout.bin_dir.join("last")).unwrap();
                symlink(root.path().join("independent"), layout.bin_dir.join("last")).unwrap();
            }
            "active" => {
                fs::remove_file(layout.data_root.join("active")).unwrap();
                symlink(
                    root.path().join("independent"),
                    layout.data_root.join("active"),
                )
                .unwrap();
            }
            "receipt" => {
                let mut foreign = receipt.clone();
                foreign.active_identity.sha256 = "a".repeat(64);
                fs::write(
                    layout.data_root.join("installation-receipt-v1.json"),
                    serde_jcs::to_vec(&foreign).unwrap(),
                )
                .unwrap();
            }
            "journal" => {
                fs::write(
                    layout.data_root.join("installation-transition-v1.json"),
                    b"pending independent journal",
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            repair_retained_versioned_installation(&layout, &receipt, 1024).is_err(),
            "{drift}"
        );
        assert!(fs::symlink_metadata(layout.bin_dir.join("first")).is_err());
        if drift == "journal" {
            assert_eq!(
                fs::read(layout.data_root.join("installation-transition-v1.json")).unwrap(),
                b"pending independent journal"
            );
        }
    }
}
