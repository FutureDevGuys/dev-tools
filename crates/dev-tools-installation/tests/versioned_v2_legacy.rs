#![cfg(target_os = "linux")]

use dev_tools_installation::{
    versioned_v2, ArtifactIdentity, VersionedAdoption, VersionedLayout, VersionedReceipt,
    VersionedTwoLevelAdoption,
};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

fn fixture(root: &Path) -> (VersionedTwoLevelAdoption, VersionedReceipt) {
    let layout = VersionedLayout {
        product: "fixture".into(),
        data_root: root.join("data"),
        bin_dir: root.join("bin"),
        artifact_name: "fixture".into(),
        owner_uid: fs::metadata(root).unwrap().uid(),
        directory_mode: 0o700,
        bin_directory_mode: None,
    };
    fs::create_dir_all(&layout.bin_dir).unwrap();
    let mut identities = Vec::new();
    for version in ["1.0.0", "2.0.0"] {
        let dir = layout.data_root.join("versions").join(version);
        fs::create_dir_all(&dir).unwrap();
        let artifact = dir.join("fixture");
        fs::write(&artifact, version).unwrap();
        fs::set_permissions(&artifact, fs::Permissions::from_mode(0o755)).unwrap();
        identities.push(ArtifactIdentity::from_file(&artifact, 1024).unwrap());
    }
    for dir in [
        &layout.data_root,
        &layout.bin_dir,
        &layout.data_root.join("versions"),
        &layout.data_root.join("versions/1.0.0"),
        &layout.data_root.join("versions/2.0.0"),
    ] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let pointer = layout.data_root.join("current");
    symlink(layout.data_root.join("versions/2.0.0"), &pointer).unwrap();
    symlink(pointer.join("fixture"), layout.bin_dir.join("fixture")).unwrap();
    let receipt = VersionedReceipt {
        schema: "dev-tools-versioned-installation-v1".into(),
        product: layout.product.clone(),
        data_root: layout.data_root.clone(),
        bin_dir: layout.bin_dir.clone(),
        artifact_name: layout.artifact_name.clone(),
        active_version: "2.0.0".into(),
        active_identity: identities[1].clone(),
        previous_version: Some("1.0.0".into()),
        previous_identity: Some(identities[0].clone()),
        aliases: vec!["fixture".into()],
    };
    (
        VersionedTwoLevelAdoption {
            adoption: VersionedAdoption {
                layout,
                version: "2.0.0".into(),
                identity: identities[1].clone(),
                aliases: vec!["fixture".into()],
            },
            version_pointer: pointer,
        },
        receipt,
    )
}

#[test]
fn legacy_cutover_preserves_authenticated_retained_identity_and_fences_v1() {
    let root = tempfile::tempdir().unwrap();
    let (request, expected) = fixture(root.path());
    let prepared = versioned_v2::legacy_adoption::prepare(&request, &expected, 1024).unwrap();
    let receipt = prepared
        .commit(|proposed| {
            assert_eq!(*proposed, expected);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        receipt, expected,
        "cutover must preserve authenticated retained ownership"
    );
    assert_eq!(
        versioned_v2::observe(&request.adoption.layout, 1024).unwrap(),
        Some(expected)
    );
    assert!(
        dev_tools_installation::adopt_two_level_versioned_installation(&request, |_| Ok(()))
            .is_err()
    );
}

#[test]
fn failed_product_cutover_retains_fence_and_explicit_resume_preserves_rollback() {
    let root = tempfile::tempdir().unwrap();
    let (request, expected) = fixture(root.path());
    let layout = &request.adoption.layout;
    let original = fs::read_link(&request.version_pointer).unwrap();
    let prepared = versioned_v2::legacy_adoption::prepare(&request, &expected, 1024).unwrap();
    assert!(prepared
        .commit(|receipt| {
            assert_eq!(*receipt, expected);
            assert!(dev_tools_installation::InstallationLock::try_acquire(
                &layout.data_root.join("installation.lock")
            )?
            .is_none());
            anyhow::bail!("interrupted product cutover")
        })
        .is_err());
    assert_eq!(fs::read_link(&request.version_pointer).unwrap(), original);
    assert!(!layout.data_root.join("active").exists());
    assert!(!layout
        .data_root
        .join("installation-receipt-v1.json")
        .exists());
    assert_eq!(
        versioned_v2::pending_recovery(layout).unwrap(),
        Some(versioned_v2::PendingRecovery::LegacyAdoption)
    );
    assert_eq!(
        versioned_v2::legacy_adoption::read_pending_receipt(layout).unwrap(),
        expected
    );
    assert!(
        dev_tools_installation::adopt_two_level_versioned_installation(&request, |_| Ok(()))
            .is_err()
    );
    assert!(versioned_v2::initialize(layout, 1024, |_| panic!("wrong recovery owner")).is_err());
    assert!(versioned_v2::recover(layout, 1024, |_| panic!("wrong recovery owner")).is_err());
    assert!(versioned_v2::legacy_adoption::prepare(&request, &expected, 1024).is_err());
    assert_eq!(
        versioned_v2::legacy_adoption::resume(layout, 1024, |receipt| {
            assert_eq!(*receipt, expected);
            Ok(())
        })
        .unwrap(),
        expected
    );
    assert!(versioned_v2::pending_recovery(layout).unwrap().is_none());
    assert!(versioned_v2::legacy_adoption::resume(layout, 1024, |_| panic!("no journal")).is_err());
    let rollback = versioned_v2::rollback_if_unchanged(layout, &expected, |_| Ok(())).unwrap();
    assert_eq!(rollback.receipt.active_version, "1.0.0");
    assert_eq!(rollback.receipt.previous_version.as_deref(), Some("2.0.0"));
}

#[test]
fn prepared_adoption_rejects_intervening_topology_and_retained_drift_before_fencing() {
    for change in [
        "alias-absence",
        "current-absence",
        "retained-bytes",
        "receipt",
        "journal",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (request, expected) = fixture(root.path());
        let layout = &request.adoption.layout;
        let prepared = versioned_v2::legacy_adoption::prepare(&request, &expected, 1024).unwrap();
        match change {
            "alias-absence" => fs::remove_file(layout.bin_dir.join("fixture")).unwrap(),
            "current-absence" => fs::remove_file(&request.version_pointer).unwrap(),
            "retained-bytes" => {
                fs::write(layout.data_root.join("versions/1.0.0/fixture"), b"drift").unwrap()
            }
            "receipt" => fs::write(
                layout.data_root.join("installation-receipt-v1.json"),
                b"foreign",
            )
            .unwrap(),
            _ => fs::write(
                layout.data_root.join("installation-transition-v1.json"),
                b"foreign",
            )
            .unwrap(),
        }
        let journal_path = layout.data_root.join("installation-transition-v1.json");
        let journal_before = fs::read(&journal_path).ok();
        assert!(
            prepared
                .commit(|_| panic!("changed observation must not fence product state"))
                .is_err(),
            "{change}"
        );
        assert_eq!(fs::read(&journal_path).ok(), journal_before, "{change}");
        assert_eq!(
            fs::metadata(&layout.data_root).unwrap().mode() & 0o777,
            0o755,
            "{change}"
        );
        assert!(!layout.data_root.join("active").exists());
    }
}

#[test]
fn adoption_process_fixture() {
    let Ok(serialized) = std::env::var("INSTALLATION_V2_ADOPTION_FIXTURE") else {
        return;
    };
    let (request, expected): (VersionedTwoLevelAdoption, VersionedReceipt) =
        serde_json::from_str(&serialized).unwrap();
    versioned_v2::legacy_adoption::prepare(&request, &expected, 1024)
        .unwrap()
        .commit(|_| {
            std::process::exit(74);
        })
        .unwrap();
    panic!("fixture must exit without unwinding inside product cutover");
}

#[test]
fn adoption_process_death_preserves_the_native_fence_for_authenticated_resume() {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let root = tempfile::tempdir().unwrap();
    let (request, expected) = fixture(root.path());
    let layout = &request.adoption.layout;
    let mut child = Command::new(std::env::current_exe().unwrap())
        .env_clear()
        .env(
            "INSTALLATION_V2_ADOPTION_FIXTURE",
            serde_json::to_string(&(&request, &expected)).unwrap(),
        )
        .current_dir(root.path())
        .args(["--exact", "adoption_process_fixture", "--nocapture"])
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
            other => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("native adoption fixture did not terminate: {other:?}");
            }
        }
    };
    assert_eq!(status.code(), Some(74));
    assert_eq!(
        versioned_v2::pending_recovery(layout).unwrap(),
        Some(versioned_v2::PendingRecovery::LegacyAdoption)
    );
    let journal = layout.data_root.join("installation-transition-v1.json");
    let before = fs::read(&journal).unwrap();
    assert!(
        versioned_v2::legacy_adoption::resume(layout, 1024, |_| anyhow::bail!("proof unavailable"))
            .is_err()
    );
    assert_eq!(fs::read(&journal).unwrap(), before);
    assert_eq!(
        versioned_v2::legacy_adoption::resume(layout, 1024, |receipt| {
            assert_eq!(*receipt, expected);
            Ok(())
        })
        .unwrap(),
        expected
    );
    assert_eq!(versioned_v2::observe(layout, 1024).unwrap(), Some(expected));
}

#[test]
fn adoption_resume_preserves_invalid_authority_and_pointer_drift() {
    for change in [
        "unknown-field",
        "wrong-layout",
        "retained-bytes",
        "foreign-alias",
        "missing-alias",
        "foreign-current",
        "receipt",
        "bound",
        "callback-journal",
        "callback-artifact",
    ] {
        let root = tempfile::tempdir().unwrap();
        let (request, expected) = fixture(root.path());
        let layout = &request.adoption.layout;
        assert!(
            versioned_v2::legacy_adoption::prepare(&request, &expected, 1024)
                .unwrap()
                .commit(|_| anyhow::bail!("park"))
                .is_err()
        );
        let journal = layout.data_root.join("installation-transition-v1.json");
        let mut bound = 1024;
        match change {
            "unknown-field" | "wrong-layout" => {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
                if change == "unknown-field" {
                    value["unrecognized"] = true.into();
                } else {
                    value["layout"]["product"] = "other".into();
                }
                fs::write(&journal, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            "retained-bytes" => {
                fs::write(layout.data_root.join("versions/1.0.0/fixture"), b"drift").unwrap()
            }
            "foreign-alias" | "missing-alias" | "foreign-current" => {
                let path = if change == "foreign-current" {
                    request.version_pointer.clone()
                } else {
                    layout.bin_dir.join("fixture")
                };
                fs::remove_file(&path).unwrap();
                if change != "missing-alias" {
                    symlink(root.path().join("foreign"), &path).unwrap();
                }
            }
            "receipt" => fs::write(
                layout.data_root.join("installation-receipt-v1.json"),
                b"foreign",
            )
            .unwrap(),
            "bound" => bound = 1,
            _ => {}
        }
        let before = fs::read(&journal).unwrap();
        let mut callback_ran = false;
        assert!(
            versioned_v2::legacy_adoption::resume(layout, bound, |_| {
                callback_ran = true;
                if change == "callback-journal" {
                    fs::write(&journal, b"callback drift")?;
                }
                if change == "callback-artifact" {
                    fs::write(layout.data_root.join("versions/1.0.0/fixture"), b"drift")?;
                }
                Ok(())
            })
            .is_err(),
            "{change}"
        );
        assert_eq!(callback_ran, change.starts_with("callback-"), "{change}");
        if change != "callback-journal" {
            assert_eq!(fs::read(&journal).unwrap(), before, "{change}");
        }
        assert!(!layout.data_root.join("active").exists(), "{change}");
    }
}

#[test]
fn active_only_adoption_preserves_unclaimed_versions_and_absent_alias_history() {
    let root = tempfile::tempdir().unwrap();
    let (request, mut expected) = fixture(root.path());
    let layout = &request.adoption.layout;
    expected.previous_version = None;
    expected.previous_identity = None;
    fs::remove_file(&request.version_pointer).unwrap();
    fs::remove_file(layout.bin_dir.join("fixture")).unwrap();
    assert!(
        versioned_v2::legacy_adoption::prepare(&request, &expected, 1024)
            .unwrap()
            .commit(|_| anyhow::bail!("park"))
            .is_err()
    );
    symlink(
        layout.data_root.join("versions/2.0.0"),
        &request.version_pointer,
    )
    .unwrap();
    assert!(
        versioned_v2::legacy_adoption::resume(layout, 1024, |_| panic!(
            "newly appeared pointer was not owned"
        ))
        .is_err()
    );
    fs::remove_file(&request.version_pointer).unwrap();
    assert_eq!(
        versioned_v2::legacy_adoption::resume(layout, 1024, |_| Ok(())).unwrap(),
        expected
    );
    assert_eq!(versioned_v2::observe(layout, 1024).unwrap(), Some(expected));
    assert_eq!(
        fs::read(layout.data_root.join("versions/1.0.0/fixture")).unwrap(),
        b"1.0.0"
    );
    assert_eq!(
        fs::metadata(layout.data_root.join("versions/1.0.0"))
            .unwrap()
            .mode()
            & 0o777,
        0o755
    );
}
