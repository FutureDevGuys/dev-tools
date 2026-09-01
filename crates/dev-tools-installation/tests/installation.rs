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
        },
        version: version.into(),
        source,
        identity,
        aliases: vec!["fixture".into(), "fixture-helper".into()],
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
    fs::set_permissions(
        &first.layout.data_root,
        fs::Permissions::from_mode(first.layout.directory_mode),
    )
    .unwrap();
    fs::set_permissions(
        first.layout.data_root.join("versions"),
        fs::Permissions::from_mode(first.layout.directory_mode),
    )
    .unwrap();
    fs::set_permissions(
        artifact.parent().unwrap(),
        fs::Permissions::from_mode(first.layout.directory_mode),
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
