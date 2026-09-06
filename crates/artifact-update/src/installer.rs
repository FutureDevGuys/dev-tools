//! Signed Linux binary installation; staging leases precede ledger/installation locks.
use crate::ledger_store::LedgerStore;
use dev_tools_installation::{
    apply_versioned_installation_if_unchanged, observe_versioned_installation, ArtifactIdentity,
    StagingArea, VersionedApplyReport, VersionedInstallRequest, VersionedLayout, VersionedReceipt,
};
use dev_tools_release::{ReleaseAuthority, ReleaseMetadata};
use dev_tools_update::artifact::{ArtifactRecord, InstallationPolicy, VersionRule};
use dev_tools_update::discovery::{compare_release_tags, ReleaseComparison};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

type Failure = (&'static str, i32);

fn staging_area(
    root: &Path,
    layout: &VersionedLayout,
    aliases: &[String],
) -> Result<StagingArea, Failure> {
    // Stable domain and length-delimited local target fields, never version or
    // remote metadata. Unrelated config/cache changes keep the target reservation.
    let mut digest = Sha256::new();
    digest.update(b"artifact-update-staging-target-v1\0");
    for value in [
        layout.product.as_bytes(),
        layout.data_root.as_os_str().as_bytes(),
        layout.bin_dir.as_os_str().as_bytes(),
        layout.artifact_name.as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(layout.owner_uid.to_be_bytes());
    digest.update((aliases.len() as u64).to_be_bytes());
    for alias in aliases {
        digest.update((alias.len() as u64).to_be_bytes());
        digest.update(alias.as_bytes());
    }
    let target: [u8; 32] = digest.finalize().into();
    let key: String = target.iter().map(|byte| format!("{byte:02x}")).collect();
    let path = root.join(key);
    let area = StagingArea::new(path.clone(), layout.owner_uid, target)
        .map_err(|_| ("staging-unavailable", 4))?;
    area.recover_initial_publication()
        .map_err(|_| ("staging-recovery-failed", 4))?;
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Deliberate reservation of a product-owned target slot, never
            // adoption of an existing empty directory or retry after collision.
            area.initialize_recoverable()
                .map_err(|_| ("staging-initialization-failed", 1))?;
        }
        Err(_) => return Err(("staging-unavailable", 4)),
        Ok(_) => {}
    }
    Ok(area)
}

pub(super) struct Progress {
    pub network_accessed: bool,
    pub changed: Option<bool>,
    pub metadata_cache_changed: Option<bool>,
    pub artifact_cache_changed: Option<bool>,
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            network_accessed: false,
            changed: Some(false),
            metadata_cache_changed: Some(false),
            artifact_cache_changed: Some(false),
        }
    }
}

pub(super) fn execute(
    record: &ArtifactRecord,
    config: &[u8],
    offline: bool,
    progress: &mut Progress,
) -> Result<VersionedApplyReport, Failure> {
    let store = LedgerStore::for_record(record).map_err(|_| ("authority-unavailable", 4))?;
    let staging = crate::native_metadata_root("artifact-staging-v1")
        .map_err(|_| ("staging-unavailable", 1))?;
    let cache = crate::signed_metadata_store().map_err(|_| ("metadata-cache-unavailable", 1))?;
    let artifacts = crate::artifact_cache::Store::new(
        crate::native_metadata_root("artifacts-v1")
            .map_err(|_| ("artifact-cache-unavailable", 1))?,
        rustix::process::geteuid().as_raw(),
    )
    .map_err(|_| ("artifact-cache-unavailable", 1))?;
    let key = crate::signed_metadata_key(config, record.id());
    if offline {
        return execute_with_sources(
            record,
            &store,
            &staging,
            progress,
            true,
            || {
                cache
                    .load(&key)
                    .map_err(|_| ("metadata-cache-invalid", 4))?
                    .map(|snapshot| snapshot.metadata)
                    .ok_or(("offline-metadata-unavailable", 3))
            },
            |metadata, authority, writer| {
                let verified = dev_tools_release::verify_release_metadata(metadata, authority)
                    .map_err(|_| ("release-authentication-failed", 4))?;
                let identity = ArtifactIdentity {
                    length: verified.artifact_length,
                    sha256: verified.artifact_sha256,
                };
                if !artifacts
                    .stage(&identity, writer)
                    .map_err(|_| ("artifact-cache-invalid", 4))?
                {
                    return Err(("offline-artifact-unavailable", 3));
                }
                Ok(())
            },
        );
    }
    let mut fetched = None;
    let report = execute_with_fetch(
        record,
        &store,
        &staging,
        progress,
        || {
            let (metadata, _) = dev_tools_update::discovery::check_static_manifest(record)
                .map_err(metadata_failure)?;
            fetched = Some(metadata.clone());
            Ok(metadata)
        },
        |metadata, authority, writer| {
            let dev_tools_release::ArtifactUrlPolicy::Exact(url) = &authority.artifact_url else {
                return Err(("unsupported-artifact-authority", 3));
            };
            let host = dev_tools_release::canonical_https_host(url)
                .map_err(|_| ("authority-unavailable", 4))?;
            let policy = dev_tools_release::HttpsPolicy {
                allowed_hosts: std::collections::BTreeSet::from([host]),
                max_redirects: 2,
                timeout: std::time::Duration::from_secs(120),
                user_agent: "artifact-update".into(),
            };
            dev_tools_release::fetch_artifact_to_staging(
                metadata,
                authority,
                &policy,
                256 * 1024 * 1024,
                writer,
            )
            .map(|_| ())
            .map_err(|error| {
                transfer_failure(
                    error
                        .downcast_ref::<dev_tools_release::ArtifactTransferError>()
                        .map(dev_tools_release::ArtifactTransferError::kind),
                )
            })
        },
    )?;
    publish_artifact_cache(progress, &artifacts, &report.receipt)?;
    // Successful installation must not leave a prior discovery cache conflicting
    // with the newly accepted ledger. Cache failure cannot undo activation.
    publish_cache(progress, || {
        cache.save_cache(
            &key,
            &fetched.ok_or("metadata-cache-unavailable")?,
            crate::unix_now()?,
        )
    })?;
    Ok(report)
}

fn publish_artifact_cache(
    progress: &mut Progress,
    cache: &crate::artifact_cache::Store,
    receipt: &VersionedReceipt,
) -> Result<(), Failure> {
    progress.artifact_cache_changed = None;
    let source = receipt
        .data_root
        .join("versions")
        .join(&receipt.active_version)
        .join(&receipt.artifact_name);
    let changed = cache
        .save_executable(&source, &receipt.active_identity)
        .map_err(|_| ("artifact-cache-unavailable", 1))?;
    progress.artifact_cache_changed = Some(changed);
    Ok(())
}

fn publish_cache(
    progress: &mut Progress,
    publish: impl FnOnce() -> Result<bool, String>,
) -> Result<(), Failure> {
    progress.metadata_cache_changed = None;
    let changed = publish().map_err(|_| ("metadata-cache-unavailable", 1))?;
    progress.metadata_cache_changed = Some(changed);
    Ok(())
}

fn metadata_failure(error: dev_tools_update::discovery::DiscoveryError) -> Failure {
    use dev_tools_update::discovery::DiscoveryError;
    match error {
        DiscoveryError::Authentication | DiscoveryError::Acceptance => {
            ("release-authentication-failed", 4)
        }
        DiscoveryError::InvalidMetadata
        | DiscoveryError::Ambiguous
        | DiscoveryError::InventoryLimit => ("release-metadata-invalid", 4),
        DiscoveryError::UnsupportedSource => ("unsupported-source", 3),
        _ => ("release-unavailable", 1),
    }
}

fn transfer_failure(kind: Option<dev_tools_release::ArtifactTransferErrorKind>) -> Failure {
    use dev_tools_release::ArtifactTransferErrorKind;
    match kind {
        Some(ArtifactTransferErrorKind::Authentication) => ("release-authentication-failed", 4),
        Some(ArtifactTransferErrorKind::Integrity) => ("artifact-integrity-failed", 4),
        Some(ArtifactTransferErrorKind::InvalidLimit) => ("artifact-limit-exceeded", 4),
        Some(ArtifactTransferErrorKind::Storage) => ("staging-unavailable", 1),
        _ => ("artifact-unavailable", 1),
    }
}

fn execute_with_fetch(
    record: &ArtifactRecord,
    store: &LedgerStore,
    staging_root: &Path,
    progress: &mut Progress,
    fetch_metadata: impl FnOnce() -> Result<ReleaseMetadata, Failure>,
    fetch_artifact: impl FnOnce(&ReleaseMetadata, &ReleaseAuthority, &mut File) -> Result<(), Failure>,
) -> Result<VersionedApplyReport, Failure> {
    execute_with_sources(
        record,
        store,
        staging_root,
        progress,
        false,
        fetch_metadata,
        fetch_artifact,
    )
}

fn execute_with_sources(
    record: &ArtifactRecord,
    store: &LedgerStore,
    staging_root: &Path,
    progress: &mut Progress,
    offline: bool,
    fetch_metadata: impl FnOnce() -> Result<ReleaseMetadata, Failure>,
    fetch_artifact: impl FnOnce(&ReleaseMetadata, &ReleaseAuthority, &mut File) -> Result<(), Failure>,
) -> Result<VersionedApplyReport, Failure> {
    let authority = record.release_authority().ok_or(("check-only", 3))?;
    if authority.target != format!("linux-{}", std::env::consts::ARCH) {
        return Err(("non-native-target", 3));
    }
    let Some(InstallationPolicy::VersionedBinary(config)) = record.installation() else {
        return Err(("installation-unconfigured", 3));
    };
    let owner = rustix::process::geteuid().as_raw();
    for (path, mode) in [(config.data_root(), 0o700), (config.bin_dir(), 0o755)] {
        crate::private_directory::inspect_directory(path, owner, mode)
            .map_err(|_| ("installation-authority-unavailable", 4))?;
    }
    let layout = VersionedLayout {
        product: record.id().into(),
        data_root: config.data_root().into(),
        bin_dir: config.bin_dir().into(),
        artifact_name: config.artifact_name().into(),
        owner_uid: owner,
        directory_mode: 0o700,
        bin_directory_mode: Some(0o755),
    };
    let prior = observe_versioned_installation(&layout, 256 * 1024 * 1024)
        .map_err(|_| ("installation-authority-unavailable", 4))?;
    let mut aliases = config.aliases().to_vec();
    aliases.sort();
    if let Some(receipt) = &prior {
        if receipt.aliases != aliases {
            return Err(("installation-authority-unavailable", 4));
        }
    } else {
        for alias in &aliases {
            match std::fs::symlink_metadata(layout.bin_dir.join(alias)) {
                Ok(_) => return Err(("external", 3)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(("installation-authority-unavailable", 4)),
            }
        }
    }
    let (mut proposed, identity) = store
        .load(record)
        .map_err(|_| ("authority-unavailable", 4))?
        .ok_or(("trust-initialization-required", 3))?;
    let staging = crate::private_directory::PrivateDirectory::new(staging_root.into(), owner)
        .map_err(|_| ("staging-unavailable", 4))?;
    staging.inspect().map_err(|_| ("staging-unavailable", 4))?;
    progress.network_accessed = !offline;
    let metadata = fetch_metadata()?;
    let (verified, acceptance_changed) = proposed
        .accept(record, &metadata)
        .map_err(|_| ("release-authentication-failed", 4))?;
    if offline && acceptance_changed {
        return Err(("offline-metadata-unaccepted", 4));
    }
    let version = verified.version.to_string();
    let artifact_identity = ArtifactIdentity {
        length: verified.artifact_length,
        sha256: verified.artifact_sha256,
    };
    if artifact_identity.length > 256 * 1024 * 1024 {
        return Err(("artifact-limit-exceeded", 4));
    }
    layout
        .validate_candidate(&version, &artifact_identity, &aliases)
        .map_err(|_| ("installation-layout-unsupported", 3))?;
    if let Some(receipt) = &prior {
        match compare_release_tags(
            &VersionRule::SemverTag {
                prefix: String::new(),
            },
            &receipt.active_version,
            &version,
        )
        .map_err(|_| ("installed-version-unavailable", 4))?
        {
            ReleaseComparison::Newer => {}
            ReleaseComparison::Equivalent if receipt.active_identity == artifact_identity => {}
            _ => return Err(("installation-version-conflict", 4)),
        }
    }
    let evidence =
        crate::signed_cache::Store::new(layout.data_root.join("release-evidence-v1"), owner)
            .map_err(|_| ("retained-evidence-unavailable", 4))?;
    let retained = retained_proofs(
        record,
        &evidence,
        prior.as_ref(),
        &version,
        &metadata,
        &proposed,
    )?;
    staging.ensure().map_err(|_| ("staging-unavailable", 4))?;
    let area = staging_area(staging_root, &layout, &aliases)?;
    let mut candidate = area
        .try_acquire()
        .map_err(|_| ("staging-unavailable", 4))?
        .ok_or(("staging-busy", 3))?;
    fetch_artifact(&metadata, &authority, candidate.file_mut())?;
    candidate
        .file_mut()
        .sync_all()
        .map_err(|_| ("staging-unavailable", 1))?;
    if ArtifactIdentity::from_file(candidate.path(), 256 * 1024 * 1024)
        .map_err(|_| ("artifact-integrity-failed", 4))?
        != artifact_identity
    {
        return Err(("artifact-integrity-failed", 4));
    }
    // After this boundary, publication failures may leave durable accepted state.
    progress.changed = None;
    let (accepted_identity, ledger_changed) = if offline {
        (identity, false)
    } else {
        let (_, ledger_changed) = store
            .transaction(
                record,
                crate::ledger_store::LedgerExpectation::Current(identity),
                |ledger| {
                    ledger
                        .accept(record, &metadata)
                        .map(|_| ())
                        .map_err(|_| "release acceptance failed".into())
                },
            )
            .map_err(|_| ("release-acceptance-conflict", 4))?;
        let (_, accepted_identity) = store
            .load(record)
            .map_err(|_| ("authority-unavailable", 4))?
            .ok_or(("authority-unavailable", 4))?;
        (accepted_identity, ledger_changed)
    };
    let request = VersionedInstallRequest {
        layout,
        version: version.clone(),
        source: candidate.path().into(),
        identity: artifact_identity.clone(),
        aliases,
    };
    let mut evidence_changed = false;
    let report = store
        .with_current(record, &accepted_identity, |ledger| {
            // Reauthentication plus an unchanged acceptance transition prevents a
            // concurrent metadata check from changing trust before activation.
            let mut current = ledger.clone();
            if current
                .accept(record, &metadata)
                .map_err(|_| "release acceptance changed")?
                .1
            {
                return Err("release acceptance changed".into());
            }
            apply_versioned_installation_if_unchanged(&request, prior.as_ref(), |_| {
                for (key, proof) in &retained {
                    evidence_changed |= evidence
                        .save(key, proof, 0)
                        .map_err(std::io::Error::other)?;
                }
                evidence_changed |= evidence
                    .save(
                        &crate::retained_evidence::key(&version, &artifact_identity),
                        &metadata,
                        0,
                    )
                    .map_err(std::io::Error::other)?;
                Ok(())
            })
            .map_err(|_| "installation activation failed".into())
        })
        .map_err(|_| ("installation-activation-failed", 4))?;
    progress.changed = Some(report.changed || ledger_changed || evidence_changed);
    candidate
        .cleanup()
        .map_err(|_| ("staging-cleanup-failed", 1))?;
    Ok(report)
}

fn retained_proofs(
    record: &ArtifactRecord,
    store: &crate::signed_cache::Store,
    prior: Option<&VersionedReceipt>,
    candidate_version: &str,
    metadata: &ReleaseMetadata,
    ledger: &dev_tools_update::manifest_ledger::ManifestLedger,
) -> Result<Vec<(String, ReleaseMetadata)>, Failure> {
    let Some(prior) = prior else {
        return Ok(Vec::new());
    };
    let mut versions = vec![(prior.active_version.as_str(), &prior.active_identity)];
    if prior.active_version == candidate_version {
        if let (Some(version), Some(identity)) = (&prior.previous_version, &prior.previous_identity)
        {
            versions.push((version, identity));
        }
    }
    let mut proofs = Vec::new();
    for (version, identity) in versions {
        let key = crate::retained_evidence::key(version, identity);
        let snapshot = store
            .load(&key)
            .map_err(|_| ("retained-evidence-unavailable", 4))?
            .ok_or(("retained-evidence-required", 4))?;
        let proof = ReleaseMetadata {
            root: metadata.root.clone(),
            manifest: snapshot.metadata.manifest,
        };
        let verified = ledger
            .verify_retained_metadata(record, &proof)
            .map_err(|_| ("retained-evidence-invalid", 4))?;
        if verified.version.to_string() != version
            || verified.artifact_length != identity.length
            || verified.artifact_sha256 != identity.sha256
        {
            return Err(("retained-evidence-invalid", 4));
        }
        proofs.push((key, proof));
    }
    Ok(proofs)
}

#[cfg(test)]
mod tests {
    fn assert_staging_payload(root: &Path, pending: bool) -> std::path::PathBuf {
        let entries: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir())
            .collect();
        assert_eq!(entries.len(), 1);
        let reservation = &entries[0];
        assert!(reservation.join("staging-reservation-v1.json").is_file());
        assert!(reservation.join("staging.lock").is_file());
        assert_eq!(reservation.join("payload").exists(), pending);
        assert_eq!(
            std::fs::read_dir(reservation).unwrap().count(),
            if pending { 3 } else { 2 }
        );
        reservation.join("payload")
    }

    #[test]
    fn offline_install_reuses_only_accepted_cached_bytes_without_ledger_writes() {
        use std::os::unix::fs::PermissionsExt;
        for accepted in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let bytes = b"inert offline fixture";
            let (catalog, metadata) =
                crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
            let record = catalog.get("example").unwrap();
            let owner = temp.path().metadata().unwrap().uid();
            let store = LedgerStore::new(temp.path().join("ledger"), owner).unwrap();
            store
                .transaction(record, LedgerExpectation::FirstUse, |ledger| {
                    if accepted {
                        ledger.accept(record, &metadata).unwrap();
                    }
                    Ok(())
                })
                .unwrap();
            let ledger_path = temp.path().join("ledger/ledger.json");
            let before = std::fs::read(&ledger_path).unwrap();
            let modified = ledger_path.metadata().unwrap().modified().unwrap();
            let source = temp.path().join("source");
            std::fs::write(&source, bytes).unwrap();
            std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
            let identity = ArtifactIdentity::from_file(&source, 1024).unwrap();
            let cache =
                crate::artifact_cache::Store::new(temp.path().join("cache"), owner).unwrap();
            cache.save_executable(&source, &identity).unwrap();
            std::fs::remove_file(source).unwrap();
            let mut progress = Progress::default();
            let result = execute_with_sources(
                record,
                &store,
                &temp.path().join("staging"),
                &mut progress,
                true,
                || Ok(metadata.clone()),
                |_, _, writer| {
                    assert!(cache.stage(&identity, writer).unwrap());
                    Ok(())
                },
            );
            if accepted {
                assert!(
                    result.is_ok(),
                    "accepted cached bytes must install: {result:?}"
                );
                assert_eq!(
                    std::fs::read(temp.path().join("bin/example")).unwrap(),
                    bytes
                );
            } else {
                assert!(
                    result.is_err(),
                    "offline cache must not advance unaccepted metadata"
                );
                assert!(!temp.path().join("data").exists());
            }
            assert!(!progress.network_accessed);
            assert_eq!(std::fs::read(&ledger_path).unwrap(), before);
            assert_eq!(
                ledger_path.metadata().unwrap().modified().unwrap(),
                modified
            );
        }
    }

    use super::*;
    use crate::ledger_store::LedgerExpectation;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn authenticated_recovery_requires_retained_proof_and_preserves_ledger() {
        use std::os::unix::fs::PermissionsExt;
        for committed in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let owner = temp.path().metadata().unwrap().uid();
            let store = LedgerStore::new(temp.path().join("ledger"), owner).unwrap();
            let (catalog, metadata) =
                crate::signed_check_tests::installation_fixture(2, "1.2.3", b"first", temp.path());
            let record = catalog.get("example").unwrap();
            store
                .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
                .unwrap();
            let report = execute_with_fetch(
                record,
                &store,
                &temp.path().join("staging"),
                &mut Progress::default(),
                || Ok(metadata),
                |_, _, writer| {
                    writer.write_all(b"first").unwrap();
                    Ok(())
                },
            )
            .unwrap();
            let journal = temp.path().join("data/installation-transition-v1.json");
            if !committed {
                std::fs::remove_file(temp.path().join("data/installation-receipt-v1.json"))
                    .unwrap();
            }
            let pending = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1", "prior": null, "next": report.receipt,
        }))
        .unwrap();
            std::fs::write(&journal, &pending).unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
            let ledger = std::fs::read(temp.path().join("ledger/ledger.json")).unwrap();
            let proof = temp.path().join("data/release-evidence-v1").join(format!(
                "{}.cache",
                crate::retained_evidence::key("1.2.3", &report.receipt.active_identity)
            ));
            let proof_bytes = std::fs::read(&proof).unwrap();
            std::fs::remove_file(&proof).unwrap();
            let mut changed = Some(false);
            assert!(crate::recovery::execute_with_store(record, &store, &mut changed).is_err());
            assert_eq!(std::fs::read(&journal).unwrap(), pending);
            assert_eq!(
                std::fs::read(temp.path().join("bin/example")).unwrap(),
                b"first"
            );
            std::fs::write(&proof, proof_bytes).unwrap();
            std::fs::set_permissions(&proof, std::fs::Permissions::from_mode(0o600)).unwrap();
            let (recovered, receipt) =
                crate::recovery::execute_with_store(record, &store, &mut changed)
                    .expect("authenticated journal must recover");
            assert!(recovered);
            assert_eq!(receipt, committed.then_some(report.receipt));
            assert_eq!(
                std::fs::symlink_metadata(temp.path().join("bin/example")).is_ok(),
                committed
            );
            assert_eq!(changed, Some(true));
            assert!(!journal.exists());
            assert_eq!(
                std::fs::read(temp.path().join("ledger/ledger.json")).unwrap(),
                ledger
            );
            assert!(
                !crate::recovery::execute_with_store(record, &store, &mut changed)
                    .unwrap()
                    .0
            );
            assert_eq!(changed, Some(false));
        }
    }

    #[test]
    fn authenticated_rollback_swaps_retained_bytes_without_rewinding_ledger() {
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().metadata().unwrap().uid();
        let store = LedgerStore::new(temp.path().join("ledger"), owner).unwrap();
        for (generation, version, bytes) in [
            (2, "1.2.3", b"first".as_slice()),
            (3, "1.2.4", b"second".as_slice()),
        ] {
            let (catalog, metadata) = crate::signed_check_tests::installation_fixture(
                generation,
                version,
                bytes,
                temp.path(),
            );
            let record = catalog.get("example").unwrap();
            if generation == 2 {
                store
                    .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
                    .unwrap();
            }
            execute_with_fetch(
                record,
                &store,
                &temp.path().join("staging"),
                &mut Progress::default(),
                || Ok(metadata),
                |_, _, writer| {
                    writer.write_all(bytes).unwrap();
                    Ok(())
                },
            )
            .unwrap();
        }
        let (catalog, _) =
            crate::signed_check_tests::installation_fixture(3, "1.2.4", b"second", temp.path());
        let record = catalog.get("example").unwrap();
        let ledger = std::fs::read(temp.path().join("ledger/ledger.json")).unwrap();
        let mut changed = Some(false);
        let result = crate::rollback::execute_with_store(record, &store, &mut changed)
            .expect("authenticated retained rollback must succeed");
        assert_eq!(result.receipt.active_version, "1.2.3");
        assert_eq!(result.receipt.previous_version.as_deref(), Some("1.2.4"));
        assert_eq!(changed, Some(true));
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            b"first"
        );
        assert_eq!(
            std::fs::read(temp.path().join("ledger/ledger.json")).unwrap(),
            ledger
        );
        let proof = temp.path().join("data/release-evidence-v1").join(format!(
            "{}.cache",
            crate::retained_evidence::key(
                "1.2.4",
                result.receipt.previous_identity.as_ref().unwrap()
            )
        ));
        let proof_bytes = std::fs::read(&proof).unwrap();
        std::fs::remove_file(&proof).unwrap();
        changed = Some(false);
        assert!(crate::rollback::execute_with_store(record, &store, &mut changed).is_err());
        assert_eq!(changed, Some(false));
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            b"first"
        );
        assert!(!proof.exists());
        std::fs::write(&proof, proof_bytes).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&proof, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (_, rotated) = crate::signed_check_tests::installation_fixture_with_rotation(
            4,
            "1.2.5",
            b"third",
            temp.path(),
            Some(true),
        );
        let (_, identity) = store.load(record).unwrap().unwrap();
        store
            .transaction(record, LedgerExpectation::Current(identity), |ledger| {
                ledger
                    .accept(record, &rotated)
                    .map(|_| ())
                    .map_err(|_| "fixture".into())
            })
            .unwrap();
        changed = Some(false);
        assert!(crate::rollback::execute_with_store(record, &store, &mut changed).is_err());
        assert_eq!(changed, Some(false));
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            b"first"
        );
    }

    #[test]
    fn discovery_cache_change_is_separate_from_durable_installation_change() {
        let mut progress = Progress::default();
        publish_cache(&mut progress, || Ok(true)).unwrap();
        assert_eq!(progress.changed, Some(false));
        assert_eq!(progress.metadata_cache_changed, Some(true));
        publish_cache(&mut progress, || Ok(false)).unwrap();
        assert_eq!(progress.metadata_cache_changed, Some(false));
        assert!(publish_cache(&mut progress, || Err("late publication failure".into())).is_err());
        assert_eq!(progress.changed, Some(false));
        assert_eq!(progress.metadata_cache_changed, None);
    }

    #[test]
    fn transfer_outcomes_distinguish_operational_failure_from_authenticity() {
        use dev_tools_release::ArtifactTransferErrorKind as Kind;
        use dev_tools_update::discovery::DiscoveryError;
        for kind in [Kind::Authentication, Kind::Integrity, Kind::InvalidLimit] {
            assert_eq!(transfer_failure(Some(kind)).1, 4);
        }
        for kind in [Some(Kind::Transport), Some(Kind::Storage), None] {
            assert_eq!(transfer_failure(kind).1, 1);
        }
        assert_eq!(metadata_failure(DiscoveryError::Unavailable).1, 1);
        assert_eq!(metadata_failure(DiscoveryError::Authentication).1, 4);
        assert_eq!(metadata_failure(DiscoveryError::Acceptance).1, 4);
    }

    #[test]
    fn signed_build_metadata_is_exact_and_oversized_layout_versions_never_commit() {
        for version in [
            "1.2.3+build.1".to_owned(),
            format!("1.2.3+{}", "a".repeat(123)),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let bytes = b"inert version fixture";
            let (catalog, metadata) =
                crate::signed_check_tests::installation_fixture(2, &version, bytes, temp.path());
            let record = catalog.get("example").unwrap();
            let store = LedgerStore::new(
                temp.path().join("ledger"),
                temp.path().metadata().unwrap().uid(),
            )
            .unwrap();
            store
                .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
                .unwrap();
            let original = std::fs::read(temp.path().join("ledger/ledger.json")).unwrap();
            let mut downloaded = false;
            let result = execute_with_fetch(
                record,
                &store,
                &temp.path().join("staging"),
                &mut Progress::default(),
                || Ok(metadata.clone()),
                |_, _, writer| {
                    downloaded = true;
                    writer.write_all(bytes).unwrap();
                    Ok(())
                },
            );
            if version.len() > 128 {
                assert_eq!(result.unwrap_err(), ("installation-layout-unsupported", 3));
                assert!(!downloaded && !temp.path().join("data").exists());
                assert_eq!(
                    std::fs::read(temp.path().join("ledger/ledger.json")).unwrap(),
                    original
                );
            } else {
                assert_eq!(result.unwrap().receipt.active_version, version);
                assert!(downloaded);
            }
        }
    }

    #[test]
    fn upgrade_refreshes_retained_roots_but_rejects_a_revoked_rollback_signer() {
        for revoked in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let bytes = b"first inert bytes";
            let (catalog, metadata) =
                crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
            let record = catalog.get("example").unwrap();
            let owner = temp.path().metadata().unwrap().uid();
            let store = LedgerStore::new(temp.path().join("ledger"), owner).unwrap();
            store
                .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
                .unwrap();
            let first = execute_with_fetch(
                record,
                &store,
                &temp.path().join("staging"),
                &mut Progress::default(),
                || Ok(metadata.clone()),
                |_, _, writer| {
                    writer.write_all(bytes).unwrap();
                    Ok(())
                },
            )
            .unwrap();
            let next_bytes = b"new signer, new inert bytes";
            let (next_catalog, next_metadata) =
                crate::signed_check_tests::installation_fixture_with_rotation(
                    3,
                    "1.2.4",
                    next_bytes,
                    temp.path(),
                    Some(revoked),
                );
            let next = next_catalog.get("example").unwrap();
            // Model an explicit check accepting the new root before install.
            let (_, identity) = store.load(next).unwrap().unwrap();
            store
                .transaction(next, LedgerExpectation::Current(identity), |ledger| {
                    ledger
                        .accept(next, &next_metadata)
                        .map(|_| ())
                        .map_err(|_| "fixture".into())
                })
                .unwrap();
            let ledger_bytes = std::fs::read(temp.path().join("ledger/ledger.json")).unwrap();
            let evidence = crate::signed_cache::Store::new(
                temp.path().join("data/release-evidence-v1"),
                owner,
            )
            .unwrap();
            let key = crate::retained_evidence::key("1.2.3", &first.receipt.active_identity);
            let original = evidence.load(&key).unwrap().unwrap().metadata;
            let mut downloaded = false;
            let result = execute_with_fetch(
                next,
                &store,
                &temp.path().join("staging"),
                &mut Progress::default(),
                || Ok(next_metadata.clone()),
                |_, _, writer| {
                    downloaded = true;
                    writer.write_all(next_bytes).unwrap();
                    Ok(())
                },
            );
            if revoked {
                assert_eq!(result.unwrap_err(), ("retained-evidence-invalid", 4));
                assert!(!downloaded);
                assert_eq!(
                    std::fs::read(temp.path().join("bin/example")).unwrap(),
                    bytes
                );
                assert_eq!(evidence.load(&key).unwrap().unwrap().metadata, original);
            } else {
                assert!(result.is_ok());
                assert!(downloaded);
                let refreshed = evidence.load(&key).unwrap().unwrap().metadata;
                assert_eq!(refreshed.manifest, original.manifest);
                assert_eq!(refreshed.root, next_metadata.root);
                assert!(crate::retained_evidence::verify(
                    &evidence,
                    next,
                    "1.2.3",
                    &first.receipt.active_identity,
                    || Ok(store.load(next).unwrap().unwrap().0)
                )
                .unwrap());
            }
            assert_eq!(
                std::fs::read(temp.path().join("ledger/ledger.json")).unwrap(),
                ledger_bytes
            );
        }
    }

    #[test]
    fn proof_publication_failure_never_activates_and_preserves_accepted_ledger() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"inert publication fixture";
        let (catalog, metadata) =
            crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
        let record = catalog.get("example").unwrap();
        let owner = temp.path().metadata().unwrap().uid();
        let store = LedgerStore::new(temp.path().join("ledger"), owner).unwrap();
        store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        let data = temp.path().join("data");
        crate::private_directory::PrivateDirectory::new(data.clone(), owner)
            .unwrap()
            .ensure()
            .unwrap();
        let untouched = temp.path().join("untouched");
        std::fs::create_dir(&untouched).unwrap();
        std::os::unix::fs::symlink(&untouched, data.join("release-evidence-v1")).unwrap();
        let mut progress = Progress::default();
        assert!(execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                writer.write_all(bytes).unwrap();
                Ok(())
            }
        )
        .is_err());
        assert_eq!(progress.changed, None);
        assert!(!data.join("installation-receipt-v1.json").exists());
        assert!(!temp.path().join("bin/example").exists());
        assert_eq!(std::fs::read_dir(&untouched).unwrap().count(), 0);
        let (mut accepted, _) = store.load(record).unwrap().unwrap();
        assert!(!accepted.accept(record, &metadata).unwrap().1);
        std::fs::remove_file(data.join("release-evidence-v1")).unwrap();
        assert!(execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                writer.write_all(bytes).unwrap();
                Ok(())
            }
        )
        .is_ok());
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            bytes
        );
    }

    #[test]
    fn signed_install_publishes_receipt_bound_evidence_without_executing_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"inert signed fixture, never an executable program";
        let (catalog, metadata) =
            crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
        let record = catalog.get("example").unwrap();
        let store = LedgerStore::new(
            temp.path().join("ledger"),
            temp.path().metadata().unwrap().uid(),
        )
        .unwrap();
        store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        let mut progress = Progress::default();
        let report = execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                writer.write_all(bytes).unwrap();
                Ok(())
            },
        );
        assert!(
            report.is_ok(),
            "signed bytes must reach managed activation: {report:?}"
        );
        let report = report.unwrap();
        assert_eq!(report.receipt.active_version, "1.2.3");
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            bytes
        );
        assert!(progress.network_accessed);
        assert_eq!(progress.changed, Some(true));
        let artifacts = crate::artifact_cache::Store::new(
            temp.path().join("artifacts"),
            temp.path().metadata().unwrap().uid(),
        )
        .unwrap();
        publish_artifact_cache(&mut progress, &artifacts, &report.receipt).unwrap();
        assert_eq!(progress.artifact_cache_changed, Some(true));
        let mut cached = Vec::new();
        assert!(artifacts
            .stage(&report.receipt.active_identity, &mut cached)
            .unwrap());
        assert_eq!(cached, bytes);
        publish_artifact_cache(&mut progress, &artifacts, &report.receipt).unwrap();
        assert_eq!(progress.artifact_cache_changed, Some(false));
        let cache_path = std::fs::read_dir(temp.path().join("artifacts"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().is_some_and(|value| value == "artifact"))
            .unwrap();
        std::fs::write(cache_path, b"cache drift").unwrap();
        assert!(publish_artifact_cache(&mut progress, &artifacts, &report.receipt).is_err());
        assert_eq!(progress.artifact_cache_changed, None);
        assert_eq!(progress.changed, Some(true));
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            bytes
        );
        let evidence = crate::signed_cache::Store::new(
            temp.path().join("data/release-evidence-v1"),
            temp.path().metadata().unwrap().uid(),
        )
        .unwrap();
        assert!(crate::retained_evidence::verify(
            &evidence,
            record,
            "1.2.3",
            &report.receipt.active_identity,
            || Ok(store.load(record).unwrap().unwrap().0)
        )
        .unwrap());
        assert_staging_payload(&temp.path().join("staging"), false);
        let receipt_bytes =
            std::fs::read(temp.path().join("data/installation-receipt-v1.json")).unwrap();
        let replay = execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                writer.write_all(bytes).unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert!(!replay.changed);
        assert_eq!(progress.changed, Some(false));
        assert_eq!(
            std::fs::read(temp.path().join("data/installation-receipt-v1.json")).unwrap(),
            receipt_bytes
        );
        let next_bytes = b"second inert fixture";
        let (next_catalog, next_metadata) =
            crate::signed_check_tests::installation_fixture(3, "1.2.4", next_bytes, temp.path());
        let next = next_catalog.get("example").unwrap();
        let upgraded = execute_with_fetch(
            next,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(next_metadata.clone()),
            |_, _, writer| {
                writer.write_all(next_bytes).unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(upgraded.receipt.previous_version.as_deref(), Some("1.2.3"));
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            next_bytes
        );
        assert_eq!(
            std::fs::read(temp.path().join("data/previous")).unwrap(),
            bytes
        );
        assert!(crate::retained_evidence::verify(
            &evidence,
            next,
            "1.2.3",
            &report.receipt.active_identity,
            || Ok(store.load(next).unwrap().unwrap().0)
        )
        .unwrap());
    }

    #[test]
    fn install_rejects_missing_trust_and_bad_bytes_without_durable_acceptance() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"expected bytes";
        let (catalog, metadata) =
            crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
        let record = catalog.get("example").unwrap();
        let root = temp.path().join("ledger");
        let store = LedgerStore::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let mut progress = Progress::default();
        assert_eq!(
            execute_with_fetch(
                record,
                &store,
                &temp.path().join("staging"),
                &mut progress,
                || panic!("missing trust must not retrieve metadata"),
                |_, _, _| panic!("missing trust must not download")
            )
            .unwrap_err(),
            ("trust-initialization-required", 3)
        );
        assert!(!progress.network_accessed && !root.exists());
        store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        let original = std::fs::read(root.join("ledger.json")).unwrap();
        assert_eq!(
            execute_with_fetch(
                record,
                &store,
                &temp.path().join("staging"),
                &mut progress,
                || Ok(metadata.clone()),
                |_, _, writer| {
                    writer.write_all(b"wrong bytes").unwrap();
                    Ok(())
                }
            )
            .unwrap_err(),
            ("artifact-integrity-failed", 4)
        );
        assert_eq!(std::fs::read(root.join("ledger.json")).unwrap(), original);
        assert!(!temp.path().join("data").exists());
        let abandoned = assert_staging_payload(&temp.path().join("staging"), true);
        assert_eq!(std::fs::read(&abandoned).unwrap(), b"wrong bytes");
        assert_eq!(progress.changed, Some(false));
        let legacy = temp.path().join("staging/.old-unmarked-file");
        std::fs::write(&legacy, b"unknown ownership").unwrap();
        execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                assert_eq!(
                    writer.metadata().unwrap().len(),
                    0,
                    "residual bytes must be removed before reuse"
                );
                writer.write_all(bytes).unwrap();
                Ok(())
            },
        )
        .unwrap();
        assert!(!abandoned.exists());
        assert_eq!(std::fs::read(&legacy).unwrap(), b"unknown ownership");
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            bytes
        );
    }

    #[test]
    fn staging_lease_blocks_competing_download_without_touching_live_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"inert lease fixture";
        let (catalog, metadata) =
            crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
        let record = catalog.get("example").unwrap();
        let store = LedgerStore::new(
            temp.path().join("ledger"),
            temp.path().metadata().unwrap().uid(),
        )
        .unwrap();
        store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        let mut progress = Progress::default();
        execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                writer.write_all(bytes).unwrap();
                let mut downloaded = false;
                let nested = execute_with_fetch(
                    record,
                    &store,
                    &temp.path().join("staging"),
                    &mut Progress::default(),
                    || Ok(metadata.clone()),
                    |_, _, _| {
                        downloaded = true;
                        Ok(())
                    },
                );
                assert_eq!(nested.unwrap_err(), ("staging-busy", 3));
                assert!(!downloaded);
                assert_eq!(writer.metadata().unwrap().len(), bytes.len() as u64);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            bytes
        );
    }

    #[test]
    fn staging_cleanup_failure_reports_known_activation_without_deleting_unknown_files() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"inert cleanup fixture";
        let (catalog, metadata) =
            crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
        let record = catalog.get("example").unwrap();
        let store = LedgerStore::new(
            temp.path().join("ledger"),
            temp.path().metadata().unwrap().uid(),
        )
        .unwrap();
        store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        let mut progress = Progress::default();
        let mut unowned = None;
        let result = execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                writer.write_all(bytes).unwrap();
                let payload = assert_staging_payload(&temp.path().join("staging"), true);
                let path = payload.parent().unwrap().join("unowned");
                std::fs::write(&path, b"leave untouched").unwrap();
                unowned = Some(path);
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err(), ("staging-cleanup-failed", 1));
        assert_eq!(progress.changed, Some(true));
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            bytes
        );
        assert_eq!(std::fs::read(unowned.unwrap()).unwrap(), b"leave untouched");
    }

    #[test]
    fn same_release_concurrent_install_cannot_bypass_receipt_precondition() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"inert race fixture";
        let (catalog, metadata) =
            crate::signed_check_tests::installation_fixture(2, "1.2.3", bytes, temp.path());
        let record = catalog.get("example").unwrap();
        let store = LedgerStore::new(
            temp.path().join("ledger"),
            temp.path().metadata().unwrap().uid(),
        )
        .unwrap();
        store
            .transaction(record, LedgerExpectation::FirstUse, |ledger| {
                ledger
                    .accept(record, &metadata)
                    .map(|_| ())
                    .map_err(|_| "fixture".into())
            })
            .unwrap();
        let mut progress = Progress::default();
        let result = execute_with_fetch(
            record,
            &store,
            &temp.path().join("staging"),
            &mut progress,
            || Ok(metadata.clone()),
            |_, _, writer| {
                execute_with_fetch(
                    record,
                    &store,
                    &temp.path().join("other-staging"),
                    &mut Progress::default(),
                    || Ok(metadata.clone()),
                    |_, _, other| {
                        other.write_all(bytes).unwrap();
                        Ok(())
                    },
                )
                .unwrap();
                writer.write_all(bytes).unwrap();
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err(), ("installation-activation-failed", 4));
        assert_eq!(
            std::fs::read(temp.path().join("bin/example")).unwrap(),
            bytes
        );
        let receipt: VersionedReceipt = serde_json::from_slice(
            &std::fs::read(temp.path().join("data/installation-receipt-v1.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.active_version, "1.2.3");
        assert!(receipt.previous_version.is_none());
        assert_staging_payload(&temp.path().join("staging"), true);
        assert_staging_payload(&temp.path().join("other-staging"), false);
        assert_eq!(progress.changed, None);
    }
}
