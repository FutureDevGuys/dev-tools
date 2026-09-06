//! Product-owned local cutover. The common adapter supplies original signed
//! evidence before entry; this transaction performs no network or execution.
use super::*;
use dev_tools_installation::{
    read_atomic_document, retire_atomic_document, versioned_v2, write_atomic_document,
    ArtifactIdentity, DocumentAuthority,
};
use dev_tools_update::manifest_ledger::ManifestLedger;

const SCHEMA: &str = "update-all-release-authority-v2";
const STATE_NAME: &str = "release-authority-v2.json";
const PROOF_COUNT_LIMIT: usize = 3;
// Each of three root/manifest pairs is bounded independently. JSON string
// escaping can require six bytes per original byte.
const AUTHORITY_LIMIT: u64 = 6 * 2 * 3 * METADATA_LIMIT + 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    root: String,
    manifest: String,
}

impl Proof {
    fn from_metadata(metadata: &ReleaseMetadata) -> Result<Self> {
        let proof = Self {
            root: String::from_utf8(metadata.root.clone())?,
            manifest: String::from_utf8(metadata.manifest.clone())?,
        };
        proof.metadata()?;
        Ok(proof)
    }

    fn metadata(&self) -> Result<ReleaseMetadata> {
        for bytes in [self.root.as_bytes(), self.manifest.as_bytes()] {
            if bytes.is_empty() || bytes.len() as u64 > METADATA_LIMIT {
                bail!("retained release proof exceeds its bound");
            }
        }
        Ok(ReleaseMetadata {
            root: self.root.as_bytes().to_vec(),
            manifest: self.manifest.as_bytes().to_vec(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityDocument {
    schema: String,
    captured_identity: Option<ArtifactIdentity>,
    ledger: String,
    proofs: Vec<Proof>,
}

struct AcceptedAuthority {
    document: AuthorityDocument,
    ledger: ManifestLedger,
    releases: Vec<SharedVerifiedRelease>,
}

// This authority is confined to captured history and receipt-bound migration.
// It must never be used for online release discovery or candidate acceptance.
fn migration_authority(product: Product) -> ReleaseAuthority {
    ReleaseAuthority {
        trusted_root_key: env!("UPDATE_ALL_TRUST_ROOT_PUBLIC_KEY").into(),
        product: product.id().into(),
        accepted_manifest_schemas: vec![
            "dev-tools-product-v2".into(),
            "dev-tools-product-v1".into(),
        ],
        target: target_id(),
        artifact_url: ArtifactUrlPolicy::GitHubRelease {
            owner: "FutureDevGuys".into(),
            repository: "dev-tools".into(),
        },
        require_source_commit: false,
        engine_protocol: ENGINE_PROTOCOL,
    }
}

fn document_authority(paths: &Paths) -> Result<DocumentAuthority> {
    Ok(DocumentAuthority {
        limit: AUTHORITY_LIMIT,
        ..state_document_authority(paths)?
    })
}

impl AcceptedAuthority {
    fn validate(document: AuthorityDocument, product: Product) -> Result<Self> {
        if document.schema != SCHEMA || document.proofs.len() > PROOF_COUNT_LIMIT {
            bail!("invalid product release authority document");
        }
        let authority = migration_authority(product);
        let ledger =
            ManifestLedger::from_bytes_with_authority(document.ledger.as_bytes(), &authority)?;
        let mut releases = Vec::new();
        let mut exact_accepted_proof = false;
        for proof in &document.proofs {
            let metadata = proof.metadata()?;
            releases.push(ledger.verify_retained_with_authority(&authority, &metadata)?);
            let mut candidate = ledger.clone();
            exact_accepted_proof |= candidate
                .accept_release_metadata(&authority, &metadata)
                .is_ok_and(|(_, changed)| !changed);
        }
        let empty =
            ManifestLedger::import_release_state(&authority, SharedReleaseState::default())?;
        if ledger.to_bytes()? != empty.to_bytes()? && !exact_accepted_proof {
            bail!("captured acceptance history lacks its exact signed proof");
        }
        Ok(Self {
            document,
            ledger,
            releases,
        })
    }

    fn verify_receipt(&self, receipt: Option<&VersionedReceipt>) -> Result<()> {
        let Some(receipt) = receipt else {
            return Ok(());
        };
        let mut identities = vec![(receipt.active_version.as_str(), &receipt.active_identity)];
        match (&receipt.previous_version, &receipt.previous_identity) {
            (Some(version), Some(identity)) => identities.push((version.as_str(), identity)),
            (None, None) => {}
            _ => bail!("retained installation identity is incomplete"),
        }
        for (version, identity) in identities {
            if !self.releases.iter().any(|release| {
                release.version.to_string() == version
                    && release.artifact_length == identity.length
                    && release.artifact_sha256 == identity.sha256
            }) {
                bail!("installation receipt lacks an authenticated retained release proof");
            }
        }
        Ok(())
    }
}

fn load(product: Product, paths: &Paths) -> Result<AcceptedAuthority> {
    let document = read_atomic_document(
        &paths.product_root.join(STATE_NAME),
        &document_authority(paths)?,
    )?
    .context("initialized installation lacks its release authority")?;
    AcceptedAuthority::validate(serde_json::from_slice(&document.bytes)?, product)
}

pub(super) fn observe_authenticated(paths: &Paths) -> Result<Option<VersionedReceipt>> {
    let layout = shared_installation_layout(Product::UpdateAll, paths)?;
    let receipt = versioned_v2::observe(&layout, ARTIFACT_LIMIT)?;
    load(Product::UpdateAll, paths)?.verify_receipt(receipt.as_ref())?;
    Ok(receipt)
}

fn migration_history(paths: &Paths) -> Result<ReleaseState> {
    match dev_tools_installation::observe_retired_atomic_document(
        &paths.state,
        &state_document_authority(paths)?,
    )? {
        Some(retired) => match retired.captured {
            Some(document) => parse_json(&document.bytes, "captured release state"),
            None => Ok(ReleaseState::default()),
        },
        None => load_state(paths),
    }
}

/// Read the current acceptance authority without advancing or initializing it.
/// Captured legacy history is only admissible before completed v2 cutover.
pub(super) fn observation_ledger(paths: &Paths) -> Result<ManifestLedger> {
    let layout = shared_installation_layout(Product::UpdateAll, paths)?;
    if versioned_v2::read_receipt_metadata(&layout).is_ok() {
        return Ok(load(Product::UpdateAll, paths)?.ledger);
    }
    let state = migration_history(paths)?;
    legacy_ledger(&state)
}

fn legacy_ledger(state: &ReleaseState) -> Result<ManifestLedger> {
    ManifestLedger::import_release_state(
        &migration_authority(Product::UpdateAll),
        SharedReleaseState {
            accepted_root_generation: state.accepted_root_generation,
            accepted_root_sha256: state.accepted_root_sha256.clone(),
            accepted_generation: state.accepted_generation,
            accepted_version: state.accepted_version.clone(),
            accepted_manifest_sha256: state.accepted_manifest_sha256.clone(),
            accepted_binary_sha256: state.accepted_binary_sha256.clone(),
        },
    )
    .map_err(Into::into)
}

/// Metadata-only acceptance, under the caller's outer release lease. This does
/// not initialize installation v2, retire legacy state or recover a journal.
pub(super) struct MetadataAcceptance<'a> {
    destination: PathBuf,
    authority: DocumentAuthority,
    expected: Option<ArtifactIdentity>,
    state: MetadataState,
    _lease: &'a dev_tools_installation::InstallationLock,
}

enum MetadataState {
    Legacy(ReleaseState),
    Initialized(AcceptedAuthority, Option<VersionedReceipt>),
}

impl<'a> MetadataAcceptance<'a> {
    pub(super) fn begin(
        paths: &'a Paths,
        lease: &'a dev_tools_installation::InstallationLock,
    ) -> Result<Self> {
        let layout = shared_installation_layout(Product::UpdateAll, paths)?;
        if path_entry_present(
            &layout.data_root.join("installation-transition-v1.json"),
            "inspect pending installation",
        )? {
            bail!("metadata acceptance cannot recover pending installation");
        }
        let initialized = versioned_v2::read_receipt_metadata(&layout).is_ok();
        let (destination, authority) = if initialized {
            (
                paths.product_root.join(STATE_NAME),
                document_authority(paths)?,
            )
        } else {
            (paths.state.clone(), state_document_authority(paths)?)
        };
        let original = read_atomic_document(&destination, &authority)?;
        let state = if initialized {
            let document = original
                .as_ref()
                .context("initialized release authority is missing")?;
            let accepted = AcceptedAuthority::validate(
                serde_json::from_slice(&document.bytes)?,
                Product::UpdateAll,
            )?;
            let receipt = versioned_v2::observe(&layout, ARTIFACT_LIMIT)?;
            accepted.verify_receipt(receipt.as_ref())?;
            MetadataState::Initialized(accepted, receipt)
        } else {
            let state = match &original {
                Some(document) => parse_json(&document.bytes, "release state")?,
                None => ReleaseState::default(),
            };
            // Validate complete legacy history before network and mutation.
            legacy_ledger(&state)?;
            dev_tools_installation::observe_versioned_installation(&layout, ARTIFACT_LIMIT)?;
            MetadataState::Legacy(state)
        };
        Ok(Self {
            destination,
            authority,
            expected: original.map(|document| document.identity),
            state,
            _lease: lease,
        })
    }

    pub(super) fn accept(
        self,
        metadata: &ReleaseMetadata,
        online: &ReleaseAuthority,
    ) -> Result<SharedVerifiedRelease> {
        let (verified, bytes) = match self.state {
            MetadataState::Legacy(mut state) => {
                let verified = verify_release_metadata(metadata, online)?;
                let legacy = verify_downloaded_manifest(Product::UpdateAll, metadata)?;
                accept_manifest_metadata(&mut state, &legacy)?;
                (verified, serde_json::to_vec_pretty(&state)?)
            }
            MetadataState::Initialized(mut accepted, receipt) => {
                let (verified, _) = accepted.ledger.accept_release_metadata(online, metadata)?;
                let mut proofs = vec![Proof::from_metadata(metadata)?];
                // Keep only receipt-owned releases plus the new exact accepted
                // proof. Rebind retained manifests to the newly accepted root,
                // enforcing its revocations before any publication.
                for (proof, release) in accepted.document.proofs.iter().zip(&accepted.releases) {
                    let retained = receipt.as_ref().is_some_and(|receipt| {
                        release.version.to_string() == receipt.active_version
                            || receipt.previous_version.as_deref()
                                == Some(release.version.to_string().as_str())
                    });
                    if retained
                        && !proofs
                            .iter()
                            .any(|existing| existing.manifest == proof.manifest)
                    {
                        proofs.push(Proof {
                            root: String::from_utf8(metadata.root.clone())?,
                            manifest: proof.manifest.clone(),
                        });
                    }
                }
                accepted.document.ledger = String::from_utf8(accepted.ledger.to_bytes()?)?;
                accepted.document.proofs = proofs;
                let next = AcceptedAuthority::validate(accepted.document, Product::UpdateAll)?;
                next.verify_receipt(receipt.as_ref())?;
                (verified, serde_json::to_vec(&next.document)?)
            }
        };
        if !verified.version.pre.is_empty() {
            bail!("metadata acceptance requires a stable release");
        }
        let current = read_atomic_document(&self.destination, &self.authority)?;
        if current.as_ref().map(|document| &document.identity) != self.expected.as_ref() {
            bail!("release authority changed during metadata retrieval");
        }
        write_atomic_document(
            &self.destination,
            &bytes,
            &self.authority,
            self.expected.as_ref(),
        )?;
        Ok(verified)
    }
}

/// Explicit local initialization/resumption only. The outer release lease is
/// acquired before the installation lock, then the retirement lease. Missing
/// proofs or an interrupted publication leave the upgrade journal in place;
/// no error restores the legacy writer. Supplied evidence is not freshness.
pub(super) fn initialize(
    product: Product,
    paths: &Paths,
    evidence: &[ReleaseMetadata],
) -> Result<(bool, Option<VersionedReceipt>)> {
    if evidence.len() > PROOF_COUNT_LIMIT {
        bail!("too many retained release proofs");
    }
    let layout = shared_installation_layout(product, paths)?;
    dev_tools_installation::ensure_owned_directory(
        &layout.data_root,
        layout.owner_uid,
        layout.directory_mode,
    )?;
    let _lease = acquire_release_writer(paths)?;
    let result = versioned_v2::initialize(&layout, ARTIFACT_LIMIT, |receipt| {
        let (_, captured) = retire_atomic_document(
            &paths.state,
            &state_document_authority(paths)?,
            receipt.is_none(),
        )?;
        let captured_identity = captured.as_ref().map(|document| document.identity.clone());
        let destination = paths.product_root.join(STATE_NAME);
        if read_atomic_document(&destination, &document_authority(paths)?)?.is_some() {
            let accepted = load(product, paths)?;
            if accepted.document.captured_identity != captured_identity {
                bail!("release authority differs from captured legacy history");
            }
            return accepted.verify_receipt(receipt);
        }
        let state: ReleaseState = match captured {
            Some(document) => parse_json(&document.bytes, "captured release state")?,
            None => ReleaseState::default(),
        };
        let ledger = ManifestLedger::import_release_state(
            &migration_authority(product),
            SharedReleaseState {
                accepted_root_generation: state.accepted_root_generation,
                accepted_root_sha256: state.accepted_root_sha256,
                accepted_generation: state.accepted_generation,
                accepted_version: state.accepted_version,
                accepted_manifest_sha256: state.accepted_manifest_sha256,
                accepted_binary_sha256: state.accepted_binary_sha256,
            },
        )?;
        let accepted = AcceptedAuthority::validate(
            AuthorityDocument {
                schema: SCHEMA.into(),
                captured_identity,
                ledger: String::from_utf8(ledger.to_bytes()?)?,
                proofs: evidence
                    .iter()
                    .map(Proof::from_metadata)
                    .collect::<Result<_>>()?,
            },
            product,
        )?;
        accepted.verify_receipt(receipt)?;
        write_atomic_document(
            &destination,
            &serde_json::to_vec(&accepted.document)?,
            &document_authority(paths)?,
            None,
        )?;
        Ok(())
    })?;
    // The installation primitive skips its callback on an initialized repeat.
    // Absence or corruption here must never be treated as fresh initialization.
    load(product, paths)?.verify_receipt(result.1.as_ref())?;
    Ok(result)
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;

    fn metadata() -> ReleaseMetadata {
        ReleaseMetadata {
            root: include_bytes!("../../../../release-trust/dev-tools-root.json").to_vec(),
            manifest: include_bytes!(
                "../../../../tests/fixtures/releases/update-all-0.1.6-v2.json"
            )
            .to_vec(),
        }
    }

    fn accepted_state(paths: &Paths) -> Result<()> {
        create_private_dir(&paths.product_root)?;
        let verified = verify_downloaded_manifest(Product::UpdateAll, &metadata())?;
        let mut legacy = ReleaseState::default();
        accept_manifest_metadata(&mut legacy, &verified)?;
        save_state(paths, &legacy)
    }

    #[test]
    fn cutover_retires_legacy_state_and_preserves_accepted_history() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        let metadata = metadata();
        let before = fs::read(&paths.state)?;
        assert!(initialize(Product::UpdateAll, &paths, &[metadata.clone()])?.0);
        assert!(
            paths.state.is_dir(),
            "legacy metadata writer remains enabled"
        );
        assert_ne!(fs::read(&paths.state).ok(), Some(before));
        assert!(load_state(&paths).is_err());
        let accepted = load(Product::UpdateAll, &paths)?;
        let mut ledger = accepted.ledger;
        assert!(
            !ledger
                .accept_release_metadata(&migration_authority(Product::UpdateAll), &metadata)?
                .1
        );
        assert!(!initialize(Product::UpdateAll, &paths, &[])?.0);
        Ok(())
    }

    #[test]
    fn missing_proof_retains_both_fences_and_explicit_retry_resumes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        assert!(initialize(Product::UpdateAll, &paths, &[]).is_err());
        let layout = shared_installation_layout(Product::UpdateAll, &paths)?;
        assert!(paths.state.is_dir());
        let journal_path = layout.data_root.join("installation-transition-v1.json");
        let journal = fs::read(&journal_path)?;
        assert!(read_versioned_installation_receipt(&layout)?.is_none());
        assert!(versioned_v2::observe(&layout, ARTIFACT_LIMIT).is_err());
        assert!(!paths.product_root.join(STATE_NAME).exists());
        assert!(initialize(Product::UpdateAll, &paths, &[]).is_err());
        assert_eq!(fs::read(&journal_path)?, journal);
        assert!(initialize(Product::UpdateAll, &paths, &[metadata()])?.0);
        assert!(versioned_v2::observe(&layout, ARTIFACT_LIMIT)?.is_none());
        assert!(!journal_path.exists());
        Ok(())
    }

    #[test]
    fn interrupted_history_is_readable_without_resuming_retirement() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        assert!(initialize(Product::UpdateAll, &paths, &[]).is_err());
        let journal_path = paths.product_root.join("installation-transition-v1.json");
        let journal = fs::read(&journal_path)?;
        let history = migration_history(&paths)?;
        assert_eq!(history.accepted_version.as_deref(), Some("0.1.6"));
        assert_eq!(fs::read(&journal_path)?, journal);
        assert!(!paths.product_root.join(STATE_NAME).exists());
        Ok(())
    }

    #[test]
    fn initialized_missing_authority_never_resets_or_reimports() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        initialize(Product::UpdateAll, &paths, &[metadata()])?;
        let destination = paths.product_root.join(STATE_NAME);
        // Test-owned corruption: retain the original document as evidence.
        fs::rename(&destination, directory.path().join("retained-authority"))?;
        let layout = shared_installation_layout(Product::UpdateAll, &paths)?;
        let receipt_path = layout.data_root.join("installation-receipt-v1.json");
        let receipt = fs::read(&receipt_path)?;
        assert!(initialize(Product::UpdateAll, &paths, &[metadata()]).is_err());
        assert!(!destination.exists());
        assert_eq!(fs::read(&receipt_path)?, receipt);
        assert!(!layout
            .data_root
            .join("installation-transition-v1.json")
            .exists());
        Ok(())
    }

    #[test]
    fn empty_first_use_is_explicit_and_read_only_absence_creates_nothing() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        assert!(load(Product::UpdateAll, &paths).is_err());
        assert!(!paths.product_root.exists());
        assert!(initialize(Product::UpdateAll, &paths, &[])?.0);
        assert!(paths.state.is_dir());
        assert!(!initialize(Product::UpdateAll, &paths, &[])?.0);
        assert!(load(Product::UpdateAll, &paths)?
            .document
            .captured_identity
            .is_none());
        Ok(())
    }

    #[test]
    fn invalid_captured_history_cannot_be_replaced_with_empty_authority() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        create_private_dir(&paths.product_root)?;
        let legacy = ReleaseState {
            accepted_generation: 5,
            ..ReleaseState::default()
        };
        save_state(&paths, &legacy)?;
        assert!(initialize(Product::UpdateAll, &paths, &[]).is_err());
        assert!(paths.state.is_dir());
        let (_, captured) =
            retire_atomic_document(&paths.state, &state_document_authority(&paths)?, false)?;
        assert_eq!(
            captured.context("captured history")?.bytes,
            serde_json::to_vec_pretty(&legacy)?
        );
        assert!(!paths.product_root.join(STATE_NAME).exists());
        assert!(initialize(Product::UpdateAll, &paths, &[metadata()]).is_err());
        Ok(())
    }

    #[test]
    fn proof_rejection_preserves_interrupted_cutover_and_unknown_destination() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        let mut corrupted = metadata();
        corrupted.manifest = b"{}".to_vec();
        assert!(initialize(Product::UpdateAll, &paths, &[corrupted]).is_err());
        let destination = paths.product_root.join(STATE_NAME);
        write_atomic_document(&destination, b"{}", &document_authority(&paths)?, None)?;
        assert!(initialize(Product::UpdateAll, &paths, &[metadata()]).is_err());
        assert_eq!(fs::read(destination)?, b"{}");
        Ok(())
    }

    #[test]
    fn receipt_hashes_without_matching_signed_evidence_cannot_complete_cutover() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        let source = directory.path().join("candidate");
        fs::write(&source, b"not the signed artifact")?;
        let layout = shared_installation_layout(Product::UpdateAll, &paths)?;
        let identity = ArtifactIdentity {
            length: 23,
            sha256: sha256_hex(b"not the signed artifact"),
        };
        let receipt = apply_versioned_installation(
            &VersionedInstallRequest {
                layout: layout.clone(),
                source,
                version: "0.1.6".into(),
                identity,
                aliases: vec!["update-all".into()],
            },
            |_| Ok(()),
        )?
        .receipt;
        assert!(initialize(Product::UpdateAll, &paths, &[metadata()]).is_err());
        assert_eq!(read_versioned_installation_receipt(&layout)?, Some(receipt));
        assert!(paths.state.is_dir());
        assert!(layout
            .data_root
            .join("installation-transition-v1.json")
            .exists());
        assert!(!paths.product_root.join(STATE_NAME).exists());
        Ok(())
    }

    #[test]
    fn retained_proof_binding_checks_both_versions_length_and_digest() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        initialize(Product::UpdateAll, &paths, &[metadata()])?;
        let accepted = load(Product::UpdateAll, &paths)?;
        let release = &accepted.releases[0];
        // This tests signature-to-receipt binding only. Installation-byte and
        // link custody are independently enforced by versioned_v2.
        let identity = ArtifactIdentity {
            length: release.artifact_length,
            sha256: release.artifact_sha256.clone(),
        };
        let mut receipt = VersionedReceipt {
            schema: "dev-tools-versioned-installation-v1".into(),
            product: "update-all".into(),
            data_root: paths.product_root.clone(),
            bin_dir: paths.bin_dir.clone(),
            artifact_name: "update-all".into(),
            active_version: "0.1.6".into(),
            active_identity: identity.clone(),
            previous_version: Some("0.1.6".into()),
            previous_identity: Some(identity.clone()),
            aliases: vec!["update-all".into()],
        };
        accepted.verify_receipt(Some(&receipt))?;
        receipt.previous_version = Some("0.1.5".into());
        assert!(accepted.verify_receipt(Some(&receipt)).is_err());
        receipt.previous_version = Some("0.1.6".into());
        receipt.previous_identity = Some(ArtifactIdentity {
            length: identity.length + 1,
            ..identity.clone()
        });
        assert!(accepted.verify_receipt(Some(&receipt)).is_err());
        receipt.previous_identity = Some(identity.clone());
        receipt.active_identity.sha256 = "0".repeat(64);
        assert!(accepted.verify_receipt(Some(&receipt)).is_err());
        Ok(())
    }

    #[test]
    fn cutover_rejects_a_live_product_writer_before_creating_upgrade_state() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(directory.path());
        accepted_state(&paths)?;
        let original = fs::read(&paths.state)?;
        let _lease = acquire_release_writer(&paths)?;
        assert!(initialize(Product::UpdateAll, &paths, &[metadata()]).is_err());
        assert_eq!(fs::read(&paths.state)?, original);
        assert!(!paths
            .product_root
            .join("installation-transition-v1.json")
            .exists());
        assert!(!paths.product_root.join(STATE_NAME).exists());
        Ok(())
    }
}
