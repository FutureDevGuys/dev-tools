//! Explicit offline custody of a historical artifact. This does not accept a
//! release, activate it, authorize rollback, or execute the supplied artifact.
use super::*;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FailureKind {
    InvalidConfiguration,
    Unsupported,
    Blocked,
    Operational,
    Authenticity,
    Integrity,
    Authority,
    Interrupted,
}

impl FailureKind {
    fn exit_code(self) -> u8 {
        match self {
            Self::InvalidConfiguration => 2,
            Self::Unsupported | Self::Blocked => 3,
            Self::Operational => 1,
            Self::Authenticity | Self::Integrity | Self::Authority => 4,
            Self::Interrupted => 130,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct RetentionResult {
    schema: &'static str,
    pub product: &'static str,
    operation: &'static str,
    pub outcome: &'static str,
    pub changed: Option<bool>,
    pub exit_code: u8,
    pub error_kind: Option<FailureKind>,
    retained_version: Option<String>,
    source_commit: Option<String>,
    artifact_sha256: Option<String>,
    artifact_length: Option<u64>,
}

#[derive(Default)]
struct Progress {
    changed: Option<bool>,
}

impl Progress {
    fn enter(&mut self) {
        if self.changed != Some(true) {
            self.changed = None;
        }
    }

    fn complete(&mut self, changed: bool) {
        self.changed = Some(self.changed == Some(true) || changed);
    }
}

pub(crate) fn retain(product: Product, bundle: &OfflineBundlePaths) -> RetentionResult {
    let mut progress = Progress {
        changed: Some(false),
    };
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let result = native::run(product, bundle, &mut progress);
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    let result: std::result::Result<SharedVerifiedRelease, FailureKind> = {
        let _ = bundle;
        Err(FailureKind::Unsupported)
    };
    let mut report = RetentionResult {
        schema: "update-all-product-retention-v1",
        product: product.id(),
        operation: "retain",
        outcome: "failed",
        changed: progress.changed,
        exit_code: 0,
        error_kind: None,
        retained_version: None,
        source_commit: None,
        artifact_sha256: None,
        artifact_length: None,
    };
    match result {
        Ok(release) => {
            report.outcome = if progress.changed == Some(true) {
                "retained"
            } else {
                "no_op"
            };
            report.retained_version = Some(release.version.to_string());
            report.source_commit = release.source_commit;
            report.artifact_sha256 = Some(release.artifact_sha256);
            report.artifact_length = Some(release.artifact_length);
        }
        Err(kind) => {
            report.error_kind = Some(kind);
            report.exit_code = kind.exit_code();
        }
    }
    report
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod native {
    use super::*;
    use dev_tools_installation::{
        AtomicDocument, DocumentAuthority, DocumentDirectoryPreparation, ExistingDocumentDirectory,
    };
    use dev_tools_update::manifest_ledger::ManifestLedger;
    use std::ffi::OsStr;
    use std::os::unix::fs::MetadataExt;

    type RetentionOutcome<T> = std::result::Result<T, FailureKind>;
    const RECEIPT_SCHEMA: &str = "update-all-retained-artifact-v1";
    const JOURNAL_SCHEMA: &str = "update-all-retention-publication-v1";
    const JOURNAL_NAME: &str = "pending.json";
    // A manifest may need six bytes per input byte when encoded as a JSON string.
    const DOCUMENT_LIMIT: u64 = 6 * METADATA_LIMIT + 8192;

    #[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct RetentionReceipt {
        schema: String,
        layout: VersionedLayout,
        version: String,
        target: String,
        source_commit: String,
        identity: ArtifactIdentity,
        manifest_sha256: String,
        // Original signed bytes are proof input, not a claim of prior acceptance.
        // Current-root verification is repeated for every explicit operation.
        manifest: String,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Journal {
        schema: String,
        retention: RetentionReceipt,
    }

    fn authority(error: anyhow::Error) -> FailureKind {
        match error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        {
            Some(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                FailureKind::Interrupted
            }
            Some(error) if error.kind() != std::io::ErrorKind::PermissionDenied => {
                FailureKind::Operational
            }
            _ => FailureKind::Authority,
        }
    }

    fn managed_receipt(product: Product, paths: &Paths) -> Result<VersionedReceipt> {
        let layout = shared_installation_layout(product, paths)?;
        let receipt = match dev_tools_installation::versioned_v2::read_receipt_metadata(&layout) {
            Ok(_) if product == Product::UpdateAll => protocol::observe_authenticated(paths)?,
            Ok(_) => dev_tools_installation::versioned_v2::observe(&layout, ARTIFACT_LIMIT)?,
            Err(_) => {
                dev_tools_installation::observe_versioned_installation(&layout, ARTIFACT_LIMIT)?
            }
        };
        receipt.context("retention requires an existing managed installation")
    }

    fn ledger(
        product: Product,
        paths: &Paths,
        policy: &ReleaseAuthority,
    ) -> Result<ManifestLedger> {
        if product == Product::UpdateAll {
            return protocol::observation_ledger(paths);
        }
        let state = load_state(paths)?;
        ManifestLedger::import_release_state(
            policy,
            SharedReleaseState {
                accepted_root_generation: state.accepted_root_generation,
                accepted_root_sha256: state.accepted_root_sha256,
                accepted_generation: state.accepted_generation,
                accepted_version: state.accepted_version,
                accepted_manifest_sha256: state.accepted_manifest_sha256,
                accepted_binary_sha256: state.accepted_binary_sha256,
            },
        )
        .map_err(Into::into)
    }

    fn receipt_bytes(receipt: &RetentionReceipt) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(receipt)?;
        if bytes.is_empty() || bytes.len() as u64 > DOCUMENT_LIMIT {
            bail!("retention receipt exceeds its bound");
        }
        Ok(bytes)
    }

    fn private_directory(path: &Path, uid: u32, mode: u32) -> Result<DocumentDirectoryPreparation> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.is_dir()
                    && metadata.uid() == uid
                    && metadata.mode() & 0o7777 == mode => {}
            Ok(_) => bail!("retention parent has unsafe filesystem authority"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect retention parent"),
        }
        DocumentDirectoryPreparation::observe(path, uid, mode)
    }

    fn read_receipt(
        directory: &DocumentDirectoryPreparation,
        name: &OsStr,
        policy: &DocumentAuthority,
        expected: &RetentionReceipt,
    ) -> Result<Option<AtomicDocument>> {
        let document = directory.read(name, policy)?;
        if let Some(document) = &document {
            let actual: RetentionReceipt = serde_json::from_slice(&document.bytes)?;
            if actual != *expected || actual.schema != RECEIPT_SCHEMA {
                bail!("retention receipt does not bind the requested artifact");
            }
        }
        Ok(document)
    }

    fn read_journal(
        directory: &DocumentDirectoryPreparation,
        policy: &DocumentAuthority,
        expected: &RetentionReceipt,
    ) -> RetentionOutcome<Option<AtomicDocument>> {
        let document = directory
            .read(OsStr::new(JOURNAL_NAME), policy)
            .map_err(authority)?;
        if let Some(document) = &document {
            let journal: Journal =
                serde_json::from_slice(&document.bytes).map_err(|_| FailureKind::Authority)?;
            if journal.schema != JOURNAL_SCHEMA {
                return Err(FailureKind::Authority);
            }
            if journal.retention != *expected {
                // A pending operation is never discarded or reinterpreted for
                // another bundle. Resume its exact original manifest/payload.
                return Err(FailureKind::Blocked);
            }
        }
        Ok(document)
    }

    fn acknowledge_artifact(
        directory: &ExistingDocumentDirectory,
        name: &OsStr,
        payload: &[u8],
        policy: &DocumentAuthority,
        expected: &ArtifactIdentity,
    ) -> Result<()> {
        let current = directory
            .read(name, policy)?
            .context("owned retained artifact disappeared")?;
        if current.identity != *expected {
            bail!("owned retained artifact changed");
        }
        // Matching publication acknowledges file and parent synchronization;
        // it never repairs content, mode, ownership or a conflicting leaf.
        directory.write(name, payload, policy, Some(expected))?;
        Ok(())
    }

    pub(super) fn run(
        product: Product,
        bundle: &OfflineBundlePaths,
        progress: &mut Progress,
    ) -> RetentionOutcome<SharedVerifiedRelease> {
        offline::validate_paths(bundle).map_err(|_| FailureKind::InvalidConfiguration)?;
        require_current_runtime(product).map_err(|_| FailureKind::Unsupported)?;
        let paths = Paths::resolve(product).map_err(|_| FailureKind::InvalidConfiguration)?;
        let layout = shared_installation_layout(product, &paths).map_err(authority)?;
        let uid = offline::current_uid();
        if layout.owner_uid != uid {
            return Err(FailureKind::Authority);
        }
        // No initialization, adoption, pointer repair or installation recovery.
        // This read also prevents an absent/external root from being created.
        let before = managed_receipt(product, &paths).map_err(authority)?;
        let _lease = acquire_release_writer(&paths).map_err(|error| {
            if error.downcast_ref::<ReleaseMutationBusy>().is_some() {
                FailureKind::Blocked
            } else {
                authority(error)
            }
        })?;
        if managed_receipt(product, &paths).map_err(authority)? != before {
            return Err(FailureKind::Blocked);
        }
        let metadata = ReleaseMetadata {
            root: offline::read_input(&bundle.root_document, METADATA_LIMIT, uid)
                .map_err(authority)?,
            manifest: offline::read_input(&bundle.manifest, METADATA_LIMIT, uid)
                .map_err(authority)?,
        };
        let mut policy = release_authority(product);
        policy.accepted_manifest_schemas = vec!["dev-tools-product-v2".into()];
        policy.require_source_commit = true;
        let accepted = ledger(product, &paths, &policy).map_err(authority)?;
        // Verification is read-only. Never call accept_release_metadata, cache
        // publication, protocol initialization or any activation primitive.
        let verified = accepted
            .verify_retained_with_authority(&policy, &metadata)
            .map_err(|_| FailureKind::Authenticity)?;
        let payload =
            offline::read_input(&bundle.artifact, ARTIFACT_LIMIT, uid).map_err(authority)?;
        dev_tools_release::verify_artifact_bytes(&verified, &payload)
            .map_err(|_| FailureKind::Integrity)?;
        let identity = ArtifactIdentity {
            length: verified.artifact_length,
            sha256: verified.artifact_sha256.clone(),
        };
        let version = verified.version.to_string();
        layout
            .validate_candidate(&version, &identity, &before.aliases)
            .map_err(authority)?;
        let binding = RetentionReceipt {
            schema: RECEIPT_SCHEMA.into(),
            layout: layout.clone(),
            version: version.clone(),
            target: verified.target.clone(),
            source_commit: verified
                .source_commit
                .clone()
                .ok_or(FailureKind::Authenticity)?,
            identity: identity.clone(),
            manifest_sha256: verified.manifest_sha256.clone(),
            manifest: String::from_utf8(metadata.manifest)
                .map_err(|_| FailureKind::Authenticity)?,
        };
        let document_policy = DocumentAuthority {
            owner_uid: uid,
            mode: 0o600,
            limit: DOCUMENT_LIMIT,
        };
        let artifact_policy = DocumentAuthority {
            owner_uid: uid,
            mode: 0o755,
            limit: ARTIFACT_LIMIT,
        };
        let documents = private_directory(
            &paths.product_root.join("retention-v1"),
            uid,
            layout.directory_mode,
        )
        .map_err(authority)?;
        let receipt_name = format!("{version}.json");
        let retained = read_receipt(
            &documents,
            OsStr::new(&receipt_name),
            &document_policy,
            &binding,
        )
        .map_err(authority)?;
        let pending = read_journal(&documents, &document_policy, &binding)?;
        let version_directory =
            private_directory(&paths.versions.join(&version), uid, layout.directory_mode)
                .map_err(authority)?;
        let artifact_name = OsStr::new(&layout.artifact_name);
        let existing = version_directory
            .read(artifact_name, &artifact_policy)
            .map_err(authority)?;
        let pinned = if existing.is_some() {
            dev_tools_installation::versioned_artifact_is_retained(&layout, &version, &identity)
                .map_err(authority)?
        } else {
            false
        };
        let endpoint = if before.active_version == version {
            Some(&before.active_identity)
        } else if before.previous_version.as_deref() == Some(version.as_str()) {
            before.previous_identity.as_ref()
        } else {
            None
        };
        if endpoint.is_some_and(|owned| *owned != identity) {
            return Err(FailureKind::Integrity);
        }
        if let Some(existing) = &existing {
            if existing.identity != identity {
                return Err(FailureKind::Integrity);
            }
            if retained.is_none() && pending.is_none() && endpoint.is_none() && !pinned {
                // Equal signed bytes alone never establish destination ownership.
                return Err(FailureKind::Authority);
            }
        }
        if retained.is_some() && existing.is_some() && pending.is_none() && pinned {
            let directory = ExistingDocumentDirectory::open(&paths.versions.join(&version), uid)
                .map_err(authority)?;
            acknowledge_artifact(
                &directory,
                artifact_name,
                &payload,
                &artifact_policy,
                &identity,
            )
            .map_err(authority)?;
            let directory =
                ExistingDocumentDirectory::open(&paths.product_root.join("retention-v1"), uid)
                    .map_err(authority)?;
            progress.enter();
            let changed = directory
                .write(
                    OsStr::new(&receipt_name),
                    &receipt_bytes(&binding).map_err(authority)?,
                    &document_policy,
                    retained.as_ref().map(|document| &document.identity),
                )
                .map_err(authority)?;
            progress.complete(changed);
            progress.enter();
            let changed =
                dev_tools_installation::retain_versioned_artifact(&layout, &version, &identity)
                    .map_err(authority)?;
            progress.complete(changed);
            if managed_receipt(product, &paths).map_err(authority)? != before {
                return Err(FailureKind::Authority);
            }
            return Ok(verified);
        }
        // All inputs, destination custody and pending intent are admitted before
        // entering any retention publication. A crash can resume only this
        // exact product/layout/source/manifest/length/digest binding.
        let receipt_bytes = receipt_bytes(&binding).map_err(authority)?;
        let journal_bytes = serde_json::to_vec(&Journal {
            schema: JOURNAL_SCHEMA.into(),
            retention: binding.clone(),
        })
        .map_err(|_| FailureKind::Authority)?;
        if journal_bytes.len() as u64 > DOCUMENT_LIMIT {
            return Err(FailureKind::Authority);
        }
        progress.enter();
        let (documents, created) = documents.prepare().map_err(authority)?;
        progress.complete(created);
        let journal = match pending {
            Some(document) => document,
            None => {
                progress.enter();
                documents
                    .publish_new(OsStr::new(JOURNAL_NAME), &journal_bytes, &document_policy)
                    .map_err(authority)?;
                progress.complete(true);
                documents
                    .read(OsStr::new(JOURNAL_NAME), &document_policy)
                    .map_err(authority)?
                    .ok_or(FailureKind::Authority)?
            }
        };
        progress.enter();
        let (version_directory, created) = version_directory.prepare().map_err(authority)?;
        progress.complete(created);
        if existing.is_some() {
            acknowledge_artifact(
                &version_directory,
                artifact_name,
                &payload,
                &artifact_policy,
                &identity,
            )
            .map_err(authority)?;
        } else {
            progress.enter();
            version_directory
                .publish_new(artifact_name, &payload, &artifact_policy)
                .map_err(authority)?;
            progress.complete(true);
        }
        progress.enter();
        let changed = documents
            .write(
                OsStr::new(&receipt_name),
                &receipt_bytes,
                &document_policy,
                retained.as_ref().map(|document| &document.identity),
            )
            .map_err(authority)?;
        progress.complete(changed);
        progress.enter();
        let changed =
            dev_tools_installation::retain_versioned_artifact(&layout, &version, &identity)
                .map_err(authority)?;
        progress.complete(changed);
        // Reobserve active/previous and every owned pointer without repair;
        // retention cannot acknowledge an unrelated installation transition.
        if managed_receipt(product, &paths).map_err(authority)? != before {
            return Err(FailureKind::Authority);
        }
        progress.enter();
        let changed = documents
            .remove(
                OsStr::new(JOURNAL_NAME),
                &document_policy,
                &journal.identity,
            )
            .map_err(authority)?;
        progress.complete(changed);
        Ok(verified)
    }
}
