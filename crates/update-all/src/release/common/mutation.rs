//! Product-owned orchestration of the existing ledger and installation protocol.
use super::*;
use dev_tools_installation::{ArtifactIdentity, DocumentAuthority, InstallationLock};
use dev_tools_product::CommonOperation;

pub(super) struct MutationAdapter {
    observation: CommonAdapter,
    request: OperationRequest,
    lease: Option<InstallationLock>,
    metadata: Option<ReleaseMetadata>,
    evidence: Option<Vec<ReleaseMetadata>>,
    cache_expected: Option<Option<ArtifactIdentity>>,
    initial: Option<InstallationSnapshot>,
    bundle: Option<OfflineBundlePaths>,
    bundle_payload: Option<Vec<u8>>,
}

impl MutationAdapter {
    pub(super) fn new(
        paths: Result<Paths>,
        checked_at_unix: u64,
        request: OperationRequest,
    ) -> Self {
        Self {
            observation: CommonAdapter {
                paths,
                checked_at_unix,
            },
            request,
            lease: None,
            metadata: None,
            evidence: None,
            cache_expected: None,
            initial: None,
            bundle: None,
            bundle_payload: None,
        }
    }

    fn paths(&self) -> Result<Paths, UpdateError> {
        self.observation
            .paths
            .as_ref()
            .cloned()
            .map_err(|_| UpdateError::new(UpdateErrorKind::InvalidConfiguration))
    }

    fn acquire(&mut self, paths: &Paths) -> Result<(), UpdateError> {
        if self.lease.is_none() {
            let layout =
                shared_installation_layout(Product::UpdateAll, paths).map_err(authority)?;
            if layout.owner_uid != super::super::offline::current_uid() {
                return Err(UpdateError::new(UpdateErrorKind::Authority).with_changed(false));
            }
            dev_tools_installation::ensure_owned_directory(
                &layout.data_root,
                layout.owner_uid,
                layout.directory_mode,
            )
            .map_err(authority)?;
            self.lease = Some(acquire_release_writer(paths).map_err(|error| {
                UpdateError::new(if error.downcast_ref::<ReleaseMutationBusy>().is_some() {
                    UpdateErrorKind::Blocked
                } else {
                    UpdateErrorKind::Authority
                })
            })?);
        }
        Ok(())
    }

    fn cache_input(paths: &Paths) -> Result<Option<(CandidateCache, ArtifactIdentity)>> {
        let Some(document) = dev_tools_installation::read_atomic_document(
            &CandidateCache::path(paths),
            &CandidateCache::authority(paths)?,
        )?
        else {
            return Ok(None);
        };
        let cache: CandidateCache = serde_json::from_slice(&document.bytes)?;
        verify_release_metadata(&cache.metadata()?, &candidate_authority())?;
        Ok(Some((cache, document.identity)))
    }

    fn payload_path(paths: &Paths, verified: &SharedVerifiedRelease) -> PathBuf {
        paths
            .product_root
            .join("cache/authenticated-payloads")
            .join(format!(
                "{}-{}",
                verified.root_sha256, verified.manifest_sha256
            ))
    }

    fn payload_available(paths: &Paths, verified: &SharedVerifiedRelease) -> Result<bool> {
        let policy = DocumentAuthority {
            owner_uid: state_document_authority(paths)?.owner_uid,
            mode: 0o700,
            limit: ARTIFACT_LIMIT,
        };
        let Some(document) = dev_tools_installation::read_atomic_document(
            &Self::payload_path(paths, verified),
            &policy,
        )?
        else {
            return Ok(false);
        };
        dev_tools_release::verify_artifact_bytes(verified, &document.bytes)?;
        Ok(true)
    }

    fn retained_metadata(version: &str) -> Result<ReleaseMetadata> {
        let version = Version::parse(version)?;
        if !version.pre.is_empty() {
            bail!("retained proof version is not stable");
        }
        let base = format!("{RELEASE_DOWNLOAD_BASE}update-all/v{version}");
        Ok(ReleaseMetadata {
            root: https_get(&format!("{base}/dev-tools-root.json"), None, METADATA_LIMIT)?.bytes,
            manifest: https_get(
                &format!("{base}/update-all-stable.json"),
                None,
                METADATA_LIMIT,
            )?
            .bytes,
        })
    }

    fn capture_cache(&mut self, paths: &Paths) -> Result<Vec<ReleaseMetadata>, UpdateError> {
        let input = Self::cache_input(paths).map_err(authority)?;
        self.cache_expected = Some(input.as_ref().map(|(_, identity)| identity.clone()));
        input
            .map(|(cache, _)| cache.metadata())
            .transpose()
            .map(|metadata| metadata.into_iter().collect())
            .map_err(authority)
    }

    fn load_bundle(&mut self) -> Result<Option<AuthenticatedCandidate>, UpdateError> {
        let paths = self.paths()?;
        let bundle = self
            .bundle
            .take()
            .ok_or_else(|| authority("missing explicit bundle"))?;
        super::super::offline::validate_paths(&bundle).map_err(authority)?;
        let uid = super::super::offline::current_uid();
        let metadata = ReleaseMetadata {
            root: super::super::offline::read_input(&bundle.root_document, METADATA_LIMIT, uid)
                .map_err(authority)?,
            manifest: super::super::offline::read_input(&bundle.manifest, METADATA_LIMIT, uid)
                .map_err(authority)?,
        };
        let mut ledger = protocol::observation_ledger(&paths).map_err(authority)?;
        let (verified, _) = ledger
            .accept_release_metadata(&candidate_authority(), &metadata)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authenticity))?;
        let bytes = super::super::offline::read_input(&bundle.artifact, ARTIFACT_LIMIT, uid)
            .map_err(authority)?;
        dev_tools_release::verify_artifact_bytes(&verified, &bytes)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Integrity))?;
        let prior = Self::cache_input(&paths).map_err(authority)?;
        self.cache_expected = Some(prior.as_ref().map(|(_, identity)| identity.clone()));
        let checked_at = prior
            .as_ref()
            .and_then(|(cache, _)| {
                let retained =
                    verify_release_metadata(&cache.metadata().ok()?, &candidate_authority())
                        .ok()?;
                (retained == verified).then_some(cache.checked_at_unix)
            })
            .unwrap_or(0);
        let mut local = prior
            .map(|(cache, _)| cache.metadata())
            .transpose()
            .map_err(authority)?
            .into_iter()
            .collect::<Vec<_>>();
        local.push(metadata.clone());
        self.evidence = Some(
            protocol::gather_evidence(&paths, local, None)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Blocked))?,
        );
        self.metadata = Some(metadata);
        // Availability is held authenticated bytes, not a promise of a durable
        // cache entry. Activation publishes this snapshot through the same cache.
        self.bundle_payload = Some(bytes);
        Ok(Some(AuthenticatedCandidate::new(
            verified, checked_at, true,
        )?))
    }

    fn store_payload(
        paths: &Paths,
        verified: &SharedVerifiedRelease,
        bytes: &[u8],
    ) -> Result<(), UpdateError> {
        dev_tools_release::verify_artifact_bytes(verified, bytes)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Integrity))?;
        let path = Self::payload_path(paths, verified);
        let parent = path
            .parent()
            .ok_or_else(|| authority("invalid payload path"))?;
        let owner_uid = state_document_authority(paths)
            .map_err(authority)?
            .owner_uid;
        dev_tools_installation::ensure_owned_directory(parent, owner_uid, 0o700)
            .map_err(authority)?;
        dev_tools_installation::write_atomic_document(
            &path,
            bytes,
            &DocumentAuthority {
                owner_uid,
                mode: 0o700,
                limit: ARTIFACT_LIMIT,
            },
            None,
        )
        .map_err(authority)?;
        Ok(())
    }
}

#[cfg(target_arch = "x86_64")]
pub(super) fn bundle(bundle: &OfflineBundlePaths) -> Result<Activation> {
    let paths = Paths::resolve(Product::UpdateAll)?;
    let request = if classify_install(Product::UpdateAll, &paths)? == InstallClassification::Absent
    {
        OperationRequest::install(true)
    } else {
        OperationRequest::apply(true)
    };
    let mut adapter = MutationAdapter::new(Ok(paths.clone()), now_unix(), request);
    adapter.bundle = Some(OfflineBundlePaths {
        root_document: bundle.root_document.clone(),
        manifest: bundle.manifest.clone(),
        artifact: bundle.artifact.clone(),
    });
    let result = execute(
        &UpdatePolicy::standard(ProductId::parse("update-all")?),
        request,
        now_unix(),
        &mut adapter,
    );
    legacy_common_activation(&paths, result)
}

fn authority(_: impl std::fmt::Display) -> UpdateError {
    UpdateError::new(UpdateErrorKind::Authority)
}

fn mutation_failure(error: anyhow::Error) -> UpdateError {
    UpdateError::new(
        if error.downcast_ref::<CandidateHealthFailure>().is_some() {
            UpdateErrorKind::Operational
        } else if error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
        }) {
            UpdateErrorKind::Interrupted
        } else {
            UpdateErrorKind::Authority
        },
    )
}

impl UpdateAdapter for MutationAdapter {
    fn inspect(&mut self) -> Result<InstallationSnapshot, UpdateError> {
        let paths = self.paths()?;
        let snapshot = (|| {
            let layout =
                shared_installation_layout(Product::UpdateAll, &paths).map_err(authority)?;
            // Classification is unknown until original signed proofs and exact
            // endpoint custody are revalidated inside explicit preparation.
            if dev_tools_installation::versioned_v2::pending_recovery(&layout)
                .map_err(authority)?
                .is_some()
            {
                protocol::observation_ledger(&paths).map_err(authority)?;
                return Ok(InstallationSnapshot::pending_recovery());
            }
            match CommonAdapter::observe(&paths) {
                Ok(snapshot)
                    if snapshot.state() != dev_tools_product::InstallationState::Unknown =>
                {
                    Ok(snapshot)
                }
                result => {
                    let legacy_receipt =
                        read_versioned_installation_receipt(&layout).map_err(authority)?;
                    let legacy =
                        observe_legacy_topology(Product::UpdateAll, &paths).map_err(authority)?;
                    if legacy_receipt.is_some() || legacy.present {
                        protocol::observation_ledger(&paths).map_err(authority)?;
                        Ok(InstallationSnapshot::pending_recovery())
                    } else {
                        result.map_err(authority)
                    }
                }
            }
        })()?;
        self.initial.get_or_insert_with(|| snapshot.clone());
        Ok(snapshot)
    }

    fn load_authenticated_candidate(
        &mut self,
    ) -> Result<Option<AuthenticatedCandidate>, UpdateError> {
        if self.bundle.is_some() {
            return self.load_bundle();
        }
        let paths = self.paths()?;
        let Some(candidate) = CandidateCache::load(&paths).map_err(authority)? else {
            return Ok(None);
        };
        let local = self.capture_cache(&paths)?;
        self.metadata = local.first().cloned();
        self.evidence = Some(
            protocol::gather_evidence(&paths, local, None)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Blocked))?,
        );
        let available = Self::payload_available(&paths, candidate.verified()).map_err(authority)?;
        Ok(Some(AuthenticatedCandidate::new(
            candidate.verified().clone(),
            candidate.checked_at_unix(),
            available,
        )?))
    }

    fn refresh_authenticated_candidate(&mut self) -> Result<AuthenticatedCandidate, UpdateError> {
        let paths = self.paths()?;
        self.acquire(&paths)?;
        let mut ledger = protocol::observation_ledger(&paths).map_err(authority)?;
        let mut local = self.capture_cache(&paths)?;
        let (root_url, manifest_url) = resolve_release_urls(Product::UpdateAll)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Network))?;
        let metadata = ReleaseMetadata {
            root: https_get(&root_url, None, METADATA_LIMIT)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Network))?
                .bytes,
            manifest: https_get(&manifest_url, None, METADATA_LIMIT)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Network))?
                .bytes,
        };
        // This temporary ledger validates monotonic admission but is not a
        // replacement for durable acceptance before activation.
        let (verified, _) = ledger
            .accept_release_metadata(&candidate_authority(), &metadata)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Authenticity))?;
        local.push(metadata.clone());
        let mut fetch = Self::retained_metadata;
        self.evidence = Some(
            protocol::gather_evidence(&paths, local, Some(&mut fetch))
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?,
        );
        self.metadata = Some(metadata);
        let available = Self::payload_available(&paths, &verified).map_err(authority)?;
        AuthenticatedCandidate::new(verified, self.observation.checked_at_unix, available)
    }

    fn prepare_mutation(
        &mut self,
        request: OperationRequest,
        candidate: Option<&AuthenticatedCandidate>,
    ) -> Result<bool, UpdateError> {
        let paths = self.paths().map_err(|error| error.with_changed(false))?;
        self.acquire(&paths)
            .map_err(|error| error.with_changed(false))?;
        if request != self.request {
            return Err(UpdateError::new(UpdateErrorKind::Authority).with_changed(false));
        }
        if self.evidence.is_none() {
            let local = self
                .capture_cache(&paths)
                .map_err(|error| error.with_changed(false))?;
            self.evidence = Some(
                protocol::gather_evidence(&paths, local, None)
                    .map_err(|_| UpdateError::new(UpdateErrorKind::Blocked).with_changed(false))?,
            );
        }
        if let Some(expected) = &self.cache_expected {
            let current = dev_tools_installation::read_atomic_document(
                &CandidateCache::path(&paths),
                &CandidateCache::authority(&paths)
                    .map_err(|_| authority("invalid cache authority").with_changed(false))?,
            )
            .map_err(|_| authority("cache observation failed").with_changed(false))?;
            if current.as_ref().map(|document| &document.identity) != expected.as_ref() {
                return Err(UpdateError::new(UpdateErrorKind::Authority).with_changed(false));
            }
        }
        let lease = self
            .lease
            .as_ref()
            .ok_or_else(|| UpdateError::new(UpdateErrorKind::Authority))?;
        let evidence = self
            .evidence
            .as_deref()
            .ok_or_else(|| UpdateError::new(UpdateErrorKind::Authority))?;
        let changed = protocol::prepare_mutation(&paths, evidence, lease).map_err(authority)?;
        if !changed {
            let current = CommonAdapter::observe(&paths)
                .map_err(|_| authority("installation observation failed").with_changed(false))?;
            if self.initial.as_ref() != Some(&current) {
                return Err(UpdateError::new(UpdateErrorKind::Blocked).with_changed(false));
            }
        }
        if let Some(candidate) = candidate {
            let metadata = self
                .metadata
                .as_ref()
                .ok_or_else(|| authority("missing candidate evidence").with_changed(changed))?;
            let verified = protocol::MetadataAcceptance::begin(&paths, lease)
                .and_then(|acceptance| acceptance.accept(metadata, &candidate_authority()))
                .map_err(|_| authority("candidate acceptance failed").with_changed(changed))?;
            if verified != *candidate.verified() {
                return Err(authority("candidate changed").with_changed(changed));
            }
            let cache = CandidateCache {
                schema: CACHE_SCHEMA.into(),
                root: String::from_utf8(metadata.root.clone())
                    .map_err(|_| authority("invalid root").with_changed(changed))?,
                manifest: String::from_utf8(metadata.manifest.clone())
                    .map_err(|_| authority("invalid manifest").with_changed(changed))?,
                checked_at_unix: candidate.checked_at_unix(),
            };
            let bytes = serde_json::to_vec(&cache).map_err(|_| {
                UpdateError::new(UpdateErrorKind::Operational).with_changed(changed)
            })?;
            dev_tools_installation::write_atomic_document(
                &CandidateCache::path(&paths),
                &bytes,
                &CandidateCache::authority(&paths)
                    .map_err(|_| authority("invalid cache authority").with_changed(changed))?,
                self.cache_expected
                    .as_ref()
                    .and_then(|expected| expected.as_ref()),
            )
            .map_err(|_| authority("candidate cache publication failed").with_changed(changed))?;
        }
        Ok(changed)
    }

    fn prepare_artifact(
        &mut self,
        candidate: &AuthenticatedCandidate,
    ) -> Result<AuthenticatedCandidate, UpdateError> {
        let paths = self.paths()?;
        if self.request.is_offline() || self.request.operation() == CommonOperation::UpdateRollback
        {
            return Err(UpdateError::new(UpdateErrorKind::Blocked));
        }
        let metadata = self
            .metadata
            .as_ref()
            .ok_or_else(|| authority("missing candidate evidence"))?;
        let verified =
            verify_release_metadata(metadata, &candidate_authority()).map_err(authority)?;
        if verified != *candidate.verified() {
            return Err(authority("candidate changed"));
        }
        let bytes = super::super::fetch_artifact(&Artifact {
            url: verified.artifact_url.clone(),
            length: verified.artifact_length,
            sha256: verified.artifact_sha256.clone(),
        })
        .map_err(|_| UpdateError::new(UpdateErrorKind::Network))?;
        dev_tools_release::verify_artifact_bytes(&verified, &bytes)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Integrity))?;
        Self::store_payload(&paths, &verified, &bytes)?;
        if !Self::payload_available(&paths, &verified).map_err(authority)? {
            return Err(authority("payload unavailable"));
        }
        AuthenticatedCandidate::new(verified, candidate.checked_at_unix(), true)
    }

    fn install(&mut self, candidate: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        self.apply(candidate)
    }
    fn apply(&mut self, candidate: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        let paths = self.paths()?;
        if self.lease.is_none() {
            return Err(authority("release lease is absent").with_changed(false));
        }
        if let Some(bytes) = self.bundle_payload.take() {
            Self::store_payload(&paths, candidate.verified(), &bytes)
                .map_err(|error| error.with_changed(false))?;
        }
        protocol::activate(
            &paths,
            candidate.verified(),
            &Self::payload_path(&paths, candidate.verified()),
        )
        .map_err(mutation_failure)
    }
    fn rollback(&mut self) -> Result<bool, UpdateError> {
        let paths = self.paths()?;
        if self.lease.is_none() {
            return Err(authority("release lease is absent").with_changed(false));
        }
        protocol::rollback(&paths).map_err(mutation_failure)
    }
}
