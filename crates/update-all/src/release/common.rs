//! Common observation and metadata-only refresh. Installation mutation remains
//! on legacy routes until the common mutation adapter is qualified.
use super::*;
use dev_tools_product::{OperationResultV2, ProductId};
use dev_tools_update::{
    execute, AuthenticatedCandidate, InstallationSnapshot, OperationRequest, UpdateAdapter,
    UpdateError, UpdateErrorKind, UpdatePolicy,
};

pub(crate) fn status() -> Result<OperationResultV2> {
    run(OperationRequest::status())
}

pub(crate) fn check() -> Result<OperationResultV2> {
    run(OperationRequest::check())
}

fn run(request: OperationRequest) -> Result<OperationResultV2> {
    let policy = UpdatePolicy::standard(ProductId::parse("update-all")?);
    let paths = Paths::resolve(Product::UpdateAll);
    let checked_at_unix = now_unix();
    Ok(execute(
        &policy,
        request,
        checked_at_unix,
        &mut CommonAdapter {
            paths,
            checked_at_unix,
        },
    ))
}

struct CommonAdapter {
    paths: Result<Paths>,
    checked_at_unix: u64,
}

const CACHE_SCHEMA: &str = "update-all-authenticated-candidate-v1";
const CACHE_LIMIT: u64 = 12 * METADATA_LIMIT + 4096;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateCache {
    schema: String,
    root: String,
    manifest: String,
    checked_at_unix: u64,
}

fn candidate_authority() -> ReleaseAuthority {
    ReleaseAuthority {
        trusted_root_key: env!("UPDATE_ALL_TRUST_ROOT_PUBLIC_KEY").into(),
        product: Product::UpdateAll.id().into(),
        accepted_manifest_schemas: vec!["dev-tools-product-v2".into()],
        target: target_id(),
        artifact_url: ArtifactUrlPolicy::GitHubRelease {
            owner: "FutureDevGuys".into(),
            repository: "dev-tools".into(),
        },
        require_source_commit: true,
        engine_protocol: ENGINE_PROTOCOL,
    }
}

impl CandidateCache {
    fn path(paths: &Paths) -> PathBuf {
        paths
            .product_root
            .join("cache/authenticated-candidate-v1.json")
    }

    fn authority(paths: &Paths) -> Result<dev_tools_installation::DocumentAuthority> {
        Ok(dev_tools_installation::DocumentAuthority {
            limit: CACHE_LIMIT,
            ..state_document_authority(paths)?
        })
    }

    fn metadata(&self) -> Result<ReleaseMetadata> {
        if self.schema != CACHE_SCHEMA
            || [self.root.as_bytes(), self.manifest.as_bytes()]
                .iter()
                .any(|bytes| bytes.is_empty() || bytes.len() as u64 > METADATA_LIMIT)
        {
            bail!("invalid authenticated candidate cache");
        }
        Ok(ReleaseMetadata {
            root: self.root.as_bytes().to_vec(),
            manifest: self.manifest.as_bytes().to_vec(),
        })
    }

    fn load(paths: &Paths) -> Result<Option<AuthenticatedCandidate>> {
        let authority = Self::authority(paths)?;
        let Some(document) =
            dev_tools_installation::read_atomic_document(&Self::path(paths), &authority)?
        else {
            return Ok(None);
        };
        let cache: Self = serde_json::from_slice(&document.bytes)?;
        let metadata = cache.metadata()?;
        let mut ledger = protocol::observation_ledger(paths)?;
        let (verified, changed) =
            ledger.accept_release_metadata(&candidate_authority(), &metadata)?;
        // Cached bytes can only describe the exact independently accepted release.
        // Even a valid signature cannot advance or recreate durable history here.
        if changed {
            bail!("cached release is not the accepted candidate");
        }
        Ok(Some(AuthenticatedCandidate::new(
            verified,
            cache.checked_at_unix,
            false,
        )?))
    }
}

impl CommonAdapter {
    #[cfg(target_os = "linux")]
    fn refresh_with(
        paths: &Paths,
        checked_at_unix: u64,
        fetch: impl FnOnce() -> Result<ReleaseMetadata>,
    ) -> Result<AuthenticatedCandidate, UpdateError> {
        let authority_error = |_| UpdateError::new(UpdateErrorKind::Authority);
        let layout =
            shared_installation_layout(Product::UpdateAll, paths).map_err(authority_error)?;
        dev_tools_installation::ensure_owned_directory(
            &layout.data_root,
            layout.owner_uid,
            layout.directory_mode,
        )
        .map_err(authority_error)?;
        let lease = acquire_release_writer(paths).map_err(|error| {
            UpdateError::new(if error.downcast_ref::<ReleaseMutationBusy>().is_some() {
                UpdateErrorKind::Blocked
            } else {
                UpdateErrorKind::Authority
            })
        })?;
        if path_entry_present(
            &layout.data_root.join("installation-transition-v1.json"),
            "inspect pending installation",
        )
        .map_err(authority_error)?
        {
            dev_tools_installation::versioned_v2::pending_recovery(&layout)
                .map_err(authority_error)?;
            return Err(UpdateError::new(UpdateErrorKind::Blocked));
        }
        let acceptance =
            protocol::MetadataAcceptance::begin(paths, &lease).map_err(authority_error)?;
        let cache_path = CandidateCache::path(paths);
        let cache_authority = CandidateCache::authority(paths).map_err(authority_error)?;
        let original = dev_tools_installation::read_atomic_document(&cache_path, &cache_authority)
            .map_err(authority_error)?;
        if let Some(document) = &original {
            let cache: CandidateCache = serde_json::from_slice(&document.bytes)
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authority))?;
            let metadata = cache.metadata().map_err(authority_error)?;
            verify_release_metadata(&metadata, &candidate_authority()).map_err(authority_error)?;
        }
        // Only original metadata crosses this boundary. Production uses the
        // admitted HTTPS transport, never artifact retrieval or execution.
        let metadata = fetch().map_err(|error| {
            UpdateError::new(if error.downcast_ref::<IntegrityFailure>().is_some() {
                UpdateErrorKind::Authenticity
            } else {
                UpdateErrorKind::Network
            })
        })?;
        let cache = CandidateCache {
            schema: CACHE_SCHEMA.into(),
            root: String::from_utf8(metadata.root.clone())
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authenticity))?,
            manifest: String::from_utf8(metadata.manifest.clone())
                .map_err(|_| UpdateError::new(UpdateErrorKind::Authenticity))?,
            checked_at_unix,
        };
        cache.metadata().map_err(authority_error)?;
        let bytes = serde_json::to_vec(&cache)
            .map_err(|_| UpdateError::new(UpdateErrorKind::Operational))?;
        let current = dev_tools_installation::read_atomic_document(&cache_path, &cache_authority)
            .map_err(authority_error)?;
        let expected = original.as_ref().map(|document| &document.identity);
        if current.as_ref().map(|document| &document.identity) != expected {
            return Err(UpdateError::new(UpdateErrorKind::Authority));
        }
        // Publish history first. Cache failure can leave evidence unavailable,
        // but cannot leave a cache that establishes unaccepted authority.
        let verified = acceptance
            .accept(&metadata, &candidate_authority())
            .map_err(authority_error)?;
        dev_tools_installation::write_atomic_document(
            &cache_path,
            &bytes,
            &cache_authority,
            expected,
        )
        .map_err(authority_error)?;
        AuthenticatedCandidate::new(verified, cache.checked_at_unix, false)
    }

    #[cfg(target_os = "linux")]
    fn observe(paths: &Paths) -> Result<InstallationSnapshot> {
        use dev_tools_installation::{observe_versioned_installation, versioned_v2};
        if !paths.bin_dir.is_absolute() || !paths.public_binary.is_absolute() {
            bail!("public command authority must be absolute");
        }
        state_document_authority(paths)?;
        match classify_install(Product::UpdateAll, paths)? {
            InstallClassification::External => return Ok(InstallationSnapshot::external(None)),
            InstallClassification::Absent => {
                // Admit legacy state without interpreting its observational active
                // version or check time as receipt ownership or fresh evidence.
                load_state(paths)?;
                return Ok(InstallationSnapshot::absent());
            }
            InstallClassification::Managed => {}
        }
        let layout = shared_installation_layout(Product::UpdateAll, paths)?;
        if path_entry_present(
            &layout.data_root.join("installation-transition-v1.json"),
            "inspect pending installation",
        )? {
            // Recognized pending v2 state is observable, never recovered here.
            // A legacy/unknown journal fails closed and retains its own repair route.
            versioned_v2::pending_recovery(&layout)?
                .context("installation transition disappeared during observation")?;
            return Ok(InstallationSnapshot::unknown(None));
        }
        let initialized = versioned_v2::read_receipt_metadata(&layout).is_ok();
        let receipt = if initialized {
            protocol::observe_authenticated(paths)?
        } else {
            // This is a strict v1 decoder, not a default on invalid v2 bytes.
            // Complete observation checks links and bytes without legacy recovery.
            load_state(paths)?;
            observe_versioned_installation(&layout, ARTIFACT_LIMIT)?
        };
        match receipt {
            Some(receipt) => Ok(InstallationSnapshot::managed(Some(Version::parse(
                &receipt.active_version,
            )?))),
            None if initialized => Ok(InstallationSnapshot::managed(None)),
            None => Ok(InstallationSnapshot::unknown(None)),
        }
    }
}

impl UpdateAdapter for CommonAdapter {
    fn inspect(&mut self) -> Result<InstallationSnapshot, UpdateError> {
        let paths = self
            .paths
            .as_ref()
            .map_err(|_| UpdateError::new(UpdateErrorKind::InvalidConfiguration))?;
        #[cfg(target_os = "linux")]
        return Self::observe(paths).map_err(|_| UpdateError::new(UpdateErrorKind::Authority));
        #[cfg(not(target_os = "linux"))]
        Err(UpdateError::new(UpdateErrorKind::Unsupported))
    }

    fn load_authenticated_candidate(
        &mut self,
    ) -> Result<Option<AuthenticatedCandidate>, UpdateError> {
        let paths = self
            .paths
            .as_ref()
            .map_err(|_| UpdateError::new(UpdateErrorKind::InvalidConfiguration))?;
        CandidateCache::load(paths).map_err(|_| UpdateError::new(UpdateErrorKind::Authority))
    }

    fn refresh_authenticated_candidate(&mut self) -> Result<AuthenticatedCandidate, UpdateError> {
        let paths = self
            .paths
            .as_ref()
            .map_err(|_| UpdateError::new(UpdateErrorKind::InvalidConfiguration))?;
        #[cfg(target_os = "linux")]
        return Self::refresh_with(paths, self.checked_at_unix, || {
            let (root_url, manifest_url) = resolve_release_urls(Product::UpdateAll)?;
            Ok(ReleaseMetadata {
                root: https_get(&root_url, None, METADATA_LIMIT)?.bytes,
                manifest: https_get(&manifest_url, None, METADATA_LIMIT)?.bytes,
            })
        });
        #[cfg(not(target_os = "linux"))]
        Err(UpdateError::new(UpdateErrorKind::Unsupported))
    }

    fn install(&mut self, _: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        Err(UpdateError::new(UpdateErrorKind::Unsupported).with_changed(false))
    }

    fn apply(&mut self, _: &AuthenticatedCandidate) -> Result<bool, UpdateError> {
        Err(UpdateError::new(UpdateErrorKind::Unsupported).with_changed(false))
    }

    fn rollback(&mut self) -> Result<bool, UpdateError> {
        Err(UpdateError::new(UpdateErrorKind::Unsupported).with_changed(false))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use dev_tools_installation::versioned_v2;
    use dev_tools_product::{InstallationState, OperationOutcome};

    #[cfg(target_arch = "x86_64")]
    fn signed_metadata() -> ReleaseMetadata {
        ReleaseMetadata {
            root: include_bytes!("../../../../release-trust/dev-tools-root.json").to_vec(),
            manifest: include_bytes!(
                "../../../../tests/fixtures/releases/update-all-0.1.6-v2.json"
            )
            .to_vec(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn common_check_publishes_separate_history_and_bounded_cache_without_installation() -> Result<()>
    {
        use dev_tools_product::CacheFreshness;
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        let checked_at = now_unix();
        let candidate = CommonAdapter::refresh_with(&paths, checked_at, || Ok(signed_metadata()))?;
        assert_eq!(candidate.verified().version.to_string(), "0.1.6");
        assert!(!candidate.artifact_available());
        assert_eq!(candidate.checked_at_unix(), checked_at);
        assert!(paths.state.is_file());
        assert!(!paths
            .product_root
            .join("installation-receipt-v1.json")
            .exists());
        assert!(!paths
            .product_root
            .join("installation-transition-v1.json")
            .exists());
        assert!(!paths
            .product_root
            .join("release-authority-v2.json")
            .exists());
        assert!(!paths.versions.exists());
        assert!(!paths.public_binary.exists());
        let history = fs::read(&paths.state)?;
        let cache = fs::read(CandidateCache::path(&paths))?;
        assert_eq!(CandidateCache::load(&paths)?, Some(candidate));
        let expired = execute(
            &UpdatePolicy::standard(ProductId::parse("update-all")?),
            OperationRequest::status(),
            checked_at + 24 * 60 * 60 + 1,
            &mut CommonAdapter {
                paths: Ok(super::super::tests::state_test_paths(root.path())),
                checked_at_unix: checked_at,
            },
        );
        assert_eq!(expired.outcome, OperationOutcome::Unknown);
        assert_eq!(expired.cache_freshness, Some(CacheFreshness::Expired));
        assert_eq!(expired.available_version.as_deref(), Some("0.1.6"));
        assert_eq!(fs::read(&paths.state)?, history);
        assert_eq!(fs::read(CandidateCache::path(&paths))?, cache);
        fs::remove_file(CandidateCache::path(&paths))?;
        assert_eq!(CandidateCache::load(&paths)?, None);
        assert_eq!(fs::read(&paths.state)?, history);
        CommonAdapter::refresh_with(&paths, checked_at, || Ok(signed_metadata()))?;
        assert_eq!(fs::read(&paths.state)?, history);
        assert_eq!(fs::read(CandidateCache::path(&paths))?, cache);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn common_check_uses_initialized_authority_and_never_recovers_pending_state() -> Result<()> {
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        protocol::initialize(Product::UpdateAll, &paths, &[])?;
        CommonAdapter::refresh_with(&paths, now_unix(), || Ok(signed_metadata()))?;
        assert!(paths.state.is_dir());
        let authority = paths.product_root.join("release-authority-v2.json");
        let before = fs::read(&authority)?;
        let receipt = paths.product_root.join("installation-receipt-v1.json");
        let receipt_before = fs::read(&receipt)?;
        assert_eq!(
            CandidateCache::load(&paths)?
                .unwrap()
                .verified()
                .version
                .to_string(),
            "0.1.6"
        );
        CommonAdapter::refresh_with(&paths, now_unix(), || Ok(signed_metadata()))?;
        assert_eq!(fs::read(&authority)?, before);
        assert_eq!(fs::read(&receipt)?, receipt_before);
        fs::remove_file(&authority)?;
        let error = CommonAdapter::refresh_with(&paths, now_unix(), || {
            panic!("missing authority must stop before network")
        })
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::Authority);
        assert!(!authority.exists());
        assert_eq!(fs::read(&receipt)?, receipt_before);

        let pending = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(pending.path());
        let layout = shared_installation_layout(Product::UpdateAll, &paths)?;
        assert!(
            versioned_v2::initialize(&layout, ARTIFACT_LIMIT, |_| bail!("interrupted")).is_err()
        );
        let journal = paths.product_root.join("installation-transition-v1.json");
        let before = fs::read(&journal)?;
        let error = CommonAdapter::refresh_with(&paths, now_unix(), || {
            panic!("pending state must stop before network")
        })
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::Blocked);
        assert_eq!(fs::read(&journal)?, before);
        assert!(!paths.state.exists());
        assert!(!CandidateCache::path(&paths).exists());
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn common_check_rejects_invalid_metadata_and_changed_history_without_cache_publication(
    ) -> Result<()> {
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        CommonAdapter::refresh_with(&paths, now_unix(), || Ok(signed_metadata()))?;
        let history = fs::read(&paths.state)?;
        let cache_path = CandidateCache::path(&paths);
        let cache = fs::read(&cache_path)?;
        let mut invalid = signed_metadata();
        invalid.manifest = b"{}".to_vec();
        assert!(CommonAdapter::refresh_with(&paths, now_unix(), || Ok(invalid)).is_err());
        assert_eq!(fs::read(&paths.state)?, history);
        assert_eq!(fs::read(&cache_path)?, cache);
        let error = CommonAdapter::refresh_with(&paths, now_unix(), || {
            fs::write(&paths.state, b"intervening authority")?;
            Ok(signed_metadata())
        })
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::Authority);
        assert_eq!(fs::read(&paths.state)?, b"intervening authority");
        assert_eq!(fs::read(&cache_path)?, cache);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn common_cache_rejects_hostile_documents_and_serializes_refresh() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        CommonAdapter::refresh_with(&paths, now_unix(), || Ok(signed_metadata()))?;
        let cache = CandidateCache::path(&paths);
        let bytes = fs::read(&cache)?;
        let history = fs::read(&paths.state)?;
        let lease = acquire_release_writer(&paths)?;
        let error = CommonAdapter::refresh_with(&paths, now_unix(), || {
            panic!("busy writer must stop before network")
        })
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::Blocked);
        assert_eq!(fs::read(&cache)?, bytes);
        drop(lease);
        let mut unknown: serde_json::Value = serde_json::from_slice(&bytes)?;
        unknown["unexpected_authority"] = true.into();
        for hostile in [
            serde_json::to_vec(&unknown)?,
            b"unmarked bytes".to_vec(),
            vec![b' '; CACHE_LIMIT as usize + 1],
        ] {
            fs::write(&cache, &hostile)?;
            assert!(CandidateCache::load(&paths).is_err());
            let error = CommonAdapter::refresh_with(&paths, now_unix(), || {
                panic!("hostile cache must stop before network")
            })
            .unwrap_err();
            assert_eq!(error.kind(), UpdateErrorKind::Authority);
            assert_eq!(fs::read(&cache)?, hostile);
            assert_eq!(fs::read(&paths.state)?, history);
        }
        fs::write(&cache, &bytes)?;
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o644))?;
        assert!(CandidateCache::load(&paths).is_err());
        fs::set_permissions(&cache, fs::Permissions::from_mode(0o600))?;
        let outside = root.path().join("outside");
        fs::rename(&cache, &outside)?;
        std::os::unix::fs::symlink(&outside, &cache)?;
        assert!(CandidateCache::load(&paths).is_err());
        let error = CommonAdapter::refresh_with(&paths, now_unix(), || {
            panic!("linked cache must stop before network")
        })
        .unwrap_err();
        assert_eq!(error.kind(), UpdateErrorKind::Authority);
        assert_eq!(fs::read(&outside)?, bytes);
        assert_eq!(fs::read(&paths.state)?, history);
        Ok(())
    }

    fn observe(paths: Paths) -> OperationResultV2 {
        execute(
            &UpdatePolicy::standard(ProductId::parse("update-all").unwrap()),
            OperationRequest::status(),
            now_unix(),
            &mut CommonAdapter {
                paths: Ok(paths),
                checked_at_unix: now_unix(),
            },
        )
    }

    #[test]
    fn common_status_preserves_pending_cutover_and_requires_initialized_authority() -> Result<()> {
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        let layout = shared_installation_layout(Product::UpdateAll, &paths)?;
        assert!(
            versioned_v2::initialize(&layout, ARTIFACT_LIMIT, |_| bail!("interrupted")).is_err()
        );
        let journal = layout.data_root.join("installation-transition-v1.json");
        let before = fs::read(&journal)?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.installation_state, Some(InstallationState::Unknown));
        assert_eq!(result.outcome, OperationOutcome::Unknown);
        assert_eq!(result.changed, Some(false));
        assert_eq!(fs::read(&journal)?, before);
        assert!(!paths.state.exists());

        protocol::initialize(Product::UpdateAll, &paths, &[])?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.installation_state, Some(InstallationState::Managed));
        assert_eq!(result.installed_version, None);
        assert_eq!(result.outcome, OperationOutcome::Unknown);
        assert_eq!(result.changed, Some(false));
        let authority = paths.product_root.join("release-authority-v2.json");
        let retained = fs::read(&authority)?;
        fs::remove_file(&authority)?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.exit_code, 4);
        assert_eq!(result.changed, Some(false));
        assert!(!authority.exists());
        assert!(paths.state.is_dir());
        assert!(!retained.is_empty());
        Ok(())
    }

    #[test]
    fn common_status_does_not_promote_legacy_observations_to_freshness() -> Result<()> {
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        create_private_dir(&paths.product_root)?;
        save_state(
            &paths,
            &ReleaseState {
                active_version: Some("999.0.0".into()),
                last_successful_check_unix: Some(now_unix()),
                ..ReleaseState::default()
            },
        )?;
        let before = fs::read(&paths.state)?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.installed_version, None);
        assert_eq!(result.available_version, None);
        assert_eq!(result.outcome, OperationOutcome::Unknown);
        assert_eq!(fs::read(&paths.state)?, before);
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn common_status_reauthenticates_original_cache_against_separate_history() -> Result<()> {
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        let metadata = ReleaseMetadata {
            root: include_bytes!("../../../../release-trust/dev-tools-root.json").to_vec(),
            manifest: include_bytes!(
                "../../../../tests/fixtures/releases/update-all-0.1.6-v2.json"
            )
            .to_vec(),
        };
        create_private_dir(&paths.product_root)?;
        let mut state = ReleaseState::default();
        accept_manifest_metadata(
            &mut state,
            &verify_downloaded_manifest(Product::UpdateAll, &metadata)?,
        )?;
        save_state(&paths, &state)?;
        let history = fs::read(&paths.state)?;
        let cache = paths
            .product_root
            .join("cache/authenticated-candidate-v1.json");
        let document = serde_json::json!({
            "schema": "update-all-authenticated-candidate-v1",
            "root": String::from_utf8(metadata.root)?,
            "manifest": String::from_utf8(metadata.manifest)?,
            "checked_at_unix": now_unix()
        });
        let authority = dev_tools_installation::DocumentAuthority {
            limit: 12 * METADATA_LIMIT + 4096,
            ..state_document_authority(&paths)?
        };
        dev_tools_installation::write_atomic_document(
            &cache,
            &serde_json::to_vec(&document)?,
            &authority,
            None,
        )?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.available_version.as_deref(), Some("0.1.6"));
        assert_eq!(result.changed, Some(false));
        assert_eq!(fs::read(&paths.state)?, history);
        // A cache cannot reestablish lost acceptance history.
        fs::remove_file(&paths.state)?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.exit_code, 4);
        assert!(!paths.state.exists());
        assert!(cache.exists());
        Ok(())
    }

    #[test]
    fn common_status_checks_legacy_receipt_bytes_without_repair() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir()?;
        let paths = super::super::tests::state_test_paths(root.path());
        let layout = shared_installation_layout(Product::UpdateAll, &paths)?;
        let source = root.path().join("source");
        fs::write(&source, b"receipt-owned fixture")?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700))?;
        let identity = ArtifactIdentity {
            length: 21,
            sha256: format!("{:x}", Sha256::digest(b"receipt-owned fixture")),
        };
        apply_versioned_installation(
            &VersionedInstallRequest {
                layout,
                version: "1.0.0".into(),
                source,
                identity,
                aliases: vec!["update-all".into()],
            },
            |_| Ok(()),
        )?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.installation_state, Some(InstallationState::Managed));
        assert_eq!(result.installed_version.as_deref(), Some("1.0.0"));
        assert_eq!(result.outcome, OperationOutcome::Unknown);
        fs::remove_file(&paths.public_binary)?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.exit_code, 4);
        assert!(!paths.public_binary.exists());
        assert_eq!(result.changed, Some(false));
        std::os::unix::fs::symlink(paths.product_root.join("active"), &paths.public_binary)?;
        let artifact = paths.versions.join("1.0.0/update-all");
        fs::write(&artifact, b"corrupted fixture")?;
        let result = observe(super::super::tests::state_test_paths(root.path()));
        assert_eq!(result.exit_code, 4);
        assert_eq!(result.installed_version, None);
        assert_eq!(fs::read(&artifact)?, b"corrupted fixture");
        Ok(())
    }
}
