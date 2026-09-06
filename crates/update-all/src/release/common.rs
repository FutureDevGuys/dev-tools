//! Common local observation. Mutation and metadata refresh remain on their
//! legacy public routes until the authenticated common adapter is qualified.
use super::*;
use dev_tools_product::{OperationResultV2, ProductId};
use dev_tools_update::{
    execute, AuthenticatedCandidate, InstallationSnapshot, OperationRequest, UpdateAdapter,
    UpdateError, UpdateErrorKind, UpdatePolicy,
};

pub(crate) fn status() -> Result<OperationResultV2> {
    let policy = UpdatePolicy::standard(ProductId::parse("update-all")?);
    let paths = Paths::resolve(Product::UpdateAll);
    Ok(execute(
        &policy,
        OperationRequest::status(),
        now_unix(),
        &mut StatusAdapter { paths },
    ))
}

struct StatusAdapter {
    paths: Result<Paths>,
}

impl StatusAdapter {
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

impl UpdateAdapter for StatusAdapter {
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
        // Legacy HTTP observations and six-hour check timestamps are not the
        // common authenticated candidate cache. Absence cannot mean current.
        Ok(None)
    }

    fn refresh_authenticated_candidate(&mut self) -> Result<AuthenticatedCandidate, UpdateError> {
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

    fn observe(paths: Paths) -> OperationResultV2 {
        execute(
            &UpdatePolicy::standard(ProductId::parse("update-all").unwrap()),
            OperationRequest::status(),
            now_unix(),
            &mut StatusAdapter { paths: Ok(paths) },
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
