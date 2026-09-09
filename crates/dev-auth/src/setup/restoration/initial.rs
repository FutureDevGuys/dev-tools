//! Fixed candidate-only native helper retirement. Original absence belongs to
//! the outer retained generation; these methods never infer it from live files.
use super::*;

impl InitialInstallationRestoration {
    fn initial_helper_authorities(
        &self,
    ) -> Result<Vec<(&'static str, DocumentAuthority, ArtifactIdentity)>> {
        let sidecar = serde_json::to_vec_pretty(&expected_setup_helper_receipt(
            &self.paths.data_root.join("dev-auth-setup-helper"),
            &self.candidate,
            &crate::release_manifest::target_id()?,
        ))?;
        Ok(vec![
            (
                "dev-auth-setup-helper",
                DocumentAuthority {
                    owner_uid: 0,
                    mode: 0o755,
                    limit: BINARY_LIMIT,
                },
                self.shared.active_identity.clone(),
            ),
            (
                SETUP_HELPER_RECEIPT_NAME,
                DocumentAuthority {
                    owner_uid: 0,
                    mode: 0o644,
                    limit: RECEIPT_LIMIT,
                },
                ArtifactIdentity {
                    length: sidecar.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(&sidecar)),
                },
            ),
        ])
    }

    pub(super) fn require_initial_native_authority(&self) -> Result<()> {
        if self.candidate.mode != InstallMode::Strong
            || !nix::unistd::Uid::effective().is_root()
            || self.paths != SetupPaths::strong()
            || !release_supports_setup_helper(&self.candidate)
        {
            bail!("initial native retirement requires exact system candidate authority");
        }
        let source = Path::new(&self.candidate.executable);
        let directory = dev_tools_installation::ExistingDocumentDirectory::open(
            source
                .parent()
                .context("initial native source has no parent")?,
            0,
        )?;
        let document = directory
            .read(
                source
                    .file_name()
                    .context("initial native source has no name")?,
                &DocumentAuthority {
                    owner_uid: 0,
                    mode: 0o755,
                    limit: BINARY_LIMIT,
                },
            )?
            .context("initial native continuation executable is absent")?;
        if document.identity != self.shared.active_identity {
            bail!("initial native continuation executable changed");
        }
        Ok(())
    }

    pub(super) fn observe_initial_native_helpers(&self) -> Result<()> {
        if self.candidate.mode == InstallMode::UserOnly {
            return Ok(());
        }
        self.require_initial_native_authority()?;
        for (name, authority, expected) in self.initial_helper_authorities()? {
            if self
                .directory
                .read(OsStr::new(name), &authority)?
                .is_some_and(|document| document.identity != expected)
            {
                bail!("initial native helper is outside retained candidate authority");
            }
        }
        self.observe_initial_privileged_launcher()
    }

    pub(super) fn retire_initial_native_helpers(&self) -> Result<bool> {
        if self.candidate.mode == InstallMode::UserOnly {
            return Ok(false);
        }
        self.require_initial_native_authority()?;
        if self
            .admitted_receipt()?
            .is_some_and(|receipt| !receipt.transparent_aliases.is_empty())
        {
            bail!("initial helper retirement requires inactive integrations");
        }
        self.verify_inactive_transparent()?;
        // Observe every fixed leaf before removing one. Exact candidate bytes
        // remain removal authority after a receipt or sibling leaf disappears.
        self.observe_initial_native_helpers()?;
        let mut changed = self.retire_initial_privileged_launcher()?;
        for (name, authority, expected) in self.initial_helper_authorities()? {
            changed |= self
                .directory
                .remove(OsStr::new(name), &authority, &expected)?;
        }
        Ok(changed)
    }
}
