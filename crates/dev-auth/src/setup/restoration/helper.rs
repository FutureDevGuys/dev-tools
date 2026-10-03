use super::*;

const NAME: &str = "dev-auth-setup-helper";

impl RetainedInstallationRestoration {
    pub(crate) fn verify_restored_setup_helper(&self, prior_sidecar: &[u8]) -> Result<()> {
        if !nix::unistd::Uid::effective().is_root()
            || !release_supports_setup_helper(&self.original)
            || !self.admitted_receipt()?.transparent_aliases.is_empty()
        {
            bail!("restored helper requires native root and inactive retained authority");
        }
        self.verify_inactive_transparent()?;
        let helper = self
            .receipt_directory
            .read(
                OsStr::new(NAME),
                &DocumentAuthority {
                    owner_uid: 0,
                    mode: 0o755,
                    limit: BINARY_LIMIT,
                },
            )?
            .context("restored setup helper is absent")?;
        let sidecar = self
            .receipt_directory
            .read(
                OsStr::new(SETUP_HELPER_RECEIPT_NAME),
                &DocumentAuthority {
                    owner_uid: 0,
                    mode: 0o644,
                    limit: RECEIPT_LIMIT,
                },
            )?
            .context("restored setup helper receipt is absent")?;
        if helper.identity != self.original_shared.active_identity
            || sidecar.bytes != prior_sidecar
            || serde_json::from_slice::<SetupHelperReceipt>(&sidecar.bytes)?
                != expected_setup_helper_receipt(
                    &self.paths.data_root.join(NAME),
                    &self.original,
                    &crate::release_manifest::target_id()?,
                )
        {
            bail!("retained helper restoration is incomplete");
        }
        Ok(())
    }

    /// The full-generation owner validates retained bytes against the approved
    /// snapshot before calling this fixed-leaf component. It also owns native
    /// exclusion and stopped-service/session admission.
    pub(crate) fn restore_setup_helper(&self, prior_sidecar: &[u8]) -> Result<bool> {
        if !nix::unistd::Uid::effective().is_root()
            || !release_supports_setup_helper(&self.original)
            || !release_supports_setup_helper(&self.candidate)
        {
            bail!("retained helper restoration requires native root and helper-owning releases");
        }
        if !self.admitted_receipt()?.transparent_aliases.is_empty() {
            bail!("retained helper restoration requires inactive integrations");
        }
        self.verify_inactive_transparent()?;
        let helper = self.paths.data_root.join(NAME);
        let target = crate::release_manifest::target_id()?;
        if prior_sidecar.is_empty() || prior_sidecar.len() as u64 > RECEIPT_LIMIT {
            bail!("retained setup helper receipt exceeds content bounds");
        }
        let prior: SetupHelperReceipt = serde_json::from_slice(prior_sidecar)?;
        if prior != expected_setup_helper_receipt(&helper, &self.original, &target) {
            bail!("retained helper receipt disagrees with original release authority");
        }
        let candidate_sidecar = serde_json::to_vec_pretty(&expected_setup_helper_receipt(
            &helper,
            &self.candidate,
            &target,
        ))?;
        let helper_authority = DocumentAuthority {
            owner_uid: 0,
            mode: 0o755,
            limit: BINARY_LIMIT,
        };
        let sidecar_authority = DocumentAuthority {
            owner_uid: 0,
            mode: 0o644,
            limit: RECEIPT_LIMIT,
        };
        let source_path = Path::new(&self.original.executable);
        let source_directory = dev_tools_installation::ExistingDocumentDirectory::open(
            source_path
                .parent()
                .context("retained helper source has no parent")?,
            0,
        )?;
        let source = source_directory
            .read(
                source_path
                    .file_name()
                    .context("retained helper source has no leaf")?,
                &helper_authority,
            )?
            .context("retained helper source is absent")?;
        if source.identity != self.original_shared.active_identity {
            bail!("retained helper source differs from original executable");
        }
        let current = self
            .receipt_directory
            .read(OsStr::new(NAME), &helper_authority)?
            .context("retained setup helper is absent")?;
        if current.identity != self.original_shared.active_identity
            && current.identity != self.candidate_shared.active_identity
        {
            bail!("setup helper is outside retained executable authority");
        }
        let sidecar = self
            .receipt_directory
            .read(OsStr::new(SETUP_HELPER_RECEIPT_NAME), &sidecar_authority)?
            .context("retained setup helper receipt is absent")?;
        if sidecar.bytes != prior_sidecar && sidecar.bytes != candidate_sidecar {
            bail!("setup helper receipt is outside retained document authority");
        }
        // Both leaves are admitted before mutation. Either retained combination
        // is valid after interruption; unrelated bytes or missing leaves are not.
        self.current_document()?;
        let mut changed = self.receipt_directory.replace(
            OsStr::new(NAME),
            &source.bytes,
            &helper_authority,
            &helper_authority,
            &current.identity,
        )?;
        changed |= self.receipt_directory.replace(
            OsStr::new(SETUP_HELPER_RECEIPT_NAME),
            prior_sidecar,
            &sidecar_authority,
            &sidecar_authority,
            &sidecar.identity,
        )?;
        self.verify_restored_setup_helper(prior_sidecar)?;
        Ok(changed)
    }
}
