//! Candidate-only maintenance. Prior receipts derive exact candidate history;
//! they never grant authority to reinstall earlier configuration or helpers.
use super::*;

pub(crate) struct RetainedCandidateMaintenance {
    candidate: InitialInstallationRestoration,
}

impl RetainedCandidateMaintenance {
    pub(crate) fn new(
        plan: &SetupPlan,
        prior: Option<(&InstallReceipt, &VersionedReceipt, u32)>,
    ) -> Result<Self> {
        let mut candidate = InitialInstallationRestoration::new(plan)?;
        if let Some((product, shared, mode)) = prior {
            let pair = RetainedInstallationRestoration::new_with_prior_receipt_mode(
                plan, product, shared, mode,
            )?;
            candidate.candidate = pair.candidate;
            candidate.shared = pair.candidate_shared;
        }
        Ok(Self { candidate })
    }

    pub(crate) fn executable(&self) -> &Path {
        Path::new(&self.candidate.candidate.executable)
    }
    pub(crate) fn receipt(&self) -> &InstallReceipt {
        &self.candidate.candidate
    }

    pub(crate) fn observe(&self) -> Result<()> {
        self.candidate.admitted_receipt()?;
        self.candidate.observe_initial_native_helpers()?;
        dev_tools_installation::observe_retained_versioned_installation_repair(
            &shared_installation_layout(&self.candidate.paths, self.candidate.candidate.mode),
            &self.candidate.shared,
            BINARY_LIMIT,
        )?;
        for alias in TRANSPARENT_ALIASES {
            let path = self.candidate.paths.bin_dir.join(alias);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("observe retained transparent activation"),
                Ok(metadata) => {
                    if !metadata.file_type().is_symlink()
                        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
                        || metadata.nlink() != 1
                        || fs::read_link(&path)? != self.executable()
                    {
                        bail!("transparent activation is outside retained candidate authority");
                    }
                    if self.candidate.admitted_receipt()?.is_none_or(|receipt| {
                        !receipt
                            .transparent_aliases
                            .iter()
                            .any(|owned| owned == alias)
                    }) {
                        bail!(
                            "unreceipted transparent activation cannot be adopted by maintenance"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn deactivate_and_stop(&self) -> Result<bool> {
        self.candidate.deactivate()
    }
    pub(crate) fn observe_shutdown(&self) -> Result<()> {
        self.candidate.observe_initial_shutdown()
    }

    /// Missing shared/product receipts are reconstructed only from the derived
    /// retained candidate. The shared primitive excludes implicit recovery.
    pub(crate) fn repair(&self) -> Result<bool> {
        self.observe()?;
        self.candidate.require_initial_services_stopped()?;
        self.candidate.verify_inactive_transparent()?;
        let mut changed = dev_tools_installation::repair_retained_versioned_installation(
            &shared_installation_layout(&self.candidate.paths, self.candidate.candidate.mode),
            &self.candidate.shared,
            BINARY_LIMIT,
        )?;
        let authority = self.candidate.document_authority();
        if self.candidate.admitted_receipt()?.is_none() {
            changed |= self.candidate.directory.write(
                OsStr::new("install-v2.json"),
                &serde_json::to_vec_pretty(&self.candidate.candidate)?,
                &authority,
                None,
            )?;
        }
        // This nested product seam remains serialized by the enclosing native
        // lease. Receipt validation above excludes another retained endpoint.
        repair_at(&self.candidate.paths)?;
        Ok(changed)
    }

    /// Removes activation while retaining immutable continuation artifacts and
    /// the stable locks. Definition documents are withdrawn by the outer owner.
    pub(crate) fn withdraw(&self) -> Result<bool> {
        self.observe()?;
        self.candidate.restore()
    }

    pub(crate) fn verify_withdrawn(&self) -> Result<()> {
        self.candidate.verify_restored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, SetupPlan) {
        let root = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let executable = |name: &str, bytes: &[u8]| {
            let path = root.path().join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let paths = SetupPaths::user_only(&root.path().join("home"));
        let request = InstallRequest {
            purpose: Default::default(),
            mode: InstallMode::UserOnly,
            version: "0.5.0".into(),
            source_executable: executable("source", b"candidate"),
            native_git: executable("native-git", b"git"),
            native_gh: executable("native-gh", b"gh"),
            activate_transparent_launchers: false,
        };
        let plan = build_plan(&paths, &request).unwrap();
        install_at(&paths, &request).unwrap();
        (root, plan)
    }

    #[test]
    fn candidate_maintenance_repairs_owned_absence_then_withdraws_and_retries() {
        let (_root, plan) = fixture();
        let maintenance = RetainedCandidateMaintenance::new(&plan, None).unwrap();
        fs::remove_file(plan.paths.receipt_path()).unwrap();
        fs::remove_file(plan.paths.data_root.join("installation-receipt-v1.json")).unwrap();
        fs::remove_file(plan.paths.bin_dir.join("dev-auth")).unwrap();
        maintenance.observe().unwrap();
        assert!(maintenance.repair().unwrap());
        assert!(!maintenance.repair().unwrap());
        assert!(maintenance.withdraw().unwrap());
        maintenance.verify_withdrawn().unwrap();
        assert!(!maintenance.withdraw().unwrap());
        assert_eq!(fs::read(maintenance.executable()).unwrap(), b"candidate");
        assert_eq!(fs::read(&plan.request.native_git).unwrap(), b"git");
    }

    #[test]
    fn candidate_maintenance_rejects_an_independent_alias_before_repair() {
        let (_root, plan) = fixture();
        let maintenance = RetainedCandidateMaintenance::new(&plan, None).unwrap();
        fs::remove_file(plan.paths.bin_dir.join("dev-auth")).unwrap();
        fs::remove_file(plan.paths.bin_dir.join("ssh-keygen-dev-auth")).unwrap();
        std::os::unix::fs::symlink(
            &plan.request.native_git,
            plan.paths.bin_dir.join("ssh-keygen-dev-auth"),
        )
        .unwrap();
        assert!(maintenance.observe().is_err());
        assert!(maintenance.repair().is_err());
        assert!(fs::symlink_metadata(plan.paths.bin_dir.join("dev-auth")).is_err());
    }
}
