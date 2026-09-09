//! Binary portion of a retained full-generation restoration. The full setup
//! owner holds admission exclusion, validates retention and stops integrations.
use super::*;
use dev_tools_installation::{ArtifactIdentity, DocumentAuthority, VersionedReceipt};

mod helper;
mod initial;
mod launcher;
pub(crate) use launcher::StrongLauncherCompletion;
mod service;

pub(crate) fn require_candidate_services_stopped() -> Result<()> {
    service::require_candidate_services_stopped()
}

pub(super) fn require_completion_services_stopped(files: &[bool; 3]) -> Result<()> {
    service::require_completion_stopped(files)
}

pub(super) fn synchronize_completion_services(record_change: impl FnMut(bool)) -> Result<bool> {
    service::synchronize_completion(record_change)
}

/// The enclosing retained-generation owner must prove original absence before
/// selecting this case. Candidate bytes remain available after withdrawal.
pub(crate) struct InitialInstallationRestoration {
    paths: SetupPaths,
    candidate: InstallReceipt,
    shared: VersionedReceipt,
    directory: dev_tools_installation::ExistingDocumentDirectory,
}

impl InitialInstallationRestoration {
    pub(crate) fn new(plan: &SetupPlan) -> Result<Self> {
        if plan.schema != "dev-auth-setup-plan-v2" || plan.request.activate_transparent_launchers {
            bail!("initial restoration requires an inactive installation plan");
        }
        let strong = plan.request.mode == InstallMode::Strong;
        if strong
            && (!nix::unistd::Uid::effective().is_root()
                || plan.paths != SetupPaths::strong()
                || plan.verified_release.is_none())
        {
            bail!("initial strong restoration requires native system and release authority");
        }
        validate_version(&plan.request.version)?;
        validate_native_program(&plan.request.native_git, "candidate native Git")?;
        validate_native_program(&plan.request.native_gh, "candidate native GitHub CLI")?;
        let executable = plan.paths.versioned_binary(&plan.request.version);
        if file_identity(&executable)? != (plan.source_length, plan.source_sha256.clone()) {
            bail!("retained initial candidate executable changed");
        }
        if let Some(release) = &plan.verified_release {
            if release.schema != "dev-auth-verified-release-v1"
                || release.version != plan.request.version
                || release.artifact_length != plan.source_length
                || release.artifact_sha256 != plan.source_sha256
                || release.artifact_path != plan.request.source_executable
                || release.root_generation == 0
                || release.manifest_generation == 0
                || (strong && release.target != crate::release_manifest::target_id()?)
            {
                bail!("initial candidate provenance disagrees with retained approval");
            }
        }
        let release = plan.verified_release.as_ref();
        let candidate = InstallReceipt {
            schema: RECEIPT_SCHEMA.into(),
            mode: plan.request.mode,
            version: plan.request.version.clone(),
            executable: executable.display().to_string(),
            bin_dir: plan.paths.bin_dir.display().to_string(),
            executable_length: plan.source_length,
            executable_sha256: plan.source_sha256.clone(),
            source_commit: release.map(|release| release.source_commit.clone()),
            root_generation: release.map(|release| release.root_generation),
            manifest_generation: release.map(|release| release.manifest_generation),
            native_git: plan.request.native_git.display().to_string(),
            native_gh: plan.request.native_gh.display().to_string(),
            product_aliases: PRODUCT_ALIASES.map(str::to_owned).to_vec(),
            transparent_aliases: Vec::new(),
            privileged_launcher: strong.then(|| {
                plan.paths
                    .data_root
                    .join("dev-auth-workload-launcher")
                    .display()
                    .to_string()
            }),
            system_assets: if strong {
                system_asset_digests()
            } else {
                BTreeMap::new()
            },
            previous_release: None,
        };
        if strong && !release_supports_setup_helper(&candidate) {
            bail!("initial strong restoration requires a helper-owning candidate");
        }
        let layout = shared_installation_layout(&plan.paths, plan.request.mode);
        let directory = dev_tools_installation::ExistingDocumentDirectory::open(
            &plan.paths.data_root,
            layout.owner_uid,
        )?;
        let shared = VersionedReceipt {
            schema: "dev-tools-versioned-installation-v1".into(),
            product: layout.product,
            data_root: layout.data_root,
            bin_dir: layout.bin_dir,
            artifact_name: layout.artifact_name,
            active_version: candidate.version.clone(),
            active_identity: ArtifactIdentity {
                length: candidate.executable_length,
                sha256: candidate.executable_sha256.clone(),
            },
            previous_version: None,
            previous_identity: None,
            aliases: shared_product_aliases(),
        };
        Ok(Self {
            paths: plan.paths.clone(),
            candidate,
            shared,
            directory,
        })
    }

    fn document_authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            mode: receipt_permissions(self.candidate.mode),
            limit: RECEIPT_LIMIT,
        }
    }

    pub(crate) fn admitted_receipt(&self) -> Result<Option<InstallReceipt>> {
        let Some(document) = self
            .directory
            .read(OsStr::new("install-v2.json"), &self.document_authority())?
        else {
            return Ok(None);
        };
        let receipt: InstallReceipt = serde_json::from_slice(&document.bytes)?;
        let mut inactive = receipt.clone();
        inactive.transparent_aliases.clear();
        if inactive != self.candidate
            || (!receipt.transparent_aliases.is_empty()
                && receipt.transparent_aliases != TRANSPARENT_ALIASES.map(str::to_owned))
        {
            bail!("initial restoration receipt differs from approved candidate");
        }
        Ok(Some(receipt))
    }

    fn verify_inactive_transparent(&self) -> Result<()> {
        // Original absence is established by the full generation. Unreceipted
        // replacements are not ours to delete, even if they appear native.
        for alias in TRANSPARENT_ALIASES {
            require_restored_absence(&self.paths.bin_dir.join(alias))?;
        }
        Ok(())
    }

    pub(crate) fn integration_executable(&self) -> Result<PathBuf> {
        self.admitted_receipt()?;
        self.observe_initial_native_helpers()?;
        Ok(PathBuf::from(&self.candidate.executable))
    }

    pub(crate) fn deactivate(&self) -> Result<bool> {
        self.observe_initial_native_helpers()?;
        let Some(receipt) = self.admitted_receipt()? else {
            self.verify_inactive_transparent()?;
            return self.stop_initial_services();
        };
        let authority = self.document_authority();
        let document = self
            .directory
            .read(OsStr::new("install-v2.json"), &authority)?
            .context("initial restoration receipt disappeared")?;
        if serde_json::from_slice::<InstallReceipt>(&document.bytes)? != receipt {
            bail!("initial restoration receipt changed");
        }
        for alias in &receipt.transparent_aliases {
            let path = self.paths.bin_dir.join(alias);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect initial restoration launcher"),
                Ok(_) => remove_owned_alias(&path, Path::new(&receipt.executable))?,
            }
        }
        File::open(&self.paths.bin_dir)?.sync_all()?;
        self.verify_inactive_transparent()?;
        let changed = self.directory.write(
            OsStr::new("install-v2.json"),
            &serde_json::to_vec_pretty(&self.candidate)?,
            &authority,
            Some(&document.identity),
        )?;
        let service_changed = self.stop_initial_services()?;
        Ok(changed || service_changed || !receipt.transparent_aliases.is_empty())
    }

    pub(crate) fn restore(&self) -> Result<bool> {
        self.require_initial_services_stopped()?;
        self.verify_inactive_transparent()?;
        if self
            .admitted_receipt()?
            .is_some_and(|receipt| receipt != self.candidate)
        {
            bail!("initial restoration integrations remain active");
        }
        let layout = shared_installation_layout(&self.paths, self.candidate.mode);
        let mut changed = self.retire_initial_native_helpers()?;
        // Recovery is selected only for a pending binary journal. A partially
        // withdrawn installation intentionally lacks links and is not repaired.
        match fs::symlink_metadata(self.paths.data_root.join("installation-transition-v1.json")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect initial binary journal"),
            Ok(_) => {
                changed |= dev_tools_installation::recover_versioned_installation_transition(
                    &layout,
                    None,
                    &self.shared,
                    BINARY_LIMIT,
                    |_| Ok(()),
                )?
                .0;
            }
        }
        changed |= dev_tools_installation::withdraw_versioned_installation_activation(
            &layout,
            &self.shared,
            BINARY_LIMIT,
        )?;
        let authority = self.document_authority();
        if let Some(document) = self
            .directory
            .read(OsStr::new("install-v2.json"), &authority)?
        {
            if serde_json::from_slice::<InstallReceipt>(&document.bytes)? != self.candidate {
                bail!("initial restoration receipt changed before retirement");
            }
            changed |= self.directory.remove(
                OsStr::new("install-v2.json"),
                &authority,
                &document.identity,
            )?;
        } else {
            // The parent exists because retention and the immutable candidate
            // are required. An absent retry must settle prior removal as well.
            let bytes = serde_json::to_vec_pretty(&self.candidate)?;
            self.directory.remove(
                OsStr::new("install-v2.json"),
                &authority,
                &ArtifactIdentity {
                    length: bytes.len() as u64,
                    sha256: format!("{:x}", Sha256::digest(&bytes)),
                },
            )?;
        }
        changed |= self.synchronize_initial_services()?;
        self.verify_restored()?;
        Ok(changed)
    }

    pub(crate) fn verify_restored(&self) -> Result<()> {
        for (_, _, path) in installation_current_state_paths(&self.paths, self.candidate.mode) {
            require_restored_absence(&path)?;
        }
        require_restored_absence(&self.paths.data_root.join("installation-transition-v1.json"))?;
        let executable = dev_tools_installation::read_atomic_document(
            Path::new(&self.candidate.executable),
            &DocumentAuthority {
                owner_uid: nix::unistd::Uid::effective().as_raw(),
                mode: 0o755,
                limit: BINARY_LIMIT,
            },
        )?
        .context("initial restoration continuation executable disappeared")?;
        if executable.identity != self.shared.active_identity {
            bail!("initial restoration continuation executable changed");
        }
        self.verify_initial_services_absent()?;
        Ok(())
    }
}

fn require_restored_absence(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect restored absence"),
        Ok(_) => bail!("initial restoration has a remaining activation object"),
    }
}

#[cfg(test)]
fn restore_user_installation(
    plan: &SetupPlan,
    prior: &InstallReceipt,
    prior_shared: &VersionedReceipt,
) -> Result<bool> {
    let authority = RetainedInstallationRestoration::new(plan, prior, prior_shared)?;
    authority.restore()
}

pub(crate) struct RetainedInstallationRestoration {
    paths: SetupPaths,
    original: InstallReceipt,
    original_shared: VersionedReceipt,
    candidate: InstallReceipt,
    candidate_shared: VersionedReceipt,
    target: InstallReceipt,
    target_shared: VersionedReceipt,
    prior_receipt_mode: u32,
    receipt_directory: dev_tools_installation::ExistingDocumentDirectory,
}

impl RetainedInstallationRestoration {
    #[cfg(test)]
    pub(crate) fn new(
        plan: &SetupPlan,
        prior: &InstallReceipt,
        prior_shared: &VersionedReceipt,
    ) -> Result<Self> {
        Self::new_with_prior_receipt_mode(
            plan,
            prior,
            prior_shared,
            receipt_permissions(prior.mode),
        )
    }

    pub(crate) fn restore(&self) -> Result<bool> {
        self.require_retained_services_stopped()?;
        let mut changed = self.restore_privileged_launcher()?;
        changed |= self.restore_binary()?;
        changed |= self.synchronize_retained_services()?;
        // The binary boundary already observed shared history and artifacts.
        // Full verification also checks the product-owned native integrations.
        verify_receipted_installation_at(&self.paths, &self.admitted_receipt()?, false)?;
        Ok(changed)
    }

    pub(crate) fn new_with_prior_receipt_mode(
        plan: &SetupPlan,
        prior: &InstallReceipt,
        prior_shared: &VersionedReceipt,
        prior_receipt_mode: u32,
    ) -> Result<Self> {
        if plan.schema != "dev-auth-setup-plan-v2"
            || plan.request.mode != prior.mode
            || plan.request.activate_transparent_launchers
            || prior_receipt_mode & !0o777 != 0
            || !receipt_mode_matches_installation(prior_receipt_mode, prior.mode)
        {
            bail!("retained installation restoration requires matching mode and inactive approval");
        }
        validate_version(&prior.version)?;
        validate_version(&plan.request.version)?;
        let layout = shared_installation_layout(&plan.paths, prior.mode);
        match prior.mode {
            InstallMode::Strong => {
                if prior.privileged_launcher.as_deref()
                    != Some(
                        plan.paths
                            .data_root
                            .join("dev-auth-workload-launcher")
                            .to_string_lossy()
                            .as_ref(),
                    )
                    || plan.verified_release.is_none()
                {
                    bail!("retained strong restoration lacks native launcher or candidate release authority");
                }
                validate_system_asset_receipt_shape(&prior.system_assets)?;
            }
            InstallMode::UserOnly
                if prior.privileged_launcher.is_some() || !prior.system_assets.is_empty() =>
            {
                bail!("retained user-only restoration has privileged ownership");
            }
            InstallMode::UserOnly => {}
        }
        if prior.schema != RECEIPT_SCHEMA
            || Path::new(&prior.executable) != plan.paths.versioned_binary(&prior.version)
            || Path::new(&prior.bin_dir) != plan.paths.bin_dir
            || prior.product_aliases != PRODUCT_ALIASES.map(str::to_owned)
            || prior
                .transparent_aliases
                .iter()
                .any(|alias| !TRANSPARENT_ALIASES.contains(&alias.as_str()))
            || prior_shared.schema != "dev-tools-versioned-installation-v1"
            || prior_shared.product != layout.product
            || prior_shared.data_root != layout.data_root
            || prior_shared.bin_dir != layout.bin_dir
            || prior_shared.artifact_name != layout.artifact_name
        {
            bail!("retained installation has incompatible layout or ownership");
        }
        require_shared_receipt_agreement(prior, prior_shared)?;
        if prior_shared.previous_version
            != prior
                .previous_release
                .as_ref()
                .map(|release| release.version.clone())
            || prior_shared.previous_identity
                != prior
                    .previous_release
                    .as_ref()
                    .map(|release| ArtifactIdentity {
                        length: release.executable_length,
                        sha256: release.executable_sha256.clone(),
                    })
        {
            bail!("retained installation histories disagree");
        }
        for program in [&prior.native_git, &prior.native_gh] {
            validate_native_program(Path::new(program), "retained native program")?;
        }
        validate_native_program(&plan.request.native_git, "candidate native Git")?;
        validate_native_program(&plan.request.native_gh, "candidate native GitHub CLI")?;
        let candidate_path = plan.paths.versioned_binary(&plan.request.version);
        if file_identity(&candidate_path)? != (plan.source_length, plan.source_sha256.clone())
            || file_identity(Path::new(&prior.executable))?
                != (prior.executable_length, prior.executable_sha256.clone())
        {
            bail!("retained restoration executable identity changed");
        }
        let same_version = prior.version == plan.request.version;
        if same_version
            && (prior.executable_length != plan.source_length
                || prior.executable_sha256 != plan.source_sha256)
        {
            bail!("a retained version cannot identify different executable bytes");
        }
        let mut original = prior.clone();
        original.transparent_aliases.clear();
        let mut candidate = original.clone();
        candidate.version = plan.request.version.clone();
        candidate.executable = candidate_path.display().to_string();
        candidate.executable_length = plan.source_length;
        candidate.executable_sha256 = plan.source_sha256.clone();
        candidate.native_git = plan.request.native_git.display().to_string();
        candidate.native_gh = plan.request.native_gh.display().to_string();
        if prior.mode == InstallMode::Strong {
            candidate.system_assets = system_asset_digests();
        }
        if !same_version {
            candidate.source_commit = None;
            candidate.root_generation = None;
            candidate.manifest_generation = None;
            candidate.previous_release = Some(retained_release(prior));
        }
        if let Some(release) = &plan.verified_release {
            if release.schema != "dev-auth-verified-release-v1"
                || release.version != candidate.version
                || release.artifact_length != candidate.executable_length
                || release.artifact_sha256 != candidate.executable_sha256
                || release.artifact_path != plan.request.source_executable
                || release.root_generation == 0
                || release.manifest_generation == 0
                || (prior.mode == InstallMode::Strong
                    && release.target != crate::release_manifest::target_id()?)
            {
                bail!("retained candidate provenance disagrees with its approved plan");
            }
            candidate.source_commit = Some(release.source_commit.clone());
            candidate.root_generation = Some(release.root_generation);
            candidate.manifest_generation = Some(release.manifest_generation);
        }
        validate_release_transition(
            prior,
            &plan.request,
            &plan.source_sha256,
            plan.verified_release.as_ref(),
        )?;
        let mut candidate_shared = prior_shared.clone();
        if !same_version {
            candidate_shared.previous_version = Some(prior.version.clone());
            candidate_shared.previous_identity = Some(prior_shared.active_identity.clone());
            candidate_shared.active_version = candidate.version.clone();
            candidate_shared.active_identity = ArtifactIdentity {
                length: plan.source_length,
                sha256: plan.source_sha256.clone(),
            };
        }
        let mut target = original.clone();
        let mut target_shared = prior_shared.clone();
        if !same_version {
            target.previous_release = Some(retained_release(&candidate));
            target_shared.previous_version = Some(candidate.version.clone());
            target_shared.previous_identity = Some(candidate_shared.active_identity.clone());
        }
        Ok(Self {
            paths: plan.paths.clone(),
            original,
            original_shared: prior_shared.clone(),
            candidate,
            candidate_shared,
            target,
            target_shared,
            prior_receipt_mode,
            receipt_directory: dev_tools_installation::ExistingDocumentDirectory::open(
                &plan.paths.data_root,
                layout.owner_uid,
            )?,
        })
    }

    fn current_document(
        &self,
    ) -> Result<(dev_tools_installation::AtomicDocument, DocumentAuthority)> {
        let mode = fs::symlink_metadata(self.paths.receipt_path())?.mode() & 0o7777;
        if mode != self.prior_receipt_mode && mode != receipt_permissions(self.original.mode) {
            bail!("restoration receipt permissions are outside retained authority");
        }
        let authority = self.document_authority(mode);
        let document = self
            .receipt_directory
            .read(OsStr::new("install-v2.json"), &authority)?
            .context("restoration installation receipt is absent")?;
        Ok((document, authority))
    }

    pub(crate) fn admitted_receipt(&self) -> Result<InstallReceipt> {
        let (document, authority) = self.current_document()?;
        let receipt: InstallReceipt = serde_json::from_slice(&document.bytes)?;
        let mut inactive = receipt.clone();
        inactive.transparent_aliases.clear();
        if !((inactive == self.candidate
            && authority.mode == receipt_permissions(self.original.mode))
            || ((inactive == self.original || inactive == self.target)
                && authority.mode == self.prior_receipt_mode))
            || (!receipt.transparent_aliases.is_empty()
                && receipt.transparent_aliases != TRANSPARENT_ALIASES.map(str::to_owned))
        {
            bail!("installation receipt is outside the retained restoration pair");
        }
        Ok(receipt)
    }

    pub(crate) fn deactivate(&self) -> Result<bool> {
        let receipt = self.admitted_receipt()?;
        let mut inactive = receipt.clone();
        inactive.transparent_aliases.clear();
        let (current, authority) = self.current_document()?;
        if serde_json::from_slice::<InstallReceipt>(&current.bytes)? != receipt {
            bail!("restoration installation receipt changed");
        }
        for alias in &receipt.transparent_aliases {
            let path = self.paths.bin_dir.join(alias);
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect restoration launcher"),
                Ok(_) => remove_owned_alias(&path, Path::new(&receipt.executable))?,
            }
        }
        File::open(&self.paths.bin_dir)?.sync_all()?;
        self.verify_inactive_transparent()?;
        let receipt_changed = self.receipt_directory.write(
            OsStr::new("install-v2.json"),
            &serde_json::to_vec_pretty(&inactive)?,
            &authority,
            Some(&current.identity),
        )?;
        Ok(receipt_changed || !receipt.transparent_aliases.is_empty())
    }

    fn verify_inactive_transparent(&self) -> Result<()> {
        for alias in TRANSPARENT_ALIASES {
            let path = self.paths.bin_dir.join(alias);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).context("inspect inactive transparent integration")
                }
            };
            if !metadata.file_type().is_symlink() {
                continue;
            }
            let direct = fs::read_link(&path)?;
            let resolved = fs::canonicalize(&path).ok();
            let versions = self.paths.data_root.join("versions");
            if direct == self.paths.data_root.join("active")
                || direct.starts_with(&versions)
                || resolved
                    .as_ref()
                    .is_some_and(|target| target.starts_with(&versions))
            {
                bail!("unreceipted product launcher prevents inactive restoration");
            }
        }
        Ok(())
    }

    fn document_authority(&self, mode: u32) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: shared_installation_layout(&self.paths, self.original.mode).owner_uid,
            mode,
            limit: RECEIPT_LIMIT,
        }
    }

    pub(crate) fn verify_restored(&self) -> Result<InstallReceipt> {
        let current = self.verify_binary_restored()?;
        verify_receipted_installation_at(&self.paths, &current, false)?;
        self.verify_retained_services_inactive()?;
        Ok(current)
    }

    fn verify_binary_restored(&self) -> Result<InstallReceipt> {
        self.verify_inactive_transparent()?;
        let current = self.admitted_receipt()?;
        if self.current_document()?.1.mode != self.prior_receipt_mode {
            bail!("restored receipt permissions differ from retained authority");
        }
        if current != self.original && current != self.target {
            bail!("retained installation restoration is incomplete");
        }
        let shared = dev_tools_installation::observe_versioned_installation(
            &shared_installation_layout(&self.paths, self.original.mode),
            BINARY_LIMIT,
        )?
        .context("restored shared installation is absent")?;
        if !((current == self.original && shared == self.original_shared)
            || (current == self.target && shared == self.target_shared))
        {
            bail!("restored product and shared histories disagree");
        }
        // The shared receipt and both executable identities were just observed
        // under the caller's setup exclusion. Complete the product checks
        // without repeating that same shared observation.
        require_shared_receipt_agreement(&current, &shared)?;
        Ok(current)
    }

    /// Restore only the retained binary and product/shared receipt history.
    /// Strong callers restore owned assets separately before full verification.
    pub(crate) fn restore_binary(&self) -> Result<bool> {
        self.verify_inactive_transparent()?;
        self.admitted_receipt()?;
        let (document, authority) = self.current_document()?;
        let current: InstallReceipt = serde_json::from_slice(&document.bytes)?;
        if current != self.original && current != self.candidate && current != self.target {
            bail!("installation receipt is outside the retained restoration pair");
        }
        // Transparent integration deactivation belongs to full setup and must
        // precede this boundary. Missing or unrelated product aliases fail closed.
        verify_exact_alias_set(
            &self.paths.bin_dir,
            &self.paths.data_root.join("active"),
            &current.product_aliases,
            &PRODUCT_ALIASES,
            false,
        )?;
        verify_exact_alias_set(
            &self.paths.bin_dir,
            Path::new(&current.executable),
            &[],
            &TRANSPARENT_ALIASES,
            true,
        )?;
        let layout = shared_installation_layout(&self.paths, self.original.mode);
        let (mut changed, shared) =
            dev_tools_installation::recover_versioned_installation_with_verification(
                &layout,
                BINARY_LIMIT,
                |receipt| {
                    if receipt != &self.original_shared
                        && receipt != &self.candidate_shared
                        && receipt != &self.target_shared
                    {
                        bail!("binary journal is outside the retained restoration pair");
                    }
                    Ok(())
                },
            )?;
        let shared = shared.context("restoration shared receipt is absent")?;
        // The target is explicit. Retrying after a shared commit never swaps
        // back to the candidate, even if the product receipt is still stale.
        if shared == self.candidate_shared && shared != self.target_shared {
            let result = dev_tools_installation::rollback_versioned_installation_if_unchanged(
                &layout,
                &shared,
                |path| {
                    if file_identity(path)?
                        != (
                            self.target.executable_length,
                            self.target.executable_sha256.clone(),
                        )
                    {
                        bail!("restoration target executable changed");
                    }
                    Ok(())
                },
            )?;
            if result.receipt != self.target_shared {
                bail!("restoration selected an unexpected shared receipt");
            }
            changed |= result.changed;
        } else if shared != self.target_shared && shared != self.original_shared {
            bail!("shared installation is outside the retained restoration pair");
        }
        // An uncommitted candidate install may recover the exact original
        // history. Do not claim the never-committed candidate as its predecessor.
        let target = if shared == self.original_shared
            && shared != self.candidate_shared
            && shared != self.target_shared
        {
            &self.original
        } else {
            &self.target
        };
        let bytes = serde_json::to_vec_pretty(target)?;
        changed |= self.receipt_directory.replace(
            OsStr::new("install-v2.json"),
            &bytes,
            &self.document_authority(self.prior_receipt_mode),
            &authority,
            &document.identity,
        )?;
        self.verify_binary_restored()?;
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_binary_restoration_preserves_prior_receipt_permissions_and_history() {
        if !nix::unistd::Uid::effective().is_root() {
            let arguments = [
                std::ffi::OsString::from("--user"),
                "--map-root-user".into(),
                std::env::current_exe().unwrap().into_os_string(),
                "--exact".into(),
                "setup::restoration::tests::strong_binary_restoration_preserves_prior_receipt_permissions_and_history".into(),
                "--nocapture".into(),
            ];
            let output =
                dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
                    executable: Path::new("/usr/bin/unshare"),
                    arguments: &arguments,
                    environment: &BTreeMap::new(),
                    cwd: None,
                    timeout: Duration::from_secs(30),
                    output_limit: 16 * 1024,
                })
                .unwrap();
            assert!(
                output.status.success(),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            return;
        }
        for (prior, candidate) in [("0.3.11", "0.4.0"), ("0.4.0", "0.4.1")] {
            assert_strong_binary_and_launcher_restoration(prior, candidate);
        }
    }

    fn assert_strong_binary_and_launcher_restoration(prior_version: &str, candidate_version: &str) {
        let mut fixture = strong_binary_fixture(prior_version, candidate_version);
        fixture.plan.request.mode = InstallMode::Strong;
        fixture.prior.mode = InstallMode::Strong;
        fixture.prior.privileged_launcher = Some(
            fixture
                .plan
                .paths
                .data_root
                .join("dev-auth-workload-launcher")
                .display()
                .to_string(),
        );
        fixture.prior.system_assets = system_asset_digests();
        *fixture.prior.system_assets.values_mut().next().unwrap() = "9".repeat(64);
        fixture.prior.source_commit = Some("a".repeat(40));
        fixture.prior.root_generation = Some(1);
        fixture.prior.manifest_generation = Some(1);
        fixture.plan.verified_release = Some(crate::release_manifest::VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: fixture._root.path().join("discarded-root"),
            manifest_path: fixture._root.path().join("discarded-manifest"),
            root_generation: 1,
            manifest_generation: 2,
            version: fixture.plan.request.version.clone(),
            source_commit: "b".repeat(40),
            target: crate::release_manifest::target_id().unwrap(),
            artifact_path: fixture.plan.request.source_executable.clone(),
            artifact_url: "https://example.invalid/fixture".into(),
            artifact_length: fixture.plan.source_length,
            artifact_sha256: fixture.plan.source_sha256.clone(),
            root_sha256: "c".repeat(64),
            manifest_sha256: "d".repeat(64),
        });
        let mut candidate = fixture.prior.clone();
        candidate.version = fixture.plan.request.version.clone();
        candidate.executable = fixture
            .plan
            .paths
            .versioned_binary(&candidate.version)
            .display()
            .to_string();
        candidate.executable_length = fixture.plan.source_length;
        candidate.executable_sha256 = fixture.plan.source_sha256.clone();
        candidate.native_git = fixture.plan.request.native_git.display().to_string();
        candidate.native_gh = fixture.plan.request.native_gh.display().to_string();
        candidate.previous_release = Some(retained_release(&fixture.prior));
        candidate.system_assets = system_asset_digests();
        candidate.source_commit = Some("b".repeat(40));
        candidate.manifest_generation = Some(2);
        write_receipt(&fixture.plan.paths.receipt_path(), &candidate).unwrap();
        let restoration = RetainedInstallationRestoration::new_with_prior_receipt_mode(
            &fixture.plan,
            &fixture.prior,
            &fixture.shared,
            0o600,
        )
        .unwrap();
        let helper = fixture.plan.paths.data_root.join("dev-auth-setup-helper");
        let sidecar = setup_helper_receipt_path(&fixture.plan.paths);
        let target = crate::release_manifest::target_id().unwrap();
        // Retain noncanonical whitespace to prove exact prior-byte restoration.
        let mut prior_sidecar = serde_json::to_vec(&expected_setup_helper_receipt(
            &helper,
            &fixture.prior,
            &target,
        ))
        .unwrap();
        prior_sidecar.push(b'\n');
        fs::copy(&candidate.executable, &helper).unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        write_setup_helper_receipt_at(
            &sidecar,
            &expected_setup_helper_receipt(&helper, &candidate, &target),
            0,
        )
        .unwrap();
        assert!(restoration.restore_setup_helper(&prior_sidecar).unwrap());
        assert_eq!(
            fs::read(&helper).unwrap(),
            fs::read(&fixture.prior.executable).unwrap()
        );
        assert_eq!(fs::read(&sidecar).unwrap(), prior_sidecar);
        assert!(!restoration.restore_setup_helper(&prior_sidecar).unwrap());
        restoration
            .verify_restored_setup_helper(&prior_sidecar)
            .unwrap();
        write_setup_helper_receipt_at(
            &sidecar,
            &expected_setup_helper_receipt(&helper, &fixture.prior, &target),
            0,
        )
        .unwrap();
        let differently_serialized = fs::read(&sidecar).unwrap();
        assert_ne!(differently_serialized, prior_sidecar);
        assert!(restoration
            .verify_restored_setup_helper(&prior_sidecar)
            .is_err());
        assert_eq!(fs::read(&sidecar).unwrap(), differently_serialized);
        fs::write(&sidecar, &prior_sidecar).unwrap();
        // Either publication can have completed when an earlier process died.
        write_setup_helper_receipt_at(
            &sidecar,
            &expected_setup_helper_receipt(&helper, &candidate, &target),
            0,
        )
        .unwrap();
        assert!(restoration.restore_setup_helper(&prior_sidecar).unwrap());
        fs::copy(&candidate.executable, &helper).unwrap();
        assert!(restoration.restore_setup_helper(&prior_sidecar).unwrap());
        assert!(!restoration.restore_setup_helper(&prior_sidecar).unwrap());
        let original_helper = fs::read(&helper).unwrap();
        fs::write(&sidecar, b"unowned sidecar").unwrap();
        fs::copy(&candidate.executable, &helper).unwrap();
        let candidate_helper = fs::read(&helper).unwrap();
        assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
        assert_eq!(fs::read(&helper).unwrap(), candidate_helper);
        assert_eq!(fs::read(&sidecar).unwrap(), b"unowned sidecar");
        fs::write(&sidecar, &prior_sidecar).unwrap();
        fs::write(&helper, b"unowned helper").unwrap();
        assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
        assert_eq!(fs::read(&helper).unwrap(), b"unowned helper");
        assert_eq!(fs::read(&sidecar).unwrap(), prior_sidecar);
        fs::write(&helper, &original_helper).unwrap();
        for (path, ordinary_mode) in [(&helper, 0o755), (&sidecar, 0o644)] {
            for mode in [0o4755, 0o2755, 0o777] {
                fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
                assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, mode);
            }
            fs::set_permissions(path, fs::Permissions::from_mode(ordinary_mode)).unwrap();
            let extra = fixture._root.path().join("extra-helper-link");
            fs::hard_link(path, &extra).unwrap();
            assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
            assert_eq!(fs::metadata(path).unwrap().nlink(), 2);
            fs::remove_file(extra).unwrap();
            let bytes = fs::read(path).unwrap();
            fs::remove_file(path).unwrap();
            assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
            assert!(fs::symlink_metadata(path).is_err());
            symlink(&fixture.prior.executable, path).unwrap();
            assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
            assert_eq!(
                fs::read_link(path).unwrap(),
                PathBuf::from(&fixture.prior.executable)
            );
            fs::remove_file(path).unwrap();
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(ordinary_mode)).unwrap();
        }
        let mut wrong_prior = expected_setup_helper_receipt(&helper, &fixture.prior, &target);
        wrong_prior.source_commit = Some("e".repeat(40));
        assert!(restoration
            .restore_setup_helper(&serde_json::to_vec(&wrong_prior).unwrap())
            .is_err());
        fs::set_permissions(
            &fixture.prior.executable,
            fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
        fs::set_permissions(&fixture.prior.executable, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!restoration.restore_setup_helper(&prior_sidecar).unwrap());
        let launcher = fixture
            .plan
            .paths
            .data_root
            .join("dev-auth-workload-launcher");
        fs::copy(&candidate.executable, &launcher).unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o4755)).unwrap();
        assert!(restoration.restore_privileged_launcher().unwrap());
        assert_eq!(
            fs::read(&launcher).unwrap(),
            fs::read(&fixture.prior.executable).unwrap()
        );
        let target_mode = if prior_version == "0.3.11" {
            0o755
        } else {
            0o4755
        };
        assert_eq!(
            fs::metadata(&launcher).unwrap().mode() & 0o7777,
            target_mode
        );
        assert!(!restoration.restore_privileged_launcher().unwrap());
        // Retry after the candidate's set-ID permission was durably removed.
        fs::copy(&candidate.executable, &launcher).unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(restoration.restore_privileged_launcher().unwrap());
        // Retry after ordinary target bytes were published but before the
        // prior release's final permission bits were restored.
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            restoration.restore_privileged_launcher().unwrap(),
            target_mode != 0o755
        );
        assert_eq!(
            fs::metadata(&launcher).unwrap().mode() & 0o7777,
            target_mode
        );
        fs::write(&launcher, b"unowned executable").unwrap();
        assert!(restoration.restore_privileged_launcher().is_err());
        assert_eq!(fs::read(&launcher).unwrap(), b"unowned executable");
        fs::copy(&fixture.prior.executable, &launcher).unwrap();
        for mode in [0o6755, 0o2755, 0o777] {
            fs::set_permissions(&launcher, fs::Permissions::from_mode(mode)).unwrap();
            assert!(restoration.restore_privileged_launcher().is_err());
            assert_eq!(fs::metadata(&launcher).unwrap().mode() & 0o7777, mode);
        }
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o755)).unwrap();
        let extra_link = fixture._root.path().join("unowned-launcher-link");
        fs::hard_link(&launcher, &extra_link).unwrap();
        assert!(restoration.restore_privileged_launcher().is_err());
        assert_eq!(fs::metadata(&launcher).unwrap().nlink(), 2);
        fs::remove_file(&extra_link).unwrap();
        fs::remove_file(&launcher).unwrap();
        symlink(&fixture.prior.executable, &launcher).unwrap();
        assert!(restoration.restore_privileged_launcher().is_err());
        assert_eq!(
            fs::read_link(&launcher).unwrap(),
            PathBuf::from(&fixture.prior.executable)
        );
        fs::remove_file(&launcher).unwrap();
        assert!(restoration.restore_privileged_launcher().is_err());
        assert!(fs::symlink_metadata(&launcher).is_err());
        fs::copy(&fixture.prior.executable, &launcher).unwrap();
        fs::set_permissions(
            &fixture.prior.executable,
            fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        assert!(restoration.restore_privileged_launcher().is_err());
        fs::set_permissions(&fixture.prior.executable, fs::Permissions::from_mode(0o755)).unwrap();
        let mut active = candidate.clone();
        active.transparent_aliases = TRANSPARENT_ALIASES.map(str::to_owned).to_vec();
        write_receipt(&fixture.plan.paths.receipt_path(), &active).unwrap();
        assert!(restoration.restore_setup_helper(&prior_sidecar).is_err());
        assert!(restoration.restore_privileged_launcher().is_err());
        write_receipt(&fixture.plan.paths.receipt_path(), &candidate).unwrap();
        restoration.restore_privileged_launcher().unwrap();
        assert_eq!(
            fs::metadata(&launcher).unwrap().mode() & 0o7777,
            target_mode
        );
        assert!(restoration.restore_binary().unwrap());
        let restored = read_receipt(&fixture.plan.paths.receipt_path()).unwrap();
        assert_eq!(restored.version, fixture.prior.version);
        assert_eq!(restored.native_git, fixture.prior.native_git);
        assert_eq!(restored.source_commit, fixture.prior.source_commit);
        assert_eq!(restored.system_assets, fixture.prior.system_assets);
        assert_eq!(
            restored.previous_release,
            Some(retained_release(&candidate))
        );
        assert_eq!(
            fs::metadata(fixture.plan.paths.receipt_path())
                .unwrap()
                .mode()
                & 0o7777,
            0o600
        );
        assert!(!restoration.restore_binary().unwrap());
        // The shared rollback already committed. A stale product receipt must
        // be completed toward the prior target, never swap forward on retry.
        write_receipt(&fixture.plan.paths.receipt_path(), &candidate).unwrap();
        assert!(restoration.restore_binary().unwrap());
        assert!(!restoration.restore_binary().unwrap());
        assert_eq!(
            read_receipt(&fixture.plan.paths.receipt_path()).unwrap(),
            restored
        );
    }

    fn strong_binary_fixture(prior_version: &str, candidate_version: &str) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let paths = SetupPaths {
            data_root: root.path().join("data"),
            bin_dir: root.path().join("bin"),
        };
        let source = root.path().join("candidate");
        fs::write(&source, b"original executable").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
        for name in ["old-git", "old-gh", "new-git", "new-gh"] {
            fs::copy(&source, root.path().join(name)).unwrap();
        }
        let mut request = dev_tools_installation::VersionedInstallRequest {
            layout: shared_installation_layout(&paths, InstallMode::Strong),
            version: prior_version.into(),
            source: source.clone(),
            identity: ArtifactIdentity::from_file(&source, BINARY_LIMIT).unwrap(),
            aliases: shared_product_aliases(),
        };
        let shared = dev_tools_installation::apply_versioned_installation(&request, |_| Ok(()))
            .unwrap()
            .receipt;
        let prior = InstallReceipt {
            schema: RECEIPT_SCHEMA.into(),
            mode: InstallMode::Strong,
            version: request.version.clone(),
            executable: paths
                .versioned_binary(&request.version)
                .display()
                .to_string(),
            bin_dir: paths.bin_dir.display().to_string(),
            executable_length: request.identity.length,
            executable_sha256: request.identity.sha256.clone(),
            source_commit: None,
            root_generation: None,
            manifest_generation: None,
            native_git: root.path().join("old-git").display().to_string(),
            native_gh: root.path().join("old-gh").display().to_string(),
            product_aliases: PRODUCT_ALIASES.map(str::to_owned).to_vec(),
            transparent_aliases: Vec::new(),
            privileged_launcher: Some(
                paths
                    .data_root
                    .join("dev-auth-workload-launcher")
                    .display()
                    .to_string(),
            ),
            system_assets: system_asset_digests(),
            previous_release: None,
        };
        fs::write(&source, b"successor executable").unwrap();
        request.version = candidate_version.into();
        request.identity = ArtifactIdentity::from_file(&source, BINARY_LIMIT).unwrap();
        dev_tools_installation::apply_versioned_installation(&request, |_| Ok(())).unwrap();
        let plan = SetupPlan {
            schema: "dev-auth-setup-plan-v2".into(),
            paths,
            request: InstallRequest {
                mode: InstallMode::Strong,
                version: request.version,
                source_executable: source,
                native_git: root.path().join("new-git"),
                native_gh: root.path().join("new-gh"),
                activate_transparent_launchers: false,
            },
            source_length: request.identity.length,
            source_sha256: request.identity.sha256,
            verified_release: None,
        };
        Fixture {
            _root: root,
            plan,
            prior,
            shared,
        }
    }

    fn initial_fixture() -> (tempfile::TempDir, InitialInstallationRestoration) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let home = root.path().join("home");
        fs::create_dir(&home).unwrap();
        let source = root.path().join("candidate");
        fs::write(&source, b"initial candidate fixture").unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
        let native_git = root.path().join("git");
        let native_gh = root.path().join("gh");
        fs::copy(&source, &native_git).unwrap();
        fs::copy(&source, &native_gh).unwrap();
        let request = InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.4.0".into(),
            source_executable: source.clone(),
            native_git,
            native_gh,
            activate_transparent_launchers: false,
        };
        let plan = build_plan(&SetupPaths::user_only(&home), &request).unwrap();
        apply_plan(&plan, &render_plan(&plan).unwrap().1).unwrap();
        let restoration = InitialInstallationRestoration::new(&plan).unwrap();
        (root, restoration)
    }

    #[test]
    fn initial_restoration_removes_activation_and_resumes_partial_absence() {
        for absent in 0..4 {
            let (_root, restoration) = initial_fixture();
            let paths = &restoration.paths;
            let evidence = paths.data_root.join("retained-generation-fixture");
            fs::write(&evidence, b"outer retained authority").unwrap();
            let artifact = fs::read(&restoration.candidate.executable).unwrap();
            let lock_inode = fs::metadata(paths.data_root.join("installation.lock"))
                .unwrap()
                .ino();
            if absent >= 1 {
                fs::remove_file(paths.bin_dir.join("dev-auth")).unwrap();
            }
            if absent >= 2 {
                fs::remove_file(paths.data_root.join("active")).unwrap();
            }
            if absent >= 3 {
                fs::remove_file(paths.data_root.join("installation-receipt-v1.json")).unwrap();
                fs::remove_file(paths.receipt_path()).unwrap();
            }
            assert!(restoration.restore().unwrap());
            restoration.verify_restored().unwrap();
            assert!(!restoration.restore().unwrap());
            assert_eq!(
                fs::read(&restoration.candidate.executable).unwrap(),
                artifact
            );
            assert_eq!(fs::read(evidence).unwrap(), b"outer retained authority");
            assert_eq!(
                fs::metadata(paths.data_root.join("installation.lock"))
                    .unwrap()
                    .ino(),
                lock_inode
            );
        }
    }

    #[test]
    fn initial_restoration_rejects_foreign_authority_and_changed_continuation() {
        for drift in ["product", "shared", "transparent", "artifact"] {
            let (root, restoration) = initial_fixture();
            let paths = &restoration.paths;
            match drift {
                "product" => {
                    let mut receipt = restoration.candidate.clone();
                    receipt.source_commit = Some("a".repeat(40));
                    write_receipt(&paths.receipt_path(), &receipt).unwrap();
                }
                "shared" => {
                    let mut receipt = restoration.shared.clone();
                    receipt.active_identity.sha256 = "a".repeat(64);
                    fs::write(
                        paths.data_root.join("installation-receipt-v1.json"),
                        serde_json::to_vec(&receipt).unwrap(),
                    )
                    .unwrap();
                }
                "transparent" => {
                    symlink(&restoration.candidate.executable, paths.bin_dir.join("git")).unwrap()
                }
                "artifact" => fs::hard_link(
                    &restoration.candidate.executable,
                    root.path().join("hardlink"),
                )
                .unwrap(),
                _ => unreachable!(),
            }
            let product = fs::read(paths.receipt_path()).unwrap();
            let active = fs::read_link(paths.data_root.join("active")).unwrap();
            assert!(restoration.restore().is_err(), "{drift}");
            assert_eq!(fs::read(paths.receipt_path()).unwrap(), product);
            assert_eq!(
                fs::read_link(paths.data_root.join("active")).unwrap(),
                active
            );
        }
        let (root, restoration) = initial_fixture();
        restoration.restore().unwrap();
        fs::hard_link(
            &restoration.candidate.executable,
            root.path().join("hardlink"),
        )
        .unwrap();
        assert!(restoration.verify_restored().is_err());
    }

    #[test]
    fn initial_restoration_recovers_only_candidate_binary_journals() {
        for committed in [false, true] {
            let (_root, restoration) = initial_fixture();
            let paths = &restoration.paths;
            let journal = paths.data_root.join("installation-transition-v1.json");
            if !committed {
                fs::remove_file(paths.data_root.join("installation-receipt-v1.json")).unwrap();
                fs::remove_file(paths.receipt_path()).unwrap();
            }
            fs::write(&journal, serde_json::to_vec(&serde_json::json!({
                "schema": "dev-tools-versioned-transition-v1", "prior": null, "next": restoration.shared,
            })).unwrap()).unwrap();
            fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(restoration.restore().unwrap());
            restoration.verify_restored().unwrap();
            assert!(!journal.exists());
            assert!(!restoration.restore().unwrap());
        }
        let (_root, restoration) = initial_fixture();
        let journal = restoration
            .paths
            .data_root
            .join("installation-transition-v1.json");
        let mut foreign = restoration.shared.clone();
        foreign.active_identity.sha256 = "a".repeat(64);
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1", "prior": restoration.shared, "next": foreign,
        })).unwrap();
        fs::write(&journal, &bytes).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(restoration.restore().is_err());
        assert_eq!(fs::read(&journal).unwrap(), bytes);
        let noninitial = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1",
            "prior": restoration.shared,
            "next": restoration.shared,
        }))
        .unwrap();
        fs::write(&journal, &noninitial).unwrap();
        assert!(
            restoration.restore().is_err(),
            "initial absence cannot authorize a noninitial journal"
        );
        assert_eq!(fs::read(&journal).unwrap(), noninitial);
    }

    struct Fixture {
        _root: tempfile::TempDir,
        plan: SetupPlan,
        prior: InstallReceipt,
        shared: VersionedReceipt,
    }

    impl Fixture {
        fn new(same_version: bool) -> Self {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let home = root.path().join("home");
            fs::create_dir(&home).unwrap();
            let paths = SetupPaths::user_only(&home);
            let source = root.path().join("candidate");
            let executable = |path: &Path, bytes: &[u8]| {
                fs::write(path, bytes).unwrap();
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            };
            executable(&source, b"old executable");
            let mut request = InstallRequest {
                mode: InstallMode::UserOnly,
                version: "0.3.11".into(),
                source_executable: source.clone(),
                native_git: root.path().join("old-git"),
                native_gh: root.path().join("old-gh"),
                activate_transparent_launchers: false,
            };
            executable(&request.native_git, b"old native git");
            executable(&request.native_gh, b"old native gh");
            request.version = "0.3.10".into();
            executable(&source, b"original history executable");
            install_at(&paths, &request).unwrap();
            request.version = "0.3.11".into();
            executable(&source, b"old executable");
            install_at(&paths, &request).unwrap();
            let prior = read_receipt(&paths.receipt_path()).unwrap();
            let shared = verify_shared_installation(&paths, &prior).unwrap();
            if !same_version {
                request.version = "0.4.0".into();
                executable(&source, b"successor executable");
            }
            request.native_git = root.path().join("new-git");
            request.native_gh = root.path().join("new-gh");
            executable(&request.native_git, b"new native git");
            executable(&request.native_gh, b"new native gh");
            let plan = build_plan(&paths, &request).unwrap();
            apply_plan(&plan, &render_plan(&plan).unwrap().1).unwrap();
            Self {
                _root: root,
                plan,
                prior,
                shared,
            }
        }
    }

    #[test]
    fn restores_prior_native_authority_and_retry_never_swaps_forward() {
        let fixture = Fixture::new(false);
        assert!(restore_user_installation(&fixture.plan, &fixture.prior, &fixture.shared).unwrap());
        let restored = read_receipt(&fixture.plan.paths.receipt_path()).unwrap();
        assert_eq!(restored.version, fixture.prior.version);
        assert_eq!(restored.native_git, fixture.prior.native_git);
        assert_eq!(restored.native_gh, fixture.prior.native_gh);
        assert!(restored.transparent_aliases.is_empty());
        assert_eq!(restored.previous_release.as_ref().unwrap().version, "0.4.0");
        assert!(
            !restore_user_installation(&fixture.plan, &fixture.prior, &fixture.shared).unwrap()
        );
        assert_eq!(
            read_receipt(&fixture.plan.paths.receipt_path()).unwrap(),
            restored
        );
        verify_at_read_only(&fixture.plan.paths).unwrap();
    }

    #[test]
    fn same_version_restoration_restores_native_programs_without_binary_rollback() {
        let fixture = Fixture::new(true);
        assert!(restore_user_installation(&fixture.plan, &fixture.prior, &fixture.shared).unwrap());
        assert_eq!(
            read_receipt(&fixture.plan.paths.receipt_path()).unwrap(),
            fixture.prior
        );
        assert!(
            !restore_user_installation(&fixture.plan, &fixture.prior, &fixture.shared).unwrap()
        );
    }

    #[test]
    fn inactive_restoration_rejects_an_unreceipted_product_launcher() {
        let fixture = Fixture::new(false);
        let restoration =
            RetainedInstallationRestoration::new(&fixture.plan, &fixture.prior, &fixture.shared)
                .unwrap();
        let alias = fixture.plan.paths.bin_dir.join("git");
        symlink(&restoration.candidate.executable, &alias).unwrap();
        let before = fs::read(fixture.plan.paths.receipt_path()).unwrap();
        assert!(restoration.restore().is_err());
        assert_eq!(fs::read(fixture.plan.paths.receipt_path()).unwrap(), before);
        assert_eq!(
            fs::read_link(&alias).unwrap(),
            Path::new(&restoration.candidate.executable)
        );
        fs::remove_file(&alias).unwrap();
        fs::write(&alias, b"unrelated native program").unwrap();
        assert!(restoration.restore().unwrap());
        restoration.verify_restored().unwrap();
        assert_eq!(fs::read(alias).unwrap(), b"unrelated native program");
    }

    #[test]
    fn inactive_restoration_also_rejects_a_launcher_to_an_older_retained_version() {
        let fixture = Fixture::new(false);
        let restoration =
            RetainedInstallationRestoration::new(&fixture.plan, &fixture.prior, &fixture.shared)
                .unwrap();
        let older = fixture
            .plan
            .paths
            .versioned_binary(&fixture.prior.previous_release.as_ref().unwrap().version);
        let alias = fixture.plan.paths.bin_dir.join("git");
        symlink(&older, &alias).unwrap();
        let before = fs::read(fixture.plan.paths.receipt_path()).unwrap();
        assert!(restoration.restore().is_err());
        assert_eq!(fs::read(fixture.plan.paths.receipt_path()).unwrap(), before);
        assert_eq!(fs::read_link(alias).unwrap(), older);
    }

    fn journal(
        fixture: &Fixture,
        prior: &VersionedReceipt,
        next: &VersionedReceipt,
    ) -> (PathBuf, Vec<u8>) {
        let path = fixture
            .plan
            .paths
            .data_root
            .join("installation-transition-v1.json");
        let bytes = serde_json::to_vec(&serde_json::json!({ "schema": "dev-tools-versioned-transition-v1", "prior": prior, "next": next })).unwrap();
        fs::write(&path, &bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (path, bytes)
    }

    #[test]
    fn restoration_recovers_both_sides_of_shared_commit_before_product_publication() {
        for committed in [false, true] {
            let fixture = Fixture::new(false);
            let restoration = RetainedInstallationRestoration::new(
                &fixture.plan,
                &fixture.prior,
                &fixture.shared,
            )
            .unwrap();
            let layout = shared_installation_layout(&fixture.plan.paths, InstallMode::UserOnly);
            if committed {
                dev_tools_installation::rollback_versioned_installation_if_unchanged(
                    &layout,
                    &restoration.candidate_shared,
                    |_| Ok(()),
                )
                .unwrap();
            }
            let (journal, _) = journal(
                &fixture,
                &restoration.candidate_shared,
                &restoration.target_shared,
            );
            if !committed {
                // Deterministic interruption after a link switch, before the
                // receipt commit. This is not a process-death simulation.
                let active = fixture.plan.paths.data_root.join("active");
                fs::remove_file(&active).unwrap();
                symlink(&restoration.target.executable, &active).unwrap();
            }
            assert!(restoration.restore().unwrap());
            assert!(!journal.exists());
            assert_eq!(restoration.verify_restored().unwrap(), restoration.target);
            assert!(!restoration.restore().unwrap());
        }
    }

    #[test]
    fn unrelated_product_or_journal_authority_is_preserved_without_recovery() {
        for product_drift in [false, true] {
            let fixture = Fixture::new(false);
            let restoration = RetainedInstallationRestoration::new(
                &fixture.plan,
                &fixture.prior,
                &fixture.shared,
            )
            .unwrap();
            let mut next = restoration.target_shared.clone();
            if product_drift {
                let mut current = restoration.candidate.clone();
                current.native_git = fixture.prior.native_git.clone();
                write_receipt(&fixture.plan.paths.receipt_path(), &current).unwrap();
            } else {
                next.active_identity.sha256 = "a".repeat(64);
            }
            let (journal_path, journal_bytes) =
                journal(&fixture, &restoration.candidate_shared, &next);
            let product = fs::read(fixture.plan.paths.receipt_path()).unwrap();
            let shared = fs::read(
                fixture
                    .plan
                    .paths
                    .data_root
                    .join("installation-receipt-v1.json"),
            )
            .unwrap();
            let active = fs::read_link(fixture.plan.paths.data_root.join("active")).unwrap();
            assert!(restoration.restore().is_err());
            assert_eq!(fs::read(&journal_path).unwrap(), journal_bytes);
            assert_eq!(
                fs::read(fixture.plan.paths.receipt_path()).unwrap(),
                product
            );
            assert_eq!(
                fs::read(
                    fixture
                        .plan
                        .paths
                        .data_root
                        .join("installation-receipt-v1.json")
                )
                .unwrap(),
                shared
            );
            assert_eq!(
                fs::read_link(fixture.plan.paths.data_root.join("active")).unwrap(),
                active
            );
        }
    }

    #[test]
    fn bounded_deactivation_resumes_partial_alias_removal_without_recovering_journal() {
        let fixture = Fixture::new(false);
        activate_transparent_launchers_at(&fixture.plan.paths).unwrap();
        let restoration =
            RetainedInstallationRestoration::new(&fixture.plan, &fixture.prior, &fixture.shared)
                .unwrap();
        let (journal_path, journal_bytes) = journal(
            &fixture,
            &restoration.candidate_shared,
            &restoration.target_shared,
        );
        fs::remove_file(fixture.plan.paths.bin_dir.join("git")).unwrap();
        assert!(restoration.deactivate().unwrap());
        assert!(!fixture.plan.paths.bin_dir.join("gh").exists());
        assert_eq!(fs::read(journal_path).unwrap(), journal_bytes);
        assert!(!restoration.deactivate().unwrap());
    }
}
