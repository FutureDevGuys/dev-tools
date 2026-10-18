use super::*;
use std::collections::BTreeSet;
use std::fs;

pub(super) struct BindingRestoration<'a> {
    prior: &'a RetainedSetupObject,
    candidate: Option<Vec<u8>>,
    authority: DocumentAuthority,
    pinned: Vec<PinnedRestoration>,
    shells: Vec<ShellRestoration>,
}

struct PinnedRestoration {
    prior: Option<PinnedStoredGeneration>,
    candidate: Option<PinnedStoredGeneration>,
}

struct PinnedStoredGeneration {
    layout: dev_tools_installation::VersionedLayout,
    receipt: dev_tools_installation::VersionedReceipt,
}

impl PinnedRestoration {
    fn observe(&self) -> Result<()> {
        if let Some(prior) = &self.prior {
            let observed = dev_tools_installation::observe_versioned_installation(
                &prior.layout,
                512 * 1024 * 1024,
            )?;
            if observed.as_ref() != Some(&prior.receipt) {
                bail!("retained pinned artifact differs from its prior generation");
            }
        }
        if let Some(candidate) = &self.candidate {
            if !self.same_generation() {
                observe_candidate(candidate)?;
            }
        }
        Ok(())
    }

    fn same_generation(&self) -> bool {
        self.prior
            .as_ref()
            .zip(self.candidate.as_ref())
            .is_some_and(|(prior, candidate)| {
                prior.layout == candidate.layout && prior.receipt == candidate.receipt
            })
    }

    fn restore(&self) -> Result<bool> {
        self.observe()?;
        let Some(candidate) = self.candidate.as_ref().filter(|_| !self.same_generation()) else {
            return Ok(false);
        };
        if !candidate.layout.data_root.exists() {
            return Ok(false);
        }
        let has_transition = [
            "installation-receipt-v1.json",
            "installation-transition-v1.json",
        ]
        .iter()
        .any(|name| fs::symlink_metadata(candidate.layout.data_root.join(name)).is_ok());
        if !has_transition {
            return cleanup_uncommitted_candidate(candidate);
        }
        let (recovered, current) =
            dev_tools_installation::recover_versioned_installation_transition(
                &candidate.layout,
                None,
                &candidate.receipt,
                512 * 1024 * 1024,
                |_| Ok(()),
            )?;
        if current.is_none() {
            return Ok(cleanup_uncommitted_candidate(candidate)? || recovered);
        }
        if current.as_ref() != Some(&candidate.receipt) {
            bail!("pinned artifact restoration has an unknown transition endpoint");
        }
        dev_tools_installation::uninstall_versioned_installation(&candidate.layout)?;
        cleanup_uncommitted_candidate(candidate)?;
        Ok(true)
    }

    fn verify_restored(&self) -> Result<()> {
        self.observe()?;
        if let Some(candidate) = &self.candidate {
            if !self.same_generation() && observe_candidate(candidate)? {
                bail!("candidate pinned artifact remains after restoration");
            }
        }
        Ok(())
    }
}

fn observe_candidate(candidate: &PinnedStoredGeneration) -> Result<bool> {
    match fs::symlink_metadata(&candidate.layout.data_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect candidate pinned artifact root"),
        Ok(_) => {}
    }
    let has_transition = [
        "installation-receipt-v1.json",
        "installation-transition-v1.json",
    ]
    .iter()
    .any(|name| fs::symlink_metadata(candidate.layout.data_root.join(name)).is_ok());
    if !has_transition {
        // A crash may have copied the exact payload before the nested ledger
        // wrote its journal. Absence of a receipt is not absence of effects.
        return Ok(true);
    }
    let observed = dev_tools_installation::observe_versioned_installation_transition(
        &candidate.layout,
        None,
        &candidate.receipt,
        512 * 1024 * 1024,
        |_| Ok(()),
    )?;
    Ok(observed.receipt.is_some() || observed.journal_pending)
}

fn cleanup_uncommitted_candidate(candidate: &PinnedStoredGeneration) -> Result<bool> {
    let layout = &candidate.layout;
    require_pinned_directory(&layout.data_root, layout.owner_uid, layout.directory_mode)?;
    let lock_path = layout.data_root.join("installation.lock");
    let lock = dev_tools_installation::InstallationLock::acquire(&lock_path)?;
    for marker in [
        "installation-receipt-v1.json",
        "installation-transition-v1.json",
        "active",
        "previous",
    ] {
        if fs::symlink_metadata(layout.data_root.join(marker)).is_ok() {
            bail!("uncommitted pinned artifact has a transition marker");
        }
    }
    require_pinned_directory_if_present(
        &layout.bin_dir,
        layout.owner_uid,
        layout.bin_directory_mode.unwrap_or(layout.directory_mode),
    )?;
    let alias = candidate
        .receipt
        .aliases
        .first()
        .context("pinned artifact receipt has no alias")?;
    if fs::symlink_metadata(layout.bin_dir.join(alias)).is_ok() {
        bail!("uncommitted pinned artifact has an activated alias");
    }
    let versions = layout.data_root.join("versions");
    let version = versions.join("v1");
    require_pinned_directory_if_present(&versions, layout.owner_uid, layout.directory_mode)?;
    require_pinned_directory_if_present(&version, layout.owner_uid, layout.directory_mode)?;
    let payload = version.join("payload");
    if let Ok(metadata) = fs::symlink_metadata(&payload) {
        if !metadata.file_type().is_file()
            || metadata.uid() != layout.owner_uid
            || metadata.mode() & 0o777 != 0o755
            || metadata.nlink() != 1
        {
            bail!("uncommitted pinned payload has incompatible native custody");
        }
        dev_tools_installation::remove_owned_file(&payload, &candidate.receipt.active_identity)?;
    }
    remove_empty_pinned_directory(&version)?;
    remove_empty_pinned_directory(&versions)?;
    let lock_meta = fs::symlink_metadata(&lock_path)?;
    if !lock_meta.file_type().is_file()
        || lock_meta.uid() != layout.owner_uid
        || lock_meta.mode() & 0o777 != 0o600
        || lock_meta.nlink() != 1
    {
        bail!("uncommitted pinned lock has incompatible native custody");
    }
    fs::remove_file(&lock_path).context("remove uncommitted pinned lock")?;
    drop(lock);
    remove_empty_pinned_directory(&layout.data_root)?;
    remove_empty_pinned_directory(&layout.bin_dir)?;
    Ok(true)
}

fn require_pinned_directory(path: &Path, owner_uid: u32, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect pinned artifact directory")?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o777 != mode
    {
        bail!("pinned artifact directory has incompatible native custody");
    }
    Ok(())
}

fn require_pinned_directory_if_present(path: &Path, owner_uid: u32, mode: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => require_pinned_directory(path, owner_uid, mode),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("inspect pinned artifact directory"),
    }
}

fn remove_empty_pinned_directory(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove empty pinned artifact directory"),
    }
}

impl BindingRestoration<'_> {
    fn document(&self) -> Result<RestorationDocument<'_>> {
        RestorationDocument::new(
            self.prior,
            self.candidate.as_deref(),
            self.authority.clone(),
        )
    }

    fn shell_retirements(&self) -> Result<Vec<(String, crate::smart_binding::BindingReceipt)>> {
        self.shells
            .iter()
            .filter_map(|shell| match shell.same_generation() {
                Ok(false) => shell
                    .candidate
                    .as_ref()
                    .map(|candidate| Ok((shell.alias.clone(), candidate.clone()))),
                Ok(true) => None,
                Err(error) => Some(Err(error)),
            })
            .collect()
    }

    pub(super) fn observe(&self) -> Result<()> {
        let retiring = self.shell_retirements()?;
        for pinned in &self.pinned {
            pinned.observe()?;
        }
        for shell in &self.shells {
            shell.observe(&retiring)?;
        }
        if self.candidate.is_none() && self.prior.bytes.is_some() {
            return self.observe_retired_prior().map(|_| ());
        }
        self.document()?.observe().map(|_| ())
    }

    pub(super) fn restore(&self) -> Result<bool> {
        self.observe()?;
        let retiring = self.shell_retirements()?;
        let replayed_shell_retirement = match self.shells.first() {
            Some(shell) => crate::binding_activation::resume_shell_retirement_for_restoration(
                shell.mode,
                &shell.home,
                shell.uid,
                &retiring,
            )?,
            None => false,
        };
        let mut changed = if self.candidate.is_none() && self.prior.bytes.is_some() {
            let current = self.observe_retired_prior()?;
            if current.is_some() {
                false
            } else {
                let (directory, authority) = self.prior_directory()?;
                directory.write(
                    self.prior
                        .current
                        .path
                        .file_name()
                        .context("retained binding receipt has no name")?,
                    self.prior
                        .bytes
                        .as_deref()
                        .context("retained binding bytes are absent")?,
                    &authority,
                    None,
                )?
            }
        } else {
            self.document()?.restore()?
        };
        for pinned in &self.pinned {
            changed |= pinned.restore()?;
        }
        for shell in &self.shells {
            changed |= shell.restore(&retiring)?;
        }
        Ok(changed || replayed_shell_retirement)
    }

    pub(super) fn verify_restored(&self) -> Result<()> {
        let retiring = self.shell_retirements()?;
        if self.candidate.is_none() && self.prior.bytes.is_some() {
            if self.observe_retired_prior()?.is_none() {
                bail!("retained binding receipt restoration is incomplete");
            }
        } else {
            self.document()?.verify_restored()?;
        }
        for pinned in &self.pinned {
            pinned.verify_restored()?;
        }
        for shell in &self.shells {
            shell.verify_restored(&retiring)?;
        }
        Ok(())
    }

    fn prior_directory(
        &self,
    ) -> Result<(
        dev_tools_installation::ExistingDocumentDirectory,
        DocumentAuthority,
    )> {
        let identity = self
            .prior
            .current
            .identity
            .as_ref()
            .context("retained binding receipt identity is absent")?;
        if identity.owner_uid != self.authority.owner_uid || !matches!(identity.mode, 0o600 | 0o644)
        {
            bail!("retained binding receipt has incompatible custody");
        }
        let mut authority = self.authority.clone();
        authority.mode = identity.mode;
        let directory =
            open_restoration_parent(&self.prior.current.path, self.authority.owner_uid)?
                .context("retained binding receipt parent is absent")?;
        Ok((directory, authority))
    }

    fn observe_retired_prior(&self) -> Result<Option<dev_tools_installation::AtomicDocument>> {
        let (directory, authority) = self.prior_directory()?;
        let current = directory.read(
            self.prior
                .current
                .path
                .file_name()
                .context("retained binding receipt has no name")?,
            &authority,
        )?;
        if current
            .as_ref()
            .is_some_and(|document| Some(document.bytes.as_slice()) != self.prior.bytes.as_deref())
        {
            bail!("binding receipt changed outside the retained restoration pair");
        }
        Ok(current)
    }
}

pub(super) fn binding_restorations(
    generation: &RetainedSetupGeneration,
) -> Result<Vec<BindingRestoration<'_>>> {
    let plan = &generation.plan;
    if plan.intent.schema != "dev-auth-deployment-intent-v3" {
        return Ok(Vec::new());
    }
    let prior_installation =
        retained_installation_receipts(generation)?.map(|(receipt, _)| receipt);
    let candidate_executable = plan
        .installation
        .paths
        .data_root
        .join("versions")
        .join(&plan.installation.request.version)
        .join("dev-auth");
    let mut restorations = Vec::new();
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        let prior = retained_object(generation, "binding_set_receipt", &account.name)?;
        let path = crate::binding_activation::native_receipt_path(
            plan.installation.request.mode,
            &account.home,
            account.uid,
        )?;
        if prior.current.path != path {
            bail!("retained binding receipt has an unexpected native destination");
        }
        let prior_set = prior
            .bytes
            .as_ref()
            .map(|bytes| {
                serde_json::from_slice::<crate::binding_activation::BindingSetReceipt>(bytes)
            })
            .transpose()
            .context("decode prior binding set receipt")?;
        if prior_set.is_some() != prior.current.identity.is_some()
            || (prior_set.is_some() && prior_installation.is_none())
        {
            bail!("retained binding receipt does not match prior installation authority");
        }
        if let Some((set, installation)) = prior_set.as_ref().zip(prior_installation.as_ref()) {
            crate::binding_activation::validate(set, account.uid, installation)?;
        }
        let candidate_set = if plan
            .accounts
            .iter()
            .any(|active| active.name == account.name)
        {
            let plans = plan
                .intent
                .bindings
                .iter()
                .filter(|binding| binding.user == account.name)
                .map(|binding| {
                    let subject = format!("{}/{}", binding.user, binding.name);
                    let identity = document_identity(plan, "binding_plan", &subject)?;
                    crate::smart_binding::source::decode_plan(
                        candidate_bytes(&generation.candidate_documents, identity)?,
                        &identity.sha256,
                        false,
                    )
                })
                .collect::<Result<Vec<_>>>()?;
            let expected = crate::binding_activation::expected_desired_with_mode_and_identity(
                account.uid,
                plan.installation.request.mode,
                &candidate_executable,
                &plan.installation.source_sha256,
                prior_set.as_ref().zip(prior_installation.as_ref()),
                &plans,
            )?;
            (!expected.bindings.is_empty()).then_some(expected)
        } else {
            None
        };
        let candidate = candidate_set.as_ref().map(serde_jcs::to_vec).transpose()?;
        let aliases = prior_set
            .as_ref()
            .into_iter()
            .flat_map(|set| set.pinned_artifacts.keys())
            .chain(
                candidate_set
                    .as_ref()
                    .into_iter()
                    .flat_map(|set| set.pinned_artifacts.keys()),
            )
            .cloned()
            .collect::<BTreeSet<_>>();
        if !aliases.is_empty()
            && plan.installation.request.mode != crate::setup::InstallMode::Strong
        {
            bail!("pinned restoration requires a strong installation");
        }
        let mut pinned = Vec::new();
        for alias in aliases {
            let prior_binding = prior_set.as_ref().and_then(|set| set.bindings.get(&alias));
            let candidate_binding = candidate_set
                .as_ref()
                .and_then(|set| set.bindings.get(&alias))
                .filter(|binding| {
                    binding.active.intent.code_trust
                        == crate::smart_binding::BindingCodeTrust::Pinned
                });
            let prior = prior_binding
                .filter(|binding| {
                    binding.active.intent.code_trust
                        == crate::smart_binding::BindingCodeTrust::Pinned
                })
                .map(|binding| -> Result<PinnedStoredGeneration> {
                    Ok(PinnedStoredGeneration {
                        layout: crate::binding_activation::pinned_layout(
                            account.uid,
                            &alias,
                            binding,
                        )?,
                        receipt: crate::binding_activation::pinned_ledger_receipt_for_binding(
                            account.uid,
                            &alias,
                            binding,
                        )?,
                    })
                })
                .transpose()?;
            let candidate = candidate_binding
                .map(|binding| -> Result<PinnedStoredGeneration> {
                    Ok(PinnedStoredGeneration {
                        layout: crate::binding_activation::pinned_layout(
                            account.uid,
                            &alias,
                            binding,
                        )?,
                        receipt: crate::binding_activation::pinned_ledger_receipt_for_binding(
                            account.uid,
                            &alias,
                            binding,
                        )?,
                    })
                })
                .transpose()?;
            pinned.push(PinnedRestoration { prior, candidate });
        }
        let shell_aliases = prior_set
            .as_ref()
            .into_iter()
            .flat_map(|set| set.bindings.iter())
            .chain(
                candidate_set
                    .as_ref()
                    .into_iter()
                    .flat_map(|set| set.bindings.iter()),
            )
            .filter(|(_, binding)| {
                crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved)
            })
            .map(|(alias, _)| alias.clone())
            .collect::<BTreeSet<_>>();
        let shells = shell_aliases
            .into_iter()
            .map(|alias| ShellRestoration {
                mode: plan.installation.request.mode,
                home: account.home.clone(),
                uid: account.uid,
                prior: prior_set
                    .as_ref()
                    .and_then(|set| set.bindings.get(&alias))
                    .filter(|binding| {
                        crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved)
                    })
                    .cloned(),
                candidate: candidate_set
                    .as_ref()
                    .and_then(|set| set.bindings.get(&alias))
                    .filter(|binding| {
                        crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved)
                    })
                    .cloned(),
                alias,
            })
            .collect();
        restorations.push(BindingRestoration {
            prior,
            candidate,
            authority: crate::binding_activation::authority(
                plan.installation.request.mode,
                account.uid,
            ),
            pinned,
            shells,
        });
    }
    Ok(restorations)
}

struct ShellRestoration {
    mode: crate::setup::InstallMode,
    home: PathBuf,
    uid: u32,
    alias: String,
    prior: Option<crate::smart_binding::BindingReceipt>,
    candidate: Option<crate::smart_binding::BindingReceipt>,
}

impl ShellRestoration {
    fn same_generation(&self) -> Result<bool> {
        Ok(match self.prior.as_ref().zip(self.candidate.as_ref()) {
            Some((prior, candidate)) => {
                crate::binding_activation::normalized_binding_receipt(prior)?.active
                    == crate::binding_activation::normalized_binding_receipt(candidate)?.active
            }
            None => false,
        })
    }
    fn observe(&self, retiring: &[(String, crate::smart_binding::BindingReceipt)]) -> Result<()> {
        if let Some(prior) = &self.prior {
            if !crate::binding_activation::observe_shell_payload_for_restoration(
                self.mode,
                &self.home,
                self.uid,
                &self.alias,
                prior,
                crate::binding_activation::ShellRestorationObservation::RetainedComplete,
                retiring,
            )? {
                bail!("retained private shell payload is absent during restoration");
            }
        }
        if !self.same_generation()? {
            if let Some(candidate) = &self.candidate {
                crate::binding_activation::observe_shell_payload_for_restoration(
                    self.mode,
                    &self.home,
                    self.uid,
                    &self.alias,
                    candidate,
                    crate::binding_activation::ShellRestorationObservation::CandidatePartial,
                    retiring,
                )?;
            }
        }
        Ok(())
    }
    fn restore(&self, retiring: &[(String, crate::smart_binding::BindingReceipt)]) -> Result<bool> {
        self.observe(retiring)?;
        if self.same_generation()? {
            return Ok(false);
        }
        match &self.candidate {
            Some(candidate) => crate::binding_activation::retire_shell_payload(
                self.mode,
                &self.home,
                self.uid,
                &self.alias,
                candidate,
            ),
            None => Ok(false),
        }
    }
    fn verify_restored(
        &self,
        retiring: &[(String, crate::smart_binding::BindingReceipt)],
    ) -> Result<()> {
        self.observe(retiring)?;
        if !self.same_generation()? {
            if let Some(candidate) = &self.candidate {
                if crate::binding_activation::observe_shell_payload(
                    self.mode,
                    &self.home,
                    self.uid,
                    &self.alias,
                    candidate,
                )? {
                    bail!("candidate private shell source remains after restoration");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn pinned_restoration_removes_only_candidate_store_and_preserves_exact_prior() {
        let root = tempfile::tempdir().unwrap();
        let owner_uid = fs::metadata(root.path()).unwrap().uid();
        let layout = |generation: &str| dev_tools_installation::VersionedLayout {
            product: "dev-auth-binding".into(),
            data_root: root.path().join("data").join(generation),
            bin_dir: root.path().join("links").join(generation),
            artifact_name: "payload".into(),
            owner_uid,
            directory_mode: 0o700,
            bin_directory_mode: None,
        };
        let publish = |layout: dev_tools_installation::VersionedLayout, source: &Path| {
            let identity =
                dev_tools_installation::ArtifactIdentity::from_file(source, 512 * 1024 * 1024)
                    .unwrap();
            let receipt = dev_tools_installation::apply_versioned_installation_if_unchanged(
                &dev_tools_installation::VersionedInstallRequest {
                    layout: layout.clone(),
                    version: "v1".into(),
                    source: source.to_path_buf(),
                    identity,
                    aliases: vec!["bound-tool".into()],
                },
                None,
                |_| Ok(()),
            )
            .unwrap()
            .receipt;
            PinnedStoredGeneration { layout, receipt }
        };
        let prior = publish(layout("prior"), Path::new("/usr/bin/true"));
        let candidate = publish(layout("candidate"), Path::new("/usr/bin/false"));
        let restoration = PinnedRestoration {
            prior: Some(prior),
            candidate: Some(candidate),
        };
        restoration.observe().unwrap();
        assert!(restoration.restore().unwrap());
        restoration.verify_restored().unwrap();
        assert!(!restoration.restore().unwrap());
        let prior = restoration.prior.as_ref().unwrap();
        assert_eq!(
            dev_tools_installation::observe_versioned_installation(
                &prior.layout,
                512 * 1024 * 1024,
            )
            .unwrap(),
            Some(prior.receipt.clone())
        );
    }

    #[test]
    fn interrupted_prejournal_pin_copy_is_not_mistaken_for_absence() {
        let root = tempfile::tempdir().unwrap();
        let owner_uid = fs::metadata(root.path()).unwrap().uid();
        let layout = dev_tools_installation::VersionedLayout {
            product: "dev-auth-binding".into(),
            data_root: root.path().join("data/candidate"),
            bin_dir: root.path().join("links/candidate"),
            artifact_name: "payload".into(),
            owner_uid,
            directory_mode: 0o700,
            bin_directory_mode: None,
        };
        let identity = dev_tools_installation::ArtifactIdentity::from_file(
            Path::new("/usr/bin/true"),
            512 * 1024 * 1024,
        )
        .unwrap();
        layout
            .validate_candidate("v1", &identity, &["bound-tool".into()])
            .unwrap();
        let payload = layout.data_root.join("versions/v1/payload");
        fs::create_dir_all(payload.parent().unwrap()).unwrap();
        fs::set_permissions(&layout.data_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            layout.data_root.join("versions"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(payload.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        dev_tools_installation::publish_executable(Path::new("/usr/bin/true"), &payload, &identity)
            .unwrap();
        let receipt = dev_tools_installation::VersionedReceipt {
            schema: "dev-tools-versioned-installation-v1".into(),
            product: layout.product.clone(),
            data_root: layout.data_root.clone(),
            bin_dir: layout.bin_dir.clone(),
            artifact_name: layout.artifact_name.clone(),
            active_version: "v1".into(),
            active_identity: identity,
            previous_version: None,
            previous_identity: None,
            aliases: vec!["bound-tool".into()],
        };
        let restoration = PinnedRestoration {
            prior: None,
            candidate: Some(PinnedStoredGeneration { layout, receipt }),
        };
        restoration.observe().unwrap();
        fs::write(&payload, b"foreign interrupted payload").unwrap();
        assert!(restoration.restore().is_err());
        assert_eq!(fs::read(&payload).unwrap(), b"foreign interrupted payload");
        fs::write(&payload, fs::read("/usr/bin/true").unwrap()).unwrap();
        assert!(restoration.restore().unwrap());
        restoration.verify_restored().unwrap();
        assert!(!restoration.restore().unwrap());
    }

    #[test]
    fn removed_candidate_binding_receipt_restores_only_retained_prior_bytes() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("binding-set-v1.json");
        let bytes = b"retained prior binding receipt".to_vec();
        let owner_uid = fs::metadata(root.path()).unwrap().uid();
        let prior = RetainedSetupObject {
            current: CurrentPathIdentity {
                kind: "binding_set_receipt".into(),
                subject: "test-user".into(),
                path: path.clone(),
                identity: Some(CurrentFileIdentity {
                    object_type: "file".into(),
                    owner_uid,
                    mode: 0o600,
                    link_count: 1,
                    length: bytes.len() as u64,
                    sha256: sha256_hex(&bytes),
                    link_target: None,
                }),
            },
            bytes: Some(bytes.clone()),
        };
        let restoration = BindingRestoration {
            prior: &prior,
            candidate: None,
            authority: DocumentAuthority {
                owner_uid,
                mode: 0o600,
                limit: 1024 * 1024,
            },
            shells: Vec::new(),
            pinned: Vec::new(),
        };
        restoration.observe().unwrap();
        assert!(restoration.restore().unwrap());
        restoration.verify_restored().unwrap();
        assert!(!restoration.restore().unwrap());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        fs::write(&path, b"foreign binding receipt").unwrap();
        assert!(restoration.observe().is_err());
    }
}
