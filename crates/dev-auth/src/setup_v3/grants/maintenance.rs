//! Exact candidate component repair/withdrawal; policy bytes are retained.
use super::*;

pub(in crate::setup_v3) struct ComponentMaintenance {
    files: Vec<ComponentFile>,
}

struct ComponentFile {
    desired: DesiredFile,
    withdrawn: Option<Vec<u8>>,
    preparation: dev_tools_installation::DocumentDirectoryPreparation,
}

impl ComponentMaintenance {
    pub(in crate::setup_v3) fn new(generation: &RetainedSetupGeneration) -> Result<Self> {
        let plan = &generation.plan;
        let files = desired_files(plan, &generation.candidate_documents)?;
        let native_before = before_bytes(plan, "grant_sudo_conf")?;
        let native_base = render_sudo_conf(
            native_before.as_deref().unwrap_or_default(),
            plan.grant_previous_block.as_deref(),
            None,
        )?;
        let files = files
            .into_iter()
            .map(|desired| {
                let withdrawn = match desired.kind {
                    "grant_policy" => desired.bytes.clone(),
                    "grant_sudo_conf" => native_before.as_ref().map(|_| native_base.clone()),
                    _ => None,
                };
                let preparation = dev_tools_installation::DocumentDirectoryPreparation::observe(
                    Path::new(desired.path)
                        .parent()
                        .context("component file has no parent")?,
                    0,
                    0o755,
                )?;
                Ok(ComponentFile {
                    desired,
                    withdrawn,
                    preparation,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { files })
    }

    pub(in crate::setup_v3) fn observe(&self, uninstall: bool) -> Result<()> {
        for file in &self.files {
            file.observe(uninstall)?;
        }
        Ok(())
    }

    pub(in crate::setup_v3) fn stop(&self, uninstall: bool) -> Result<bool> {
        self.observe(uninstall)?;
        let service = self
            .files
            .iter()
            .find(|file| file.desired.kind == "grant_service")
            .context("component service is absent from retention")?;
        if service.observe(uninstall)?.is_none() {
            // Missing definitions never authorize a stop request. A partial
            // withdrawal must first prove that its execution domain is empty;
            // reload then establishes the manager's exact missing-unit state.
            crate::setup::restoration::require_grant_domain_empty()?;
        }
        native::reload()?;
        native::stop()
    }

    pub(in crate::setup_v3) fn observe_shutdown(&self, uninstall: bool) -> Result<()> {
        let service = self
            .files
            .iter()
            .find(|file| file.desired.kind == "grant_service")
            .context("component service is absent from retention")?;
        if service.observe(uninstall)?.is_none() {
            crate::setup::restoration::require_grant_domain_empty()?;
        } else {
            native::observe()?;
        }
        Ok(())
    }

    pub(in crate::setup_v3) fn repair(&self, plan: &SetupPlanV3) -> Result<bool> {
        self.observe(false)?;
        if !native::observe()?.stopped {
            bail!("component repair requires a stopped coordinator");
        }
        crate::setup::restoration::require_grant_domain_empty()?;
        let mut changed = false;
        for file in &self.files {
            changed |= file.publish(file.desired.bytes.as_deref(), false)?;
        }
        native::reload()?;
        if plan.intent.activation == Activation::Transparent {
            native::activate()?;
        }
        Ok(changed)
    }

    pub(in crate::setup_v3) fn withdraw(&self) -> Result<bool> {
        self.observe(true)?;
        let state = native::observe()?;
        if !state.stopped || state.enabled {
            bail!("component withdrawal requires a stopped disabled coordinator");
        }
        crate::setup::restoration::require_grant_domain_empty()?;
        let mut changed = false;
        for kind in [
            "grant_sudoers",
            "grant_sudo_conf",
            "grant_service",
            "grant_action",
            "grant_library",
            "grant_policy",
        ] {
            let file = self
                .files
                .iter()
                .find(|file| file.desired.kind == kind)
                .context("component withdrawal inventory is incomplete")?;
            changed |= file.publish(file.withdrawn.as_deref(), true)?;
        }
        native::reload()?;
        self.verify_withdrawn()?;
        Ok(changed)
    }

    pub(in crate::setup_v3) fn verify_withdrawn(&self) -> Result<()> {
        for file in &self.files {
            let current = file.observe(true)?;
            if current.as_ref().map(|doc| doc.bytes.as_slice()) != file.withdrawn.as_deref() {
                bail!("component withdrawal is incomplete");
            }
        }
        let state = native::observe()?;
        if state.loaded || !state.stopped || state.enabled {
            bail!("withdrawn component has native activation");
        }
        crate::setup::restoration::require_grant_domain_empty()
    }
}

impl ComponentFile {
    fn name(&self) -> Result<&std::ffi::OsStr> {
        Path::new(self.desired.path)
            .file_name()
            .context("component file has no leaf")
    }

    fn observe(&self, uninstall: bool) -> Result<Option<dev_tools_installation::AtomicDocument>> {
        let current = self
            .preparation
            .read_file(self.name()?, &self.desired.authority())?;
        if self.desired.kind == "grant_policy" && current.is_none() {
            // The outer maintenance snapshot preserves this policy as observed.
            // Absence cannot authorize recreating it after direction publication.
            bail!("grant policy must be present before preserving maintenance");
        }
        let bytes = current.as_ref().map(|doc| doc.bytes.as_slice());
        if bytes != self.desired.bytes.as_deref()
            && !(uninstall && bytes == self.withdrawn.as_deref())
            && current.is_some()
        {
            bail!("component file is outside retained maintenance authority");
        }
        Ok(current)
    }

    fn publish(&self, target: Option<&[u8]>, uninstall: bool) -> Result<bool> {
        let current = self.observe(uninstall)?;
        if target.is_none() && current.is_none() {
            // Settle prior removal without creating an originally absent parent.
            if let Ok(directory) = dev_tools_installation::ExistingDocumentDirectory::open(
                Path::new(self.desired.path)
                    .parent()
                    .context("component file has no parent")?,
                0,
            ) {
                if let Some(bytes) = &self.desired.bytes {
                    return directory.remove_file(
                        self.name()?,
                        &self.desired.authority(),
                        &identity(bytes),
                    );
                }
            } else {
                self.preparation
                    .read_file(self.name()?, &self.desired.authority())?;
            }
            return Ok(false);
        }
        let (directory, created) = self.preparation.prepare()?;
        let changed = match (target, current) {
            (Some(bytes), Some(current)) => directory.replace_file(
                self.name()?,
                bytes,
                &self.desired.authority(),
                &self.desired.authority(),
                &current.identity,
            )?,
            (Some(bytes), None) => {
                directory.write_file(self.name()?, bytes, &self.desired.authority(), None)?
            }
            (None, Some(current)) => {
                directory.remove_file(self.name()?, &self.desired.authority(), &current.identity)?
            }
            (None, None) => false,
        };
        Ok(changed || created)
    }
}

/// Terminal replacement planning verifies current grant authority without
/// interpreting the old release's payload using this candidate's compiled bytes.
pub(super) fn verify_terminal_replacement(generation: &RetainedSetupGeneration) -> Result<()> {
    for path in [LIBRARY, SERVICE, ACTION, SUDOERS] {
        require_fixed_absence(Path::new(path))?;
    }
    if generation.plan.intent.has_grants() {
        validate_candidate_inventory(&generation.plan, &generation.candidate_documents)?;
        let policy_identity = document_identity(&generation.plan, "grant_policy", "system")?;
        let expected_policy = candidate_bytes(&generation.candidate_documents, policy_identity)?;
        policy(expected_policy)?;
        let current_policy = dev_tools_installation::read_atomic_document(
            Path::new(crate::privilege::grants::SYSTEM_POLICY),
            &DocumentAuthority {
                owner_uid: 0,
                mode: 0o600,
                limit: DOCUMENT_LIMIT,
            },
        )?
        .context("withdrawn grant policy is absent")?;
        if current_policy.bytes != expected_policy {
            bail!("withdrawn grant policy differs from retained authority");
        }
        let before = prior(generation, "grant_sudo_conf")?;
        let expected_base = render_sudo_conf(
            before.bytes.as_deref().unwrap_or_default(),
            generation.plan.grant_previous_block.as_deref(),
            None,
        )?;
        let expected_mode = before
            .current
            .identity
            .as_ref()
            .map_or(0o644, |identity| identity.mode);
        let current_conf = dev_tools_installation::read_atomic_file(
            Path::new(SUDO_CONF),
            &DocumentAuthority {
                owner_uid: 0,
                mode: expected_mode,
                limit: DOCUMENT_LIMIT,
            },
        )?;
        if current_conf
            .as_ref()
            .map(|document| document.bytes.as_slice())
            != before.bytes.as_ref().map(|_| expected_base.as_slice())
        {
            bail!("withdrawn sudo configuration differs from retained native authority");
        }
    } else if let Some(bytes) = current_native_sudo_conf()? {
        // This generation never selected a grant component. No recognized
        // marker or product plugin can be adopted as an owned previous block.
        render_sudo_conf(&bytes, None, None)?;
    }
    let state = native::observe()?;
    if state.loaded || !state.stopped || state.enabled {
        bail!("uninstalled grant component retains native activation");
    }
    crate::setup::restoration::require_grant_domain_empty()
}

fn require_fixed_absence(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("grant enforcement file has no parent")?;
    let directory = match dev_tools_installation::ExistingDocumentDirectory::open(parent, 0) {
        Ok(directory) => directory,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(())
        }
        Err(error) => return Err(error),
    };
    if directory
        .metadata(
            path.file_name()
                .context("grant enforcement file has no leaf")?,
        )?
        .is_some()
    {
        bail!("uninstalled grant enforcement file reappeared");
    }
    Ok(())
}

fn current_native_sudo_conf() -> Result<Option<Vec<u8>>> {
    let directory = dev_tools_installation::ExistingDocumentDirectory::open(Path::new("/etc"), 0)?;
    let Some(metadata) = directory.metadata(std::ffi::OsStr::new("sudo.conf"))? else {
        return Ok(None);
    };
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.nlink() != 1
        || mode & !0o666 != 0
        || mode & 0o022 != 0
        || mode & 0o400 == 0
    {
        bail!("native sudo configuration has unsafe current authority");
    }
    let document = directory
        .read_file(
            std::ffi::OsStr::new("sudo.conf"),
            &DocumentAuthority {
                owner_uid: 0,
                mode,
                limit: DOCUMENT_LIMIT,
            },
        )?
        .context("native sudo configuration disappeared")?;
    Ok(Some(document.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn missing_preserved_grant_policy_rejects_preflight_and_cannot_be_republished() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let policy_path: &'static str = Box::leak(
            root.path()
                .join("grant-policy.json")
                .to_string_lossy()
                .into_owned()
                .into_boxed_str(),
        );
        let owner = nix::unistd::Uid::effective().as_raw();
        let file = ComponentFile {
            desired: DesiredFile {
                kind: "grant_policy",
                path: policy_path,
                mode: 0o600,
                bytes: Some(b"retained candidate policy".to_vec()),
            },
            withdrawn: Some(b"retained candidate policy".to_vec()),
            preparation: dev_tools_installation::DocumentDirectoryPreparation::observe(
                root.path(),
                owner,
                0o700,
            )
            .unwrap(),
        };
        let component = ComponentMaintenance { files: vec![file] };
        let file = &component.files[0];
        for uninstall in [false, true] {
            let error = component.observe(uninstall).unwrap_err();
            assert_eq!(
                error.to_string(),
                "grant policy must be present before preserving maintenance"
            );
            assert!(!Path::new(policy_path).exists());
            let target = if uninstall {
                file.withdrawn.as_deref()
            } else {
                file.desired.bytes.as_deref()
            };
            assert!(file.publish(target, uninstall).is_err());
            assert!(
                !Path::new(policy_path).exists(),
                "maintenance must not turn preserved absence into a policy"
            );
        }
    }
}
