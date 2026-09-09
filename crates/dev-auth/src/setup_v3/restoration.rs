use super::*;
use crate::setup::restoration::{InitialInstallationRestoration, RetainedInstallationRestoration};
use crate::setup_transition::Phase;

mod configuration;
mod integration;
#[cfg(test)]
mod native;

// The forward setup caller owns the admission lease, validates native accounts
// and admits this generation from its matching durable pending transition.
pub(super) fn retire_user_integrations(
    generation: &RetainedSetupGeneration,
    executable: &Path,
) -> Result<bool> {
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != sha256_hex(&serde_jcs::to_vec(&generation.plan)?)
    {
        bail!("integration retirement requires an intact retained generation");
    }
    validate_candidate_inventory(&generation.plan, &generation.candidate_documents)?;
    let workloads = integration::workload_retirements(generation, executable)?;
    let desktops = integration::desktop_retirements(generation)?;
    // Observe every account and integration before the first removal. A later
    // account's drift cannot silently authorize partial retirement elsewhere.
    for retirement in &workloads {
        retirement.observe()?;
    }
    for retirement in &desktops {
        retirement.observe()?;
    }
    let mut changed = false;
    for retirement in &workloads {
        changed |= retirement.retire()?;
    }
    for retirement in &desktops {
        changed |= retirement.retire()?;
    }
    for retirement in &workloads {
        retirement.verify_retired()?;
    }
    for retirement in &desktops {
        retirement.verify_retired()?;
    }
    Ok(changed)
}

enum InstallationRestoration {
    Prior(Box<RetainedInstallationRestoration>, Option<Vec<u8>>),
    Initial(Box<InitialInstallationRestoration>),
}

impl InstallationRestoration {
    fn integration_executable(&self) -> Result<PathBuf> {
        match self {
            Self::Prior(restoration, _) => {
                Ok(PathBuf::from(restoration.admitted_receipt()?.executable))
            }
            Self::Initial(restoration) => restoration.integration_executable(),
        }
    }

    fn deactivate(&self) -> Result<bool> {
        match self {
            Self::Prior(restoration, _) => {
                let mut changed = restoration.deactivate()?;
                changed |= restoration.stop_retained_services()?;
                Ok(changed)
            }
            Self::Initial(restoration) => restoration.deactivate(),
        }
    }

    fn restore(&self) -> Result<bool> {
        match self {
            Self::Prior(restoration, helper_receipt) => {
                let mut changed = match helper_receipt {
                    Some(bytes) => restoration.restore_setup_helper(bytes)?,
                    None => false,
                };
                changed |= restoration.restore()?;
                Ok(changed)
            }
            Self::Initial(restoration) => restoration.restore(),
        }
    }

    fn verify_restored(&self) -> Result<()> {
        match self {
            Self::Prior(restoration, helper_receipt) => {
                if let Some(bytes) = helper_receipt {
                    restoration.verify_restored_setup_helper(bytes)?;
                }
                if !restoration
                    .verify_restored()?
                    .transparent_aliases
                    .is_empty()
                {
                    bail!("restored integration became active");
                }
                Ok(())
            }
            Self::Initial(restoration) => restoration.verify_restored(),
        }
    }
}

fn installation_restoration(
    generation: &RetainedSetupGeneration,
) -> Result<InstallationRestoration> {
    let plan = &generation.plan;
    let prior = retained_object(generation, "installation_receipt", "system")?;
    let prior_shared = retained_object(generation, "shared_installation_receipt", "system")?;
    let prior_receipt_mode = prior
        .current
        .identity
        .as_ref()
        .map(|identity| identity.mode);
    match (&prior.bytes, &prior_shared.bytes) {
        (Some(prior), Some(shared)) => Ok(InstallationRestoration::Prior(
            Box::new(
                RetainedInstallationRestoration::new_with_prior_receipt_mode(
                    &plan.installation,
                    &serde_json::from_slice(prior)?,
                    &serde_json::from_slice(shared)?,
                    prior_receipt_mode.context("retained installation receipt mode is absent")?,
                )?,
            ),
            if plan.installation.request.mode == crate::setup::InstallMode::Strong {
                let object = retained_object(generation, "setup_helper_receipt", "system")?;
                let identity = object
                    .current
                    .identity
                    .as_ref()
                    .context("retained strong helper receipt authority is absent")?;
                if identity.owner_uid != 0
                    || identity.mode != 0o644
                    || object.current.path
                        != plan
                            .installation
                            .paths
                            .data_root
                            .join("setup-helper-v1.json")
                {
                    bail!("retained strong helper receipt has unsafe authority");
                }
                Some(
                    object
                        .bytes
                        .clone()
                        .context("retained strong helper receipt bytes are absent")?,
                )
            } else {
                None
            },
        )),
        (None, None) => {
            // Receipt absence alone cannot authorize withdrawal of a legacy or
            // unreceipted activation. The approved topology must also be absent.
            for (kind, subject, path) in crate::setup::installation_current_state_paths(
                &plan.installation.paths,
                plan.installation.request.mode,
            ) {
                if matches!(
                    kind.as_str(),
                    "privileged_workload_launcher" | "privileged_setup_helper"
                ) {
                    let mut matches = plan
                        .current_paths
                        .iter()
                        .filter(|current| current.kind == kind && current.subject == subject);
                    let current = matches
                        .next()
                        .context("initial native activation is absent from approval")?;
                    if matches.next().is_some()
                        || current.path != path
                        || current.identity.is_some()
                    {
                        bail!("initial restoration requires approved native activation absence");
                    }
                    continue;
                }
                let object = retained_object(generation, &kind, &subject)?;
                if object.current.path != path
                    || object.current.identity.is_some()
                    || object.bytes.is_some()
                {
                    bail!("initial restoration requires approved original activation absence");
                }
            }
            Ok(InstallationRestoration::Initial(Box::new(
                InitialInstallationRestoration::new(&plan.installation)?,
            )))
        }
        _ => bail!("retained installation ownership is incomplete"),
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupRestorationReportV1 {
    pub schema: String,
    pub changed: Option<bool>,
    pub verified: bool,
    pub next_action: String,
    pub retry_executable: Option<PathBuf>,
    pub error_kind: Option<String>,
    pub exit_code: i32,
}

/// Restore retained native installation authority with integrations inactive. Credentials
/// and credential-action receipts are never reverted by this operation.
pub fn restore_setup_v3(mode: crate::setup::InstallMode) -> SetupRestorationReportV1 {
    let mut progress = RecoveryProgress::new();
    let mut retry_executable = None;
    let outcome = restore_owned_inner(mode, &mut progress, &mut retry_executable);
    let result = progress.report(outcome);
    SetupRestorationReportV1 {
        schema: "dev-auth-setup-restore-v1".into(),
        changed: result.changed,
        verified: result.verified,
        next_action: result.next_action,
        retry_executable,
        error_kind: result.error_kind.map(|kind| {
            match kind {
                SetupRecoveryFailure::Authority => "setup_restoration_authority",
                SetupRecoveryFailure::Blocked => "setup_restoration_blocked",
                SetupRecoveryFailure::InvalidInput => "setup_restoration_input",
                SetupRecoveryFailure::Operational => "setup_restoration_failed",
            }
            .into()
        }),
        exit_code: result.exit_code,
    }
}

fn restore_owned_inner(
    mode: crate::setup::InstallMode,
    progress: &mut RecoveryProgress,
    retry_executable: &mut Option<PathBuf>,
) -> Result<SetupApplyReportV3> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("restoration native account is absent")?;
    let (paths, owner, deployment_mode) = match mode {
        crate::setup::InstallMode::Strong if user.uid.is_root() => (
            crate::setup::SetupPaths::strong(),
            0,
            DeploymentMode::Strong,
        ),
        crate::setup::InstallMode::UserOnly if !user.uid.is_root() => (
            crate::setup::SetupPaths::user_only(&user.dir),
            user.uid.as_raw(),
            DeploymentMode::UserOnly,
        ),
        _ => {
            progress.next_action = "run_as_installation_owner";
            bail!("restoration requires its native installation owner");
        }
    };
    let lock = crate::setup_transition::lock_path(
        deployment_mode,
        (deployment_mode == DeploymentMode::UserOnly).then_some(owner),
    )?;
    let Some(_lease) = InstallationLock::try_acquire(&lock)? else {
        progress.blocked("wait_for_active_workloads_or_setup");
        bail!("restoration requires exclusive setup ownership");
    };
    let Some(transition) = crate::setup_transition::retained_transition(&paths, owner)? else {
        progress.blocked("create_setup_plan");
        bail!("restoration requires a retained generation");
    };
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
    let plan = &generation.plan;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != transition.plan_sha256
        || sha256_hex(&serde_jcs::to_vec(plan)?) != transition.plan_sha256
        || plan.installation.paths != paths
        || plan.intent.mode != deployment_mode
        || plan.installation.request.mode != mode
        || (deployment_mode == DeploymentMode::UserOnly
            && plan.accounts
                != [NativeAccountIdentity {
                    name: user.name.clone(),
                    uid: owner,
                    gid: user.gid.as_raw(),
                    home: user.dir.clone(),
                }])
    {
        bail!("retained restoration does not match native authority");
    }
    require_apply_identity(plan)?;
    require_retained_native_accounts(plan.accounts.iter().chain(&plan.retiring_accounts))?;
    validate_candidate_inventory(plan, &generation.candidate_documents)?;
    let prior = retained_object(&generation, "installation_receipt", "system")?;
    let prior_shared = retained_object(&generation, "shared_installation_receipt", "system")?;
    for receipt in [prior, prior_shared] {
        if receipt.current.identity.as_ref().is_some_and(|identity| {
            identity.owner_uid != owner
                || !(identity.mode == 0o600
                    || (mode == crate::setup::InstallMode::Strong
                        && receipt.current.kind == "installation_receipt"
                        && identity.mode == 0o644))
        }) {
            bail!("retained installation receipt custody is incompatible");
        }
    }
    let installation = installation_restoration(&generation)?;
    *retry_executable = Some(
        paths
            .data_root
            .join("versions")
            .join(&plan.installation.request.version)
            .join("dev-auth"),
    );
    let candidate_identity = crate::setup::setup_executable_identity(&std::env::current_exe()?)?;
    if candidate_identity
        != (
            plan.installation.source_length,
            plan.installation.source_sha256.clone(),
        )
    {
        progress.next_action = "run_retained_candidate_for_restoration";
        bail!("restoration requires the exact retained candidate executable");
    }
    validate_setup_plan_v3_with_installation_check(plan, &|candidate| {
        if candidate != &plan.installation {
            bail!("restoration cannot validate another installation");
        }
        Ok(())
    })?;
    let configurations = restoration_documents(&generation)?;
    validate_prior_configuration(&generation)?;
    for document in &configurations {
        document.observe()?;
    }
    let integration_executable = installation.integration_executable()?;
    let workload_retirements =
        integration::workload_retirements(&generation, &integration_executable)?;
    for retirement in &workload_retirements {
        retirement.observe()?;
    }
    let desktop_retirements = integration::desktop_retirements(&generation)?;
    for retirement in &desktop_retirements {
        retirement.observe()?;
    }
    if deployment_mode == DeploymentMode::UserOnly {
        crate::setup::require_user_sessions_absent()?;
    }
    if transition.phase == Phase::RestoredInactive {
        for retirement in &workload_retirements {
            retirement.verify_retired()?;
        }
        for retirement in &desktop_retirements {
            retirement.verify_retired()?;
        }
        for document in &configurations {
            document.verify_restored()?;
        }
        installation.verify_restored()?;
        return Ok(restored_report(false));
    }
    progress.enter_mutation();
    progress.next_action = "retry_setup_restoration";
    let mut changed =
        crate::setup_transition::advance(&paths, owner, &transition.plan_sha256, Phase::Restoring)?;
    changed |= installation.deactivate()?;
    // Receipt-owned removal also handles a previous interrupted deactivation.
    // It neither reinstalls old launchers nor treats arbitrary files as owned.
    for retirement in &workload_retirements {
        changed |= retirement.retire()?;
    }
    for retirement in &desktop_retirements {
        changed |= retirement.retire()?;
    }
    for document in &configurations {
        changed |= document.restore()?;
    }
    changed |= installation.restore()?;
    for document in &configurations {
        document.verify_restored()?;
    }
    // restore() verified the exact binary postcondition; configuration reads
    // above do not mutate installation state and the exclusive lease remains held.
    for retirement in &workload_retirements {
        retirement.verify_retired()?;
    }
    for retirement in &desktop_retirements {
        retirement.verify_retired()?;
    }
    changed |= crate::setup_transition::advance(
        &paths,
        owner,
        &transition.plan_sha256,
        Phase::RestoredInactive,
    )?;
    Ok(restored_report(changed))
}

fn restored_report(changed: bool) -> SetupApplyReportV3 {
    SetupApplyReportV3 {
        schema: "dev-auth-setup-restore-v1".into(),
        changed,
        verified: true,
        input_required: Vec::new(),
        blocked: Vec::new(),
        next_action: "create_setup_plan".into(),
        actions: Vec::new(),
    }
}

fn require_retained_native_accounts<'a>(
    accounts: impl Iterator<Item = &'a NativeAccountIdentity>,
) -> Result<()> {
    for expected in accounts {
        let current = nix::unistd::User::from_name(&expected.name)?
            .context("retained native account is absent")?;
        if current.name != expected.name
            || current.uid.as_raw() != expected.uid
            || current.gid.as_raw() != expected.gid
            || current.dir != expected.home
        {
            bail!("retained native account identity changed after approval");
        }
    }
    Ok(())
}

pub(super) fn retained_object<'a>(
    generation: &'a RetainedSetupGeneration,
    kind: &str,
    subject: &str,
) -> Result<&'a RetainedSetupObject> {
    let expected = generation
        .plan
        .current_paths
        .iter()
        .find(|current| current.kind == kind && current.subject == subject)
        .context("retained path is absent from the approved inventory")?;
    let mut matches = generation
        .documents
        .iter()
        .filter(|object| object.current == *expected);
    let object = matches.next().context("retained object is absent")?;
    if matches.next().is_some() {
        bail!("retained object is ambiguous");
    }
    match (&object.current.identity, &object.bytes) {
        (None, None) => {}
        (Some(identity), Some(bytes))
            if identity.object_type == "file"
                && identity.link_count == 1
                && identity.link_target.is_none()
                && !bytes.is_empty()
                && bytes.len() as u64 <= DOCUMENT_LIMIT
                && bytes.len() as u64 == identity.length
                && sha256_hex(bytes) == identity.sha256 => {}
        _ => bail!("retained document does not match its approved identity"),
    }
    Ok(object)
}

struct RestorationDocument<'a> {
    prior: &'a RetainedSetupObject,
    candidate: Option<&'a [u8]>,
    authority: DocumentAuthority,
    prior_authority: DocumentAuthority,
    directory: Option<dev_tools_installation::ExistingDocumentDirectory>,
}

impl<'a> RestorationDocument<'a> {
    fn new(
        prior: &'a RetainedSetupObject,
        candidate: Option<&'a [u8]>,
        authority: DocumentAuthority,
    ) -> Result<Self> {
        let mut prior_authority = authority.clone();
        if let Some(identity) = &prior.current.identity {
            if identity.owner_uid != authority.owner_uid
                || !matches!(identity.mode, 0o600 | 0o644)
                || !matches!(authority.mode, 0o600 | 0o644)
            {
                bail!("restoration document has incompatible prior custody");
            }
            prior_authority.mode = identity.mode;
        }
        let directory = open_restoration_parent(&prior.current.path, authority.owner_uid)?;
        Ok(Self {
            prior,
            candidate,
            authority,
            prior_authority,
            directory,
        })
    }

    fn observe(
        &self,
    ) -> Result<Option<(dev_tools_installation::AtomicDocument, DocumentAuthority)>> {
        let current = match &self.directory {
            Some(directory) => {
                // Admit bytes and permissions as a pair. Trying the candidate
                // authority after a prior-mode mismatch never admits prior
                // bytes with candidate permissions (or the inverse).
                if let Ok(Some(document)) = directory.read(self.name()?, &self.prior_authority) {
                    if Some(document.bytes.as_slice()) == self.prior.bytes.as_deref() {
                        return Ok(Some((document, self.prior_authority.clone())));
                    }
                }
                directory.read(self.name()?, &self.authority)?
            }
            None => {
                if open_restoration_parent(&self.prior.current.path, self.authority.owner_uid)?
                    .is_some()
                {
                    bail!("restoration directory appeared outside retained selection");
                }
                None
            }
        };
        let bytes = current.as_ref().map(|document| document.bytes.as_slice());
        if current.is_none() && self.prior.bytes.is_none() {
            return Ok(None);
        }
        if self.candidate.is_none() || bytes != self.candidate {
            bail!("configuration changed outside the retained restoration pair");
        }
        Ok(current.map(|document| (document, self.authority.clone())))
    }

    fn restore(&self) -> Result<bool> {
        let current = self.observe()?;
        let Some(directory) = &self.directory else {
            if self.prior.bytes.is_some() {
                bail!("prior restoration directory is absent");
            }
            return Ok(false);
        };
        let name = self.name()?;
        if let Some(bytes) = &self.prior.bytes {
            if let Some((current, authority)) = &current {
                return directory.replace(
                    name,
                    bytes,
                    &self.prior_authority,
                    authority,
                    &current.identity,
                );
            }
            return directory.write(name, bytes, &self.prior_authority, None);
        }
        if let Some((current, authority)) = current {
            return directory.remove(name, &authority, &current.identity);
        }
        // If the candidate created this parent, a retry after unlink must sync
        // absence. An untouched absent parent is not created by restoration.
        if self.candidate.is_some() {
            let bytes = self
                .candidate
                .context("candidate removal identity is absent")?;
            directory.remove(
                name,
                &self.authority,
                &dev_tools_installation::ArtifactIdentity {
                    length: bytes.len() as u64,
                    sha256: sha256_hex(bytes),
                },
            )?;
        }
        Ok(false)
    }

    fn name(&self) -> Result<&std::ffi::OsStr> {
        self.prior
            .current
            .path
            .file_name()
            .context("restoration document has no leaf name")
    }

    fn verify_restored(&self) -> Result<()> {
        let current = self.observe()?;
        if current
            .as_ref()
            .map(|(document, _)| document.bytes.as_slice())
            != self.prior.bytes.as_deref()
            || current
                .as_ref()
                .is_some_and(|(_, authority)| authority.mode != self.prior_authority.mode)
        {
            bail!("retained configuration restoration is incomplete");
        }
        Ok(())
    }
}

fn open_restoration_parent(
    path: &Path,
    owner_uid: u32,
) -> Result<Option<dev_tools_installation::ExistingDocumentDirectory>> {
    let parent = path
        .parent()
        .context("restoration document has no parent")?;
    match dev_tools_installation::ExistingDocumentDirectory::open(parent, owner_uid) {
        Ok(directory) => Ok(Some(directory)),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn restoration_documents(
    generation: &RetainedSetupGeneration,
) -> Result<Vec<RestorationDocument<'_>>> {
    let plan = &generation.plan;
    if plan.intent.mode == DeploymentMode::Strong {
        let mut documents = system_asset_documents(generation)?;
        for spec in configuration::strong_configuration_specs(generation)? {
            documents.push(RestorationDocument::new(
                spec.prior,
                spec.candidate,
                spec.authority,
            )?);
        }
        return Ok(documents);
    }
    let account = plan
        .accounts
        .first()
        .context("restoration account is absent")?;
    let administrator = document_identity(plan, "administrator_policy", "system")?;
    let documents = [
        "user_policy",
        "user_configuration",
        "retained_user_policy",
        "retained_user_configuration",
    ]
    .into_iter()
    .map(|kind| {
        let prior = retained_object(generation, kind, &account.name)?;
        if prior
            .current
            .identity
            .as_ref()
            .is_some_and(|identity| identity.owner_uid != account.uid || identity.mode != 0o600)
        {
            bail!("retained user configuration has incompatible custody");
        }
        let candidate = match kind {
            "user_policy" => Some(candidate_bytes(
                &generation.candidate_documents,
                document_identity(plan, kind, &account.name).unwrap_or(administrator),
            )?),
            "user_configuration" => Some(candidate_bytes(
                &generation.candidate_documents,
                document_identity(plan, kind, &account.name)?,
            )?),
            _ => None,
        };
        RestorationDocument::new(
            prior,
            candidate,
            DocumentAuthority {
                owner_uid: account.uid,
                mode: 0o600,
                limit: DOCUMENT_LIMIT,
            },
        )
    })
    .collect::<Result<Vec<_>>>()?;
    Ok(documents)
}

fn system_asset_candidate(
    prior: &RetainedSetupObject,
    receipt: &BTreeMap<String, String>,
) -> Result<&'static [u8]> {
    let assets = crate::setup::linux_system_assets();
    crate::setup::validate_system_asset_receipt_shape(receipt)?;
    let (path, candidate, mode) = assets
        .into_iter()
        .find(|(path, _, _)| *path == prior.current.path)
        .context("retained system asset is not a fixed product destination")?;
    let identity = prior
        .current
        .identity
        .as_ref()
        .context("retained system asset is absent")?;
    let bytes = prior
        .bytes
        .as_deref()
        .context("retained system asset bytes are absent")?;
    if prior.current.kind != "system_integration"
        || prior.current.subject != path.display().to_string()
        || identity.object_type != "file"
        || identity.link_target.is_some()
        || identity.owner_uid != 0
        || identity.mode != mode
        || identity.link_count != 1
        || bytes.is_empty()
        || bytes.len() as u64 > DOCUMENT_LIMIT
        || bytes.len() as u64 != identity.length
        || sha256_hex(bytes) != identity.sha256
        || receipt.get(&prior.current.subject) != Some(&identity.sha256)
    {
        bail!("retained system asset differs from receipt-owned content or custody");
    }
    Ok(candidate.as_bytes())
}

fn system_asset_documents(
    generation: &RetainedSetupGeneration,
) -> Result<Vec<RestorationDocument<'_>>> {
    if generation.plan.intent.mode != DeploymentMode::Strong {
        return Ok(Vec::new());
    }
    let object = retained_object(generation, "installation_receipt", "system")?;
    let receipt: Option<crate::setup::InstallReceipt> = object
        .bytes
        .as_deref()
        .map(serde_json::from_slice)
        .transpose()?;
    if receipt
        .as_ref()
        .is_some_and(|receipt| receipt.mode != crate::setup::InstallMode::Strong)
    {
        bail!("system asset restoration requires a strong prior receipt");
    }
    if receipt.is_none()
        && (object.current.identity.is_some()
            || retained_object(generation, "shared_installation_receipt", "system")?
                .current
                .identity
                .is_some()
            || retained_object(generation, "shared_installation_receipt", "system")?
                .bytes
                .is_some())
    {
        bail!("initial system asset retirement requires retained receipt absence");
    }
    crate::setup::linux_system_assets()
        .into_iter()
        .map(|(path, _, mode)| {
            let prior = retained_object(
                generation,
                "system_integration",
                &path.display().to_string(),
            )?;
            let candidate = match &receipt {
                Some(receipt) => system_asset_candidate(prior, &receipt.system_assets)?,
                None => initial_system_asset_candidate(prior)?,
            };
            RestorationDocument::new(
                prior,
                Some(candidate),
                DocumentAuthority {
                    owner_uid: 0,
                    mode,
                    limit: DOCUMENT_LIMIT,
                },
            )
        })
        .collect()
}

fn initial_system_asset_candidate(prior: &RetainedSetupObject) -> Result<&'static [u8]> {
    let (path, content, _) = crate::setup::linux_system_assets()
        .into_iter()
        .find(|(path, _, _)| *path == prior.current.path)
        .context("initial system asset is not a fixed product destination")?;
    if prior.current.kind != "system_integration"
        || prior.current.subject != path.display().to_string()
        || prior.current.identity.is_some()
        || prior.bytes.is_some()
    {
        bail!("initial system asset retirement requires approved original absence");
    }
    Ok(content.as_bytes())
}

fn validate_prior_configuration(generation: &RetainedSetupGeneration) -> Result<()> {
    if generation.plan.intent.mode == DeploymentMode::Strong {
        return configuration::validate_prior_strong_configuration(generation);
    }
    let account = generation
        .plan
        .accounts
        .first()
        .context("restoration account is absent")?;
    for (policy_kind, config_kind) in [
        ("user_policy", "user_configuration"),
        ("retained_user_policy", "retained_user_configuration"),
    ] {
        let policy = retained_object(generation, policy_kind, &account.name)?;
        let config = retained_object(generation, config_kind, &account.name)?;
        match (&policy.bytes, &config.bytes) {
            (None, None) => {}
            (Some(policy), Some(config)) => {
                let policy = parse_runtime_administrator(policy)?;
                if policy.mode() != SystemMode::UserOnly {
                    bail!("retained user policy has incompatible mode");
                }
                let resolved = policy.resolve_user(&account.name, config)?;
                validate_resolved_workspace_authority(&resolved, account.uid)?;
            }
            _ => bail!("retained configuration has no matching policy generation"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn initial_system_assets_require_exact_fixed_absent_approval() {
        for (path, bytes, _) in crate::setup::linux_system_assets() {
            let mut prior = RetainedSetupObject {
                current: CurrentPathIdentity {
                    kind: "system_integration".into(),
                    subject: path.display().to_string(),
                    path: path.to_path_buf(),
                    identity: None,
                },
                bytes: None,
            };
            assert_eq!(
                initial_system_asset_candidate(&prior).unwrap(),
                bytes.as_bytes()
            );
            prior.bytes = Some(Vec::new());
            assert!(initial_system_asset_candidate(&prior).is_err());
            prior.bytes = None;
            prior.current.identity = Some(CurrentFileIdentity {
                object_type: "file".into(),
                owner_uid: 0,
                mode: 0o644,
                link_count: 1,
                length: bytes.len() as u64,
                sha256: sha256_hex(bytes.as_bytes()),
                link_target: None,
            });
            assert!(initial_system_asset_candidate(&prior).is_err());
            prior.current.identity = None;
            prior.current.path = "/unowned/asset".into();
            assert!(initial_system_asset_candidate(&prior).is_err());
            prior.current.path = path.into();
            prior.current.subject = "unowned".into();
            assert!(initial_system_asset_candidate(&prior).is_err());
        }
    }

    #[test]
    fn retained_account_selection_rejects_changed_native_identity() {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .unwrap()
            .unwrap();
        let account = NativeAccountIdentity {
            name: user.name.clone(),
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home: user.dir.clone(),
        };
        require_retained_native_accounts(std::iter::once(&account)).unwrap();
        for changed in ["name", "uid", "gid", "home"] {
            let mut candidate = account.clone();
            match changed {
                "name" => candidate.name = "dev-auth-fixture-absent-account".into(),
                "uid" => candidate.uid ^= 1,
                "gid" => candidate.gid ^= 1,
                "home" => candidate.home = user.dir.join("unapproved"),
                _ => unreachable!(),
            }
            assert!(
                require_retained_native_accounts(std::iter::once(&candidate)).is_err(),
                "{changed}"
            );
        }
    }

    #[test]
    fn system_asset_restoration_requires_fixed_receipted_root_authority() {
        let assets = crate::setup::linux_system_assets();
        let receipt = assets
            .iter()
            .map(|(path, _, _)| {
                (
                    path.display().to_string(),
                    sha256_hex(b"retained prior asset"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        for (path, candidate, mode) in assets {
            let prior = RetainedSetupObject {
                current: CurrentPathIdentity {
                    kind: "system_integration".into(),
                    subject: path.display().to_string(),
                    path: path.into(),
                    identity: Some(CurrentFileIdentity {
                        object_type: "file".into(),
                        owner_uid: 0,
                        mode,
                        link_count: 1,
                        length: b"retained prior asset".len() as u64,
                        sha256: sha256_hex(b"retained prior asset"),
                        link_target: None,
                    }),
                },
                bytes: Some(b"retained prior asset".to_vec()),
            };
            assert_eq!(
                system_asset_candidate(&prior, &receipt).unwrap(),
                candidate.as_bytes()
            );
            let copy = || RetainedSetupObject {
                current: prior.current.clone(),
                bytes: prior.bytes.clone(),
            };
            let mut changed = copy();
            changed.bytes.as_mut().unwrap().push(b'!');
            assert!(system_asset_candidate(&changed, &receipt).is_err());
            let mut changed = copy();
            changed.current.path = PathBuf::from("/unowned/asset");
            assert!(system_asset_candidate(&changed, &receipt).is_err());
            let mut changed = copy();
            changed.current.identity.as_mut().unwrap().mode = 0o600;
            assert!(system_asset_candidate(&changed, &receipt).is_err());
            let mut changed = copy();
            changed.current.identity.as_mut().unwrap().owner_uid = 1000;
            assert!(system_asset_candidate(&changed, &receipt).is_err());
            let mut changed_receipt = receipt.clone();
            changed_receipt.insert(path.display().to_string(), "a".repeat(64));
            assert!(system_asset_candidate(&prior, &changed_receipt).is_err());
            let mut changed_receipt = receipt.clone();
            changed_receipt.insert("/unowned/asset".into(), "a".repeat(64));
            assert!(system_asset_candidate(&prior, &changed_receipt).is_err());
            let mut changed = copy();
            changed.bytes = None;
            changed.current.identity = None;
            assert!(system_asset_candidate(&changed, &receipt).is_err());
        }
    }

    #[test]
    #[ignore = "requires Linux subordinate UID/GID mappings and unshare"]
    fn native_root_document_restoration_preserves_distinct_account_ownership() {
        if !nix::unistd::Uid::effective().is_root() {
            let arguments = [
                std::ffi::OsString::from("--user"),
                "--map-auto".into(),
                "--map-root-user".into(),
                std::env::current_exe().unwrap().into_os_string(),
                "--exact".into(),
                "setup_v3::restoration::tests::native_root_document_restoration_preserves_distinct_account_ownership".into(),
                "--ignored".into(),
                "--nocapture".into(),
            ];
            let output =
                dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
                    executable: Path::new("/usr/bin/unshare"),
                    arguments: &arguments,
                    environment: &BTreeMap::new(),
                    cwd: None,
                    timeout: std::time::Duration::from_secs(30),
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
        let root = tempfile::tempdir().unwrap();
        for owner in [1000, 1001] {
            let parent = root.path().join(owner.to_string());
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
            nix::unistd::chown(&parent, Some(nix::unistd::Uid::from_raw(owner)), None).unwrap();
            let path = parent.join("config.toml");
            fs::write(&path, b"candidate").unwrap();
            nix::unistd::chown(&path, Some(nix::unistd::Uid::from_raw(owner)), None).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let prior = RetainedSetupObject {
                current: CurrentPathIdentity {
                    kind: "user_configuration".into(),
                    subject: owner.to_string(),
                    path: path.clone(),
                    identity: Some(CurrentFileIdentity {
                        object_type: "file".into(),
                        owner_uid: owner,
                        mode: 0o600,
                        link_count: 1,
                        length: 5,
                        sha256: sha256_hex(b"prior"),
                        link_target: None,
                    }),
                },
                bytes: Some(b"prior".to_vec()),
            };
            let authority = DocumentAuthority {
                owner_uid: owner,
                mode: 0o600,
                limit: 1024,
            };
            let restoration =
                RestorationDocument::new(&prior, Some(b"candidate"), authority).unwrap();
            assert!(restoration.restore().unwrap());
            assert_eq!(fs::read(&path).unwrap(), b"prior");
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert_eq!(metadata.uid(), owner);
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            restoration.verify_restored().unwrap();
            assert!(!restoration.restore().unwrap());
            let wrong = DocumentAuthority {
                owner_uid: 0,
                mode: 0o600,
                limit: 1024,
            };
            assert!(RestorationDocument::new(&prior, Some(b"candidate"), wrong).is_err());
            // Root retirement uses the same retained user directory, without
            // changing its owner or deleting any other account's documents.
            let absent = RetainedSetupObject {
                current: CurrentPathIdentity {
                    identity: None,
                    ..prior.current.clone()
                },
                bytes: None,
            };
            let removal = RestorationDocument::new(
                &absent,
                Some(b"prior"),
                DocumentAuthority {
                    owner_uid: owner,
                    mode: 0o600,
                    limit: 1024,
                },
            )
            .unwrap();
            assert!(removal.restore().unwrap());
            removal.verify_restored().unwrap();
            assert!(!removal.restore().unwrap());
            assert_eq!(fs::metadata(&parent).unwrap().uid(), owner);
        }
    }

    #[test]
    fn restoration_document_restores_prior_private_permissions() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("administrator-policy.toml");
        let owner = fs::metadata(root.path()).unwrap().uid();
        let prior_bytes = b"prior private authority";
        let candidate_bytes = b"candidate public authority";
        let prior = RetainedSetupObject {
            current: CurrentPathIdentity {
                kind: "administrator_policy".into(),
                subject: "system".into(),
                path: path.clone(),
                identity: Some(CurrentFileIdentity {
                    object_type: "file".into(),
                    owner_uid: owner,
                    mode: 0o600,
                    link_count: 1,
                    length: prior_bytes.len() as u64,
                    sha256: sha256_hex(prior_bytes),
                    link_target: None,
                }),
            },
            bytes: Some(prior_bytes.to_vec()),
        };
        fs::write(&path, candidate_bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let restoration = RestorationDocument::new(
            &prior,
            Some(candidate_bytes),
            DocumentAuthority {
                owner_uid: owner,
                mode: 0o644,
                limit: 1024,
            },
        )
        .unwrap();
        assert!(restoration.restore().unwrap());
        assert_eq!(fs::read(&path).unwrap(), prior_bytes);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
        restoration.verify_restored().unwrap();
        assert!(!restoration.restore().unwrap());
        // Neither crossed byte/mode pair is an approved generation.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(restoration.restore().is_err());
        assert_eq!(fs::read(&path).unwrap(), prior_bytes);
        fs::write(&path, candidate_bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(restoration.restore().is_err());
        assert_eq!(fs::read(&path).unwrap(), candidate_bytes);
    }

    #[test]
    fn restoration_document_cannot_be_redirected_after_directory_selection() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("configuration");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let path = parent.join("policy-v3.toml");
        let owner = fs::metadata(&parent).unwrap().uid();
        let prior = RetainedSetupObject {
            current: CurrentPathIdentity {
                kind: "user_policy".into(),
                subject: "fixture".into(),
                path: path.clone(),
                identity: None,
            },
            bytes: Some(b"prior".to_vec()),
        };
        fs::write(&path, b"candidate").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let restoration = RestorationDocument::new(
            &prior,
            Some(b"candidate"),
            DocumentAuthority {
                owner_uid: owner,
                mode: 0o600,
                limit: 1024,
            },
        )
        .unwrap();
        let retained = root.path().join("retained-parent");
        fs::rename(&parent, &retained).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, b"candidate").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(restoration.restore().is_err());
        assert_eq!(fs::read(&path).unwrap(), b"candidate");
        assert_eq!(
            fs::read(retained.join("policy-v3.toml")).unwrap(),
            b"candidate"
        );
    }
}
