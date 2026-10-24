//! Full-generation maintenance with separately retained, value-free credential
//! evidence. This never enrolls credentials or restores a previous policy.
use super::*;
use crate::setup::restoration::RetainedCandidateMaintenance;
use crate::setup_transition::Phase;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Repair,
    Uninstall,
}

impl Operation {
    fn phase(self) -> Phase {
        match self {
            Self::Repair => Phase::Repairing,
            Self::Uninstall => Phase::Uninstalling,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Repair => "repair",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupMaintenanceReportV1 {
    pub schema: String,
    pub operation: String,
    pub changed: Option<bool>,
    pub verified: bool,
    pub next_action: String,
    pub retry_executable: Option<PathBuf>,
    pub error_kind: Option<String>,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    plan_sha256: String,
    operation: Operation,
    credentials: Option<CredentialObservation>,
    preserved_documents: Vec<SelectedDocument>,
    binding_documents: Vec<SelectedDocument>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CredentialObservation {
    ready_slots: BTreeSet<String>,
    action_receipt_sha256: Option<String>,
}

fn observe_credentials(plan: &SetupPlanV3) -> Result<CredentialObservation> {
    Ok(CredentialObservation {
        ready_slots: ready_credential_slots(plan)?,
        action_receipt_sha256: read_atomic_document(
            &credential_action_receipt_path(plan),
            &credential_action_authority(plan)?,
        )?
        .map(|document| document.identity.sha256),
    })
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SelectedDocument {
    path: PathBuf,
    owner_uid: u32,
    mode: u32,
    bytes: Option<Vec<u8>>,
}

impl SelectedDocument {
    fn authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.owner_uid,
            mode: self.mode,
            limit: DOCUMENT_LIMIT,
        }
    }
    fn read(&self) -> Result<Option<dev_tools_installation::AtomicDocument>> {
        read_atomic_document(&self.path, &self.authority())
    }
    fn verify(&self) -> Result<()> {
        if self.read()?.as_ref().map(|doc| doc.bytes.as_slice()) != self.bytes.as_deref() {
            bail!("preserved document changed during maintenance");
        }
        Ok(())
    }
    fn observe_repair(&self) -> Result<()> {
        if self
            .read()?
            .as_ref()
            .is_some_and(|doc| Some(doc.bytes.as_slice()) != self.bytes.as_deref())
        {
            bail!("maintenance document has foreign replacement bytes");
        }
        Ok(())
    }
    fn publish(&self, withdraw: bool) -> Result<bool> {
        self.observe_repair()?;
        let preparation = dev_tools_installation::DocumentDirectoryPreparation::observe(
            self.path
                .parent()
                .context("maintenance document has no parent")?,
            self.owner_uid,
            0o755,
        )?;
        let current = preparation.read(
            self.path
                .file_name()
                .context("maintenance document has no leaf")?,
            &self.authority(),
        )?;
        if withdraw && current.is_none() {
            return match dev_tools_installation::ExistingDocumentDirectory::open(
                self.path
                    .parent()
                    .context("maintenance document has no parent")?,
                self.owner_uid,
            ) {
                Ok(directory) => match &self.bytes {
                    Some(bytes) => directory.remove(
                        self.path
                            .file_name()
                            .context("maintenance document has no leaf")?,
                        &self.authority(),
                        &dev_tools_installation::ArtifactIdentity {
                            length: bytes.len() as u64,
                            sha256: sha256_hex(bytes),
                        },
                    ),
                    None => Ok(false),
                },
                Err(error)
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
                {
                    Ok(false)
                }
                Err(error) => Err(error),
            };
        }
        if !withdraw && current.is_none() && self.bytes.is_none() {
            return Ok(false);
        }
        let (directory, created) = preparation.prepare()?;
        let name = self
            .path
            .file_name()
            .context("maintenance document has no leaf")?;
        let changed = if withdraw {
            match current {
                Some(doc) => directory.remove(name, &self.authority(), &doc.identity)?,
                None => false,
            }
        } else {
            match (&self.bytes, current) {
                (Some(bytes), Some(doc)) => {
                    directory.write(name, bytes, &self.authority(), Some(&doc.identity))?
                }
                (Some(bytes), None) => directory.write(name, bytes, &self.authority(), None)?,
                (None, Some(_)) => bail!("unowned document appeared during maintenance"),
                (None, None) => false,
            }
        };
        Ok(changed || created)
    }
}

pub fn repair_setup_v3(mode: crate::setup::InstallMode) -> SetupMaintenanceReportV1 {
    run(mode, Operation::Repair)
}
pub fn uninstall_setup_v3(mode: crate::setup::InstallMode) -> SetupMaintenanceReportV1 {
    run(mode, Operation::Uninstall)
}

fn run(mode: crate::setup::InstallMode, operation: Operation) -> SetupMaintenanceReportV1 {
    let mut progress = RecoveryProgress::new();
    progress.next_action = if operation == Operation::Repair {
        "retry_setup_repair"
    } else {
        "retry_setup_uninstall"
    };
    let mut retry_executable = None;
    let result = inner(mode, operation, &mut progress, &mut retry_executable);
    let report = progress.report(result);
    SetupMaintenanceReportV1 {
        schema: "dev-auth-setup-maintenance-report-v1".into(),
        operation: operation.name().into(),
        changed: report.changed,
        verified: report.verified,
        next_action: report.next_action,
        retry_executable,
        error_kind: report.error_kind.map(|kind| {
            match kind {
                SetupRecoveryFailure::Authority => "setup_maintenance_authority",
                SetupRecoveryFailure::Blocked => "setup_maintenance_blocked",
                SetupRecoveryFailure::InvalidInput => "setup_maintenance_input",
                SetupRecoveryFailure::Operational => "setup_maintenance_failed",
            }
            .into()
        }),
        exit_code: report.exit_code,
    }
}

fn inner(
    mode: crate::setup::InstallMode,
    operation: Operation,
    progress: &mut RecoveryProgress,
    retry: &mut Option<PathBuf>,
) -> Result<SetupApplyReportV3> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("maintenance native account is absent")?;
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
            progress.blocked("run_as_installation_owner");
            bail!("maintenance requires the native installation owner");
        }
    };
    let lock = crate::setup_transition::lock_path(
        deployment_mode,
        (deployment_mode == DeploymentMode::UserOnly).then_some(owner),
    )?;
    let Some(_lease) = InstallationLock::try_acquire(&lock)? else {
        progress.blocked("wait_for_active_workloads_or_setup");
        bail!("maintenance requires exclusive setup ownership");
    };
    crate::setup::require_strong_maintenance_quiescence(&paths, mode).inspect_err(|_| {
        progress.blocked("wait_for_maintenance_cleanup");
    })?;
    let transition = crate::setup_transition::retained_transition(&paths, owner)?
        .context("maintenance requires retained setup authority")?;
    if !(transition.phase == Phase::Accepted
        || transition.phase == operation.phase()
        || (operation == Operation::Uninstall && transition.phase == Phase::UninstalledInactive))
    {
        progress.blocked("finish_existing_setup_direction");
        bail!("another retained setup direction excludes maintenance");
    }
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
    let plan = &generation.plan;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != transition.plan_sha256
        || sha256_hex(&serde_jcs::to_vec(plan)?) != transition.plan_sha256
        || plan.installation.paths != paths
        || plan.intent.mode != deployment_mode
        || plan.installation.request.mode != mode
    {
        bail!("maintenance generation does not match its native authority");
    }
    require_apply_identity(plan)?;
    restoration::require_retained_native_accounts(
        plan.accounts.iter().chain(&plan.retiring_accounts),
    )?;
    if deployment_mode == DeploymentMode::UserOnly
        && plan.accounts
            != [NativeAccountIdentity {
                name: user.name,
                uid: owner,
                gid: user.gid.as_raw(),
                home: user.dir,
            }]
    {
        bail!("maintenance native account identity changed");
    }
    validate_candidate_inventory(plan, &generation.candidate_documents)?;
    *retry = Some(paths.versioned_binary(&plan.installation.request.version));
    if crate::setup::setup_executable_identity(&std::env::current_exe()?)?
        != (
            plan.installation.source_length,
            plan.installation.source_sha256.clone(),
        )
    {
        progress.blocked("run_retained_candidate_for_maintenance");
        bail!("maintenance requires the exact retained candidate");
    }
    validate_setup_plan_v3_with_installation_check(plan, &|_| Ok(()))?;
    if deployment_mode == DeploymentMode::UserOnly {
        crate::setup::require_user_sessions_absent()?;
    }
    let prior = retained_installation_receipts(&generation)?;
    let prior_mode = restoration::retained_object(&generation, "installation_receipt", "system")?
        .current
        .identity
        .as_ref()
        .map(|identity| identity.mode);
    let core = RetainedCandidateMaintenance::new(
        &plan.installation,
        prior.as_ref().map(|(product, shared)| {
            (
                product,
                shared,
                prior_mode.unwrap_or(if mode == crate::setup::InstallMode::Strong {
                    0o644
                } else {
                    0o600
                }),
            )
        }),
    )?;
    let config = configuration_documents(&generation)?;
    let component = plan
        .intent
        .has_grants()
        .then(|| grants::maintenance::ComponentMaintenance::new(&generation))
        .transpose()?;
    if operation == Operation::Repair
        && transition.phase == Phase::Accepted
        && postcondition_satisfied(
            plan,
            &transition.plan_sha256,
            &generation.candidate_documents,
        )
    {
        return Ok(completed(false, "none"));
    }
    let snapshot = match &transition.maintenance_bytes {
        Some(bytes) => serde_json::from_slice::<Snapshot>(bytes)?,
        None => capture(&generation, operation, &config)?,
    };
    validate_snapshot(&snapshot, &generation, operation)?;
    verify_preservation(&snapshot, plan)?;
    let assets = enforcement_documents(plan)?;
    if operation == Operation::Uninstall && transition.phase == Phase::UninstalledInactive {
        core.verify_withdrawn()?;
        restoration::verify_user_integrations_retired(&generation, core.executable())?;
        for doc in &snapshot.binding_documents {
            if doc.read()?.is_some() {
                bail!("withdrawn binding receipt reappeared");
            }
        }
        verify_absent_documents(&assets)?;
        if let Some(component) = &component {
            component.verify_withdrawn()?;
        }
        return Ok(completed(false, "create_setup_plan"));
    }
    core.observe()?;
    core.observe_shutdown()?;
    if operation == Operation::Repair {
        revalidate_candidate_documents(
            plan,
            &|candidate| {
                if candidate != &plan.installation {
                    bail!("maintenance cannot validate another installation");
                }
                Ok(())
            },
            &generation.candidate_documents,
            BindingSourceCheck::RetainedAccepted,
        )?;
        verify_binding_payloads(plan, &snapshot.binding_documents, core.receipt())?;
    }
    restoration::observe_user_integrations(&generation, core.executable())?;
    for doc in &snapshot.binding_documents {
        doc.observe_repair()?;
    }
    if operation == Operation::Repair {
        for doc in &config {
            doc.observe_repair()?;
        }
    }
    if let Some(component) = &component {
        component.observe(operation == Operation::Uninstall)?;
        component.observe_shutdown(operation == Operation::Uninstall)?;
    }
    for doc in &assets {
        doc.observe_repair()?;
    }
    let encoded = serde_jcs::to_vec(&snapshot)?;
    progress.enter_mutation();
    progress.next_action = if operation == Operation::Repair {
        "retry_setup_repair"
    } else {
        "retry_setup_uninstall"
    };
    progress.record_change(crate::setup_transition::begin_maintenance(
        &paths,
        owner,
        &transition.plan_sha256,
        operation.phase(),
        || Ok(encoded),
    )?);
    if let Some(component) = &component {
        progress.record_change(component.stop(operation == Operation::Uninstall)?);
    }
    // Active grants hold short admission leases; stop precedes kernel emptiness.
    if mode == crate::setup::InstallMode::Strong {
        crate::setup::restoration::require_grant_domain_empty()?;
    }
    progress.record_change(core.deactivate_and_stop()?);
    progress.record_change(restoration::retire_user_integrations(
        &generation,
        core.executable(),
    )?);
    verify_preservation(&snapshot, plan)?;
    if operation == Operation::Repair {
        progress.record_change(core.repair()?);
        for doc in &config {
            progress.record_change(doc.publish(false)?);
        }
        // Binding publication uses the same retained approved plans and intact
        // copied artifacts. Missing copied payloads cannot be rediscovered.
        progress.record_change(activate_retained_candidate(
            plan,
            &snapshot.binding_documents,
        )?);
        if let Some(component) = &component {
            progress.record_change(component.repair(plan)?);
        }
        verify_preservation(&snapshot, plan)?;
        verify_postcondition(
            plan,
            &transition.plan_sha256,
            &generation.candidate_documents,
        )?;
        progress.record_change(crate::setup_transition::advance(
            &paths,
            owner,
            &transition.plan_sha256,
            Phase::Accepted,
        )?);
        return Ok(completed(false, "none"));
    }
    if let Some(component) = &component {
        progress.record_change(component.withdraw()?);
    }
    for doc in &snapshot.binding_documents {
        progress.record_change(doc.publish(true)?);
    }
    for doc in &assets {
        progress.record_change(doc.publish(true)?);
    }
    progress.record_change(core.withdraw()?);
    core.verify_withdrawn()?;
    restoration::verify_user_integrations_retired(&generation, core.executable())?;
    verify_absent_documents(&snapshot.binding_documents)?;
    verify_absent_documents(&assets)?;
    verify_preservation(&snapshot, plan)?;
    progress.record_change(crate::setup_transition::advance(
        &paths,
        owner,
        &transition.plan_sha256,
        Phase::UninstalledInactive,
    )?);
    Ok(completed(false, "create_setup_plan"))
}

fn verify_absent_documents(documents: &[SelectedDocument]) -> Result<()> {
    for document in documents {
        if document.read()?.is_some() {
            bail!("retired maintenance document reappeared");
        }
    }
    Ok(())
}

fn activate_retained_candidate(plan: &SetupPlanV3, documents: &[SelectedDocument]) -> Result<bool> {
    let installation = crate::setup::read_install_receipt_at(&plan.installation.paths)?
        .context("repaired installation receipt is absent")?;
    let bindings = verify_binding_payloads(plan, documents, &installation)?;
    let mut changed = false;
    for document in documents {
        changed |= document.publish(false)?;
    }
    if plan.intent.mode == DeploymentMode::Strong && broker_desired(&plan.intent) {
        crate::setup::start_system_broker_at(&plan.installation.paths)?;
    }
    if plan.intent.activation == Activation::Transparent {
        for account in &plan.accounts {
            let workloads = resolved_workloads_for_account(plan, account)?;
            let intents = bindings
                .get(&account.name)
                .map(|set| {
                    set.bindings
                        .iter()
                        .map(|(alias, binding)| (alias.clone(), binding.active.intent.clone()))
                        .collect::<BTreeMap<_, _>>()
                })
                .unwrap_or_default();
            let mut aliases = workloads
                .keys()
                .chain(intents.keys())
                .cloned()
                .collect::<Vec<_>>();
            aliases.sort();
            aliases.dedup();
            crate::setup::reconcile_workload_launchers_at(
                &account.home,
                Path::new(&installation.executable),
                &aliases,
                account.uid,
            )?;
            crate::setup::reconcile_desktop_entries_at(
                &account.home,
                &desktop_workloads_with_bindings(&workloads, &intents)?,
                account.uid,
            )?;
        }
        crate::setup::activate_transparent_launchers_at(&plan.installation.paths)?;
    }
    Ok(changed)
}

fn verify_binding_payloads(
    plan: &SetupPlanV3,
    documents: &[SelectedDocument],
    installation: &crate::setup::InstallReceipt,
) -> Result<BTreeMap<String, crate::binding_activation::BindingSetReceipt>> {
    let mut bindings = BTreeMap::new();
    // Verify every payload before publishing even the first account receipt.
    for document in documents {
        let Some(bytes) = &document.bytes else {
            continue;
        };
        let set: crate::binding_activation::BindingSetReceipt = serde_json::from_slice(bytes)?;
        let account = plan
            .accounts
            .iter()
            .find(|account| account.uid == set.account_uid)
            .context("retained binding account is absent")?;
        crate::binding_activation::validate(&set, account.uid, installation)?;
        for (alias, binding) in &set.bindings {
            if set.pinned_artifacts.contains_key(alias) {
                crate::binding_activation::verify_pinned_artifact(account.uid, alias, binding)?;
            }
            if crate::smart_binding::is_pinned_shell_resolution(&binding.active.resolved) {
                crate::binding_activation::verify_shell_payload(
                    plan.installation.request.mode,
                    &account.home,
                    account.uid,
                    alias,
                    binding,
                )?;
            }
        }
        bindings.insert(account.name.clone(), set);
    }
    Ok(bindings)
}

fn completed(changed: bool, next: &str) -> SetupApplyReportV3 {
    SetupApplyReportV3 {
        schema: "dev-auth-setup-maintenance-report-v1".into(),
        changed,
        verified: true,
        input_required: Vec::new(),
        blocked: Vec::new(),
        next_action: next.into(),
        actions: Vec::new(),
    }
}

fn capture(
    generation: &RetainedSetupGeneration,
    operation: Operation,
    config: &[SelectedDocument],
) -> Result<Snapshot> {
    let plan = &generation.plan;
    let credentials = if plan.intent.purpose.is_credentials() {
        if operation == Operation::Repair {
            verify_credential_postcondition(plan, &generation.plan_sha256)?;
        }
        Some(observe_credentials(plan)?)
    } else {
        None
    };
    let mut preserved_documents = Vec::new();
    for doc in config {
        let mut preserved = doc.clone();
        preserved.bytes = doc.read()?.map(|current| current.bytes);
        preserved_documents.push(preserved);
    }
    Ok(Snapshot {
        schema: "dev-auth-setup-maintenance-generation-v1".into(),
        plan_sha256: generation.plan_sha256.clone(),
        operation,
        credentials,
        preserved_documents,
        binding_documents: binding_documents(generation)?,
    })
}

fn validate_snapshot(
    snapshot: &Snapshot,
    generation: &RetainedSetupGeneration,
    operation: Operation,
) -> Result<()> {
    if snapshot.schema != "dev-auth-setup-maintenance-generation-v1"
        || snapshot.plan_sha256 != generation.plan_sha256
        || snapshot.operation != operation
        || snapshot.credentials.is_some() != generation.plan.intent.purpose.is_credentials()
    {
        bail!("retained maintenance snapshot has incompatible authority");
    }
    let expected = configuration_documents(generation)?;
    if snapshot.preserved_documents.len() != expected.len()
        || snapshot
            .preserved_documents
            .iter()
            .zip(&expected)
            .any(|(actual, expected)| {
                actual.path != expected.path
                    || actual.owner_uid != expected.owner_uid
                    || actual.mode != expected.mode
            })
    {
        bail!("retained maintenance document inventory changed");
    }
    if snapshot.binding_documents != binding_documents(generation)? {
        bail!("retained maintenance binding authority changed");
    }
    Ok(())
}

fn verify_preservation(snapshot: &Snapshot, plan: &SetupPlanV3) -> Result<()> {
    if let Some(expected) = &snapshot.credentials {
        if observe_credentials(plan)? != *expected {
            bail!("credential state changed during maintenance");
        }
    }
    if snapshot.operation == Operation::Uninstall {
        for doc in &snapshot.preserved_documents {
            doc.verify()?;
        }
    }
    Ok(())
}

fn configuration_documents(generation: &RetainedSetupGeneration) -> Result<Vec<SelectedDocument>> {
    let plan = &generation.plan;
    let mut docs = Vec::new();
    for current in &plan.current_paths {
        if !matches!(
            current.kind.as_str(),
            "administrator_policy"
                | "user_policy"
                | "user_configuration"
                | "retained_user_policy"
                | "retained_user_configuration"
                | "retiring_user_configuration_v2"
                | "retiring_user_configuration_v3"
                | "maintenance_policy"
                | "grant_policy"
        ) {
            continue;
        }
        let account = plan
            .accounts
            .iter()
            .chain(&plan.retiring_accounts)
            .find(|account| account.name == current.subject);
        let owner = account.map_or(0, |account| account.uid);
        let mode = if current.kind == "administrator_policy" || current.kind == "maintenance_policy"
        {
            0o644
        } else {
            0o600
        };
        let candidate = plan
            .source_documents
            .iter()
            .find(|doc| doc.kind == current.kind && doc.subject == current.subject)
            .or_else(|| {
                (current.kind == "user_policy")
                    .then(|| {
                        plan.source_documents.iter().find(|doc| {
                            doc.kind == "administrator_policy" && doc.subject == "system"
                        })
                    })
                    .flatten()
            });
        let bytes = match candidate {
            Some(identity) => {
                Some(candidate_bytes(&generation.candidate_documents, identity)?.to_vec())
            }
            None => restoration::retained_object(generation, &current.kind, &current.subject)?
                .bytes
                .clone(),
        };
        docs.push(SelectedDocument {
            path: current.path.clone(),
            owner_uid: owner,
            mode,
            bytes,
        });
    }
    Ok(docs)
}

fn enforcement_documents(plan: &SetupPlanV3) -> Result<Vec<SelectedDocument>> {
    if plan.intent.mode != DeploymentMode::Strong {
        return Ok(Vec::new());
    }
    let mut docs = crate::setup::linux_system_assets()
        .into_iter()
        .map(|(path, bytes, mode)| SelectedDocument {
            path: path.to_path_buf(),
            owner_uid: 0,
            mode,
            bytes: Some(bytes.as_bytes().to_vec()),
        })
        .collect::<Vec<_>>();
    if crate::setup::maintenance::supports_version(&plan.installation.request.version) {
        docs.push(SelectedDocument {
            path: crate::setup::maintenance::POLKIT_PATH.into(),
            owner_uid: 0,
            mode: 0o644,
            bytes: Some(crate::setup::maintenance::POLKIT.as_bytes().to_vec()),
        });
        // Exact sidecar bytes derive from candidate installation provenance.
        let transition = crate::setup_transition::retained_transition(&plan.installation.paths, 0)?
            .context("maintenance sidecar has no retained generation")?;
        let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
        let prior = retained_installation_receipts(&generation)?.map(|(receipt, _)| receipt);
        docs.push(SelectedDocument {
            path: crate::setup::maintenance::RECEIPT_PATH.into(),
            owner_uid: 0,
            mode: 0o644,
            bytes: Some(crate::setup::maintenance::candidate_sidecar(
                &plan.installation,
                prior.as_ref(),
            )?),
        });
    }
    Ok(docs)
}

fn binding_documents(generation: &RetainedSetupGeneration) -> Result<Vec<SelectedDocument>> {
    let plan = &generation.plan;
    if plan.intent.schema != "dev-auth-deployment-intent-v3" {
        return Ok(Vec::new());
    }
    let prior_installation =
        retained_installation_receipts(generation)?.map(|(receipt, _)| receipt);
    let mut docs = Vec::new();
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        let prior = restoration::retained_object(generation, "binding_set_receipt", &account.name)?;
        let prior_set = prior
            .bytes
            .as_ref()
            .map(|bytes| {
                serde_json::from_slice::<crate::binding_activation::BindingSetReceipt>(bytes)
            })
            .transpose()?;
        let plans = plan
            .intent
            .bindings
            .iter()
            .filter(|binding| binding.user == account.name)
            .map(|binding| {
                let identity = document_identity(
                    plan,
                    "binding_plan",
                    &format!("{}/{}", binding.user, binding.name),
                )?;
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
            &plan
                .installation
                .paths
                .versioned_binary(&plan.installation.request.version),
            &plan.installation.source_sha256,
            prior_set.as_ref().zip(prior_installation.as_ref()),
            &plans,
        )?;
        let authority =
            crate::binding_activation::authority(plan.installation.request.mode, account.uid);
        docs.push(SelectedDocument {
            path: prior.current.path.clone(),
            owner_uid: authority.owner_uid,
            mode: authority.mode,
            bytes: (!expected.bindings.is_empty())
                .then(|| serde_jcs::to_vec(&expected))
                .transpose()?,
        });
    }
    Ok(docs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn retained_document_repair_and_retirement_preserve_foreign_replacements() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let selected = SelectedDocument {
            path: root.path().join("policy"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
            mode: 0o600,
            bytes: Some(b"accepted policy".to_vec()),
        };
        assert!(selected.publish(false).unwrap());
        assert!(!selected.publish(false).unwrap());
        let mut foreign = selected.clone();
        foreign.bytes = Some(b"independent policy".to_vec());
        let current = selected.read().unwrap().unwrap();
        write_atomic_document(
            &selected.path,
            foreign.bytes.as_deref().unwrap(),
            &selected.authority(),
            Some(&current.identity),
        )
        .unwrap();
        assert!(selected.publish(false).is_err());
        assert!(selected.publish(true).is_err());
        foreign.verify().unwrap();
        assert!(foreign.publish(true).unwrap());
        assert!(!foreign.publish(true).unwrap());
        assert!(!selected.path.exists());
    }
}
