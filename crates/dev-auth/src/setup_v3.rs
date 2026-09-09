use crate::credential_input::{
    load_credential_inputs, CredentialInputContext, CredentialInputSource, CredentialMaterial,
};
use crate::deployment::{
    canonical_deployment_intent, Activation, CredentialIntent, DeploymentCredential,
    DeploymentIntent, DeploymentMode,
};
use crate::policy_v2::SystemMode;
use crate::runtime_policy::{parse_runtime_administrator, RuntimeAdministrator};
use crate::setup::{render_plan, SetupPlan};
use anyhow::{bail, Context, Result};
use dev_tools_installation::{
    read_atomic_document, write_atomic_document, DocumentAuthority, InstallationLock,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const DOCUMENT_LIMIT: u64 = 1024 * 1024;
const CURRENT_OBJECT_LIMIT: u64 = 256 * 1024 * 1024;

#[cfg(all(test, target_os = "linux"))]
mod recovery_native;

#[cfg(target_os = "linux")]
mod restoration;
#[cfg(target_os = "linux")]
pub use restoration::{restore_setup_v3, SetupRestorationReportV1};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DocumentIdentity {
    pub kind: String,
    pub subject: String,
    pub path: PathBuf,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeAccountIdentity {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentFileIdentity {
    pub object_type: String,
    pub owner_uid: u32,
    pub mode: u32,
    pub link_count: u64,
    pub length: u64,
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_target: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CurrentPathIdentity {
    pub kind: String,
    pub subject: String,
    pub path: PathBuf,
    pub identity: Option<CurrentFileIdentity>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupActionV3 {
    pub order: u32,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupPlanV3 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_schema: Option<String>,
    pub schema: String,
    pub intent: DeploymentIntent,
    pub intent_sha256: String,
    pub installation: SetupPlan,
    pub source_documents: Vec<DocumentIdentity>,
    pub accounts: Vec<NativeAccountIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub retiring_accounts: Vec<NativeAccountIdentity>,
    pub current_paths: Vec<CurrentPathIdentity>,
    pub current_credential_ready: BTreeSet<String>,
    pub current_broker_state: String,
    pub current_state_sha256: String,
    pub actions: Vec<SetupActionV3>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequirements {
    pub required: BTreeSet<String>,
    pub blocked: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupApplyReportV3 {
    pub schema: String,
    pub changed: bool,
    pub verified: bool,
    pub input_required: Vec<String>,
    pub blocked: Vec<String>,
    pub next_action: String,
    pub actions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum SetupRecoveryFailure {
    #[serde(rename = "setup_recovery_authority")]
    Authority,
    #[serde(rename = "setup_recovery_blocked")]
    Blocked,
    #[serde(rename = "setup_recovery_input")]
    InvalidInput,
    #[serde(rename = "setup_recovery_failed")]
    Operational,
}

impl SetupRecoveryFailure {
    fn exit_code(self) -> i32 {
        match self {
            Self::Authority => 4,
            Self::Blocked => 3,
            Self::InvalidInput => 2,
            Self::Operational => 1,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupRecoveryReportV1 {
    pub schema: String,
    pub changed: Option<bool>,
    pub verified: bool,
    pub input_required: Vec<String>,
    pub blocked: Vec<String>,
    pub next_action: String,
    pub actions: Vec<String>,
    pub error_kind: Option<SetupRecoveryFailure>,
    pub exit_code: i32,
}

struct RecoveryProgress {
    entered_mutation: bool,
    established_change: bool,
    failure: SetupRecoveryFailure,
    next_action: &'static str,
}

impl RecoveryProgress {
    fn new() -> Self {
        Self {
            entered_mutation: false,
            established_change: false,
            failure: SetupRecoveryFailure::Authority,
            next_action: "inspect_setup_authority",
        }
    }

    fn blocked(&mut self, next_action: &'static str) {
        self.failure = SetupRecoveryFailure::Blocked;
        self.next_action = next_action;
    }

    fn enter_mutation(&mut self) {
        self.entered_mutation = true;
        self.failure = SetupRecoveryFailure::Operational;
        self.next_action = "retry_setup_recovery";
    }

    fn record_change(&mut self, changed: bool) {
        self.established_change |= changed;
    }

    fn report(self, outcome: Result<SetupApplyReportV3>) -> SetupRecoveryReportV1 {
        match outcome {
            Ok(report) => SetupRecoveryReportV1 {
                schema: "dev-auth-setup-recover-v1".into(),
                changed: Some(report.changed || self.established_change),
                verified: report.verified,
                input_required: report.input_required,
                blocked: report.blocked,
                next_action: report.next_action,
                actions: report.actions,
                error_kind: None,
                exit_code: if report.verified { 0 } else { 3 },
            },
            Err(_) => SetupRecoveryReportV1 {
                schema: "dev-auth-setup-recover-v1".into(),
                changed: if self.established_change {
                    Some(true)
                } else if self.entered_mutation {
                    None
                } else {
                    Some(false)
                },
                verified: false,
                input_required: Vec::new(),
                blocked: Vec::new(),
                next_action: self.next_action.into(),
                actions: Vec::new(),
                error_kind: Some(self.failure),
                exit_code: self.failure.exit_code(),
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CredentialActionReceipt {
    schema: String,
    action_set_sha256: String,
    completed: BTreeSet<String>,
}

pub fn credential_requirements(
    credentials: &[DeploymentCredential],
    ready_slots: &BTreeSet<String>,
) -> CredentialRequirements {
    let mut required = BTreeSet::new();
    let mut blocked = Vec::new();
    for credential in credentials {
        match credential.intent {
            CredentialIntent::Preserve if !ready_slots.contains(&credential.slot) => {
                blocked.push(credential.slot.clone());
            }
            CredentialIntent::EnrollIfAbsent if !ready_slots.contains(&credential.slot) => {
                required.insert(credential.slot.clone());
            }
            CredentialIntent::Rotate => {
                required.insert(credential.slot.clone());
            }
            CredentialIntent::Preserve
            | CredentialIntent::EnrollIfAbsent
            | CredentialIntent::Revoke => {}
        }
    }
    CredentialRequirements { required, blocked }
}

pub fn required_credential_slots_for_plan(plan: &SetupPlanV3) -> Result<CredentialRequirements> {
    validate_setup_plan_v3(plan)?;
    requirements_for_validated_plan(plan)
}

fn requirements_for_validated_plan(plan: &SetupPlanV3) -> Result<CredentialRequirements> {
    let ready = ready_credential_slots(plan)?;
    let mut requirements = credential_requirements(&plan.intent.credentials, &ready);
    let action_set_sha256 = credential_action_set_sha256(&plan.intent)?;
    let completed = read_credential_action_receipt(plan, &action_set_sha256)?;
    requirements.required.retain(|slot| {
        let intent = plan
            .intent
            .credentials
            .iter()
            .find(|credential| &credential.slot == slot)
            .map(|credential| credential.intent);
        intent != Some(CredentialIntent::Rotate) || !completed.contains(slot)
    });
    Ok(requirements)
}

pub fn apply_setup_plan_v3(
    plan: &SetupPlanV3,
    approved_sha256: &str,
    credentials: &BTreeMap<String, CredentialMaterial>,
) -> Result<SetupApplyReportV3> {
    let declared = declared_credential_slots(plan);
    if credentials.keys().any(|slot| !declared.contains(slot)) {
        bail!("credential material names a slot outside the approved setup plan");
    }
    apply_setup_plan_v3_with_loader(plan, approved_sha256, |_, _| {
        Ok(LoadedCredentialMaterials::Borrowed(credentials))
    })
}

pub fn apply_setup_plan_v3_from_sources(
    plan: &SetupPlanV3,
    approved_sha256: &str,
    sources: &BTreeMap<String, CredentialInputSource>,
    context: &CredentialInputContext,
    stdin: &mut dyn Read,
) -> Result<SetupApplyReportV3> {
    let declared = declared_credential_slots(plan);
    if sources.keys().any(|slot| !declared.contains(slot)) {
        bail!("credential input names a slot outside the approved setup plan");
    }
    apply_setup_plan_v3_with_loader(plan, approved_sha256, |declared, required| {
        load_credential_inputs(declared, required, sources, context, stdin)
            .map(LoadedCredentialMaterials::Owned)
    })
}

/// Resume an already-owned setup using the approved candidate and private
/// transition authority. This never discovers or installs a new release.
pub fn recover_setup_v3(
    mode: crate::setup::InstallMode,
    sources: &BTreeMap<String, CredentialInputSource>,
    stdin: &mut dyn Read,
) -> SetupRecoveryReportV1 {
    let mut progress = RecoveryProgress::new();
    let outcome = recover_setup_v3_inner(mode, sources, stdin, &mut progress);
    progress.report(outcome)
}

fn recover_setup_v3_inner(
    mode: crate::setup::InstallMode,
    sources: &BTreeMap<String, CredentialInputSource>,
    stdin: &mut dyn Read,
    progress: &mut RecoveryProgress,
) -> Result<SetupApplyReportV3> {
    if !cfg!(target_os = "linux") {
        progress.blocked("native_recovery_backend_required");
        bail!("setup recovery requires a qualified native observation backend");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("setup recovery native account is absent")?;
    let (paths, owner_uid, deployment_mode) = match mode {
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
            bail!("setup recovery requires the installation's native owner");
        }
    };
    let lock = crate::setup_transition::lock_path(
        deployment_mode,
        (deployment_mode == DeploymentMode::UserOnly).then_some(owner_uid),
    )?;
    let Some(_lease) = InstallationLock::try_acquire(&lock)? else {
        progress.blocked("wait_for_active_workloads_or_setup");
        bail!("setup recovery requires active workloads and other setup operations to finish");
    };
    let Some(transition) = crate::setup_transition::retained_transition(&paths, owner_uid)? else {
        progress.blocked("create_setup_plan");
        bail!("setup recovery requires a retained setup transition");
    };
    let generation: RetainedSetupGeneration =
        serde_json::from_slice(&transition.bytes).context("parse retained setup generation")?;
    let plan = &generation.plan;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != transition.plan_sha256
        || sha256_hex(&serde_jcs::to_vec(plan)?) != transition.plan_sha256
        || plan.installation.paths != paths
        || plan.intent.mode != deployment_mode
        || plan.installation.request.mode != mode
    {
        bail!("retained setup does not match its native transition authority");
    }
    require_apply_identity(plan)?;
    if matches!(
        transition.phase,
        crate::setup_transition::Phase::Restoring
            | crate::setup_transition::Phase::RestoredInactive
    ) {
        progress.blocked(
            if transition.phase == crate::setup_transition::Phase::Restoring {
                "finish_setup_restoration"
            } else {
                "create_setup_plan"
            },
        );
        bail!("setup restoration cannot resume forward");
    }
    let prior_installation = retained_installation_receipts(&generation)?;
    let running_candidate = std::env::current_exe()?;
    let (running_length, running_sha256) =
        crate::setup::setup_executable_identity(&running_candidate)?;
    if running_length != plan.installation.source_length
        || running_sha256 != plan.installation.source_sha256
    {
        bail!("setup recovery must run from the exact approved candidate");
    }
    let installed = crate::setup::retained_candidate_validation_from_source(
        &plan.installation,
        prior_installation
            .as_ref()
            .map(|(receipt, shared)| (receipt, shared)),
        Some(&running_candidate),
    )?;
    let validate_installed = |installation: &SetupPlan| installed.validate(installation);
    validate_setup_plan_v3_with_installation_check(plan, &validate_installed)?;
    revalidate_candidate_documents(plan, &validate_installed, &generation.candidate_documents)?;
    let declared = declared_credential_slots(plan);
    if sources.keys().any(|slot| !declared.contains(slot)) {
        progress.failure = SetupRecoveryFailure::InvalidInput;
        progress.next_action = "correct_credential_input";
        bail!("credential input names a slot outside the retained setup plan");
    }
    let before = deployment_state_fingerprint(plan)?;
    if postcondition_satisfied(
        plan,
        &transition.plan_sha256,
        &generation.candidate_documents,
    ) {
        progress.enter_mutation();
        let changed = crate::setup_transition::accept(&paths, owner_uid, &transition.plan_sha256)?;
        return Ok(SetupApplyReportV3 {
            schema: "dev-auth-setup-recover-v1".into(),
            changed,
            verified: true,
            input_required: Vec::new(),
            blocked: Vec::new(),
            next_action: "none".into(),
            actions: Vec::new(),
        });
    }
    if transition.phase != crate::setup_transition::Phase::Pending {
        progress.blocked("repair_setup");
        bail!("accepted setup no longer satisfies its retained authority; explicit repair is required");
    }
    if deployment_mode == DeploymentMode::UserOnly {
        crate::setup::require_user_sessions_absent()?;
    }
    progress.enter_mutation();
    crate::setup_transition::begin(&paths, owner_uid, &transition.plan_sha256, || {
        bail!("setup recovery cannot initialize a transition")
    })?;
    let mut actions = Vec::new();
    let binary_changed =
        installed.finish_binary_transition(|changed| progress.record_change(changed))?;
    if binary_changed {
        actions.push(installed.binary_recovery_action().into());
    }
    let integrations_changed = deactivate_and_stop_candidate(plan, &mut actions)?;
    progress.record_change(integrations_changed);
    let mut allowed_owner_uids = plan
        .accounts
        .iter()
        .map(|account| account.uid)
        .collect::<BTreeSet<_>>();
    allowed_owner_uids.insert(owner_uid);
    let context = CredentialInputContext {
        mode: deployment_mode,
        allowed_owner_uids,
    };
    let mut report = finish_setup_candidate(
        plan,
        &transition.plan_sha256,
        &generation.candidate_documents,
        |declared, required| {
            load_credential_inputs(declared, required, sources, &context, stdin)
                .map(LoadedCredentialMaterials::Owned)
        },
        before,
        actions,
    )?;
    report.changed |= integrations_changed || binary_changed;
    report.schema = "dev-auth-setup-recover-v1".into();
    Ok(report)
}

#[cfg(target_os = "linux")]
fn retained_installation_receipts(
    generation: &RetainedSetupGeneration,
) -> Result<
    Option<(
        crate::setup::InstallReceipt,
        dev_tools_installation::VersionedReceipt,
    )>,
> {
    let plan = &generation.plan;
    let owner_uid = apply_owner_uid(plan)?;
    let receipt = restoration::retained_object(generation, "installation_receipt", "system")?;
    let shared = restoration::retained_object(generation, "shared_installation_receipt", "system")?;
    for (object, path) in [
        (
            receipt,
            plan.installation.paths.data_root.join("install-v2.json"),
        ),
        (
            shared,
            plan.installation
                .paths
                .data_root
                .join("installation-receipt-v1.json"),
        ),
    ] {
        if object.current.path != path
            || object.current.identity.as_ref().is_some_and(|identity| {
                identity.owner_uid != owner_uid
                    || !(identity.mode == 0o600
                        || (object.current.kind == "installation_receipt"
                            && plan.intent.mode == DeploymentMode::Strong
                            && identity.mode == 0o644))
            })
        {
            bail!("retained binary receipt has incompatible native authority");
        }
    }
    match (&receipt.bytes, &shared.bytes) {
        (None, None) => Ok(None),
        (Some(receipt), Some(shared)) => Ok(Some((
            serde_json::from_slice(receipt)?,
            serde_json::from_slice(shared)?,
        ))),
        _ => bail!("retained binary recovery requires paired installation receipts"),
    }
}

#[cfg(not(target_os = "linux"))]
fn retained_installation_receipts(
    _generation: &RetainedSetupGeneration,
) -> Result<
    Option<(
        crate::setup::InstallReceipt,
        dev_tools_installation::VersionedReceipt,
    )>,
> {
    bail!("retained binary receipt observation requires a native Linux backend")
}

fn apply_setup_plan_v3_with_loader<'a, F>(
    plan: &SetupPlanV3,
    approved_sha256: &str,
    load_credentials: F,
) -> Result<SetupApplyReportV3>
where
    F: FnOnce(&BTreeSet<String>, &BTreeSet<String>) -> Result<LoadedCredentialMaterials<'a>>,
{
    let (_, digest) = render_setup_plan_v3(plan)?;
    if digest != approved_sha256.to_ascii_lowercase() {
        bail!("setup plan v3 does not match the approved digest");
    }
    require_apply_identity(plan)?;
    let _deployment_lock = InstallationLock::try_acquire(&deployment_lock_path(plan)?)
        .context("acquire full setup transaction lock")?
        .context("setup requires active workloads and other setup operations to finish")?;
    let documents = revalidate_public_plan_inputs(plan)?;
    let before = deployment_state_fingerprint(plan)?;
    let requires_new_transition = crate::setup_transition::retained_transition(
        &plan.installation.paths,
        apply_owner_uid(plan)?,
    )?
    .is_some_and(|transition| transition.phase == crate::setup_transition::Phase::RestoredInactive);
    if !requires_new_transition && postcondition_satisfied(plan, &digest, &documents) {
        let changed = crate::setup_transition::settle_verified(
            &plan.installation.paths,
            apply_owner_uid(plan)?,
            &digest,
        )?;
        return Ok(SetupApplyReportV3 {
            schema: "dev-auth-setup-apply-v3".into(),
            changed,
            verified: true,
            input_required: Vec::new(),
            blocked: Vec::new(),
            next_action: "none".into(),
            actions: Vec::new(),
        });
    }
    if !crate::setup_transition::resumable(
        &plan.installation.paths,
        apply_owner_uid(plan)?,
        &digest,
    )? {
        require_initial_or_resumable_state(plan)?;
    }
    if plan.intent.mode == DeploymentMode::UserOnly {
        crate::setup::require_user_sessions_absent()?;
    }
    crate::setup_transition::begin(
        &plan.installation.paths,
        apply_owner_uid(plan)?,
        &digest,
        || capture_retained_generation(plan, &digest),
    )?;

    let mut actions = Vec::new();
    let integrations_changed = deactivate_and_stop_candidate(plan, &mut actions)?;
    let (_, install_digest) = render_plan(&plan.installation)?;
    crate::setup::apply_plan(&plan.installation, &install_digest)?;
    actions.push("install_release".into());
    let mut report =
        finish_setup_candidate(plan, &digest, &documents, load_credentials, before, actions)?;
    report.changed |= integrations_changed;
    Ok(report)
}

fn finish_setup_candidate<'a, F>(
    plan: &SetupPlanV3,
    digest: &str,
    documents: &[RetainedCandidateDocument],
    load_credentials: F,
    before: String,
    mut actions: Vec<String>,
) -> Result<SetupApplyReportV3>
where
    F: FnOnce(&BTreeSet<String>, &BTreeSet<String>) -> Result<LoadedCredentialMaterials<'a>>,
{
    let declared = declared_credential_slots(plan);
    install_configuration(plan, documents, &mut actions)?;

    let requirements = requirements_for_validated_plan(plan)?;
    let mut blocked = requirements.blocked.clone();
    blocked.sort();
    blocked.dedup();
    let credentials =
        match load_credentials_if_unblocked(&requirements, &declared, load_credentials)? {
            Some(credentials) => credentials,
            None => {
                let after = deployment_state_fingerprint(plan)?;
                return Ok(SetupApplyReportV3 {
                    schema: "dev-auth-setup-apply-v3".into(),
                    changed: before != after,
                    verified: false,
                    input_required: Vec::new(),
                    blocked,
                    next_action: "resolve_blocked_credential_slots".into(),
                    actions,
                });
            }
        };
    let credentials = credentials.as_ref();
    let input_required = requirements
        .required
        .iter()
        .filter(|slot| !credentials.contains_key(*slot))
        .cloned()
        .collect::<Vec<_>>();
    if !input_required.is_empty() {
        let after = deployment_state_fingerprint(plan)?;
        return Ok(SetupApplyReportV3 {
            schema: "dev-auth-setup-apply-v3".into(),
            changed: before != after,
            verified: false,
            input_required,
            blocked,
            next_action: "provide_credential_input".into(),
            actions,
        });
    }

    let action_set_sha256 = credential_action_set_sha256(&plan.intent)?;
    apply_credential_actions(plan, &action_set_sha256, credentials, &mut actions)?;
    start_and_activate_candidate(plan, &mut actions)?;
    if !postcondition_satisfied(plan, digest, documents) {
        bail!("setup plan v3 postcondition verification failed");
    }
    crate::setup_transition::accept(&plan.installation.paths, apply_owner_uid(plan)?, digest)?;
    let after = deployment_state_fingerprint(plan)?;
    Ok(SetupApplyReportV3 {
        schema: "dev-auth-setup-apply-v3".into(),
        changed: before != after,
        verified: true,
        input_required: Vec::new(),
        blocked: Vec::new(),
        next_action: "none".into(),
        actions,
    })
}

fn load_credentials_if_unblocked<'a, F>(
    requirements: &CredentialRequirements,
    declared: &BTreeSet<String>,
    load_credentials: F,
) -> Result<Option<LoadedCredentialMaterials<'a>>>
where
    F: FnOnce(&BTreeSet<String>, &BTreeSet<String>) -> Result<LoadedCredentialMaterials<'a>>,
{
    if !requirements.blocked.is_empty() {
        return Ok(None);
    }
    load_credentials(declared, &requirements.required).map(Some)
}

enum LoadedCredentialMaterials<'a> {
    Borrowed(&'a BTreeMap<String, CredentialMaterial>),
    Owned(BTreeMap<String, CredentialMaterial>),
}

impl LoadedCredentialMaterials<'_> {
    fn as_ref(&self) -> &BTreeMap<String, CredentialMaterial> {
        match self {
            Self::Borrowed(materials) => materials,
            Self::Owned(materials) => materials,
        }
    }
}

fn declared_credential_slots(plan: &SetupPlanV3) -> BTreeSet<String> {
    plan.intent
        .credentials
        .iter()
        .map(|credential| credential.slot.clone())
        .collect()
}

pub fn verify_setup_plan_v3(
    plan: &SetupPlanV3,
    approved_sha256: &str,
) -> Result<SetupApplyReportV3> {
    let (_, digest) = render_setup_plan_v3(plan)?;
    if digest != approved_sha256.to_ascii_lowercase() {
        bail!("setup plan v3 does not match the approved digest");
    }
    require_apply_identity(plan)?;
    let documents = revalidate_public_plan_inputs(plan)?;
    let verified = postcondition_satisfied(plan, &digest, &documents)
        && crate::setup_transition::require_accepted(
            &plan.installation.paths,
            apply_owner_uid(plan)?,
        )
        .is_ok();
    Ok(SetupApplyReportV3 {
        schema: "dev-auth-setup-verify-v3".into(),
        changed: false,
        verified,
        input_required: Vec::new(),
        blocked: Vec::new(),
        next_action: if verified { "none" } else { "apply" }.into(),
        actions: Vec::new(),
    })
}

pub fn setup_apply_candidate_path(
    plan: &SetupPlanV3,
    approved_sha256: &str,
) -> Result<Option<PathBuf>> {
    let (_, digest) = render_setup_plan_v3(plan)?;
    if digest != approved_sha256.to_ascii_lowercase() {
        bail!("setup plan v3 does not match the approved digest");
    }
    require_apply_identity(plan)?;
    revalidate_public_plan_inputs(plan)?;
    let source = if let Some(release) = &plan.installation.verified_release {
        let storage =
            crate::stable_release::native_release_storage(plan.installation.request.mode)?;
        let accepted = crate::stable_release::load_exact_accepted_release(&storage, release)?;
        canonical_plan_release_source(
            &plan.installation.request.source_executable,
            release,
            &accepted,
        )?
    } else if plan.intent.mode == DeploymentMode::Strong {
        bail!("strong setup apply requires an authenticated accepted release")
    } else {
        plan.installation.request.source_executable.clone()
    };
    let (source_length, source_sha256) = crate::setup::setup_executable_identity(&source)?;
    if source_length != plan.installation.source_length
        || source_sha256 != plan.installation.source_sha256
    {
        bail!("verified setup candidate changed before apply handoff");
    }
    let current =
        fs::canonicalize(std::env::current_exe()?).context("resolve running setup executable")?;
    let (current_length, current_sha256) = crate::setup::setup_executable_identity(&current)?;
    if current_length == source_length && current_sha256 == source_sha256 {
        Ok(None)
    } else {
        Ok(Some(source))
    }
}

fn canonical_plan_release_source(
    requested_source: &Path,
    planned: &crate::release_manifest::VerifiedDevAuthRelease,
    accepted: &crate::stable_release::StagedStableRelease,
) -> Result<PathBuf> {
    if accepted.verified != *planned || requested_source != accepted.verified.artifact_path {
        bail!("setup plan release paths do not match the canonical accepted release cache");
    }
    Ok(accepted.verified.artifact_path.clone())
}

fn require_apply_identity(plan: &SetupPlanV3) -> Result<()> {
    match plan.intent.mode {
        DeploymentMode::Strong if !nix::unistd::Uid::effective().is_root() => {
            bail!("strong setup apply requires root")
        }
        DeploymentMode::UserOnly => {
            let current = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
                .context("effective native account does not exist")?;
            if current.uid.is_root()
                || plan.accounts.len() != 1
                || plan.accounts[0].uid != current.uid.as_raw()
                || plan.accounts[0].name != current.name
            {
                bail!("user-only setup apply requires its exact native account");
            }
        }
        DeploymentMode::Strong => {}
    }
    Ok(())
}

fn revalidate_public_plan_inputs(plan: &SetupPlanV3) -> Result<Vec<RetainedCandidateDocument>> {
    if let Some(release) = &plan.installation.verified_release {
        let storage =
            crate::stable_release::native_release_storage(plan.installation.request.mode)?;
        crate::stable_release::require_accepted_release(&storage, release)?;
    }
    let documents = approved_candidate_documents(plan)?;
    revalidate_candidate_documents(plan, &validate_live_installation_plan, &documents)?;
    Ok(documents)
}

fn revalidate_candidate_documents(
    plan: &SetupPlanV3,
    validate_installation: &dyn Fn(&SetupPlan) -> Result<()>,
    documents: &[RetainedCandidateDocument],
) -> Result<()> {
    validate_candidate_inventory(plan, documents)?;
    let prior_policy = approved_prior_policy(plan)?;
    let rebuilt = build_setup_plan_v3_with_reader(
        plan.intent.clone(),
        plan.installation.clone(),
        false,
        &|path, kind, subject| {
            let document = documents
                .iter()
                .find(|document| {
                    document.identity.path == path
                        && document.identity.kind == kind
                        && document.identity.subject == subject
                })
                .context("retained setup is missing a required candidate document")?;
            Ok(OpenedDocument {
                identity: document.identity.clone(),
                bytes: document.bytes.clone(),
            })
        },
        validate_installation,
        prior_policy.as_deref(),
    )?;
    if rebuilt.authority_schema != plan.authority_schema
        || rebuilt.intent_sha256 != plan.intent_sha256
        || rebuilt.source_documents != plan.source_documents
        || rebuilt.accounts != plan.accounts
        || rebuilt.retiring_accounts != plan.retiring_accounts
        || rebuilt.actions != plan.actions
    {
        bail!("setup plan v3 public inputs changed after approval");
    }
    Ok(())
}

fn require_initial_or_resumable_state(plan: &SetupPlanV3) -> Result<()> {
    let rebuilt = build_setup_plan_v3_at(plan.intent.clone(), plan.installation.clone(), false)?;
    if rebuilt.current_state_sha256 == plan.current_state_sha256 {
        return Ok(());
    }
    let report = crate::setup::verify_at_read_only(&plan.installation.paths)
        .context("setup state changed and is not a receipt-owned resumable candidate")?;
    if report.version != plan.installation.request.version
        || Path::new(&report.executable)
            != plan
                .installation
                .paths
                .data_root
                .join("versions")
                .join(&plan.installation.request.version)
                .join("dev-auth")
    {
        bail!("setup state changed outside the approved resumable candidate");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn deactivate_and_stop_candidate(plan: &SetupPlanV3, actions: &mut Vec<String>) -> Result<bool> {
    let transition = crate::setup_transition::retained_transition(
        &plan.installation.paths,
        apply_owner_uid(plan)?,
    )?
    .context("integration retirement requires retained setup authority")?;
    let generation: RetainedSetupGeneration = serde_json::from_slice(&transition.bytes)?;
    if transition.phase != crate::setup_transition::Phase::Pending
        || generation.plan != *plan
        || generation.plan_sha256 != transition.plan_sha256
    {
        bail!("integration retirement requires the matching pending setup generation");
    }
    let executable = match fs::symlink_metadata(installation_receipt_path(plan)) {
        Ok(_) => {
            // Journal recovery needs retained binary-transaction authority;
            // inspecting the release before retirement cannot confer it.
            let report = crate::setup::verify_at_read_only(&plan.installation.paths)?;
            if report.transparent_launchers_active {
                crate::setup::deactivate_transparent_launchers_at(&plan.installation.paths)?;
                actions.push("deactivate_transparent_launchers".into());
            }
            if plan.intent.mode == DeploymentMode::Strong {
                crate::setup::stop_system_broker_at(&plan.installation.paths)?;
                actions.push("stop_broker".into());
            }
            PathBuf::from(report.executable)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => plan
            .installation
            .paths
            .data_root
            .join("versions")
            .join(&plan.installation.request.version)
            .join("dev-auth"),
        Err(error) => return Err(error).context("inspect setup installation receipt"),
    };
    let changed = restoration::retire_user_integrations(&generation, &executable)?;
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        actions.push(format!("deactivate_user_integrations:{}", account.name));
    }
    Ok(changed)
}

// Retain the existing non-Linux implementation until a native descriptor-bound
// retirement backend is available. Linux qualification does not widen support.
#[cfg(not(target_os = "linux"))]
fn deactivate_and_stop_candidate(plan: &SetupPlanV3, actions: &mut Vec<String>) -> Result<bool> {
    match fs::symlink_metadata(installation_receipt_path(plan)) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).context("inspect setup installation receipt"),
    }
    let report = crate::setup::verify_at(&plan.installation.paths)?;
    if report.transparent_launchers_active {
        crate::setup::deactivate_transparent_launchers_at(&plan.installation.paths)?;
        actions.push("deactivate_transparent_launchers".into());
    }
    if plan.intent.mode == DeploymentMode::Strong {
        crate::setup::stop_system_broker_at(&plan.installation.paths)?;
        actions.push("stop_broker".into());
    }
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        crate::setup::reconcile_workload_launchers_at(
            &account.home,
            Path::new(&report.executable),
            &[],
            account.uid,
        )?;
        crate::setup::reconcile_desktop_entries_at(&account.home, &BTreeMap::new(), account.uid)?;
        actions.push(format!("deactivate_user_integrations:{}", account.name));
    }
    Ok(false)
}

fn install_configuration(
    plan: &SetupPlanV3,
    documents: &[RetainedCandidateDocument],
    actions: &mut Vec<String>,
) -> Result<()> {
    let administrator = document_identity(plan, "administrator_policy", "system")?;
    match plan.intent.mode {
        DeploymentMode::Strong => {
            with_candidate_source(documents, administrator, |source| {
                crate::setup::reconcile_system_policy_at(
                    &plan.installation.paths,
                    source,
                    &administrator.sha256,
                    current_document_sha(plan, "administrator_policy", "system")?,
                )
            })?;
            actions.push("install_administrator_policy".into());
            for account in &plan.accounts {
                let config = document_identity(plan, "user_configuration", &account.name)?;
                with_candidate_source(documents, config, |source| {
                    crate::setup::reconcile_inactive_user_config_for_account_at(
                        &plan.installation.paths,
                        source,
                        &config.sha256,
                        &account.name,
                        current_document_sha(plan, "user_configuration", &account.name)?,
                    )
                })?;
                actions.push(format!("install_user_configuration:{}", account.name));
            }
        }
        DeploymentMode::UserOnly => {
            let account = plan
                .accounts
                .first()
                .context("user-only deployment has no native account")?;
            let policy =
                document_identity(plan, "user_policy", &account.name).unwrap_or(administrator);
            with_candidate_source(documents, policy, |source| {
                crate::setup::reconcile_user_policy_for_account_at(
                    &plan.installation.paths,
                    source,
                    &policy.sha256,
                    &account.name,
                    current_document_sha(plan, "user_policy", &account.name)?,
                )
            })?;
            actions.push(format!("install_user_policy:{}", account.name));
            let config = document_identity(plan, "user_configuration", &account.name)?;
            with_candidate_source(documents, config, |source| {
                crate::setup::reconcile_inactive_user_config_for_account_at(
                    &plan.installation.paths,
                    source,
                    &config.sha256,
                    &account.name,
                    current_document_sha(plan, "user_configuration", &account.name)?,
                )
            })?;
            actions.push(format!("install_user_configuration:{}", account.name));
        }
    }
    Ok(())
}

fn apply_credential_actions(
    plan: &SetupPlanV3,
    action_set_sha256: &str,
    credentials: &BTreeMap<String, CredentialMaterial>,
    actions: &mut Vec<String>,
) -> Result<()> {
    let mut completed = read_credential_action_receipt(plan, action_set_sha256)?;
    for credential in &plan.intent.credentials {
        let ready = credential_slot_ready(plan.intent.mode, &credential.slot);
        match credential.intent {
            CredentialIntent::Preserve => {}
            CredentialIntent::EnrollIfAbsent if !ready => {
                let material = credentials
                    .get(&credential.slot)
                    .context("required credential input disappeared before enrollment")?;
                enroll_credential(plan, &credential.slot, material.expose())?;
                actions.push(format!("enroll_credential:{}", credential.slot));
            }
            CredentialIntent::EnrollIfAbsent => {}
            CredentialIntent::Rotate if !completed.contains(&credential.slot) => {
                let material = credentials
                    .get(&credential.slot)
                    .context("required credential input disappeared before rotation")?;
                if complete_credential_action(
                    &credential.slot,
                    &mut completed,
                    || rotate_credential(plan, &credential.slot, material.expose()),
                    |completed| write_credential_action_receipt(plan, action_set_sha256, completed),
                )? {
                    actions.push(format!("rotate_credential:{}", credential.slot));
                }
            }
            CredentialIntent::Rotate => {}
            CredentialIntent::Revoke if !completed.contains(&credential.slot) => {
                if complete_credential_action(
                    &credential.slot,
                    &mut completed,
                    || {
                        if ready {
                            revoke_credential(plan, &credential.slot)?;
                        }
                        Ok(())
                    },
                    |completed| write_credential_action_receipt(plan, action_set_sha256, completed),
                )? && ready
                {
                    actions.push(format!("revoke_credential:{}", credential.slot));
                }
            }
            CredentialIntent::Revoke => {}
        }
    }
    write_credential_action_receipt(plan, action_set_sha256, &completed)?;
    Ok(())
}

fn complete_credential_action<Action, Persist>(
    slot: &str,
    completed: &mut BTreeSet<String>,
    action: Action,
    persist: Persist,
) -> Result<bool>
where
    Action: FnOnce() -> Result<()>,
    Persist: FnOnce(&BTreeSet<String>) -> Result<()>,
{
    if completed.contains(slot) {
        return Ok(false);
    }
    action()?;
    completed.insert(slot.to_owned());
    persist(completed)?;
    Ok(true)
}

fn enroll_credential(plan: &SetupPlanV3, slot: &str, value: &[u8]) -> Result<()> {
    match plan.intent.mode {
        DeploymentMode::Strong => crate::setup::enroll_system_service_credential_slot(slot, value),
        DeploymentMode::UserOnly => {
            crate::runtime::enroll_user_broker_service_token_for_slot(slot, value)
        }
    }
}

fn rotate_credential(plan: &SetupPlanV3, slot: &str, value: &[u8]) -> Result<()> {
    match plan.intent.mode {
        DeploymentMode::Strong => crate::setup::rotate_system_service_credential_slot_at(
            &plan.installation.paths,
            slot,
            value,
        ),
        DeploymentMode::UserOnly => {
            crate::runtime::rotate_user_broker_service_token_for_slot(slot, value)
        }
    }
}

fn revoke_credential(plan: &SetupPlanV3, slot: &str) -> Result<()> {
    match plan.intent.mode {
        DeploymentMode::Strong => {
            crate::setup::revoke_system_service_credential_slot_at(&plan.installation.paths, slot)
        }
        DeploymentMode::UserOnly => crate::runtime::revoke_user_broker_service_token_for_slot(slot),
    }
}

fn start_and_activate_candidate(plan: &SetupPlanV3, actions: &mut Vec<String>) -> Result<()> {
    if plan.intent.mode == DeploymentMode::Strong && broker_desired(&plan.intent) {
        crate::setup::start_system_broker_at(&plan.installation.paths)?;
        actions.push("start_broker".into());
    }
    if plan.intent.activation == Activation::Transparent {
        let setup = crate::setup::verify_at(&plan.installation.paths)?;
        for account in &plan.accounts {
            let workloads = resolved_workloads_for_account(plan, account)?;
            let aliases = workloads.keys().cloned().collect::<Vec<_>>();
            crate::setup::reconcile_workload_launchers_at(
                &account.home,
                Path::new(&setup.executable),
                &aliases,
                account.uid,
            )?;
            crate::setup::reconcile_desktop_entries_at(&account.home, &workloads, account.uid)?;
            actions.push(format!("install_user_integrations:{}", account.name));
        }
        crate::setup::activate_transparent_launchers_at(&plan.installation.paths)?;
        actions.push("activate_transparent_launchers".into());
    }
    Ok(())
}

fn postcondition_satisfied(
    plan: &SetupPlanV3,
    digest: &str,
    documents: &[RetainedCandidateDocument],
) -> bool {
    verify_postcondition(plan, digest, documents).is_ok()
}

fn verify_postcondition(
    plan: &SetupPlanV3,
    digest: &str,
    documents: &[RetainedCandidateDocument],
) -> Result<()> {
    let setup = crate::setup::verify_at_read_only(&plan.installation.paths)?;
    let transparent_expected = plan.intent.activation == Activation::Transparent;
    if setup.version != plan.installation.request.version
        || setup.transparent_launchers_active != transparent_expected
    {
        bail!("installed release does not match the deployment intent");
    }
    let administrator = document_identity(plan, "administrator_policy", "system")?;
    let system_policy = parse_runtime_administrator(candidate_bytes(documents, administrator)?)?;
    match plan.intent.mode {
        DeploymentMode::Strong => {
            require_exact_document(
                Path::new(crate::policy_store::SYSTEM_POLICY_PATH),
                administrator,
            )?;
        }
        DeploymentMode::UserOnly => {}
    }
    for account in &plan.accounts {
        let user = nix::unistd::User::from_name(&account.name)?
            .context("deployment account disappeared during verification")?;
        let config_identity = document_identity(plan, "user_configuration", &account.name)?;
        let config_path = crate::policy_store::runtime_user_config_path(&system_policy, &user);
        require_exact_document(&config_path, config_identity)?;
        let user_config = read_document_bytes(&config_path)?;
        let policy = match plan.intent.mode {
            DeploymentMode::Strong => system_policy.clone(),
            DeploymentMode::UserOnly => {
                let policy_identity =
                    document_identity(plan, "user_policy", &account.name).unwrap_or(administrator);
                let path = crate::policy_store::user_policy_destination(&system_policy, &user);
                require_exact_document(&path, policy_identity)?;
                parse_runtime_administrator(&read_document_bytes(&path)?)?
            }
        };
        let resolved = policy.resolve_user(&account.name, &user_config)?;
        let expected_workloads = if plan.intent.activation == Activation::Transparent {
            resolved.workloads
        } else {
            BTreeMap::new()
        };
        crate::setup::verify_user_integrations_at(
            &account.home,
            Path::new(&setup.executable),
            &expected_workloads,
            account.uid,
        )?;
    }
    for account in &plan.retiring_accounts {
        crate::setup::verify_user_integrations_at(
            &account.home,
            Path::new(&setup.executable),
            &BTreeMap::new(),
            account.uid,
        )?;
    }
    verify_credential_postcondition(plan, digest)?;
    if plan.intent.mode == DeploymentMode::Strong {
        let probe = crate::broker_client::probe_system_broker();
        if broker_desired(&plan.intent)
            && !matches!(probe, crate::broker_protocol::BrokerSessionProbe::NoSession)
        {
            bail!("system broker is not ready outside a workload session");
        }
        if !broker_desired(&plan.intent)
            && !matches!(
                probe,
                crate::broker_protocol::BrokerSessionProbe::Unavailable { .. }
            )
        {
            bail!("system broker remains active when the deployment requires it stopped");
        }
    }
    Ok(())
}

fn verify_credential_postcondition(plan: &SetupPlanV3, _plan_digest: &str) -> Result<()> {
    let action_set_sha256 = credential_action_set_sha256(&plan.intent)?;
    let completed = read_credential_action_receipt(plan, &action_set_sha256)?;
    for credential in &plan.intent.credentials {
        let ready = credential_slot_ready(plan.intent.mode, &credential.slot);
        match credential.intent {
            CredentialIntent::Preserve | CredentialIntent::EnrollIfAbsent if !ready => {
                bail!("required credential slot is not enrolled")
            }
            CredentialIntent::Rotate if !ready || !completed.contains(&credential.slot) => {
                bail!("credential rotation is not complete")
            }
            CredentialIntent::Revoke if ready || !completed.contains(&credential.slot) => {
                bail!("credential revocation is not complete")
            }
            CredentialIntent::Preserve
            | CredentialIntent::EnrollIfAbsent
            | CredentialIntent::Rotate
            | CredentialIntent::Revoke => {}
        }
    }
    Ok(())
}

fn ready_credential_slots(plan: &SetupPlanV3) -> Result<BTreeSet<String>> {
    let mut ready = BTreeSet::new();
    for credential in &plan.intent.credentials {
        if credential_slot_ready(plan.intent.mode, &credential.slot) {
            ready.insert(credential.slot.clone());
        }
    }
    Ok(ready)
}

fn credential_slot_ready(mode: DeploymentMode, slot: &str) -> bool {
    match mode {
        DeploymentMode::Strong => crate::setup::system_service_credential_slot_ready(slot),
        DeploymentMode::UserOnly => {
            crate::runtime::user_broker_service_token_for_slot(slot).is_ok()
        }
    }
}

fn broker_desired(intent: &DeploymentIntent) -> bool {
    intent.mode == DeploymentMode::Strong && intent.activation == Activation::Transparent
}

fn resolved_workloads_for_account(
    plan: &SetupPlanV3,
    account: &NativeAccountIdentity,
) -> Result<BTreeMap<String, crate::policy_v2::ResolvedWorkload>> {
    let user = nix::unistd::User::from_name(&account.name)?
        .context("deployment account disappeared while activating integrations")?;
    let policy = match plan.intent.mode {
        DeploymentMode::Strong => crate::policy_store::load_runtime_system_policy_at(Path::new(
            crate::policy_store::SYSTEM_POLICY_PATH,
        ))?,
        DeploymentMode::UserOnly => {
            let path = crate::policy_store::runtime_user_policy_path(&user)?;
            crate::policy_store::load_runtime_user_policy_at(&path, account.uid)?
        }
    };
    Ok(crate::policy_store::resolve_runtime_config_at(
        &policy,
        &account.name,
        &crate::policy_store::runtime_user_config_path(&policy, &user),
        account.uid,
    )?
    .workloads)
}

fn document_identity<'a>(
    plan: &'a SetupPlanV3,
    kind: &str,
    subject: &str,
) -> Result<&'a DocumentIdentity> {
    plan.source_documents
        .iter()
        .find(|document| document.kind == kind && document.subject == subject)
        .with_context(|| format!("setup plan is missing {kind} for {subject}"))
}

fn current_document_sha<'a>(
    plan: &'a SetupPlanV3,
    kind: &str,
    subject: &str,
) -> Result<Option<&'a str>> {
    let current = plan
        .current_paths
        .iter()
        .find(|identity| identity.kind == kind && identity.subject == subject)
        .with_context(|| format!("setup plan is missing current {kind} state for {subject}"))?;
    Ok(current
        .identity
        .as_ref()
        .map(|identity| identity.sha256.as_str()))
}

fn require_exact_document(path: &Path, identity: &DocumentIdentity) -> Result<()> {
    let bytes = read_document_bytes(path)?;
    if bytes.len() as u64 != identity.length || sha256_hex(&bytes) != identity.sha256 {
        bail!("installed configuration does not match the approved source");
    }
    Ok(())
}

fn read_document_bytes(path: &Path) -> Result<Vec<u8>> {
    read_bounded(path)
}

fn installation_receipt_path(plan: &SetupPlanV3) -> PathBuf {
    plan.installation.paths.data_root.join("install-v2.json")
}

fn credential_action_receipt_path(plan: &SetupPlanV3) -> PathBuf {
    plan.installation
        .paths
        .data_root
        .join("credential-actions-v2.json")
}

fn read_credential_action_receipt(
    plan: &SetupPlanV3,
    action_set_sha256: &str,
) -> Result<BTreeSet<String>> {
    let path = credential_action_receipt_path(plan);
    let Some(document) = read_atomic_document(&path, &credential_action_authority(plan)?)? else {
        return Ok(BTreeSet::new());
    };
    let receipt: CredentialActionReceipt =
        serde_json::from_slice(&document.bytes).context("parse credential action receipt")?;
    if receipt.schema != "dev-auth-credential-actions-v2"
        || receipt.action_set_sha256 != action_set_sha256
    {
        return Ok(BTreeSet::new());
    }
    Ok(receipt.completed)
}

fn write_credential_action_receipt(
    plan: &SetupPlanV3,
    action_set_sha256: &str,
    completed: &BTreeSet<String>,
) -> Result<()> {
    let receipt = CredentialActionReceipt {
        schema: "dev-auth-credential-actions-v2".into(),
        action_set_sha256: action_set_sha256.into(),
        completed: completed.clone(),
    };
    let bytes = serde_jcs::to_vec(&receipt).context("serialize credential action receipt")?;
    let path = credential_action_receipt_path(plan);
    let authority = credential_action_authority(plan)?;
    let current = read_atomic_document(&path, &authority)?;
    write_atomic_document(
        &path,
        &bytes,
        &authority,
        current.as_ref().map(|document| &document.identity),
    )?;
    Ok(())
}

fn credential_action_set_sha256(intent: &DeploymentIntent) -> Result<String> {
    #[derive(Serialize)]
    struct CredentialActionSet<'a> {
        mode: DeploymentMode,
        credentials: &'a [DeploymentCredential],
    }
    Ok(sha256_hex(
        &serde_jcs::to_vec(&CredentialActionSet {
            mode: intent.mode,
            credentials: &intent.credentials,
        })
        .context("canonicalize credential action set")?,
    ))
}

fn credential_action_authority(plan: &SetupPlanV3) -> Result<DocumentAuthority> {
    Ok(DocumentAuthority {
        owner_uid: apply_owner_uid(plan)?,
        mode: 0o600,
        limit: DOCUMENT_LIMIT,
    })
}

fn apply_owner_uid(plan: &SetupPlanV3) -> Result<u32> {
    match plan.intent.mode {
        DeploymentMode::Strong => Ok(0),
        DeploymentMode::UserOnly => Ok(plan
            .accounts
            .first()
            .context("user-only plan has no native account")?
            .uid),
    }
}

fn deployment_lock_path(plan: &SetupPlanV3) -> Result<PathBuf> {
    match plan.intent.mode {
        DeploymentMode::Strong => deployment_lock_path_for(DeploymentMode::Strong, None),
        DeploymentMode::UserOnly => {
            let account = plan
                .accounts
                .first()
                .context("user-only plan has no native account")?;
            deployment_lock_path_for(DeploymentMode::UserOnly, Some(account.uid))
        }
    }
}

fn deployment_lock_path_for(mode: DeploymentMode, owner_uid: Option<u32>) -> Result<PathBuf> {
    crate::setup_transition::lock_path(mode, owner_uid)
}

fn deployment_state_fingerprint(plan: &SetupPlanV3) -> Result<String> {
    #[derive(Serialize)]
    struct State<'a> {
        files: Vec<(PathBuf, Option<(u64, String)>)>,
        credential_ready: BTreeSet<String>,
        broker: &'a str,
    }
    let mut paths = vec![
        installation_receipt_path(plan),
        credential_action_receipt_path(plan),
        crate::setup_transition::state_path(&plan.installation.paths),
    ];
    match plan.intent.mode {
        DeploymentMode::Strong => {
            paths.push(PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH));
        }
        DeploymentMode::UserOnly => {}
    }
    for account in &plan.accounts {
        let user = nix::unistd::User::from_name(&account.name)?
            .context("deployment account disappeared while fingerprinting state")?;
        paths.push(user.dir.join(if plan.authority_schema.is_some() {
            crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH
        } else {
            crate::policy_store::USER_CONFIG_RELATIVE_PATH
        }));
        if plan.intent.mode == DeploymentMode::UserOnly {
            paths.push(user.dir.join(if plan.authority_schema.is_some() {
                crate::policy_store::USER_POLICY_V3_RELATIVE_PATH
            } else {
                crate::policy_store::USER_POLICY_RELATIVE_PATH
            }));
        }
    }
    for account in &plan.retiring_accounts {
        paths.push(
            account
                .home
                .join(crate::policy_store::USER_CONFIG_RELATIVE_PATH),
        );
        paths.push(
            account
                .home
                .join(crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH),
        );
        paths.extend(
            crate::setup::user_integration_receipt_paths(&account.home, &account.name)
                .into_iter()
                .map(|(_, _, path)| path),
        );
    }
    paths.sort();
    paths.dedup();
    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let identity = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("inspect deployment state"),
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    bail!("deployment state contains an unsafe object");
                }
                let bytes = read_bounded(&path)?;
                Some((bytes.len() as u64, sha256_hex(&bytes)))
            }
        };
        files.push((path, identity));
    }
    let broker = if plan.intent.mode == DeploymentMode::UserOnly {
        "user_only"
    } else {
        match crate::broker_client::probe_system_broker() {
            crate::broker_protocol::BrokerSessionProbe::NoSession => "ready",
            crate::broker_protocol::BrokerSessionProbe::Verified { .. } => "admitted",
            crate::broker_protocol::BrokerSessionProbe::Invalid { .. } => "invalid",
            crate::broker_protocol::BrokerSessionProbe::Unavailable { .. } => "unavailable",
        }
    };
    Ok(sha256_hex(
        &serde_jcs::to_vec(&State {
            files,
            credential_ready: ready_credential_slots(plan)?,
            broker,
        })
        .context("serialize deployment state")?,
    ))
}

pub fn build_setup_plan_v3(
    intent: DeploymentIntent,
    installation: SetupPlan,
) -> Result<SetupPlanV3> {
    build_setup_plan_v3_at(intent, installation, true)
}

pub fn build_setup_plan_v3_for_verified_release(
    intent: DeploymentIntent,
    verified: crate::release_manifest::VerifiedDevAuthRelease,
) -> Result<SetupPlanV3> {
    let administrator = read_document(
        &intent.administrator_policy,
        "administrator_policy",
        "system",
    )?;
    let policy = parse_runtime_administrator(&administrator.bytes)
        .context("validate administrator policy")?;
    let mode = match intent.mode {
        DeploymentMode::Strong => crate::setup::InstallMode::Strong,
        DeploymentMode::UserOnly => crate::setup::InstallMode::UserOnly,
    };
    let installation = crate::setup::build_verified_release_plan_with_native_programs(
        mode,
        false,
        verified,
        PathBuf::from(policy.programs()["git"]),
        PathBuf::from(policy.programs()["gh"]),
    )?;
    build_setup_plan_v3(intent, installation)
}

pub fn build_setup_plan_v3_at(
    intent: DeploymentIntent,
    installation: SetupPlan,
    require_privileged: bool,
) -> Result<SetupPlanV3> {
    let prior_policy = read_prior_system_policy(intent.mode)?;
    let plan = build_setup_plan_v3_with_reader(
        intent,
        installation,
        require_privileged,
        &read_document,
        &validate_live_installation_plan,
        prior_policy.as_deref(),
    )?;
    require_prior_policy_snapshot(&plan, prior_policy.as_deref())?;
    Ok(plan)
}

fn build_setup_plan_v3_with_reader(
    intent: DeploymentIntent,
    installation: SetupPlan,
    require_privileged: bool,
    read_source: &dyn Fn(&Path, &str, &str) -> Result<OpenedDocument>,
    validate_installation: &dyn Fn(&SetupPlan) -> Result<()>,
    prior_policy: Option<&[u8]>,
) -> Result<SetupPlanV3> {
    let intent_bytes = canonical_deployment_intent(&intent)?;
    let intent_sha256 = sha256_hex(&intent_bytes);
    validate_installation(&installation).context("validate staged installation plan")?;
    let current_user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective native account does not exist")?;
    let expected_install_mode = match intent.mode {
        DeploymentMode::Strong => crate::setup::InstallMode::Strong,
        DeploymentMode::UserOnly => crate::setup::InstallMode::UserOnly,
    };
    if installation.request.mode != expected_install_mode
        || installation.request.activate_transparent_launchers
    {
        bail!("deployment intent and staged installation plan disagree");
    }
    require_canonical_installation_layout(
        intent.mode,
        &installation.paths,
        Some(&current_user.dir),
    )?;
    if require_privileged
        && intent.mode == DeploymentMode::Strong
        && !nix::unistd::Uid::effective().is_root()
    {
        bail!("strong setup planning requires root");
    }

    let administrator = read_source(
        &intent.administrator_policy,
        "administrator_policy",
        "system",
    )?;
    let administrator_policy = parse_runtime_administrator(&administrator.bytes)
        .context("validate administrator policy")?;
    if administrator_policy.authority_schema().is_some()
        && semver::Version::parse(&installation.request.version)? < semver::Version::new(0, 4, 0)
    {
        bail!("logical authority requires a compatible runtime release");
    }
    let expected_policy_mode = match intent.mode {
        DeploymentMode::Strong => SystemMode::Strong,
        DeploymentMode::UserOnly => SystemMode::UserOnly,
    };
    if administrator_policy.mode() != expected_policy_mode {
        bail!("administrator policy mode does not match deployment mode");
    }
    if installation.request.native_git != Path::new(administrator_policy.programs()["git"]) {
        bail!("staged installation does not target the administrator-pinned native Git");
    }
    if installation.request.native_gh != Path::new(administrator_policy.programs()["gh"]) {
        bail!("staged installation does not target the administrator-pinned native GitHub CLI");
    }

    validate_policy_program_authority(
        &administrator_policy,
        intent.mode,
        current_user.uid.as_raw(),
    )?;
    crate::setup::require_setup_prerequisites(
        expected_install_mode,
        current_user.uid.as_raw(),
        &administrator_policy,
    )?;
    if intent.mode == DeploymentMode::UserOnly
        && (intent.users.len() != 1 || intent.users[0].name != current_user.name)
    {
        bail!("user-only deployment may manage only the effective native account");
    }

    let mut documents = vec![administrator.identity];
    let mut accounts = Vec::with_capacity(intent.users.len());
    let mut account_names = BTreeSet::new();
    let mut used_credential_slots = BTreeSet::new();
    for user in &intent.users {
        let account = nix::unistd::User::from_name(&user.name)?
            .with_context(|| format!("native account {} does not exist", user.name))?;
        if !account_names.insert(account.name.clone()) {
            bail!("deployment resolves more than one user to the same native account");
        }
        if !administrator_policy.allowed_users().contains(&account.name) {
            bail!("native account is outside administrator policy");
        }
        let config = read_source(&user.config, "user_configuration", &account.name)?;
        let mut resolved = administrator_policy
            .resolve_user(&account.name, &config.bytes)
            .with_context(|| format!("resolve policy for native account {}", account.name))?;
        documents.push(config.identity);
        if let Some(policy_path) = &user.policy {
            let user_policy = read_source(policy_path, "user_policy", &account.name)?;
            let parsed = parse_runtime_administrator(&user_policy.bytes)
                .with_context(|| format!("validate user-only policy for {}", account.name))?;
            if intent.mode != DeploymentMode::UserOnly || parsed.mode() != SystemMode::UserOnly {
                bail!("per-user policy is valid only for user-only deployment");
            }
            administrator_policy
                .require_narrows(&parsed)
                .with_context(|| {
                    format!(
                        "prove user-only policy narrows administrator policy for {}",
                        account.name
                    )
                })?;
            resolved = parsed
                .resolve_user(&account.name, &config.bytes)
                .with_context(|| format!("resolve user-only policy for {}", account.name))?;
            documents.push(user_policy.identity);
        }
        used_credential_slots.extend(
            resolved
                .authority_profiles
                .values()
                .flat_map(|profile| profile.credential_slots.iter().cloned()),
        );
        validate_resolved_workspace_authority(&resolved, account.uid.as_raw()).with_context(
            || {
                format!(
                    "validate workspace authority for native account {}",
                    account.name
                )
            },
        )?;
        accounts.push(NativeAccountIdentity {
            name: account.name,
            uid: account.uid.as_raw(),
            gid: account.gid.as_raw(),
            home: account.dir,
        });
    }
    validate_deployment_user_set(
        intent.mode,
        &administrator_policy
            .allowed_users()
            .iter()
            .cloned()
            .collect(),
        &account_names,
    )?;
    documents.sort_by(|left, right| {
        (&left.kind, &left.subject, &left.path).cmp(&(&right.kind, &right.subject, &right.path))
    });
    accounts.sort_by(|left, right| left.name.cmp(&right.name));
    let retiring_accounts = resolve_retiring_accounts(intent.mode, prior_policy, &accounts)?;

    let declared_credential_slots = intent
        .credentials
        .iter()
        .map(|credential| credential.slot.clone())
        .collect::<BTreeSet<_>>();
    let policy_credential_slots = administrator_policy
        .credential_slot_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    validate_deployment_credential_slots(
        &policy_credential_slots,
        &declared_credential_slots,
        &used_credential_slots,
    )?;
    if intent.activation == Activation::Transparent
        && intent.credentials.iter().any(|credential| {
            used_credential_slots.contains(&credential.slot)
                && credential.intent == CredentialIntent::Revoke
        })
    {
        bail!("transparent activation conflicts with required credential revocation");
    }

    let authority_schema = administrator_policy.authority_schema().map(str::to_owned);
    let (current_paths, current_credential_ready, current_broker_state) = current_state_snapshot(
        &installation,
        &intent,
        &accounts,
        &retiring_accounts,
        authority_schema.as_deref(),
    )?;
    let current_state_sha256 = stored_current_state_digest(
        &current_paths,
        &current_credential_ready,
        &current_broker_state,
    )?;
    let actions = planned_action_contract(&intent);
    let plan = SetupPlanV3 {
        authority_schema,
        schema: "dev-auth-setup-plan-v3".into(),
        intent,
        intent_sha256,
        installation,
        source_documents: documents,
        accounts,
        retiring_accounts,
        current_paths,
        current_credential_ready,
        current_broker_state,
        current_state_sha256,
        actions,
    };
    validate_setup_plan_v3_with_installation_check(&plan, validate_installation)?;
    Ok(plan)
}

fn read_prior_system_policy(mode: DeploymentMode) -> Result<Option<Vec<u8>>> {
    if mode != DeploymentMode::Strong {
        return Ok(None);
    }
    let path = Path::new(crate::policy_store::SYSTEM_POLICY_PATH);
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect previous administrator policy"),
    };
    if !metadata.file_type().is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        bail!("previous administrator policy has unsafe authority");
    }
    let document = read_atomic_document(
        path,
        &DocumentAuthority {
            owner_uid: 0,
            mode: metadata.mode() & 0o777,
            limit: DOCUMENT_LIMIT,
        },
    )?
    .context("previous administrator policy disappeared")?;
    Ok(Some(document.bytes))
}

fn require_prior_policy_snapshot(plan: &SetupPlanV3, bytes: Option<&[u8]>) -> Result<()> {
    if plan.intent.mode != DeploymentMode::Strong {
        return Ok(());
    }
    let current = prior_policy_identity(plan)?;
    validate_prior_policy_bytes(current, bytes)
}

fn prior_policy_identity(plan: &SetupPlanV3) -> Result<&CurrentPathIdentity> {
    plan.current_paths
        .iter()
        .find(|current| {
            current.kind == "administrator_policy"
                && current.subject == "system"
                && current.path == Path::new(crate::policy_store::SYSTEM_POLICY_PATH)
        })
        .context("approved previous administrator policy identity is absent")
}

fn validate_prior_policy_bytes(current: &CurrentPathIdentity, bytes: Option<&[u8]>) -> Result<()> {
    match (&current.identity, bytes) {
        (None, None) => Ok(()),
        (Some(identity), Some(bytes))
            if identity.object_type == "file"
                && identity.owner_uid == 0
                && identity.mode & 0o022 == 0
                && identity.link_count == 1
                && bytes.len() as u64 <= DOCUMENT_LIMIT
                && bytes.len() as u64 == identity.length
                && sha256_hex(bytes) == identity.sha256 =>
        {
            Ok(())
        }
        _ => bail!("previous administrator policy differs from its approved snapshot"),
    }
}

fn approved_prior_policy(plan: &SetupPlanV3) -> Result<Option<Vec<u8>>> {
    if plan.intent.mode != DeploymentMode::Strong {
        return Ok(None);
    }
    let current = prior_policy_identity(plan)?;
    let digest = sha256_hex(&serde_jcs::to_vec(plan)?);
    let object = match crate::setup_transition::retained_transition(
        &plan.installation.paths,
        apply_owner_uid(plan)?,
    )? {
        Some(transition) if transition.plan_sha256 == digest => {
            return retained_prior_policy(plan, &digest, &transition.bytes);
        }
        _ => capture_retained_object(current)?,
    };
    validate_prior_policy_bytes(current, object.bytes.as_deref())?;
    Ok(object.bytes)
}

fn retained_prior_policy(
    plan: &SetupPlanV3,
    digest: &str,
    bytes: &[u8],
) -> Result<Option<Vec<u8>>> {
    let current = prior_policy_identity(plan)?;
    let generation: RetainedSetupGeneration = serde_json::from_slice(bytes)?;
    if generation.schema != "dev-auth-retained-setup-generation-v1"
        || generation.plan_sha256 != digest
        || generation.plan != *plan
    {
        bail!("previous policy retention does not match the approved plan");
    }
    let mut matching = generation
        .documents
        .into_iter()
        .filter(|object| object.current == *current);
    let object = matching
        .next()
        .context("retained previous policy is absent")?;
    if matching.next().is_some() {
        bail!("retained previous policy is ambiguous");
    }
    validate_prior_policy_bytes(current, object.bytes.as_deref())?;
    Ok(object.bytes)
}

fn resolve_retiring_accounts(
    mode: DeploymentMode,
    prior_policy: Option<&[u8]>,
    desired: &[NativeAccountIdentity],
) -> Result<Vec<NativeAccountIdentity>> {
    let Some(bytes) = prior_policy else {
        return Ok(Vec::new());
    };
    if mode != DeploymentMode::Strong {
        bail!("user-only setup cannot retire another native account");
    }
    let policy =
        parse_runtime_administrator(bytes).context("validate previous administrator policy")?;
    if policy.mode() != SystemMode::Strong {
        bail!("previous system policy has incompatible installation authority");
    }
    let mut accounts = Vec::new();
    for name in policy.allowed_users() {
        if desired.iter().any(|account| &account.name == name) {
            continue;
        }
        let user = nix::unistd::User::from_name(name)?
            .context("retiring native account is absent; explicit identity recovery is required")?;
        accounts.push(NativeAccountIdentity {
            name: user.name,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home: user.dir,
        });
    }
    accounts.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(accounts)
}

fn validate_deployment_user_set(
    mode: DeploymentMode,
    policy_users: &BTreeSet<String>,
    deployment_users: &BTreeSet<String>,
) -> Result<()> {
    if mode == DeploymentMode::Strong && policy_users != deployment_users {
        bail!("strong deployment users must exactly match administrator policy users");
    }
    Ok(())
}

fn validate_deployment_credential_slots(
    policy: &BTreeSet<String>,
    declared: &BTreeSet<String>,
    used: &BTreeSet<String>,
) -> Result<()> {
    if declared != policy {
        bail!("deployment credential slots must exactly match administrator policy");
    }
    if !used.is_subset(declared) {
        bail!("deployment intent omits a credential slot required by a user authority profile");
    }
    Ok(())
}

fn require_canonical_installation_layout(
    mode: DeploymentMode,
    paths: &crate::setup::SetupPaths,
    user_home: Option<&Path>,
) -> Result<()> {
    let expected = match mode {
        DeploymentMode::Strong => crate::setup::SetupPaths::strong(),
        DeploymentMode::UserOnly => crate::setup::SetupPaths::user_only(
            user_home.context("user-only deployment has no native account home")?,
        ),
    };
    if paths != &expected {
        bail!("deployment installation layout is not canonical");
    }
    Ok(())
}

fn validate_policy_program_authority(
    policy: &RuntimeAdministrator,
    mode: DeploymentMode,
    owner_uid: u32,
) -> Result<()> {
    let mut programs = policy.programs().into_iter().collect::<Vec<_>>();
    programs.extend(policy.provider_programs());
    programs.extend(
        policy
            .trusted_launchers()
            .iter()
            .map(|(name, path)| (name.as_str(), path.as_str())),
    );
    programs.extend(
        policy
            .sandbox_adapters()
            .iter()
            .map(|(name, adapter)| (name.as_str(), adapter.executable.as_str())),
    );
    for (description, path) in programs {
        let description = if description == "op" {
            "1Password CLI"
        } else {
            description
        };
        match mode {
            DeploymentMode::Strong => {
                crate::setup::validate_root_owned_executable(Path::new(path), description)?
            }
            DeploymentMode::UserOnly => crate::setup::validate_user_or_root_executable(
                Path::new(path),
                owner_uid,
                description,
            )?,
        }
    }
    Ok(())
}

fn validate_resolved_workspace_authority(
    policy: &crate::policy_v2::ResolvedPolicy,
    owner_uid: u32,
) -> Result<()> {
    for workload in policy.workloads.values() {
        for root in &workload.workspace_roots {
            validate_workspace_root_authority(Path::new(&root.path), root.access, owner_uid)?;
        }
    }
    Ok(())
}

fn validate_workspace_root_authority(
    path: &Path,
    access: crate::policy_v2::WorkspaceAccess,
    owner_uid: u32,
) -> Result<()> {
    if !path.is_absolute() || fs::canonicalize(path).ok().as_deref() != Some(path) {
        bail!("workspace root is absent, noncanonical, or symlinked");
    }
    let metadata = fs::symlink_metadata(path).context("inspect workspace root")?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o022 != 0
        || (metadata.uid() != 0 && metadata.uid() != owner_uid)
        || (access == crate::policy_v2::WorkspaceAccess::ReadWrite && metadata.uid() != owner_uid)
    {
        bail!("workspace root has unsafe filesystem authority");
    }
    Ok(())
}

pub fn render_setup_plan_v3(plan: &SetupPlanV3) -> Result<(Vec<u8>, String)> {
    validate_setup_plan_v3(plan)?;
    let bytes = serde_jcs::to_vec(plan).context("canonicalize setup plan v3")?;
    let digest = sha256_hex(&bytes);
    Ok((bytes, digest))
}

pub fn write_setup_plan_v3_at(path: &Path, plan: &SetupPlanV3) -> Result<String> {
    if !path.is_absolute() {
        bail!("setup plan v3 output path must be absolute");
    }
    let parent = path.parent().context("setup plan v3 path has no parent")?;
    if !parent.is_dir() {
        bail!("setup plan v3 parent is not a directory");
    }
    let (bytes, digest) = render_setup_plan_v3(plan)?;
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("create temporary setup plan v3")?;
    file.write_all(&bytes).context("write setup plan v3")?;
    file.sync_all().context("sync setup plan v3")?;
    drop(file);
    match fs::rename(&temporary, path) {
        Ok(()) => Ok(digest),
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            Err(error).context("publish setup plan v3")
        }
    }
}

pub fn read_setup_plan_v3_at(path: &Path) -> Result<SetupPlanV3> {
    let bytes = read_bounded(path)?;
    parse_setup_plan_v3(&bytes)
}

/// Read a privileged setup transaction only from root-owned private custody.
///
/// The setup helper uses this stricter entry point before it interprets any
/// plan content. World- or user-writable ancestors are not acceptable plan
/// authority even when the leaf itself is a root-owned regular file.
pub fn read_root_setup_plan_v3_at(path: &Path) -> Result<SetupPlanV3> {
    validate_root_plan_path(path)?;
    let document = read_atomic_document(
        path,
        &DocumentAuthority {
            owner_uid: 0,
            mode: 0o600,
            limit: DOCUMENT_LIMIT,
        },
    )?
    .context("root-owned setup plan v3 is absent")?;
    parse_setup_plan_v3(&document.bytes)
}

fn parse_setup_plan_v3(bytes: &[u8]) -> Result<SetupPlanV3> {
    let plan: SetupPlanV3 = serde_json::from_slice(bytes).context("parse setup plan v3")?;
    validate_setup_plan_v3(&plan)?;
    Ok(plan)
}

fn validate_root_plan_path(path: &Path) -> Result<()> {
    use std::path::Component;

    if !path.is_absolute() {
        bail!("root-owned setup plan path must be absolute and normalized");
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        if !matches!(
            component,
            Component::RootDir | Component::Prefix(_) | Component::Normal(_)
        ) {
            bail!("root-owned setup plan path must be absolute and normalized");
        }
        normalized.push(component.as_os_str());
    }
    if normalized.as_os_str() != path.as_os_str() {
        bail!("root-owned setup plan path must be absolute and normalized");
    }
    let parent = path
        .parent()
        .context("root-owned setup plan has no parent")?;
    let mut current = PathBuf::new();
    for component in parent.components() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "inspect root-owned setup plan ancestor {}",
                current.display()
            )
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            bail!("root-owned setup plan has unsafe ancestor authority");
        }
    }
    Ok(())
}

fn validate_setup_plan_v3(plan: &SetupPlanV3) -> Result<()> {
    validate_setup_plan_v3_with_installation_check(plan, &validate_live_installation_plan)
}

fn validate_live_installation_plan(plan: &SetupPlan) -> Result<()> {
    render_plan(plan).map(|_| ())
}

fn validate_setup_plan_v3_with_installation_check(
    plan: &SetupPlanV3,
    validate_installation: &dyn Fn(&SetupPlan) -> Result<()>,
) -> Result<()> {
    if !plan.retiring_accounts.is_empty() && plan.intent.mode != DeploymentMode::Strong {
        bail!("only strong setup may contain retiring accounts");
    }
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut homes = BTreeSet::new();
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        if !names.insert(&account.name)
            || !uids.insert(account.uid)
            || !homes.insert(&account.home)
            || !account.home.is_absolute()
            || account.home == Path::new("/")
        {
            bail!("setup account inventory has ambiguous native authority");
        }
    }
    if plan
        .retiring_accounts
        .windows(2)
        .any(|pair| pair[0].name >= pair[1].name)
    {
        bail!("retiring account inventory is not canonical");
    }
    if !matches!(
        plan.authority_schema.as_deref(),
        None | Some("dev-auth-administrator-policy-v3")
    ) {
        bail!("setup plan has an unsupported authority schema");
    }
    if plan.schema != "dev-auth-setup-plan-v3"
        || plan.intent_sha256 != sha256_hex(&canonical_deployment_intent(&plan.intent)?)
        || plan.source_documents.is_empty()
        || plan.accounts.is_empty()
        || plan.actions.is_empty()
        || plan.current_state_sha256
            != stored_current_state_digest(
                &plan.current_paths,
                &plan.current_credential_ready,
                &plan.current_broker_state,
            )?
        || plan.actions.last().map(|action| action.kind.as_str()) != Some("verify")
        || plan
            .actions
            .iter()
            .enumerate()
            .any(|(index, action)| action.order != index as u32)
    {
        bail!("dev-auth setup plan v3 has an unsupported contract");
    }
    if current_path_keys(&plan.current_paths)
        != expected_current_path_keys(
            &plan.installation,
            &plan.intent,
            &plan.accounts,
            &plan.retiring_accounts,
            plan.authority_schema.as_deref(),
        )
    {
        bail!("setup plan v3 current-state paths do not match the deployment authority");
    }
    require_canonical_installation_layout(
        plan.intent.mode,
        &plan.installation.paths,
        plan.accounts.first().map(|account| account.home.as_path()),
    )?;
    validate_installation(&plan.installation).context("validate nested installation plan")?;
    if plan.installation.request.activate_transparent_launchers {
        bail!("setup plan v3 must stage the release with transparent launchers inactive");
    }
    Ok(())
}

fn current_path_keys(paths: &[CurrentPathIdentity]) -> Vec<(String, String, PathBuf)> {
    paths
        .iter()
        .map(|path| (path.kind.clone(), path.subject.clone(), path.path.clone()))
        .collect()
}

fn expected_current_path_keys(
    installation: &SetupPlan,
    intent: &DeploymentIntent,
    accounts: &[NativeAccountIdentity],
    retiring_accounts: &[NativeAccountIdentity],
    authority_schema: Option<&str>,
) -> Vec<(String, String, PathBuf)> {
    let logical = authority_schema == Some("dev-auth-administrator-policy-v3");
    let mut paths = crate::setup::installation_current_state_paths(
        &installation.paths,
        installation.request.mode,
    );
    paths.push((
        "credential_actions".to_owned(),
        "system".to_owned(),
        installation
            .paths
            .data_root
            .join("credential-actions-v2.json"),
    ));
    paths.push((
        "setup_transition".into(),
        "system".into(),
        crate::setup_transition::state_path(&installation.paths),
    ));
    match intent.mode {
        DeploymentMode::Strong => paths.push((
            "administrator_policy".into(),
            "system".into(),
            PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH),
        )),
        DeploymentMode::UserOnly => {
            for account in accounts {
                paths.push((
                    "user_policy".into(),
                    account.name.clone(),
                    account.home.join(if logical {
                        crate::policy_store::USER_POLICY_V3_RELATIVE_PATH
                    } else {
                        crate::policy_store::USER_POLICY_RELATIVE_PATH
                    }),
                ));
            }
        }
    }
    for account in accounts {
        paths.extend(crate::setup::user_integration_receipt_paths(
            &account.home,
            &account.name,
        ));
        paths.push((
            "user_configuration".into(),
            account.name.clone(),
            account.home.join(if logical {
                crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH
            } else {
                crate::policy_store::USER_CONFIG_RELATIVE_PATH
            }),
        ));
        // Both versioned authorities remain rollback inputs, regardless of
        // which schema the candidate selects.
        paths.push((
            "retained_user_configuration".into(),
            account.name.clone(),
            account.home.join(if logical {
                crate::policy_store::USER_CONFIG_RELATIVE_PATH
            } else {
                crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH
            }),
        ));
        if intent.mode == DeploymentMode::UserOnly {
            paths.push((
                "retained_user_policy".into(),
                account.name.clone(),
                account.home.join(if logical {
                    crate::policy_store::USER_POLICY_RELATIVE_PATH
                } else {
                    crate::policy_store::USER_POLICY_V3_RELATIVE_PATH
                }),
            ));
        }
    }
    for account in retiring_accounts {
        paths.extend(crate::setup::user_integration_receipt_paths(
            &account.home,
            &account.name,
        ));
        for (kind, relative) in [
            (
                "retiring_user_configuration_v2",
                crate::policy_store::USER_CONFIG_RELATIVE_PATH,
            ),
            (
                "retiring_user_configuration_v3",
                crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH,
            ),
        ] {
            paths.push((
                kind.into(),
                account.name.clone(),
                account.home.join(relative),
            ));
        }
    }
    paths.sort();
    paths
}

pub fn planned_action_contract(intent: &DeploymentIntent) -> Vec<SetupActionV3> {
    let mut actions = Vec::new();
    let mut push = |kind: &str, subject: Option<String>| {
        actions.push(SetupActionV3 {
            order: actions.len() as u32,
            kind: kind.into(),
            subject,
        });
    };
    push("deactivate_transparent_launchers", None);
    if intent.mode == DeploymentMode::Strong {
        push("stop_broker", None);
    }
    push("install_release", None);
    if intent.mode == DeploymentMode::Strong {
        push("install_administrator_policy", None);
        push("install_system_integrations", None);
    }
    for user in &intent.users {
        if user.policy.is_some() {
            push("install_user_policy", Some(user.name.clone()));
        }
        push("install_user_configuration", Some(user.name.clone()));
    }
    for credential in &intent.credentials {
        let kind = match credential.intent {
            crate::deployment::CredentialIntent::Preserve => "preserve_credential",
            crate::deployment::CredentialIntent::EnrollIfAbsent => "enroll_credential_if_absent",
            crate::deployment::CredentialIntent::Rotate => "rotate_credential",
            crate::deployment::CredentialIntent::Revoke => "revoke_credential",
        };
        push(kind, Some(credential.slot.clone()));
    }
    if intent.activation == Activation::Transparent {
        for user in &intent.users {
            push("install_user_integrations", Some(user.name.clone()));
        }
    }
    if broker_desired(intent) {
        push("start_broker", None);
    }
    if intent.activation == Activation::Transparent {
        push("activate_transparent_launchers", None);
    }
    push("verify", None);
    actions
}

fn current_state_snapshot(
    installation: &SetupPlan,
    intent: &DeploymentIntent,
    accounts: &[NativeAccountIdentity],
    retiring_accounts: &[NativeAccountIdentity],
    authority_schema: Option<&str>,
) -> Result<(Vec<CurrentPathIdentity>, BTreeSet<String>, String)> {
    let paths = expected_current_path_keys(
        installation,
        intent,
        accounts,
        retiring_accounts,
        authority_schema,
    );
    let mut entries = Vec::with_capacity(paths.len());
    for (kind, subject, path) in paths {
        let identity = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
                    let document =
                        read_bounded_at(&path, CURRENT_OBJECT_LIMIT, "setup current-state file")?;
                    Some(CurrentFileIdentity {
                        object_type: "file".into(),
                        owner_uid: metadata.uid(),
                        mode: current_path_mode(&metadata),
                        link_count: metadata.nlink(),
                        length: document.len() as u64,
                        sha256: sha256_hex(&document),
                        link_target: None,
                    })
                } else if metadata.file_type().is_symlink() {
                    let target = fs::read_link(&path).with_context(|| {
                        format!("read setup current-state link {}", path.display())
                    })?;
                    let target_bytes = target.as_os_str().as_bytes();
                    if target_bytes.is_empty() || target_bytes.len() > 4096 {
                        bail!("setup current-state link target is invalid");
                    }
                    Some(CurrentFileIdentity {
                        object_type: "symlink".into(),
                        owner_uid: metadata.uid(),
                        mode: current_path_mode(&metadata),
                        link_count: metadata.nlink(),
                        length: target_bytes.len() as u64,
                        sha256: sha256_hex(target_bytes),
                        link_target: Some(target),
                    })
                } else {
                    bail!("setup current-state path has an unsupported object type");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("inspect setup current-state path"),
        };
        entries.push(CurrentPathIdentity {
            kind,
            subject,
            path,
            identity,
        });
    }
    let broker = if intent.mode == DeploymentMode::UserOnly {
        "user_only"
    } else {
        match crate::broker_client::probe_system_broker() {
            crate::broker_protocol::BrokerSessionProbe::NoSession => "ready",
            crate::broker_protocol::BrokerSessionProbe::Verified { .. } => "admitted",
            crate::broker_protocol::BrokerSessionProbe::Invalid { .. } => "invalid",
            crate::broker_protocol::BrokerSessionProbe::Unavailable { .. } => "unavailable",
        }
    };
    let credential_ready = intent
        .credentials
        .iter()
        .filter(|credential| credential_slot_ready(intent.mode, &credential.slot))
        .map(|credential| credential.slot.clone())
        .collect();
    Ok((entries, credential_ready, broker.to_owned()))
}

fn current_path_mode(metadata: &fs::Metadata) -> u32 {
    metadata.mode() & 0o7777
}

fn stored_current_state_digest(
    paths: &[CurrentPathIdentity],
    credential_ready: &BTreeSet<String>,
    broker: &str,
) -> Result<String> {
    #[derive(Serialize)]
    struct CurrentState<'a> {
        files: &'a [CurrentPathIdentity],
        credential_ready: &'a BTreeSet<String>,
        broker: &'a str,
    }
    Ok(sha256_hex(
        &serde_jcs::to_vec(&CurrentState {
            files: paths,
            credential_ready,
            broker,
        })
        .context("canonicalize setup current state")?,
    ))
}

struct OpenedDocument {
    identity: DocumentIdentity,
    bytes: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedSetupObject {
    current: CurrentPathIdentity,
    bytes: Option<Vec<u8>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedCandidateDocument {
    identity: DocumentIdentity,
    bytes: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedSetupGeneration {
    schema: String,
    plan_sha256: String,
    plan: SetupPlanV3,
    documents: Vec<RetainedSetupObject>,
    candidate_documents: Vec<RetainedCandidateDocument>,
}

fn approved_candidate_documents(plan: &SetupPlanV3) -> Result<Vec<RetainedCandidateDocument>> {
    let digest = sha256_hex(&serde_jcs::to_vec(plan)?);
    let documents = match crate::setup_transition::pending_generation(
        &plan.installation.paths,
        apply_owner_uid(plan)?,
        &digest,
    )? {
        Some(bytes) => {
            let generation: RetainedSetupGeneration =
                serde_json::from_slice(&bytes).context("parse retained setup generation")?;
            if generation.schema != "dev-auth-retained-setup-generation-v1"
                || generation.plan_sha256 != digest
                || generation.plan != *plan
            {
                bail!("retained setup generation does not match the approved plan");
            }
            generation.candidate_documents
        }
        None => plan
            .source_documents
            .iter()
            .map(capture_candidate_document)
            .collect::<Result<_>>()?,
    };
    validate_candidate_inventory(plan, &documents)?;
    Ok(documents)
}

fn validate_candidate_inventory(
    plan: &SetupPlanV3,
    documents: &[RetainedCandidateDocument],
) -> Result<()> {
    if documents.len() != plan.source_documents.len() {
        bail!("retained candidate inventory does not match the approved plan");
    }
    for (document, identity) in documents.iter().zip(&plan.source_documents) {
        if document.identity != *identity {
            bail!("retained candidate identity does not match the approved plan");
        }
        validate_candidate_bytes(document)?;
    }
    Ok(())
}

fn validate_candidate_bytes(document: &RetainedCandidateDocument) -> Result<()> {
    if document.bytes.is_empty()
        || document.bytes.len() as u64 > DOCUMENT_LIMIT
        || document.bytes.len() as u64 != document.identity.length
        || sha256_hex(&document.bytes) != document.identity.sha256
    {
        bail!("retained candidate bytes do not match their approved identity");
    }
    Ok(())
}

fn candidate_bytes<'a>(
    documents: &'a [RetainedCandidateDocument],
    identity: &DocumentIdentity,
) -> Result<&'a [u8]> {
    let document = documents
        .iter()
        .find(|document| document.identity == *identity)
        .context("approved candidate document is absent")?;
    validate_candidate_bytes(document)?;
    Ok(&document.bytes)
}

fn with_candidate_source<T>(
    documents: &[RetainedCandidateDocument],
    identity: &DocumentIdentity,
    apply: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    // Keep the existing bounded, digest-checking configuration installers as
    // the mutation boundary. Never recreate or overwrite the caller's source.
    let mut source = tempfile::NamedTempFile::new().context("stage retained setup input")?;
    source.write_all(candidate_bytes(documents, identity)?)?;
    source.as_file().sync_all()?;
    apply(source.path())
}

fn capture_retained_generation(plan: &SetupPlanV3, digest: &str) -> Result<Vec<u8>> {
    let mut documents = Vec::new();
    for current in &plan.current_paths {
        // Immutable release bytes retain their installation receipt authority;
        // the configuration journal never copies executable payloads.
        if matches!(
            current.kind.as_str(),
            "privileged_workload_launcher" | "privileged_setup_helper"
        ) {
            continue;
        }
        documents.push(capture_retained_object(current)?);
    }
    for account in plan.accounts.iter().chain(&plan.retiring_accounts) {
        for current in crate::setup::receipt_owned_user_integration_objects(
            &account.home,
            &account.name,
            account.uid,
            if plan.intent.mode == DeploymentMode::Strong {
                crate::setup::InstallMode::Strong
            } else {
                crate::setup::InstallMode::UserOnly
            },
        )? {
            documents.push(capture_retained_object(&current)?);
        }
    }
    // Integration inventories derive from receipts. Recheck their approved
    // bytes after inventory capture so a changed receipt cannot add authority.
    for current in plan.current_paths.iter().filter(|entry| {
        matches!(
            entry.kind.as_str(),
            "workload_launcher_receipt" | "desktop_entry_receipt"
        )
    }) {
        capture_retained_object(current)?;
    }
    serde_jcs::to_vec(&RetainedSetupGeneration {
        schema: "dev-auth-retained-setup-generation-v1".into(),
        plan_sha256: digest.into(),
        plan: plan.clone(),
        documents,
        candidate_documents: plan
            .source_documents
            .iter()
            .map(capture_candidate_document)
            .collect::<Result<_>>()?,
    })
    .context("serialize retained setup generation")
}

fn capture_candidate_document(identity: &DocumentIdentity) -> Result<RetainedCandidateDocument> {
    let document = read_document(&identity.path, &identity.kind, &identity.subject)?;
    if document.identity != *identity {
        bail!("candidate setup document changed after approval");
    }
    Ok(RetainedCandidateDocument {
        identity: document.identity,
        bytes: document.bytes,
    })
}

fn capture_retained_object(current: &CurrentPathIdentity) -> Result<RetainedSetupObject> {
    let bytes = match &current.identity {
        None => {
            match fs::symlink_metadata(&current.path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("inspect absent retained setup object"),
                Ok(_) => bail!("retained setup object appeared after approval"),
            }
            None
        }
        Some(identity) if identity.object_type == "file" => {
            let document = read_atomic_document(
                &current.path,
                &DocumentAuthority {
                    owner_uid: identity.owner_uid,
                    mode: identity.mode,
                    limit: DOCUMENT_LIMIT,
                },
            )?
            .context("retained setup document disappeared")?;
            if document.identity.length != identity.length
                || document.identity.sha256 != identity.sha256
            {
                bail!("retained setup document changed after approval");
            }
            Some(document.bytes)
        }
        Some(identity) if identity.object_type == "symlink" => {
            let metadata = fs::symlink_metadata(&current.path)?;
            let target = fs::read_link(&current.path)?;
            if !metadata.file_type().is_symlink()
                || metadata.uid() != identity.owner_uid
                || metadata.nlink() != identity.link_count
                || Some(&target) != identity.link_target.as_ref()
                || sha256_hex(target.as_os_str().as_bytes()) != identity.sha256
            {
                bail!("retained setup link changed after approval");
            }
            None
        }
        Some(_) => bail!("retained setup object has an unsupported type"),
    };
    Ok(RetainedSetupObject {
        current: current.clone(),
        bytes,
    })
}

fn read_document(path: &Path, kind: &str, subject: &str) -> Result<OpenedDocument> {
    let bytes = read_bounded(path)?;
    Ok(OpenedDocument {
        identity: DocumentIdentity {
            kind: kind.into(),
            subject: subject.into(),
            path: path.to_path_buf(),
            length: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        },
        bytes,
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    read_bounded_at(path, DOCUMENT_LIMIT, "setup source document")
}

fn read_bounded_at(path: &Path, limit: u64, description: &str) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("{description} path must be absolute");
    }
    let mut file = OpenOptions::new()
        .read(true)
        // Non-regular inputs must reach descriptor metadata inspection without
        // waiting for a FIFO writer. Regular-file reads remain synchronous.
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {description} {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect {description} {}", path.display()))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > limit
        || before.mode() & 0o022 != 0
    {
        bail!("{description} has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    let after = file
        .metadata()
        .with_context(|| format!("reinspect {description}"))?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        bail!("{description} changed while being read");
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn current_path_identity_preserves_special_permission_bits() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("launcher");
        fs::write(&path, b"non-executable mode fixture").unwrap();
        for mode in [0o755, 0o4755, 0o2755, 0o1755, 0o7755] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let metadata = fs::symlink_metadata(&path).unwrap();
            assert_eq!(metadata.mode() & 0o7777, mode, "fixture mode");
            assert_eq!(current_path_mode(&metadata), mode, "approved path identity");
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn generation_retains_receipt_owned_launchers_for_retiring_accounts() {
        let root = tempfile::tempdir().unwrap();
        let uid = nix::unistd::Uid::effective().as_raw();
        let executable = root.path().join("dev-auth");
        fs::write(&executable, b"fixture executable").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        crate::setup::reconcile_workload_launchers_at(
            root.path(),
            &executable,
            &["retiring-worker".into()],
            uid,
        )
        .unwrap();
        let intent = DeploymentIntent {
            schema: "dev-auth-deployment-v1".into(),
            mode: DeploymentMode::Strong,
            channel: crate::deployment::Channel::Stable,
            offline: true,
            activation: Activation::Inactive,
            administrator_policy: root.path().join("candidate.toml"),
            users: Vec::new(),
            credentials: Vec::new(),
        };
        let mut plan = SetupPlanV3 {
            authority_schema: Some("dev-auth-administrator-policy-v3".into()),
            schema: "dev-auth-setup-plan-v3".into(),
            intent_sha256: String::new(),
            intent,
            installation: SetupPlan {
                schema: "dev-auth-setup-plan-v2".into(),
                paths: crate::setup::SetupPaths {
                    data_root: root.path().join("data"),
                    bin_dir: root.path().join("bin"),
                },
                request: crate::setup::InstallRequest {
                    mode: crate::setup::InstallMode::Strong,
                    version: "0.4.0".into(),
                    source_executable: executable.clone(),
                    native_git: executable.clone(),
                    native_gh: executable.clone(),
                    activate_transparent_launchers: false,
                },
                source_length: 0,
                source_sha256: String::new(),
                verified_release: None,
            },
            source_documents: Vec::new(),
            accounts: Vec::new(),
            retiring_accounts: vec![NativeAccountIdentity {
                name: "retiring".into(),
                uid,
                gid: nix::unistd::Gid::effective().as_raw(),
                home: root.path().to_path_buf(),
            }],
            current_paths: Vec::new(),
            current_credential_ready: BTreeSet::new(),
            current_broker_state: "unavailable".into(),
            current_state_sha256: String::new(),
            actions: Vec::new(),
        };
        // Switching back to v2 must retain the v3 authority just as switching
        // to v3 retains v2. Neither selection is permission to lose rollback inputs.
        let mut user_only_intent = plan.intent.clone();
        user_only_intent.mode = DeploymentMode::UserOnly;
        for schema in [None, Some("dev-auth-administrator-policy-v3")] {
            let keys = expected_current_path_keys(
                &plan.installation,
                &user_only_intent,
                &plan.retiring_accounts,
                &[],
                schema,
            );
            for relative in [
                crate::policy_store::USER_CONFIG_RELATIVE_PATH,
                crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH,
                crate::policy_store::USER_POLICY_RELATIVE_PATH,
                crate::policy_store::USER_POLICY_V3_RELATIVE_PATH,
            ] {
                assert_eq!(
                    keys.iter()
                        .filter(|(_, _, path)| *path == root.path().join(relative))
                        .count(),
                    1,
                    "each authority version must be retained exactly once: {schema:?} {relative}"
                );
            }
        }
        for relative in [
            crate::policy_store::USER_CONFIG_RELATIVE_PATH,
            crate::policy_store::USER_CONFIG_V3_RELATIVE_PATH,
        ] {
            let path = root.path().join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"retiring configuration fixture").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        for (kind, subject, path) in expected_current_path_keys(
            &plan.installation,
            &plan.intent,
            &plan.accounts,
            &plan.retiring_accounts,
            plan.authority_schema.as_deref(),
        )
        .into_iter()
        .filter(|(_, subject, _)| subject == "retiring")
        {
            let identity = match fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    let document = read_document(&path, &kind, &subject).unwrap();
                    Some(CurrentFileIdentity {
                        object_type: "file".into(),
                        owner_uid: uid,
                        mode: metadata.mode() & 0o777,
                        link_count: 1,
                        length: document.identity.length,
                        sha256: document.identity.sha256,
                        link_target: None,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("fixture current path: {error}"),
            };
            plan.current_paths.push(CurrentPathIdentity {
                kind,
                subject,
                path,
                identity,
            });
        }
        let digest = sha256_hex(&serde_jcs::to_vec(&plan).unwrap());
        let bytes = capture_retained_generation(&plan, &digest).unwrap();
        let mut retained: RetainedSetupGeneration = serde_json::from_slice(&bytes).unwrap();
        for kind in [
            "retiring_user_configuration_v2",
            "retiring_user_configuration_v3",
        ] {
            assert!(retained
                .documents
                .iter()
                .any(|document| document.current.kind == kind
                    && document.bytes.as_deref()
                        == Some(b"retiring configuration fixture".as_slice())));
        }
        assert!(
            retained.documents.iter().any(|document| {
                document.current.subject == "retiring"
                    && document.current.kind == "workload_launcher"
                    && document.current.path == root.path().join(".local/bin/retiring-worker")
                    && document
                        .current
                        .identity
                        .as_ref()
                        .unwrap()
                        .link_target
                        .as_ref()
                        == Some(&executable)
            }),
            "removed account's receipt-owned launcher was not retained"
        );
        let unrelated = root.path().join(".local/bin/unowned-worker");
        fs::write(&unrelated, b"unowned worker").unwrap();
        restoration::retire_user_integrations(&retained, &executable).unwrap();
        assert!(
            fs::symlink_metadata(root.path().join(".local/bin/retiring-worker")).is_err(),
            "removed account's launcher survived deactivation"
        );
        assert_eq!(fs::read(&unrelated).unwrap(), b"unowned worker");
        crate::setup::verify_user_integrations_at(root.path(), &executable, &BTreeMap::new(), uid)
            .unwrap();

        // Exercise retained-policy selection without reading or changing the host's system policy.
        let prior_bytes = include_bytes!("../policy-v3.example.toml").to_vec();
        let prior = CurrentPathIdentity {
            kind: "administrator_policy".into(),
            subject: "system".into(),
            path: crate::policy_store::SYSTEM_POLICY_PATH.into(),
            identity: Some(CurrentFileIdentity {
                object_type: "file".into(),
                owner_uid: 0,
                mode: 0o600,
                link_count: 1,
                length: prior_bytes.len() as u64,
                sha256: sha256_hex(&prior_bytes),
                link_target: None,
            }),
        };
        plan.current_paths.push(prior.clone());
        retained.plan = plan.clone();
        let digest = sha256_hex(&serde_jcs::to_vec(&plan).unwrap());
        retained.plan_sha256.clone_from(&digest);
        retained.documents.push(RetainedSetupObject {
            current: prior,
            bytes: Some(prior_bytes.clone()),
        });
        let encoded = serde_jcs::to_vec(&retained).unwrap();
        assert_eq!(
            retained_prior_policy(&plan, &digest, &encoded).unwrap(),
            Some(prior_bytes)
        );
        assert!(retained_prior_policy(&plan, &"b".repeat(64), &encoded).is_err());
        let mut changed_plan = plan.clone();
        changed_plan.retiring_accounts[0].home = root.path().join("different-home");
        assert!(retained_prior_policy(&changed_plan, &digest, &encoded).is_err());
        retained
            .documents
            .last_mut()
            .unwrap()
            .bytes
            .as_mut()
            .unwrap()
            .push(b' ');
        assert!(
            retained_prior_policy(&plan, &digest, &serde_jcs::to_vec(&retained).unwrap()).is_err()
        );
    }

    #[test]
    fn retiring_account_inventory_is_derived_from_prior_policy_and_native_identity() {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .unwrap()
            .unwrap();
        let prior = include_str!("../policy-v3.example.toml").replace("automation", &user.name);
        let expected = NativeAccountIdentity {
            name: user.name,
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            home: user.dir,
        };
        assert_eq!(
            resolve_retiring_accounts(DeploymentMode::Strong, Some(prior.as_bytes()), &[]).unwrap(),
            vec![expected.clone()]
        );
        assert!(resolve_retiring_accounts(
            DeploymentMode::Strong,
            Some(prior.as_bytes()),
            &[expected]
        )
        .unwrap()
        .is_empty());
        assert!(resolve_retiring_accounts(DeploymentMode::Strong, None, &[])
            .unwrap()
            .is_empty());
        assert!(
            resolve_retiring_accounts(DeploymentMode::UserOnly, Some(prior.as_bytes()), &[])
                .is_err()
        );
        let missing = prior.replace(
            &nix::unistd::User::from_uid(nix::unistd::Uid::effective())
                .unwrap()
                .unwrap()
                .name,
            "dev-auth-nonexistent-retiring-fixture",
        );
        assert!(
            resolve_retiring_accounts(DeploymentMode::Strong, Some(missing.as_bytes()), &[])
                .is_err()
        );
    }

    #[test]
    fn recovery_failure_reports_preserve_unknown_progress_without_private_error_text() {
        let report =
            RecoveryProgress::new().report(Err(anyhow::anyhow!("private diagnostic sentinel")));
        assert_eq!(report.changed, Some(false));
        assert_eq!(report.exit_code, 4);
        assert_eq!(report.error_kind, Some(SetupRecoveryFailure::Authority));
        assert!(!serde_json::to_string(&report).unwrap().contains("sentinel"));

        let mut progress = RecoveryProgress::new();
        progress.enter_mutation();
        let report = progress.report(Err(anyhow::anyhow!("private diagnostic sentinel")));
        assert_eq!(report.changed, None);
        assert_eq!(report.exit_code, 1);
        assert_eq!(report.error_kind, Some(SetupRecoveryFailure::Operational));
        let encoded = serde_json::to_value(&report).unwrap();
        assert!(encoded["changed"].is_null());
        assert!(!serde_json::to_string(&report).unwrap().contains("sentinel"));

        let mut progress = RecoveryProgress::new();
        progress.enter_mutation();
        progress.record_change(true);
        progress.record_change(false);
        let report = progress.report(Err(anyhow::anyhow!("private diagnostic sentinel")));
        assert_eq!(report.changed, Some(true));
        assert_eq!(report.exit_code, 1);
        assert!(!serde_json::to_string(&report).unwrap().contains("sentinel"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn recovery_requires_native_ownership_before_inspecting_any_installation() {
        let wrong_mode = if nix::unistd::Uid::effective().is_root() {
            crate::setup::InstallMode::UserOnly
        } else {
            crate::setup::InstallMode::Strong
        };
        let report = recover_setup_v3(wrong_mode, &BTreeMap::new(), &mut &b""[..]);
        assert_eq!(report.exit_code, 4);
        assert_eq!(report.changed, Some(false));
        assert_eq!(report.next_action, "run_as_installation_owner");
    }

    #[test]
    fn candidate_retention_preserves_approved_bytes_and_rejects_source_drift() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("policy.toml");
        let bytes = b"# approved candidate policy\n";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let identity = read_document(&path, "administrator_policy", "system")
            .unwrap()
            .identity;
        let retained = capture_candidate_document(&identity).unwrap();
        assert_eq!(retained.identity, identity);
        assert_eq!(retained.bytes, bytes);
        fs::write(&path, b"# changed candidate policy\n").unwrap();
        assert!(capture_candidate_document(&identity).is_err());
        fs::remove_file(&path).unwrap();
        assert_eq!(retained.bytes, bytes);
        assert!(capture_candidate_document(&identity).is_err());
        let mut documents = vec![retained];
        let staged = with_candidate_source(&documents, &identity, |source| {
            assert_eq!(fs::read(source)?, bytes);
            Ok(source.to_path_buf())
        })
        .unwrap();
        assert!(
            !path.exists(),
            "recovery must not recreate the original input"
        );
        assert!(
            !staged.exists(),
            "temporary inputs must not outlive their use"
        );
        documents[0].bytes.push(b'!');
        assert!(candidate_bytes(&documents, &identity).is_err());
        assert!(with_candidate_source::<()>(&documents, &identity, |_| {
            panic!("drifted retention must not enter the configuration installer")
        })
        .is_err());
    }

    #[test]
    fn retained_document_preserves_exact_bytes_and_rejects_late_drift() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("policy.toml");
        let bytes = b"# prior policy fixture\n";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let current = CurrentPathIdentity {
            kind: "administrator_policy".into(),
            subject: "system".into(),
            path: path.clone(),
            identity: Some(CurrentFileIdentity {
                object_type: "file".into(),
                owner_uid: nix::unistd::Uid::effective().as_raw(),
                mode: 0o600,
                link_count: 1,
                length: bytes.len() as u64,
                sha256: sha256_hex(bytes),
                link_target: None,
            }),
        };
        let retained = capture_retained_object(&current).unwrap();
        assert_eq!(retained.bytes.as_deref(), Some(bytes.as_slice()));
        fs::write(&path, b"# replacement policy\n").unwrap();
        assert!(capture_retained_object(&current).is_err());
        assert_eq!(retained.bytes.as_deref(), Some(bytes.as_slice()));
        fs::remove_file(&path).unwrap();
        assert!(capture_retained_object(&current).is_err());
        let absent = CurrentPathIdentity {
            identity: None,
            ..current
        };
        assert!(capture_retained_object(&absent).unwrap().bytes.is_none());
        fs::write(&path, bytes).unwrap();
        assert!(capture_retained_object(&absent).is_err());
    }

    fn verified_release(artifact_path: &Path) -> crate::release_manifest::VerifiedDevAuthRelease {
        crate::release_manifest::VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: PathBuf::from("/var/lib/dev-auth/releases/cache/release/root.json"),
            manifest_path: PathBuf::from(
                "/var/lib/dev-auth/releases/cache/release/manifest.json",
            ),
            root_generation: 1,
            manifest_generation: 19,
            version: "0.3.8".into(),
            source_commit: "a".repeat(40),
            target: "x86_64-unknown-linux-gnu".into(),
            artifact_path: artifact_path.to_path_buf(),
            artifact_url: "https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv0.3.8/dev-auth-0.3.8-linux-x86_64".into(),
            artifact_length: 123,
            artifact_sha256: "b".repeat(64),
            root_sha256: "c".repeat(64),
            manifest_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn setup_candidate_requires_the_exact_canonical_accepted_cache_paths() {
        let artifact = PathBuf::from("/var/lib/dev-auth/releases/cache/release/artifact");
        let planned = verified_release(&artifact);
        let accepted = crate::stable_release::StagedStableRelease {
            verified: planned.clone(),
            directory: artifact.parent().unwrap().to_path_buf(),
        };
        assert_eq!(
            canonical_plan_release_source(&artifact, &planned, &accepted).unwrap(),
            artifact
        );

        assert!(canonical_plan_release_source(
            Path::new("/tmp/equally-signed-copy"),
            &planned,
            &accepted,
        )
        .is_err());

        let mut caller_paths = planned.clone();
        caller_paths.root_path = PathBuf::from("/tmp/root.json");
        assert!(canonical_plan_release_source(&artifact, &caller_paths, &accepted).is_err());
    }

    #[test]
    fn privileged_setup_plan_rejects_relative_and_writable_ancestor_custody() {
        assert!(validate_root_plan_path(Path::new("relative-plan.json")).is_err());
        assert!(validate_root_plan_path(Path::new("/run//dev-auth/plan.json")).is_err());
        assert!(validate_root_plan_path(Path::new("/run/dev-auth/../plan.json")).is_err());

        let root = tempfile::tempdir().unwrap();
        let plan = root.path().join("plan.json");
        fs::write(&plan, b"not parsed because custody fails first").unwrap();
        fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();
        let error = read_root_setup_plan_v3_at(&plan).unwrap_err().to_string();
        assert!(
            error.contains("unsafe ancestor authority")
                || error.contains("unsafe filesystem authority")
        );
        assert!(!error.contains("parse setup plan"));
    }

    #[test]
    fn credential_actions_persist_after_each_success_and_skip_completed_retries() {
        let mut completed = BTreeSet::new();
        let mut action_count = 0;
        let mut snapshots = Vec::new();
        assert!(complete_credential_action(
            "automation",
            &mut completed,
            || {
                action_count += 1;
                Ok(())
            },
            |completed| {
                snapshots.push(completed.clone());
                Ok(())
            },
        )
        .unwrap());
        assert!(!complete_credential_action(
            "automation",
            &mut completed,
            || {
                action_count += 1;
                Ok(())
            },
            |completed| {
                snapshots.push(completed.clone());
                Ok(())
            },
        )
        .unwrap());
        assert_eq!(action_count, 1);
        assert_eq!(snapshots, vec![BTreeSet::from(["automation".to_owned()])]);
    }

    #[test]
    fn credential_action_epoch_is_independent_of_noncredential_deployment_state() {
        let intent = DeploymentIntent {
            schema: "dev-auth-deployment-v1".into(),
            mode: DeploymentMode::Strong,
            channel: crate::deployment::Channel::Stable,
            offline: false,
            activation: Activation::Transparent,
            administrator_policy: PathBuf::from("/etc/dev-auth/policy.toml"),
            users: vec![crate::deployment::DeploymentUser {
                name: "alice".into(),
                config: PathBuf::from("/tmp/alice.toml"),
                policy: None,
            }],
            credentials: vec![DeploymentCredential {
                slot: "automation".into(),
                intent: CredentialIntent::Rotate,
            }],
        };
        let epoch = credential_action_set_sha256(&intent).unwrap();
        let unrelated_change = DeploymentIntent {
            offline: true,
            activation: Activation::Inactive,
            administrator_policy: PathBuf::from("/tmp/replacement-policy.toml"),
            users: Vec::new(),
            ..intent.clone()
        };
        assert_eq!(
            credential_action_set_sha256(&unrelated_change).unwrap(),
            epoch
        );

        let next_epoch = DeploymentIntent {
            credentials: vec![DeploymentCredential {
                slot: "automation".into(),
                intent: CredentialIntent::Preserve,
            }],
            ..intent
        };
        assert_ne!(credential_action_set_sha256(&next_epoch).unwrap(), epoch);
    }

    #[test]
    fn blocked_preserved_slots_prevent_any_credential_source_read() {
        let requirements = CredentialRequirements {
            required: BTreeSet::from(["rotation".to_owned()]),
            blocked: vec!["preserved".to_owned()],
        };
        let declared = BTreeSet::from(["preserved".to_owned(), "rotation".to_owned()]);
        let loaded = load_credentials_if_unblocked(&requirements, &declared, |_, _| {
            panic!("blocked setup must not read a credential source")
        })
        .unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn deployment_credential_intents_are_the_exact_policy_slot_set() {
        let policy = BTreeSet::from(["automation".to_owned(), "release".to_owned()]);
        let used = BTreeSet::from(["automation".to_owned()]);
        assert!(validate_deployment_credential_slots(&policy, &policy, &used).is_ok());
        assert!(validate_deployment_credential_slots(
            &policy,
            &BTreeSet::from(["automation".to_owned()]),
            &used,
        )
        .is_err());
        assert!(validate_deployment_credential_slots(
            &policy,
            &BTreeSet::from([
                "automation".to_owned(),
                "release".to_owned(),
                "undeclared".to_owned(),
            ]),
            &used,
        )
        .is_err());
    }

    #[test]
    fn strong_deployment_configures_every_administrator_authorized_user() {
        let policy = BTreeSet::from(["alice".to_owned(), "bob".to_owned()]);
        assert!(validate_deployment_user_set(DeploymentMode::Strong, &policy, &policy,).is_ok());
        assert!(validate_deployment_user_set(
            DeploymentMode::Strong,
            &policy,
            &BTreeSet::from(["alice".to_owned()]),
        )
        .is_err());
        assert!(validate_deployment_user_set(
            DeploymentMode::UserOnly,
            &policy,
            &BTreeSet::from(["alice".to_owned()]),
        )
        .is_ok());
    }

    #[test]
    fn transparent_strong_activation_always_requires_the_broker() {
        let intent = DeploymentIntent {
            schema: "dev-auth-deployment-v1".into(),
            mode: DeploymentMode::Strong,
            channel: crate::deployment::Channel::Stable,
            offline: false,
            activation: Activation::Transparent,
            administrator_policy: PathBuf::from("/etc/dev-auth/policy.toml"),
            users: Vec::new(),
            credentials: Vec::new(),
        };
        assert!(broker_desired(&intent));

        let inactive = DeploymentIntent {
            activation: Activation::Inactive,
            ..intent
        };
        assert!(!broker_desired(&inactive));

        let user_only = DeploymentIntent {
            mode: DeploymentMode::UserOnly,
            activation: Activation::Transparent,
            ..inactive
        };
        assert!(!broker_desired(&user_only));
    }

    #[test]
    fn setup_transaction_lock_is_runtime_scoped_not_installation_owned() {
        assert_eq!(
            deployment_lock_path_for(DeploymentMode::Strong, None).unwrap(),
            Path::new("/run/lock/dev-auth-setup-v3.lock")
        );
        assert_eq!(
            deployment_lock_path_for(DeploymentMode::UserOnly, Some(1000)).unwrap(),
            Path::new("/run/user/1000/dev-auth-setup-v3.lock")
        );
    }

    #[test]
    fn setup_workspace_roots_are_existing_canonical_private_authority() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        let owner_uid = fs::symlink_metadata(&workspace).unwrap().uid();
        validate_workspace_root_authority(
            &workspace,
            crate::policy_v2::WorkspaceAccess::ReadWrite,
            owner_uid,
        )
        .unwrap();

        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(validate_workspace_root_authority(
            &workspace,
            crate::policy_v2::WorkspaceAccess::ReadOnly,
            owner_uid,
        )
        .is_err());
        fs::set_permissions(&workspace, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = root.path().join("alias");
        symlink(&workspace, &alias).unwrap();
        assert!(validate_workspace_root_authority(
            &alias,
            crate::policy_v2::WorkspaceAccess::ReadOnly,
            owner_uid,
        )
        .is_err());
    }
}
