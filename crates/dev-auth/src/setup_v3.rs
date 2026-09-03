use crate::credential_input::{
    load_credential_inputs, CredentialInputContext, CredentialInputSource, CredentialMaterial,
};
use crate::deployment::{
    canonical_deployment_intent, Activation, CredentialIntent, DeploymentCredential,
    DeploymentIntent, DeploymentMode,
};
use crate::policy_v2::{
    parse_system_policy_v2, parse_user_config_v2, require_system_policy_narrows,
    resolve_policy_for_user, SystemMode,
};
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
    pub schema: String,
    pub intent: DeploymentIntent,
    pub intent_sha256: String,
    pub installation: SetupPlan,
    pub source_documents: Vec<DocumentIdentity>,
    pub accounts: Vec<NativeAccountIdentity>,
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
    revalidate_public_plan_inputs(plan)?;
    let _deployment_lock = InstallationLock::acquire(&deployment_lock_path(plan)?)
        .context("acquire full setup transaction lock")?;
    let declared = declared_credential_slots(plan);
    let before = deployment_state_fingerprint(plan)?;
    if postcondition_satisfied(plan, &digest) {
        return Ok(SetupApplyReportV3 {
            schema: "dev-auth-setup-apply-v3".into(),
            changed: false,
            verified: true,
            input_required: Vec::new(),
            blocked: Vec::new(),
            next_action: "none".into(),
            actions: Vec::new(),
        });
    }
    require_initial_or_resumable_state(plan)?;

    let mut actions = Vec::new();
    deactivate_and_stop_candidate(plan, &mut actions)?;
    let (_, install_digest) = render_plan(&plan.installation)?;
    crate::setup::apply_plan(&plan.installation, &install_digest)?;
    actions.push("install_release".into());
    install_configuration(plan, &mut actions)?;

    let requirements = required_credential_slots_for_plan(plan)?;
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
    if !postcondition_satisfied(plan, &digest) {
        bail!("setup plan v3 postcondition verification failed");
    }
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
    revalidate_public_plan_inputs(plan)?;
    let verified = postcondition_satisfied(plan, &digest);
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

fn revalidate_public_plan_inputs(plan: &SetupPlanV3) -> Result<()> {
    if let Some(release) = &plan.installation.verified_release {
        let storage =
            crate::stable_release::native_release_storage(plan.installation.request.mode)?;
        crate::stable_release::require_accepted_release(&storage, release)?;
    }
    let rebuilt = build_setup_plan_v3_at(plan.intent.clone(), plan.installation.clone(), false)?;
    if rebuilt.intent_sha256 != plan.intent_sha256
        || rebuilt.source_documents != plan.source_documents
        || rebuilt.accounts != plan.accounts
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
    let report = crate::setup::verify_at(&plan.installation.paths)
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

fn deactivate_and_stop_candidate(plan: &SetupPlanV3, actions: &mut Vec<String>) -> Result<()> {
    if fs::symlink_metadata(installation_receipt_path(plan)).is_err() {
        return Ok(());
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
    for account in &plan.accounts {
        crate::setup::reconcile_workload_launchers_at(
            &account.home,
            Path::new(&report.executable),
            &[],
            account.uid,
        )?;
        crate::setup::reconcile_desktop_entries_at(&account.home, &BTreeMap::new(), account.uid)?;
        actions.push(format!("deactivate_user_integrations:{}", account.name));
    }
    Ok(())
}

fn install_configuration(plan: &SetupPlanV3, actions: &mut Vec<String>) -> Result<()> {
    let administrator = document_identity(plan, "administrator_policy", "system")?;
    match plan.intent.mode {
        DeploymentMode::Strong => {
            crate::setup::reconcile_system_policy_at(
                &plan.installation.paths,
                &administrator.path,
                &administrator.sha256,
                current_document_sha(plan, "administrator_policy", "system")?,
            )?;
            actions.push("install_administrator_policy".into());
            for account in &plan.accounts {
                let config = document_identity(plan, "user_configuration", &account.name)?;
                crate::setup::reconcile_inactive_user_config_for_account_at(
                    &plan.installation.paths,
                    &config.path,
                    &config.sha256,
                    &account.name,
                    current_document_sha(plan, "user_configuration", &account.name)?,
                )?;
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
            crate::setup::reconcile_user_policy_for_account_at(
                &plan.installation.paths,
                &policy.path,
                &policy.sha256,
                &account.name,
                current_document_sha(plan, "user_policy", &account.name)?,
            )?;
            actions.push(format!("install_user_policy:{}", account.name));
            let config = document_identity(plan, "user_configuration", &account.name)?;
            crate::setup::reconcile_inactive_user_config_for_account_at(
                &plan.installation.paths,
                &config.path,
                &config.sha256,
                &account.name,
                current_document_sha(plan, "user_configuration", &account.name)?,
            )?;
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

fn postcondition_satisfied(plan: &SetupPlanV3, digest: &str) -> bool {
    verify_postcondition(plan, digest).is_ok()
}

fn verify_postcondition(plan: &SetupPlanV3, digest: &str) -> Result<()> {
    let setup = crate::setup::verify_at(&plan.installation.paths)?;
    let transparent_expected = plan.intent.activation == Activation::Transparent;
    if setup.version != plan.installation.request.version
        || setup.transparent_launchers_active != transparent_expected
    {
        bail!("installed release does not match the deployment intent");
    }
    let administrator = document_identity(plan, "administrator_policy", "system")?;
    let system_policy = parse_system_policy_v2(&read_document_bytes(&administrator.path)?)?;
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
        let config_path = crate::policy_store::user_config_path(&user);
        require_exact_document(&config_path, config_identity)?;
        let user_config = parse_user_config_v2(&read_document_bytes(&config_path)?)?;
        let policy = match plan.intent.mode {
            DeploymentMode::Strong => system_policy.clone(),
            DeploymentMode::UserOnly => {
                let policy_identity =
                    document_identity(plan, "user_policy", &account.name).unwrap_or(administrator);
                let path = crate::policy_store::user_policy_path(&user);
                require_exact_document(&path, policy_identity)?;
                parse_system_policy_v2(&read_document_bytes(&path)?)?
            }
        };
        let resolved = resolve_policy_for_user(&policy, &account.name, &user_config)?;
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
        DeploymentMode::Strong => crate::policy_store::load_system_policy()?,
        DeploymentMode::UserOnly => {
            let path = crate::policy_store::user_policy_path(&user);
            parse_system_policy_v2(&read_document_bytes(&path)?)?
        }
    };
    let config = parse_user_config_v2(&read_document_bytes(
        &crate::policy_store::user_config_path(&user),
    )?)?;
    Ok(resolve_policy_for_user(&policy, &account.name, &config)?.workloads)
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
    match mode {
        DeploymentMode::Strong if owner_uid.is_none() => {
            Ok(PathBuf::from("/run/lock/dev-auth-setup-v3.lock"))
        }
        DeploymentMode::UserOnly => Ok(PathBuf::from(format!(
            "/run/user/{}/dev-auth-setup-v3.lock",
            owner_uid.context("user-only deployment lock has no native owner")?
        ))),
        DeploymentMode::Strong => bail!("strong deployment lock cannot have a user owner"),
    }
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
        paths.push(crate::policy_store::user_config_path(&user));
        if plan.intent.mode == DeploymentMode::UserOnly {
            paths.push(crate::policy_store::user_policy_path(&user));
        }
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
    let policy =
        parse_system_policy_v2(&administrator.bytes).context("validate administrator policy")?;
    let mode = match intent.mode {
        DeploymentMode::Strong => crate::setup::InstallMode::Strong,
        DeploymentMode::UserOnly => crate::setup::InstallMode::UserOnly,
    };
    let installation = crate::setup::build_verified_release_plan_with_native_programs(
        mode,
        false,
        verified,
        PathBuf::from(&policy.programs.git),
        PathBuf::from(&policy.programs.gh),
    )?;
    build_setup_plan_v3(intent, installation)
}

pub fn build_setup_plan_v3_at(
    intent: DeploymentIntent,
    installation: SetupPlan,
    require_privileged: bool,
) -> Result<SetupPlanV3> {
    let intent_bytes = canonical_deployment_intent(&intent)?;
    let intent_sha256 = sha256_hex(&intent_bytes);
    render_plan(&installation).context("validate staged installation plan")?;
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

    let administrator = read_document(
        &intent.administrator_policy,
        "administrator_policy",
        "system",
    )?;
    let administrator_policy =
        parse_system_policy_v2(&administrator.bytes).context("validate administrator policy")?;
    let expected_policy_mode = match intent.mode {
        DeploymentMode::Strong => SystemMode::Strong,
        DeploymentMode::UserOnly => SystemMode::UserOnly,
    };
    if administrator_policy.mode != expected_policy_mode {
        bail!("administrator policy mode does not match deployment mode");
    }
    if installation.request.native_git != Path::new(&administrator_policy.programs.git) {
        bail!("staged installation does not target the administrator-pinned native Git");
    }
    if installation.request.native_gh != Path::new(&administrator_policy.programs.gh) {
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
        if !administrator_policy.allowed_users.contains(&account.name) {
            bail!("native account is outside administrator policy");
        }
        let config = read_document(&user.config, "user_configuration", &account.name)?;
        let user_config = parse_user_config_v2(&config.bytes).with_context(|| {
            format!("validate configuration for native account {}", account.name)
        })?;
        let mut resolved =
            resolve_policy_for_user(&administrator_policy, &account.name, &user_config)
                .with_context(|| format!("resolve policy for native account {}", account.name))?;
        documents.push(config.identity);
        if let Some(policy_path) = &user.policy {
            let user_policy = read_document(policy_path, "user_policy", &account.name)?;
            let parsed = parse_system_policy_v2(&user_policy.bytes)
                .with_context(|| format!("validate user-only policy for {}", account.name))?;
            if intent.mode != DeploymentMode::UserOnly || parsed.mode != SystemMode::UserOnly {
                bail!("per-user policy is valid only for user-only deployment");
            }
            require_system_policy_narrows(&administrator_policy, &parsed).with_context(|| {
                format!(
                    "prove user-only policy narrows administrator policy for {}",
                    account.name
                )
            })?;
            resolved = resolve_policy_for_user(&parsed, &account.name, &user_config)
                .with_context(|| format!("resolve user-only policy for {}", account.name))?;
            documents.push(user_policy.identity);
        }
        used_credential_slots.extend(
            resolved
                .authority_profiles
                .values()
                .map(|profile| profile.credential_slot.clone()),
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
        &administrator_policy.allowed_users.iter().cloned().collect(),
        &account_names,
    )?;
    documents.sort_by(|left, right| {
        (&left.kind, &left.subject, &left.path).cmp(&(&right.kind, &right.subject, &right.path))
    });
    accounts.sort_by(|left, right| left.name.cmp(&right.name));

    let declared_credential_slots = intent
        .credentials
        .iter()
        .map(|credential| credential.slot.clone())
        .collect::<BTreeSet<_>>();
    let policy_credential_slots = administrator_policy
        .credential_slots
        .keys()
        .cloned()
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

    let (current_paths, current_credential_ready, current_broker_state) =
        current_state_snapshot(&installation, &intent, &accounts)?;
    let current_state_sha256 = stored_current_state_digest(
        &current_paths,
        &current_credential_ready,
        &current_broker_state,
    )?;
    let actions = planned_action_contract(&intent);
    let plan = SetupPlanV3 {
        schema: "dev-auth-setup-plan-v3".into(),
        intent,
        intent_sha256,
        installation,
        source_documents: documents,
        accounts,
        current_paths,
        current_credential_ready,
        current_broker_state,
        current_state_sha256,
        actions,
    };
    validate_setup_plan_v3(&plan)?;
    Ok(plan)
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
    policy: &crate::policy_v2::SystemPolicyV2,
    mode: DeploymentMode,
    owner_uid: u32,
) -> Result<()> {
    let mut programs = vec![
        ("1Password CLI", policy.programs.op.as_str()),
        ("native Git", policy.programs.git.as_str()),
        ("native GitHub CLI", policy.programs.gh.as_str()),
        ("native SSH", policy.programs.ssh.as_str()),
        ("native SSH key tool", policy.programs.ssh_keygen.as_str()),
    ];
    programs.extend(
        policy
            .trusted_launchers
            .iter()
            .map(|(name, path)| (name.as_str(), path.as_str())),
    );
    programs.extend(
        policy
            .sandbox_adapters
            .iter()
            .map(|(name, adapter)| (name.as_str(), adapter.executable.as_str())),
    );
    for (description, path) in programs {
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
        != expected_current_path_keys(&plan.installation, &plan.intent, &plan.accounts)
    {
        bail!("setup plan v3 current-state paths do not match the deployment authority");
    }
    require_canonical_installation_layout(
        plan.intent.mode,
        &plan.installation.paths,
        plan.accounts.first().map(|account| account.home.as_path()),
    )?;
    render_plan(&plan.installation).context("validate nested installation plan")?;
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
) -> Vec<(String, String, PathBuf)> {
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
                    account.home.join(".config/dev-auth/policy-v2.toml"),
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
            account.home.join(".config/dev-auth/config-v2.toml"),
        ));
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
) -> Result<(Vec<CurrentPathIdentity>, BTreeSet<String>, String)> {
    let paths = expected_current_path_keys(installation, intent, accounts);
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
                        mode: metadata.mode() & 0o777,
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
                        mode: metadata.mode() & 0o777,
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
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
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
