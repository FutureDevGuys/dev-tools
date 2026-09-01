use crate::credential_input::CredentialMaterial;
use crate::deployment::{
    canonical_deployment_intent, Activation, CredentialIntent, DeploymentCredential,
    DeploymentIntent, DeploymentMode,
};
use crate::policy_v2::{
    parse_system_policy_v2, parse_user_config_v2, resolve_policy_for_user, SystemMode,
};
use crate::setup::{render_plan, SetupPlan};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const DOCUMENT_LIMIT: u64 = 1024 * 1024;

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
    pub owner_uid: u32,
    pub mode: u32,
    pub length: u64,
    pub sha256: String,
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
    plan_sha256: String,
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
    let (_, digest) = render_setup_plan_v3(plan)?;
    let completed = read_credential_action_receipt(plan, &digest)?;
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
    let (_, digest) = render_setup_plan_v3(plan)?;
    if digest != approved_sha256.to_ascii_lowercase() {
        bail!("setup plan v3 does not match the approved digest");
    }
    require_apply_identity(plan)?;
    revalidate_public_plan_inputs(plan)?;
    let declared = plan
        .intent
        .credentials
        .iter()
        .map(|credential| credential.slot.clone())
        .collect::<BTreeSet<_>>();
    if credentials.keys().any(|slot| !declared.contains(slot)) {
        bail!("credential material names a slot outside the approved setup plan");
    }
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
    let mut blocked = requirements.blocked;
    blocked.sort();
    blocked.dedup();
    let input_required = requirements
        .required
        .iter()
        .filter(|slot| !credentials.contains_key(*slot))
        .cloned()
        .collect::<Vec<_>>();
    if !blocked.is_empty() || !input_required.is_empty() {
        let after = deployment_state_fingerprint(plan)?;
        let next_action = if input_required.is_empty() {
            "resolve_blocked_credential_slots"
        } else {
            "provide_credential_input"
        };
        return Ok(SetupApplyReportV3 {
            schema: "dev-auth-setup-apply-v3".into(),
            changed: before != after,
            verified: false,
            input_required,
            blocked,
            next_action: next_action.into(),
            actions,
        });
    }

    apply_credential_actions(plan, &digest, credentials, &mut actions)?;
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

pub fn setup_apply_candidate_path(
    plan: &SetupPlanV3,
    approved_sha256: &str,
) -> Result<Option<PathBuf>> {
    let (_, digest) = render_setup_plan_v3(plan)?;
    if digest != approved_sha256.to_ascii_lowercase() {
        bail!("setup plan v3 does not match the approved digest");
    }
    let source = &plan.installation.request.source_executable;
    let (source_length, source_sha256) = crate::setup::setup_executable_identity(source)?;
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
        Ok(Some(source.clone()))
    }
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
                crate::setup::reconcile_user_config_for_account_at(
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
            crate::setup::reconcile_user_config_for_account_at(
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
    digest: &str,
    credentials: &BTreeMap<String, CredentialMaterial>,
    actions: &mut Vec<String>,
) -> Result<()> {
    let mut completed = read_credential_action_receipt(plan, digest)?;
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
                rotate_credential(plan, &credential.slot, material.expose())?;
                completed.insert(credential.slot.clone());
                actions.push(format!("rotate_credential:{}", credential.slot));
            }
            CredentialIntent::Rotate => {}
            CredentialIntent::Revoke => {
                if ready {
                    revoke_credential(plan, &credential.slot)?;
                    actions.push(format!("revoke_credential:{}", credential.slot));
                }
                completed.insert(credential.slot.clone());
            }
        }
    }
    write_credential_action_receipt(plan, digest, &completed)
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
    if setup.version != plan.installation.request.version
        || setup.transparent_launchers_active != (plan.intent.activation == Activation::Transparent)
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
        crate::setup::verify_user_integrations_at(
            &account.home,
            Path::new(&setup.executable),
            &resolved.workloads,
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
            bail!("system broker remains active after credential revocation");
        }
    }
    Ok(())
}

fn verify_credential_postcondition(plan: &SetupPlanV3, digest: &str) -> Result<()> {
    let completed = read_credential_action_receipt(plan, digest)?;
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
    intent
        .credentials
        .iter()
        .any(|credential| credential.intent != CredentialIntent::Revoke)
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
        .join("credential-actions-v1.json")
}

fn read_credential_action_receipt(plan: &SetupPlanV3, digest: &str) -> Result<BTreeSet<String>> {
    let path = credential_action_receipt_path(plan);
    let bytes = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(error).context("inspect credential action receipt"),
        Ok(metadata) => {
            let owner = apply_owner_uid(plan)?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != owner
                || metadata.mode() & 0o777 != 0o600
                || metadata.len() > DOCUMENT_LIMIT
            {
                bail!("credential action receipt has unsafe authority");
            }
            read_bounded(&path)?
        }
    };
    let receipt: CredentialActionReceipt =
        serde_json::from_slice(&bytes).context("parse credential action receipt")?;
    if receipt.schema != "dev-auth-credential-actions-v1" || receipt.plan_sha256 != digest {
        return Ok(BTreeSet::new());
    }
    Ok(receipt.completed)
}

fn write_credential_action_receipt(
    plan: &SetupPlanV3,
    digest: &str,
    completed: &BTreeSet<String>,
) -> Result<()> {
    let receipt = CredentialActionReceipt {
        schema: "dev-auth-credential-actions-v1".into(),
        plan_sha256: digest.into(),
        completed: completed.clone(),
    };
    let bytes = serde_jcs::to_vec(&receipt).context("serialize credential action receipt")?;
    let path = credential_action_receipt_path(plan);
    let parent = path
        .parent()
        .context("credential action receipt has no parent")?;
    if !parent.is_dir() {
        bail!("credential action receipt parent is absent");
    }
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .context("create credential action receipt")?;
    file.write_all(&bytes)
        .context("write credential action receipt")?;
    file.sync_all().context("sync credential action receipt")?;
    fs::rename(&temporary, &path).context("publish credential action receipt")
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

pub fn build_setup_plan_v3_at(
    intent: DeploymentIntent,
    installation: SetupPlan,
    require_privileged: bool,
) -> Result<SetupPlanV3> {
    let intent_bytes = canonical_deployment_intent(&intent)?;
    let intent_sha256 = sha256_hex(&intent_bytes);
    render_plan(&installation).context("validate staged installation plan")?;
    let expected_install_mode = match intent.mode {
        DeploymentMode::Strong => crate::setup::InstallMode::Strong,
        DeploymentMode::UserOnly => crate::setup::InstallMode::UserOnly,
    };
    if installation.request.mode != expected_install_mode
        || installation.request.activate_transparent_launchers
    {
        bail!("deployment intent and staged installation plan disagree");
    }
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

    let current_user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
        .context("effective native account does not exist")?;
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
        let resolved = resolve_policy_for_user(&administrator_policy, &account.name, &user_config)
            .with_context(|| format!("resolve policy for native account {}", account.name))?;
        used_credential_slots.extend(
            resolved
                .authority_profiles
                .values()
                .map(|profile| profile.credential_slot.clone()),
        );
        documents.push(config.identity);
        if let Some(policy_path) = &user.policy {
            let user_policy = read_document(policy_path, "user_policy", &account.name)?;
            let parsed = parse_system_policy_v2(&user_policy.bytes)
                .with_context(|| format!("validate user-only policy for {}", account.name))?;
            if intent.mode != DeploymentMode::UserOnly || parsed.mode != SystemMode::UserOnly {
                bail!("per-user policy is valid only for user-only deployment");
            }
            let resolved = resolve_policy_for_user(&parsed, &account.name, &user_config)
                .with_context(|| format!("resolve user-only policy for {}", account.name))?;
            used_credential_slots.extend(
                resolved
                    .authority_profiles
                    .values()
                    .map(|profile| profile.credential_slot.clone()),
            );
            documents.push(user_policy.identity);
        }
        accounts.push(NativeAccountIdentity {
            name: account.name,
            uid: account.uid.as_raw(),
            gid: account.gid.as_raw(),
            home: account.dir,
        });
    }
    documents.sort_by(|left, right| {
        (&left.kind, &left.subject, &left.path).cmp(&(&right.kind, &right.subject, &right.path))
    });
    accounts.sort_by(|left, right| left.name.cmp(&right.name));

    let declared_credential_slots = intent
        .credentials
        .iter()
        .map(|credential| credential.slot.clone())
        .collect::<BTreeSet<_>>();
    if declared_credential_slots
        .iter()
        .any(|slot| !administrator_policy.credential_slots.contains_key(slot))
    {
        bail!("deployment intent names a credential slot outside administrator policy");
    }
    if !used_credential_slots.is_subset(&declared_credential_slots) {
        bail!("deployment intent omits a credential slot required by a user authority profile");
    }
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
    let actions = planned_actions(&intent);
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
    let plan: SetupPlanV3 = serde_json::from_slice(&bytes).context("parse setup plan v3")?;
    validate_setup_plan_v3(&plan)?;
    Ok(plan)
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
    let mut paths = vec![
        (
            "installation_receipt".to_owned(),
            "system".to_owned(),
            installation.paths.data_root.join("install-v2.json"),
        ),
        (
            "credential_actions".to_owned(),
            "system".to_owned(),
            installation
                .paths
                .data_root
                .join("credential-actions-v1.json"),
        ),
    ];
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
        paths.push((
            "user_configuration".into(),
            account.name.clone(),
            account.home.join(".config/dev-auth/config-v2.toml"),
        ));
    }
    paths.sort();
    paths
}

fn planned_actions(intent: &DeploymentIntent) -> Vec<SetupActionV3> {
    let mut actions = Vec::new();
    let mut push = |kind: &str, subject: Option<String>| {
        actions.push(SetupActionV3 {
            order: actions.len() as u32,
            kind: kind.into(),
            subject,
        });
    };
    push("deactivate_transparent_launchers", None);
    push("stop_broker", None);
    push("install_release", None);
    push("install_administrator_policy", None);
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
    push("install_system_integrations", None);
    for user in &intent.users {
        push("install_user_integrations", Some(user.name.clone()));
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
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    bail!("setup current-state path is not a regular non-link file");
                }
                let document = read_bounded(&path)?;
                Some(CurrentFileIdentity {
                    owner_uid: metadata.uid(),
                    mode: metadata.mode() & 0o777,
                    length: document.len() as u64,
                    sha256: sha256_hex(&document),
                })
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
    if !path.is_absolute() {
        bail!("setup source document path must be absolute");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open setup source document {}", path.display()))?;
    let before = file
        .metadata()
        .with_context(|| format!("inspect setup source document {}", path.display()))?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || before.len() == 0
        || before.len() > DOCUMENT_LIMIT
        || before.mode() & 0o022 != 0
    {
        bail!("setup source document has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(DOCUMENT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .context("read setup source document")?;
    let after = file.metadata().context("reinspect setup source document")?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        bail!("setup source document changed while being read");
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
