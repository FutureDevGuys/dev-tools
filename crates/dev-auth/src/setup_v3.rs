use crate::deployment::{
    canonical_deployment_intent, Activation, DeploymentIntent, DeploymentMode,
};
use crate::policy_v2::{parse_system_policy_v2, parse_user_config_v2, resolve_policy, SystemMode};
use crate::setup::{render_plan, SetupPlan};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
    pub current_state_sha256: String,
    pub actions: Vec<SetupActionV3>,
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
        resolve_policy(&administrator_policy, &user_config)
            .with_context(|| format!("resolve policy for native account {}", account.name))?;
        documents.push(config.identity);
        if let Some(policy_path) = &user.policy {
            let user_policy = read_document(policy_path, "user_policy", &account.name)?;
            let parsed = parse_system_policy_v2(&user_policy.bytes)
                .with_context(|| format!("validate user-only policy for {}", account.name))?;
            if intent.mode != DeploymentMode::UserOnly || parsed.mode != SystemMode::UserOnly {
                bail!("per-user policy is valid only for user-only deployment");
            }
            resolve_policy(&parsed, &user_config)
                .with_context(|| format!("resolve user-only policy for {}", account.name))?;
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

    let current_state_sha256 = current_state_digest(&installation, &intent, &accounts)?;
    let actions = planned_actions(&intent);
    let plan = SetupPlanV3 {
        schema: "dev-auth-setup-plan-v3".into(),
        intent,
        intent_sha256,
        installation,
        source_documents: documents,
        accounts,
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
        || plan.actions.last().map(|action| action.kind.as_str()) != Some("verify")
        || plan
            .actions
            .iter()
            .enumerate()
            .any(|(index, action)| action.order != index as u32)
    {
        bail!("dev-auth setup plan v3 has an unsupported contract");
    }
    render_plan(&plan.installation).context("validate nested installation plan")?;
    if plan.installation.request.activate_transparent_launchers {
        bail!("setup plan v3 must stage the release with transparent launchers inactive");
    }
    Ok(())
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
    push("start_broker", None);
    if intent.activation == Activation::Transparent {
        push("activate_transparent_launchers", None);
    }
    push("verify", None);
    actions
}

fn current_state_digest(
    installation: &SetupPlan,
    intent: &DeploymentIntent,
    accounts: &[NativeAccountIdentity],
) -> Result<String> {
    #[derive(Serialize)]
    struct StateEntry {
        path: PathBuf,
        identity: Option<(u64, String)>,
    }
    let mut paths = vec![installation.paths.data_root.join("install-v2.json")];
    match intent.mode {
        DeploymentMode::Strong => paths.push(PathBuf::from("/etc/dev-auth/policy.toml")),
        DeploymentMode::UserOnly => {
            for account in accounts {
                paths.push(account.home.join(".config/dev-auth/policy-v2.toml"));
            }
        }
    }
    for account in accounts {
        paths.push(account.home.join(".config/dev-auth/config-v2.toml"));
    }
    paths.sort();
    paths.dedup();
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let identity = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    bail!("setup current-state path is not a regular non-link file");
                }
                let document = read_bounded(&path)?;
                Some((document.len() as u64, sha256_hex(&document)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).context("inspect setup current-state path"),
        };
        entries.push(StateEntry { path, identity });
    }
    Ok(sha256_hex(
        &serde_jcs::to_vec(&entries).context("canonicalize setup current state")?,
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
