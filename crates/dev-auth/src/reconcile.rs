use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const DOCUMENT_LIMIT: u64 = 1024 * 1024;
const PLAN_SCHEMA: &str = "dev-auth-user-config-reconcile-plan-v1";
pub use dev_tools_reconcile_protocol::ReconcileResult;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileState {
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserConfigReconcilePlan {
    pub schema: String,
    pub installation_paths: crate::setup::SetupPaths,
    pub installation_version: String,
    pub installation_sha256: String,
    pub account_name: String,
    pub account_uid: u32,
    pub account_home: PathBuf,
    pub source: PathBuf,
    pub source_state: FileState,
    pub policy: PathBuf,
    pub policy_state: FileState,
    pub destination: PathBuf,
    pub current_state: Option<FileState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserConfigPlanOutcome {
    Ready {
        plan: Box<UserConfigReconcilePlan>,
        result: ReconcileResult,
    },
    Deferred(ReconcileResult),
}

pub fn plan_user_config_for_protocol(source: &Path) -> Result<UserConfigPlanOutcome> {
    if !source.is_absolute() {
        bail!("reconcile source path must be absolute");
    }
    if current_installation_receipt()?.is_none() {
        return Ok(UserConfigPlanOutcome::Deferred(deferred_result(
            "setup",
            "system_installation_absent",
        )?));
    }
    let (_, installation) = crate::setup::current_installation()?;
    let user = native_user()?;
    let policy = match installation.mode {
        crate::setup::InstallMode::Strong => PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH),
        crate::setup::InstallMode::UserOnly => crate::policy_store::user_policy_path(&user),
    };
    match fs::symlink_metadata(&policy) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(UserConfigPlanOutcome::Deferred(deferred_result(
                "install_policy",
                "administrator_policy_absent",
            )?));
        }
        Err(error) => return Err(error).context("inspect reconcile policy readiness"),
        Ok(_) => {}
    }
    if installation.mode == crate::setup::InstallMode::Strong {
        match crate::broker_client::probe_system_broker() {
            crate::broker_protocol::BrokerSessionProbe::NoSession
            | crate::broker_protocol::BrokerSessionProbe::Verified { .. } => {}
            crate::broker_protocol::BrokerSessionProbe::Unavailable { .. } => {
                return Ok(UserConfigPlanOutcome::Deferred(deferred_result(
                    "start_broker",
                    "system_broker_unavailable",
                )?));
            }
            crate::broker_protocol::BrokerSessionProbe::Invalid { .. } => {
                bail!("system broker returned an invalid session result")
            }
        }
    }
    let (plan, result) = plan_user_config(source)?;
    Ok(UserConfigPlanOutcome::Ready {
        plan: Box::new(plan),
        result,
    })
}

pub fn plan_user_config(source: &Path) -> Result<(UserConfigReconcilePlan, ReconcileResult)> {
    if !source.is_absolute() {
        bail!("reconcile source path must be absolute");
    }
    let (installation_paths, installation) = crate::setup::current_installation()?;
    let user = native_user()?;
    let (source_bytes, source_state) = read_public_document(source, user.uid.as_raw())?;
    let user_config = crate::policy_v2::parse_user_config_v2(&source_bytes)?;
    let policy = match installation.mode {
        crate::setup::InstallMode::Strong => PathBuf::from(crate::policy_store::SYSTEM_POLICY_PATH),
        crate::setup::InstallMode::UserOnly => crate::policy_store::user_policy_path(&user),
    };
    let (policy_bytes, policy_state) = read_public_document(&policy, user.uid.as_raw())?;
    let parsed_policy = crate::policy_v2::parse_system_policy_v2(&policy_bytes)?;
    crate::policy_v2::resolve_policy_for_user(&parsed_policy, &user.name, &user_config)?;
    let destination = crate::policy_store::user_config_path(&user);
    let current_state = optional_installed_document(&destination, user.uid.as_raw())?;
    let plan = UserConfigReconcilePlan {
        schema: PLAN_SCHEMA.into(),
        installation_paths,
        installation_version: installation.version,
        installation_sha256: installation.executable_sha256,
        account_name: user.name,
        account_uid: user.uid.as_raw(),
        account_home: user.dir,
        source: source.to_path_buf(),
        source_state,
        policy,
        policy_state,
        destination,
        current_state,
    };
    validate_plan(&plan)?;
    let verified = plan.current_state.as_ref() == Some(&plan.source_state);
    Ok((
        plan,
        result(!verified, verified, if verified { "none" } else { "apply" })?,
    ))
}

pub fn apply_user_config(
    plan: &UserConfigReconcilePlan,
    approved_sha256: &str,
) -> Result<ReconcileResult> {
    let (_, digest) = render_plan(plan)?;
    if digest != approved_sha256.to_ascii_lowercase() {
        bail!("reconcile plan does not match the approved digest");
    }
    revalidate_plan(plan)?;
    if plan.current_state.as_ref() == Some(&plan.source_state) {
        return result(false, true, "none");
    }
    crate::setup::reconcile_user_config_for_account_at(
        &plan.installation_paths,
        &plan.source,
        &plan.source_state.sha256,
        &plan.account_name,
        plan.current_state
            .as_ref()
            .map(|state| state.sha256.as_str()),
    )?;
    let installed = optional_installed_document(&plan.destination, plan.account_uid)?;
    if installed.as_ref() != Some(&plan.source_state) {
        bail!("reconciled user configuration did not reach its approved postcondition");
    }
    result(true, true, "none")
}

pub fn verify_user_config(source: &Path) -> Result<ReconcileResult> {
    let (plan, _) = plan_user_config(source)?;
    let verified = plan.current_state.as_ref() == Some(&plan.source_state);
    result(false, verified, if verified { "none" } else { "apply" })
}

pub fn render_plan(plan: &UserConfigReconcilePlan) -> Result<(Vec<u8>, String)> {
    validate_plan(plan)?;
    let bytes = serde_jcs::to_vec(plan).context("canonicalize user reconcile plan")?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, digest))
}

pub fn write_plan(path: &Path, plan: &UserConfigReconcilePlan) -> Result<String> {
    if !path.is_absolute() {
        bail!("reconcile plan output path must be absolute");
    }
    let parent = path.parent().context("reconcile plan has no parent")?;
    let metadata = fs::symlink_metadata(parent).context("inspect reconcile plan parent")?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("reconcile plan parent has unsafe authority");
    }
    let (bytes, digest) = render_plan(plan)?;
    let temporary = path.with_extension(format!("new-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&temporary)
        .context("create reconcile plan")?;
    file.write_all(&bytes).context("write reconcile plan")?;
    let user = native_user()?;
    if nix::unistd::Uid::effective().is_root() {
        nix::unistd::fchown(&file, Some(user.uid), Some(user.gid))
            .context("assign reconcile plan to native caller")?;
    }
    file.sync_all().context("sync reconcile plan")?;
    fs::rename(&temporary, path).context("publish reconcile plan")?;
    Ok(digest)
}

pub fn read_plan(path: &Path) -> Result<UserConfigReconcilePlan> {
    let user = native_user()?;
    let (bytes, _) = read_public_document(path, user.uid.as_raw())?;
    let plan: UserConfigReconcilePlan =
        serde_json::from_slice(&bytes).context("parse user reconcile plan")?;
    validate_plan(&plan)?;
    Ok(plan)
}

fn revalidate_plan(plan: &UserConfigReconcilePlan) -> Result<()> {
    validate_plan(plan)?;
    let (paths, installation) = crate::setup::current_installation()?;
    let user = native_user()?;
    if paths != plan.installation_paths
        || installation.version != plan.installation_version
        || installation.executable_sha256 != plan.installation_sha256
        || user.name != plan.account_name
        || user.uid.as_raw() != plan.account_uid
        || user.dir != plan.account_home
    {
        bail!("reconcile authority changed after planning");
    }
    let (_, source) = read_public_document(&plan.source, plan.account_uid)?;
    let (_, policy) = read_public_document(&plan.policy, plan.account_uid)?;
    let current = optional_installed_document(&plan.destination, plan.account_uid)?;
    if source != plan.source_state || policy != plan.policy_state || current != plan.current_state {
        bail!("reconcile inputs changed after planning");
    }
    Ok(())
}

fn validate_plan(plan: &UserConfigReconcilePlan) -> Result<()> {
    if plan.schema != PLAN_SCHEMA
        || !plan.source.is_absolute()
        || !plan.policy.is_absolute()
        || !plan.destination.is_absolute()
        || plan.account_name.is_empty()
        || plan.account_home.join(".config/dev-auth/config-v2.toml") != plan.destination
        || plan.installation_version.is_empty()
    {
        bail!("user reconcile plan has an unsupported contract");
    }
    validate_state(&plan.source_state)?;
    validate_state(&plan.policy_state)?;
    if let Some(state) = &plan.current_state {
        validate_state(state)?;
    }
    Ok(())
}

fn validate_state(state: &FileState) -> Result<()> {
    if state.length == 0
        || state.length > DOCUMENT_LIMIT
        || state.sha256.len() != 64
        || !state.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("reconcile document identity is invalid");
    }
    Ok(())
}

fn native_user() -> Result<nix::unistd::User> {
    let uid = nix::unistd::Uid::effective();
    if !uid.is_root() {
        return nix::unistd::User::from_uid(uid)?
            .context("effective native account does not exist");
    }
    let sudo_uid = std::env::var("SUDO_UID")
        .context("root user reconciliation requires a native sudo caller")?
        .parse::<u32>()
        .context("native sudo caller UID is invalid")?;
    if sudo_uid == 0 {
        bail!("root user reconciliation requires a non-root native sudo caller");
    }
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(sudo_uid))?
        .context("native sudo caller account does not exist")?;
    let sudo_user = std::env::var("SUDO_USER").context("native sudo caller name is absent")?;
    if sudo_user != user.name {
        bail!("native sudo caller identity is inconsistent");
    }
    Ok(user)
}

fn optional_installed_document(path: &Path, owner_uid: u32) -> Result<Option<FileState>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("inspect installed user configuration"),
        Ok(_) => read_public_document(path, owner_uid).map(|(_, state)| Some(state)),
    }
}

fn read_public_document(path: &Path, user_uid: u32) -> Result<(Vec<u8>, FileState)> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    let mut file = options
        .open(path)
        .with_context(|| format!("open public document {}", path.display()))?;
    let before = file.metadata().context("inspect opened public document")?;
    if !before.file_type().is_file()
        || before.nlink() != 1
        || (before.uid() != 0 && before.uid() != user_uid)
        || before.mode() & 0o022 != 0
        || before.len() == 0
        || before.len() > DOCUMENT_LIMIT
    {
        bail!("public reconcile document has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    std::io::Read::by_ref(&mut file)
        .take(DOCUMENT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .context("read public reconcile document")?;
    let after = file
        .metadata()
        .context("reinspect public reconcile document")?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        bail!("public reconcile document changed while it was read");
    }
    let state = FileState {
        length: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    Ok((bytes, state))
}

fn result(changed: bool, verified: bool, next_action: &str) -> Result<ReconcileResult> {
    match (changed, verified) {
        (true, true) => Ok(ReconcileResult::changed()),
        (false, true) => Ok(ReconcileResult::verified()),
        (true, false) => ReconcileResult::change_required(next_action),
        (false, false) => ReconcileResult::pending(next_action),
    }
}

fn deferred_result(next_action: &str, diagnostic: &str) -> Result<ReconcileResult> {
    ReconcileResult::deferred(next_action, [diagnostic])
}

fn current_installation_receipt() -> Result<Option<PathBuf>> {
    let executable = fs::canonicalize(std::env::current_exe()?)
        .context("resolve current executable for reconciliation")?;
    let Some(version_directory) = executable.parent() else {
        return Ok(None);
    };
    let Some(versions_directory) = version_directory.parent() else {
        return Ok(None);
    };
    if versions_directory
        .file_name()
        .and_then(|name| name.to_str())
        != Some("versions")
    {
        return Ok(None);
    }
    let Some(data_root) = versions_directory.parent() else {
        return Ok(None);
    };
    let receipt = data_root.join("install-v2.json");
    match fs::symlink_metadata(&receipt) {
        Ok(_) => Ok(Some(receipt)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("inspect installation receipt readiness"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn canonical_plan_digest_is_stable_and_value_free() {
        let plan = UserConfigReconcilePlan {
            schema: PLAN_SCHEMA.into(),
            installation_paths: crate::setup::SetupPaths::user_only(Path::new("/home/test")),
            installation_version: "0.3.0".into(),
            installation_sha256: "a".repeat(64),
            account_name: "test".into(),
            account_uid: 1000,
            account_home: "/home/test".into(),
            source: "/srv/config/dev-auth.toml".into(),
            source_state: FileState {
                length: 10,
                sha256: "b".repeat(64),
            },
            policy: "/home/test/.config/dev-auth/policy-v2.toml".into(),
            policy_state: FileState {
                length: 20,
                sha256: "c".repeat(64),
            },
            destination: "/home/test/.config/dev-auth/config-v2.toml".into(),
            current_state: None,
        };
        let (first, first_digest) = render_plan(&plan).unwrap();
        let (second, second_digest) = render_plan(&plan).unwrap();
        assert_eq!(first, second);
        assert_eq!(first_digest, second_digest);
        assert!(!String::from_utf8(first).unwrap().contains("credential"));
    }

    #[test]
    fn published_plan_is_private_and_owned_by_native_caller() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("plan.json");
        let user = native_user().unwrap();
        let plan = UserConfigReconcilePlan {
            schema: PLAN_SCHEMA.into(),
            installation_paths: crate::setup::SetupPaths::user_only(&user.dir),
            installation_version: "0.3.0".into(),
            installation_sha256: "a".repeat(64),
            account_name: user.name,
            account_uid: user.uid.as_raw(),
            account_home: user.dir.clone(),
            source: user.dir.join("desired-config.toml"),
            source_state: FileState {
                length: 10,
                sha256: "b".repeat(64),
            },
            policy: user.dir.join("policy.toml"),
            policy_state: FileState {
                length: 20,
                sha256: "c".repeat(64),
            },
            destination: user.dir.join(".config/dev-auth/config-v2.toml"),
            current_state: None,
        };

        write_plan(&output, &plan).unwrap();

        let metadata = fs::symlink_metadata(&output).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.uid(), plan.account_uid);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(read_plan(&output).unwrap(), plan);
    }
}
