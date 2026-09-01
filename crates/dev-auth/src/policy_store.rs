use crate::policy_v2::{parse_system_policy_v2, parse_user_config_v2, resolve_policy_for_user};
use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const POLICY_LIMIT: u64 = 1024 * 1024;
pub const SYSTEM_POLICY_PATH: &str = "/etc/dev-auth/policy.toml";
pub const USER_POLICY_RELATIVE_PATH: &str = ".config/dev-auth/policy-v2.toml";
pub const USER_CONFIG_RELATIVE_PATH: &str = ".config/dev-auth/config-v2.toml";

pub fn load_system_policy() -> Result<crate::policy_v2::SystemPolicyV2> {
    load_system_policy_at(Path::new(SYSTEM_POLICY_PATH))
}

pub fn load_system_policy_at(path: &Path) -> Result<crate::policy_v2::SystemPolicyV2> {
    parse_system_policy_v2(&read_policy_file(path, 0, 0o022, "administrator policy")?)
}

pub fn load_user_config_at(path: &Path, owner_uid: u32) -> Result<crate::policy_v2::UserConfigV2> {
    parse_user_config_v2(&read_policy_file(
        path,
        owner_uid,
        0o077,
        "user configuration",
    )?)
}

pub fn load_user_policy_at(
    path: &Path,
    owner_uid: u32,
) -> Result<crate::policy_v2::SystemPolicyV2> {
    parse_system_policy_v2(&read_policy_file(
        path,
        owner_uid,
        0o077,
        "user-only administrator policy",
    )?)
}

pub fn user_config_path(user: &nix::unistd::User) -> PathBuf {
    user.dir.join(USER_CONFIG_RELATIVE_PATH)
}

pub fn user_policy_path(user: &nix::unistd::User) -> PathBuf {
    user.dir.join(USER_POLICY_RELATIVE_PATH)
}

pub fn load_user_only_resolved_policy_for_uid(
    owner_uid: u32,
) -> Result<crate::policy_v2::ResolvedPolicy> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("workload owner account does not exist")?;
    let system = load_user_policy_at(&user_policy_path(&user), owner_uid)?;
    if system.mode != crate::policy_v2::SystemMode::UserOnly {
        bail!("user-only administrator policy has the wrong mode");
    }
    if !system
        .allowed_users
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&user.name))
    {
        bail!("workload owner is outside user-only policy");
    }
    let config = load_user_config_at(&user_config_path(&user), owner_uid)?;
    resolve_policy_for_user(&system, &user.name, &config)
}

pub fn load_resolved_policy_for_uid(owner_uid: u32) -> Result<crate::policy_v2::ResolvedPolicy> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(owner_uid))?
        .context("workload owner account does not exist")?;
    let system = load_system_policy()?;
    if !system
        .allowed_users
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&user.name))
    {
        bail!("workload owner is outside administrator policy");
    }
    let config = load_user_config_at(&user_config_path(&user), owner_uid)?;
    resolve_policy_for_user(&system, &user.name, &config)
}

fn read_policy_file(
    path: &Path,
    owner_uid: u32,
    forbidden_mode: u32,
    description: &str,
) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("{description} path is not absolute");
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & forbidden_mode != 0
        || metadata.len() > POLICY_LIMIT
    {
        bail!("{description} has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .with_context(|| format!("open {description}"))?
        .take(POLICY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    if bytes.len() as u64 > POLICY_LIMIT {
        bail!("{description} exceeds the size limit");
    }
    Ok(bytes)
}
