use crate::policy_v2::{parse_system_policy_v2, parse_user_config_v2, resolve_policy_for_user};
use anyhow::{bail, Context, Result};
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
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
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {description}"))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened {description}"))?;
    if !same_policy_metadata(&metadata, &opened) {
        bail!("{description} changed while being opened");
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    (&file)
        .take(POLICY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    if bytes.len() as u64 > POLICY_LIMIT {
        bail!("{description} exceeds the size limit");
    }
    let after = file
        .metadata()
        .with_context(|| format!("reinspect {description}"))?;
    if bytes.len() as u64 != opened.len() || !same_policy_metadata(&opened, &after) {
        bail!("{description} changed while being read");
    }
    Ok(bytes)
}

fn same_policy_metadata(left: &Metadata, right: &Metadata) -> bool {
    right.file_type().is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn policy_metadata_rejects_replacement_and_changed_open_file_authority() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let observed = fs::symlink_metadata(&path).unwrap();
        let held = File::open(&path).unwrap();
        assert!(same_policy_metadata(&observed, &held.metadata().unwrap()));

        let replacement = root.path().join("replacement");
        fs::write(&replacement, b"replaced").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(!same_policy_metadata(
            &observed,
            &File::open(&path).unwrap().metadata().unwrap()
        ));

        let before = held.metadata().unwrap();
        held.set_permissions(fs::Permissions::from_mode(0o640))
            .unwrap();
        assert!(!same_policy_metadata(&before, &held.metadata().unwrap()));
    }

    #[test]
    fn policy_metadata_rejects_growth_but_not_read_access() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("policy");
        fs::write(&path, b"original").unwrap();
        let file = File::open(&path).unwrap();
        let before = file.metadata().unwrap();
        let mut bytes = Vec::new();
        (&file).read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(same_policy_metadata(&before, &file.metadata().unwrap()));
        fs::write(&path, b"longer replacement").unwrap();
        assert!(!same_policy_metadata(&before, &file.metadata().unwrap()));
    }
}
