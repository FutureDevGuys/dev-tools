use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, Metadata};
#[cfg(not(target_os = "linux"))]
use std::fs::{File, OpenOptions};
use std::io;
#[cfg(not(target_os = "linux"))]
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::PathKey;
use crate::paths::{is_absolute_for, platform_join, PathPlatform};

const RECEIPT_SCHEMA_VERSION: u64 = 1;
pub(crate) const RECEIPT_LIMIT: u64 = 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnershipReceipt {
    schema_version: u64,
    managed_overlay_id: String,
    managed_paths: Vec<PathKey>,
}

/// Return the platform-native product state root for sync-configs ownership receipts.
pub fn default_state_root() -> Result<PathBuf> {
    default_state_root_with(PathPlatform::current(), |name| env::var_os(name))
}

/// Injectable state-root resolution used to prove each platform convention
/// without mutating the process environment.
pub fn default_state_root_with<F>(platform: PathPlatform, mut variable: F) -> Result<PathBuf>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let absolute_environment_path = |value: Option<OsString>| {
        value
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .filter(|path| is_absolute_for(path, platform))
    };

    let root = match platform {
        PathPlatform::Posix => {
            if let Some(root) = absolute_environment_path(variable("XDG_STATE_HOME")) {
                root
            } else {
                let home = absolute_environment_path(variable("HOME")).ok_or_else(|| {
                    anyhow!(
                        "HOME must be an absolute path for the sync-configs state root fallback"
                    )
                })?;
                platform_join(&home, Path::new(".local/state"), platform)
            }
        }
        PathPlatform::Windows => {
            if let Some(root) = absolute_environment_path(variable("LOCALAPPDATA")) {
                root
            } else {
                let profile = absolute_environment_path(variable("USERPROFILE")).or_else(|| {
                    let mut combined = variable("HOMEDRIVE").filter(|value| !value.is_empty())?;
                    let home_path = variable("HOMEPATH").filter(|value| !value.is_empty())?;
                    combined.push(home_path);
                    absolute_environment_path(Some(combined))
                });
                let profile = profile.ok_or_else(|| {
                    anyhow!(
                        "USERPROFILE or HOMEDRIVE with HOMEPATH must provide an absolute path for the sync-configs state root fallback"
                    )
                })?;
                platform_join(&profile, Path::new(r"AppData\Local"), platform)
            }
        }
    };

    let product = platform_join(&root, Path::new("sync-configs"), platform);
    Ok(if platform == PathPlatform::Windows {
        platform_join(&product, Path::new("state"), platform)
    } else {
        product
    })
}

pub fn validate_managed_id(value: &str) -> Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("managed overlay id must contain only letters, numbers, '.', '_', or '-'");
    }
    Ok(())
}

pub fn receipt_path(managed_id: &str, state_root: Option<&Path>) -> Result<PathBuf> {
    validate_managed_id(managed_id)?;
    let root = match state_root {
        Some(root) if is_absolute_for(root, PathPlatform::current()) => root.to_path_buf(),
        Some(root) => bail!(
            "overlay ownership receipt state root must be absolute: {}",
            root.display()
        ),
        None => default_state_root()?,
    };
    Ok(root.join("overlays").join(format!("{managed_id}.json")))
}

/// Load and strictly validate one ownership receipt without exposing managed path values.
pub fn load_paths(path: &Path, managed_id: &str) -> Result<BTreeSet<PathKey>> {
    validate_managed_id(managed_id)?;
    validate_real_parent_chain(path, "overlay ownership receipt")?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "cannot inspect overlay ownership receipt {}",
                    path.display()
                )
            })
        }
    };
    validate_receipt_metadata(path, &metadata)?;
    #[cfg(target_os = "linux")]
    {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()?.join(path)
        };
        let directory = dev_tools_installation::ExistingDocumentDirectory::open(
            absolute.parent().context("overlay receipt has no parent")?,
            rustix::process::geteuid().as_raw(),
        )?;
        let document = directory
            .read(
                absolute
                    .file_name()
                    .context("overlay receipt has no name")?,
                &dev_tools_installation::DocumentAuthority {
                    owner_uid: rustix::process::geteuid().as_raw(),
                    mode: 0o600,
                    limit: RECEIPT_LIMIT,
                },
            )?
            .context("overlay receipt disappeared while being read")?;
        decode_paths(&document.bytes, managed_id)
    }
    #[cfg(not(target_os = "linux"))]
    {
        validate_real_parent_chain(path, "overlay ownership receipt")?;
        let mut file = open_receipt_no_follow(path)?;
        validate_receipt_metadata(
            path,
            &file.metadata().with_context(|| {
                format!(
                    "cannot inspect opened overlay ownership receipt {}",
                    path.display()
                )
            })?,
        )?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(RECEIPT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("cannot read overlay ownership receipt {}", path.display()))?;
        decode_paths(&bytes, managed_id)
    }
}

pub(crate) fn decode_paths(bytes: &[u8], managed_id: &str) -> Result<BTreeSet<PathKey>> {
    validate_managed_id(managed_id)?;
    if bytes.len() as u64 > RECEIPT_LIMIT {
        bail!("overlay ownership receipt exceeds its size bound");
    }
    let receipt: OwnershipReceipt = serde_json::from_slice(bytes)
        .map_err(|_| anyhow!("overlay ownership receipt has invalid JSON or fields"))?;
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        bail!("overlay ownership receipt has an unsupported schema");
    }
    if receipt.managed_overlay_id != managed_id {
        bail!("overlay ownership receipt identity does not match");
    }

    let mut paths = BTreeSet::new();
    for path_key in receipt.managed_paths {
        if path_key.is_empty() || path_key.iter().any(String::is_empty) {
            bail!("overlay ownership receipt contains an invalid managed path");
        }
        if !paths.insert(path_key) {
            bail!("overlay ownership receipt contains a duplicate managed path");
        }
    }
    Ok(paths)
}

#[cfg(target_os = "linux")]
pub(crate) fn encode_paths(managed_id: &str, paths: &BTreeSet<PathKey>) -> Result<String> {
    validate_managed_id(managed_id)?;
    if paths
        .iter()
        .any(|path| path.is_empty() || path.iter().any(String::is_empty))
    {
        bail!("cannot write an ownership receipt containing an invalid managed path");
    }
    let receipt = OwnershipReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        managed_overlay_id: managed_id.to_owned(),
        managed_paths: paths.iter().cloned().collect(),
    };
    let mut text = serde_json::to_string_pretty(&receipt)
        .context("cannot serialize overlay ownership receipt")?;
    text.push('\n');
    if text.len() as u64 > RECEIPT_LIMIT {
        bail!("overlay ownership receipt exceeds its size bound");
    }
    Ok(text)
}

fn validate_receipt_metadata(path: &Path, metadata: &Metadata) -> Result<()> {
    if !metadata.is_file() || metadata_is_link_boundary(metadata) || metadata.len() > RECEIPT_LIMIT
    {
        bail!(
            "overlay ownership receipt must be a regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if metadata.nlink() != 1 {
            bail!(
                "overlay ownership receipt must have exactly one link: {}",
                path.display()
            );
        }
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.uid() != effective_uid {
            bail!(
                "overlay ownership receipt must be owned by the current user: {}",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            bail!(
                "overlay ownership receipt must be owner-only: {}",
                path.display()
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_real_parent_chain(path: &Path, label: &str) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .with_context(|| format!("cannot resolve {label} from the current directory"))?
            .join(path)
    };
    let parent = absolute
        .parent()
        .ok_or_else(|| anyhow!("{label} has no parent: {}", path.display()))?;
    for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let parent = ancestor.to_path_buf();
        match fs::symlink_metadata(&parent) {
            Ok(metadata) if metadata.is_dir() && !metadata_is_link_boundary(&metadata) => {}
            Ok(_) => bail!(
                "{label} parent must be a real directory: {}",
                parent.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect {label} parent {}", parent.display()))
            }
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn open_receipt_no_follow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    options
        .open(path)
        .with_context(|| format!("cannot open overlay ownership receipt {}", path.display()))
}

fn metadata_is_link_boundary(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }

    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}
