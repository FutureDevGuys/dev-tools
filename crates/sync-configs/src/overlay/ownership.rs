//! Fail-closed ownership receipts and atomic overlay file replacement.

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, Metadata, Permissions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::PathKey;

const RECEIPT_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OwnershipReceipt {
    schema_version: u64,
    managed_overlay_id: String,
    managed_paths: Vec<PathKey>,
}

#[derive(Debug)]
pub(crate) enum FileSnapshot {
    Missing,
    Symlink(PathBuf),
    Regular {
        content: Vec<u8>,
        metadata: PreservedMetadata,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct PreservedMetadata {
    permissions: Permissions,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
}

impl PreservedMetadata {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            permissions: metadata.permissions(),
            #[cfg(unix)]
            uid: metadata.uid(),
            #[cfg(unix)]
            gid: metadata.gid(),
        }
    }
}

/// Return the platform-native product state root used by Python 0.1.13.
pub fn default_state_root() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let root = env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow!("LOCALAPPDATA is unavailable for the sync-configs state root")
            })?;
        return Ok(PathBuf::from(root).join("sync-configs").join("state"));
    }

    #[cfg(not(windows))]
    {
        if let Some(root) = env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
            return Ok(PathBuf::from(root).join("sync-configs"));
        }
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("HOME is unavailable for the sync-configs state root"))?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("sync-configs"))
    }
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
        Some(root) => root.to_path_buf(),
        None => default_state_root()?,
    };
    Ok(root.join("overlays").join(format!("{managed_id}.json")))
}

/// Load and strictly validate one ownership receipt without exposing managed path values.
pub fn load_paths(path: &Path, managed_id: &str) -> Result<BTreeSet<PathKey>> {
    validate_managed_id(managed_id)?;
    validate_real_parent_chain(path)?;
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
    let bytes = fs::read(path)
        .with_context(|| format!("cannot read overlay ownership receipt {}", path.display()))?;
    let receipt: OwnershipReceipt = serde_json::from_slice(&bytes).map_err(|_| {
        anyhow!(
            "overlay ownership receipt has invalid JSON or fields: {}",
            path.display()
        )
    })?;
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        bail!(
            "overlay ownership receipt has an unsupported schema: {}",
            path.display()
        );
    }
    if receipt.managed_overlay_id != managed_id {
        bail!(
            "overlay ownership receipt identity does not match: {}",
            path.display()
        );
    }

    let mut paths = BTreeSet::new();
    for path_key in receipt.managed_paths {
        if path_key.is_empty() || path_key.iter().any(String::is_empty) {
            bail!(
                "overlay ownership receipt contains an invalid managed path: {}",
                path.display()
            );
        }
        if !paths.insert(path_key) {
            bail!(
                "overlay ownership receipt contains a duplicate managed path: {}",
                path.display()
            );
        }
    }
    Ok(paths)
}

pub fn write_paths_atomic(path: &Path, managed_id: &str, paths: &BTreeSet<PathKey>) -> Result<()> {
    validate_managed_id(managed_id)?;
    if paths
        .iter()
        .any(|path| path.is_empty() || path.iter().any(String::is_empty))
    {
        bail!("cannot write an ownership receipt containing an invalid managed path");
    }
    validate_real_parent_chain(path)?;
    ensure_private_parent(path)?;
    validate_real_parent_chain(path)?;
    reject_non_regular_destination(path, "overlay ownership receipt")?;

    let receipt = OwnershipReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        managed_overlay_id: managed_id.to_owned(),
        managed_paths: paths.iter().cloned().collect(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)
        .context("cannot serialize overlay ownership receipt")?;
    bytes.push(b'\n');
    atomic_write(path, &bytes, None)
        .with_context(|| format!("cannot write overlay ownership receipt {}", path.display()))
}

pub(crate) fn snapshot_file(path: &Path) -> Result<FileSnapshot> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(FileSnapshot::Missing),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()))
        }
    };
    if metadata.file_type().is_symlink() {
        return Ok(FileSnapshot::Symlink(fs::read_link(path).with_context(
            || format!("cannot read symbolic link {}", path.display()),
        )?));
    }
    if !metadata.is_file() {
        bail!(
            "overlay target must be a regular file path: {}",
            path.display()
        );
    }
    Ok(FileSnapshot::Regular {
        content: fs::read(path).with_context(|| format!("cannot read {}", path.display()))?,
        metadata: PreservedMetadata::from_metadata(&metadata),
    })
}

pub(crate) fn restore_file(path: &Path, snapshot: &FileSnapshot) -> Result<()> {
    match snapshot {
        FileSnapshot::Missing => remove_existing_leaf(path),
        FileSnapshot::Symlink(target) => {
            remove_existing_leaf(path)?;
            create_symlink(target, path)
                .with_context(|| format!("cannot restore symbolic link {}", path.display()))
        }
        FileSnapshot::Regular { content, metadata } => atomic_write(path, content, Some(metadata)),
    }
}

pub(crate) fn atomic_write_preserving_target(path: &Path, bytes: &[u8]) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => None,
        Ok(metadata) if metadata.is_file() => Some(PreservedMetadata::from_metadata(&metadata)),
        Ok(_) => bail!(
            "overlay target must be a regular file path: {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()))
        }
    };
    atomic_write(path, bytes, metadata.as_ref())
}

fn atomic_write(path: &Path, bytes: &[u8], metadata: Option<&PreservedMetadata>) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("overlay path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("cannot create overlay parent {}", parent.display()))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot stage overlay beside {}", path.display()))?;
    temporary
        .write_all(bytes)
        .with_context(|| format!("cannot stage overlay beside {}", path.display()))?;
    temporary
        .as_file_mut()
        .flush()
        .with_context(|| format!("cannot flush staged overlay beside {}", path.display()))?;

    if let Some(metadata) = metadata {
        apply_metadata(temporary.path(), metadata)?;
    }
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("cannot sync staged overlay beside {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| {
            format!(
                "cannot atomically replace overlay target {}",
                path.display()
            )
        })?;
    Ok(())
}

fn apply_metadata(path: &Path, metadata: &PreservedMetadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::chown;

        chown(path, Some(metadata.uid), Some(metadata.gid)).with_context(|| {
            format!(
                "cannot preserve overlay target ownership at {}",
                path.display()
            )
        })?;
    }
    fs::set_permissions(path, metadata.permissions.clone()).with_context(|| {
        format!(
            "cannot preserve overlay target permissions at {}",
            path.display()
        )
    })
}

fn reject_non_regular_destination(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => bail!("{label} must be a regular file: {}", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("cannot inspect {label} {}", path.display()))
        }
    }
}

fn validate_receipt_metadata(path: &Path, metadata: &Metadata) -> Result<()> {
    if !metadata.is_file() || metadata_is_link_boundary(metadata) {
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
        // SAFETY: `geteuid` has no pointer, lifetime, initialization, or thread-safety
        // preconditions and returns the effective UID of this process by value.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            bail!(
                "overlay ownership receipt must be owned by the current user: {}",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "overlay ownership receipt must be owner-only: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn ensure_private_parent(path: &Path) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "overlay ownership receipt has no parent: {}",
            path.display()
        )
    })?;
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "cannot create overlay receipt directory {}",
            parent.display()
        )
    })?;
    let metadata = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "cannot inspect overlay receipt directory {}",
            parent.display()
        )
    })?;
    if !metadata.is_dir() || metadata_is_link_boundary(&metadata) {
        bail!(
            "overlay receipt parent must be a real directory: {}",
            parent.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "cannot make overlay receipt directory owner-only: {}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn validate_real_parent_chain(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .context("cannot resolve the overlay receipt path from the current directory")?
            .join(path)
    };
    let mut current = absolute.parent();
    while let Some(parent) = current {
        match fs::symlink_metadata(parent) {
            Ok(metadata) if metadata.is_dir() && !metadata_is_link_boundary(&metadata) => {}
            Ok(_) => bail!(
                "overlay receipt parent must be a real directory: {}",
                parent.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect overlay receipt parent {}", parent.display())
                })
            }
        }
        current = parent.parent();
    }
    Ok(())
}

fn remove_existing_leaf(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            bail!(
                "refusing to replace directory while restoring {}",
                path.display()
            )
        }
        Ok(_) => fs::remove_file(path)
            .with_context(|| format!("cannot remove {} while restoring", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn metadata_is_link_boundary(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        return metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    }

    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
fn create_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}

#[cfg(not(any(unix, windows)))]
fn create_symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symbolic-link restoration is unsupported on this platform",
    ))
}
