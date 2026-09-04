//! Fail-closed ownership receipts and atomic overlay file replacement.

use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use super::PathKey;
use crate::paths::{is_absolute_for, platform_join, PathPlatform};

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
    file.read_to_end(&mut bytes)
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
    validate_real_parent_chain(path, "overlay ownership receipt")?;
    ensure_private_parent(path)?;
    validate_real_parent_chain(path, "overlay ownership receipt")?;
    reject_non_regular_destination(path, "overlay ownership receipt", false)?;

    let receipt = OwnershipReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        managed_overlay_id: managed_id.to_owned(),
        managed_paths: paths.iter().cloned().collect(),
    };
    let mut bytes = serde_json::to_vec_pretty(&receipt)
        .context("cannot serialize overlay ownership receipt")?;
    bytes.push(b'\n');
    atomic_write(path, &bytes, None, "overlay ownership receipt", false)
        .with_context(|| format!("cannot write overlay ownership receipt {}", path.display()))
}

pub(crate) fn snapshot_file(path: &Path) -> Result<FileSnapshot> {
    validate_real_parent_chain(path, "overlay target snapshot")?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(FileSnapshot::Missing),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()))
        }
    };
    if metadata_is_unsupported_reparse_leaf(&metadata) {
        bail!(
            "overlay target snapshot must not cross a non-symlink reparse point: {}",
            path.display()
        );
    }
    if metadata.file_type().is_symlink() {
        validate_real_parent_chain(path, "overlay target snapshot")?;
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
    validate_real_parent_chain(path, "overlay target snapshot")?;
    Ok(FileSnapshot::Regular {
        content: fs::read(path).with_context(|| format!("cannot read {}", path.display()))?,
        metadata: PreservedMetadata::from_metadata(&metadata),
    })
}

pub(crate) fn restore_file(path: &Path, snapshot: &FileSnapshot) -> Result<()> {
    validate_real_parent_chain(path, "overlay target rollback")?;
    match snapshot {
        FileSnapshot::Missing => remove_existing_leaf(path, "overlay target rollback"),
        FileSnapshot::Symlink(target) => {
            remove_existing_leaf(path, "overlay target rollback")?;
            validate_real_parent_chain(path, "overlay target rollback")?;
            create_symlink(target, path)
                .with_context(|| format!("cannot restore symbolic link {}", path.display()))
        }
        FileSnapshot::Regular { content, metadata } => atomic_write(
            path,
            content,
            Some(metadata),
            "overlay target rollback",
            true,
        ),
    }
}

pub(crate) fn atomic_write_preserving_target(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_real_parent_chain(path, "overlay target")?;
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_unsupported_reparse_leaf(&metadata) => bail!(
            "overlay target must not be a non-symlink reparse point: {}",
            path.display()
        ),
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
    validate_real_parent_chain(path, "overlay target")?;
    atomic_write(path, bytes, metadata.as_ref(), "overlay target", true)
}

fn atomic_write(
    path: &Path,
    bytes: &[u8],
    metadata: Option<&PreservedMetadata>,
    label: &str,
    allow_file_symlink: bool,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("overlay path has no parent: {}", path.display()))?;
    create_real_parent_chain(path, label)?;
    validate_real_parent_chain(path, label)?;
    reject_non_regular_destination(path, label, allow_file_symlink)?;
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
    validate_real_parent_chain(path, label)?;
    reject_non_regular_destination(path, label, allow_file_symlink)?;
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

fn reject_non_regular_destination(
    path: &Path,
    label: &str,
    allow_file_symlink: bool,
) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_unsupported_reparse_leaf(&metadata) => bail!(
            "{label} must not be a non-symlink reparse point: {}",
            path.display()
        ),
        Ok(metadata) if allow_file_symlink && metadata.file_type().is_symlink() => Ok(()),
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
        let effective_uid = rustix::process::geteuid().as_raw();
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
    create_real_parent_chain(path, "overlay ownership receipt")?;
    validate_real_parent_chain(path, "overlay ownership receipt")?;
    let metadata = fs::symlink_metadata(parent).with_context(|| {
        format!(
            "cannot inspect overlay receipt directory {}",
            parent.display()
        )
    })?;
    if !metadata.is_dir() || metadata_is_link_boundary(&metadata) {
        bail!(
            "overlay ownership receipt parent must be a real directory: {}",
            parent.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        validate_real_parent_chain(path, "overlay ownership receipt")?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "cannot make overlay receipt directory owner-only: {}",
                parent.display()
            )
        })?;
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

fn create_real_parent_chain(path: &Path, label: &str) -> Result<()> {
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
        let candidate = ancestor.to_path_buf();
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_dir() && !metadata_is_link_boundary(&metadata) => {}
            Ok(_) => bail!(
                "{label} parent must be a real directory: {}",
                candidate.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(&candidate) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        let metadata = fs::symlink_metadata(&candidate).with_context(|| {
                            format!(
                                "cannot inspect raced {label} parent {}",
                                candidate.display()
                            )
                        })?;
                        if !metadata.is_dir() || metadata_is_link_boundary(&metadata) {
                            bail!(
                                "{label} parent must be a real directory: {}",
                                candidate.display()
                            );
                        }
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("cannot create {label} parent {}", candidate.display())
                        })
                    }
                }
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect {label} parent {}", candidate.display())
                })
            }
        }
    }
    validate_real_parent_chain(path, label)
}

pub(crate) fn remove_existing_leaf(path: &Path, label: &str) -> Result<()> {
    validate_real_parent_chain(path, label)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata_is_unsupported_reparse_leaf(&metadata) => bail!(
            "{label} must not cross a non-symlink reparse point: {}",
            path.display()
        ),
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            bail!(
                "refusing to replace directory while restoring {}",
                path.display()
            )
        }
        Ok(_) => {
            validate_real_parent_chain(path, label)?;
            fs::remove_file(path)
                .with_context(|| format!("cannot remove {} while restoring", path.display()))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

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

pub(crate) fn is_unsupported_reparse_leaf(
    file_type_is_symlink: bool,
    has_reparse_attribute: bool,
) -> bool {
    has_reparse_attribute && !file_type_is_symlink
}

fn metadata_is_unsupported_reparse_leaf(metadata: &Metadata) -> bool {
    is_unsupported_reparse_leaf(
        metadata.file_type().is_symlink(),
        metadata_is_link_boundary(metadata),
    )
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
