//! Linux custody primitives for overlay transactions: descriptor-relative
//! directory operations from `dev-tools-installation` and POSIX ownership.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Take};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use dev_tools_installation::{DocumentDirectoryPreparation, FileAuthority};

use super::{ParentIdentity, FILE_LIMIT};

pub(super) use dev_tools_installation::ExistingDocumentDirectory as Directory;

pub(super) const MAX_NATIVE_PATH: usize = 4096;

pub(super) fn uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(super) fn gid() -> u32 {
    rustix::process::getegid().as_raw()
}

pub(super) fn prepare(parent_path: &Path) -> Result<(Directory, ParentIdentity)> {
    let preparation = DocumentDirectoryPreparation::observe(parent_path, uid(), 0o700)?;
    let (directory, _) = preparation.prepare()?;
    let metadata = fs::symlink_metadata(parent_path)?;
    Ok((
        directory,
        ParentIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    ))
}

/// Exact ordinary-file custody of an observed leaf, or `None` when unsafe.
pub(super) fn file_authority_of(metadata: &Metadata, limit: u64) -> Option<FileAuthority> {
    if !metadata.is_file() || metadata.uid() != uid() || metadata.mode() & 0o7022 != 0 {
        return None;
    }
    Some(FileAuthority {
        owner_uid: uid(),
        group_gid: metadata.gid(),
        mode: metadata.mode() & 0o777,
        limit,
    })
}

pub(super) fn read_text(path: &Path) -> Result<String> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    let file = options.open(path).context("open overlay text input")?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > FILE_LIMIT {
        bail!("overlay input must be a bounded regular file");
    }
    let mut bounded: Take<File> = file.try_clone()?.take(FILE_LIMIT + 1);
    let mut text = String::new();
    bounded
        .read_to_string(&mut text)
        .map_err(|_| anyhow!("overlay input is not bounded UTF-8 text"))?;
    let after = file.metadata()?;
    let named = fs::metadata(path)?;
    if text.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || after.dev() != named.dev()
        || after.ino() != named.ino()
    {
        bail!("overlay text input changed while being read");
    }
    Ok(text)
}

/// Exact native leaf-name bytes: the lock/journal key and reserved-prefix test.
pub(super) fn name_key(name: &OsStr) -> Vec<u8> {
    name.as_bytes().to_vec()
}

pub(super) fn has_reserved_prefix(name: &OsStr, prefix: &str) -> bool {
    name.as_bytes().starts_with(prefix.as_bytes())
}

pub(super) fn native_len(path: &OsStr) -> usize {
    path.as_bytes().len()
}

// Authority paths retain their native bytes; lossy UTF-8 conversion would make
// distinct selected targets or raw link destinations share journal identity.
pub(super) mod native_path {
    use super::*;
    use serde::{Deserialize, Serialize};

    pub fn serialize<S: serde::Serializer>(
        path: &Path,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_PATH || bytes.contains(&0) {
            return Err(<S::Error as serde::ser::Error>::custom(
                "native path exceeds transaction bounds",
            ));
        }
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<PathBuf, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        if bytes.is_empty() || bytes.len() > MAX_NATIVE_PATH || bytes.contains(&0) {
            return Err(<D::Error as serde::de::Error>::custom(
                "native path exceeds transaction bounds",
            ));
        }
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
}
