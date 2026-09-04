#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, Result};
use clap::{Args, ValueEnum};
#[cfg(unix)]
use serde_json::json;
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
#[cfg(unix)]
use std::path::{Component, Path};

#[cfg(unix)]
use super::{current_owner_uid, read_bounded_file, require_canonical_directory, ARTIFACT_LIMIT};

#[cfg(unix)]
const MAX_FILES: usize = 128;
#[cfg(unix)]
const MAX_DEPTH: usize = 4;
#[cfg(unix)]
const MAX_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompareFormat {
    Human,
    Json,
}

#[derive(Debug, Args)]
pub(crate) struct SetCompareArgs {
    #[arg(long)]
    first: PathBuf,
    #[arg(long)]
    second: PathBuf,
    #[arg(long, value_enum, default_value_t = CompareFormat::Human)]
    format: CompareFormat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(unix)]
enum EntryFingerprint {
    Directory {
        mode: u32,
    },
    File {
        mode: u32,
        length: u64,
        sha256: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(unix)]
struct TreeFingerprint {
    root_mode: u32,
    entries: BTreeMap<PathBuf, EntryFingerprint>,
}

pub(crate) fn compare_release_sets(arguments: SetCompareArgs) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = arguments;
        bail!("release-set comparison is not accepted on this platform");
    }
    #[cfg(unix)]
    {
        let first = require_canonical_directory(&arguments.first, true)
            .context("validate first release-set directory")?;
        let second = require_canonical_directory(&arguments.second, true)
            .context("validate second release-set directory")?;
        if first == second {
            bail!("release-set comparison requires two distinct directories");
        }

        let first_tree = fingerprint_tree(&first).context("inspect first release set")?;
        let second_tree = fingerprint_tree(&second).context("inspect second release set")?;
        if first_tree != second_tree {
            bail!("release-set candidates are not byte-identical");
        }
        let total_bytes =
            first_tree
                .entries
                .values()
                .try_fold(0_u64, |total, entry| match entry {
                    EntryFingerprint::Directory { .. } => Ok(total),
                    EntryFingerprint::File { length, .. } => total
                        .checked_add(*length)
                        .context("release-set byte count overflow"),
                })?;
        let file_count = first_tree
            .entries
            .values()
            .filter(|entry| matches!(entry, EntryFingerprint::File { .. }))
            .count();
        match arguments.format {
            CompareFormat::Human => println!(
                "release sets are byte-identical ({} files, {} bytes)",
                file_count, total_bytes
            ),
            CompareFormat::Json => {
                serde_json::to_writer(
                    std::io::stdout().lock(),
                    &json!({
                        "schema": "release-admin-set-compare-v1",
                        "identical": true,
                        "files": file_count,
                        "bytes": total_bytes,
                    }),
                )
                .context("write release-set comparison result")?;
                println!();
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn fingerprint_tree(root: &Path) -> Result<TreeFingerprint> {
    let root_metadata = fs::symlink_metadata(root).context("inspect release-set root")?;
    require_private_mode(&root_metadata, "release-set root")?;
    let mut entries = BTreeMap::new();
    let mut total_bytes = 0_u64;
    visit_directory(root, root, 0, &mut total_bytes, &mut entries)?;
    if !entries
        .values()
        .any(|entry| matches!(entry, EntryFingerprint::File { .. }))
    {
        bail!("release-set candidate contains no files");
    }
    Ok(TreeFingerprint {
        root_mode: root_metadata.permissions().mode() & 0o7777,
        entries,
    })
}

#[cfg(unix)]
fn visit_directory(
    root: &Path,
    directory: &Path,
    depth: usize,
    total_bytes: &mut u64,
    entries: &mut BTreeMap<PathBuf, EntryFingerprint>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("release-set candidate exceeds its directory-depth limit");
    }
    let metadata = fs::symlink_metadata(directory).context("inspect release-set directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != current_owner_uid()
        || fs::canonicalize(directory).context("canonicalize release-set directory")? != directory
    {
        bail!("release-set directory has unsafe filesystem authority");
    }
    require_private_mode(&metadata, "release-set directory")?;
    let mut directory_entries = fs::read_dir(directory)
        .context("read release-set directory")?
        .collect::<std::io::Result<Vec<_>>>()
        .context("enumerate release-set directory")?;
    directory_entries.sort_by_key(fs::DirEntry::file_name);
    for entry in directory_entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .context("release-set entry escapes its root")?;
        if relative.as_os_str().is_empty()
            || relative.to_str().is_none()
            || !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            bail!("release-set entry name is invalid");
        }
        let metadata = fs::symlink_metadata(&path).context("inspect release-set entry")?;
        if metadata.file_type().is_dir() {
            require_private_mode(&metadata, "release-set directory")?;
            entries.insert(
                relative.to_owned(),
                EntryFingerprint::Directory {
                    mode: metadata.permissions().mode() & 0o7777,
                },
            );
            visit_directory(root, &path, depth + 1, total_bytes, entries)?;
            continue;
        }
        if !metadata.file_type().is_file()
            || metadata.uid() != current_owner_uid()
            || metadata.nlink() != 1
        {
            bail!("release-set entry has unsafe filesystem authority");
        }
        require_private_mode(&metadata, "release-set entry")?;
        let file_count = entries
            .values()
            .filter(|entry| matches!(entry, EntryFingerprint::File { .. }))
            .count();
        if file_count == MAX_FILES {
            bail!("release-set candidate exceeds its file-count limit");
        }
        *total_bytes = total_bytes
            .checked_add(metadata.len())
            .context("release-set byte count overflow")?;
        if *total_bytes > MAX_TOTAL_BYTES {
            bail!("release-set candidate exceeds its total-size limit");
        }
        let bytes = read_bounded_file(&path, ARTIFACT_LIMIT).context("read release-set entry")?;
        let after = fs::symlink_metadata(&path).context("reinspect release-set entry")?;
        if metadata.dev() != after.dev()
            || metadata.ino() != after.ino()
            || metadata.len() != after.len()
            || metadata.mode() != after.mode()
            || metadata.uid() != after.uid()
            || metadata.mtime() != after.mtime()
            || metadata.mtime_nsec() != after.mtime_nsec()
            || metadata.ctime() != after.ctime()
            || metadata.ctime_nsec() != after.ctime_nsec()
        {
            bail!("release-set entry changed while being read");
        }
        entries.insert(
            relative.to_owned(),
            EntryFingerprint::File {
                mode: metadata.permissions().mode() & 0o7777,
                length: metadata.len(),
                sha256: format!("{:x}", Sha256::digest(&bytes)),
            },
        );
    }
    Ok(())
}

#[cfg(unix)]
fn require_private_mode(metadata: &fs::Metadata, label: &str) -> Result<()> {
    if metadata.uid() != current_owner_uid()
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o7000 != 0
    {
        bail!("{label} has unsafe filesystem authority");
    }
    Ok(())
}
