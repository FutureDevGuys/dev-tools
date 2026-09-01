use crate::deployment::DeploymentMode;
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use zeroize::Zeroizing;

const CREDENTIAL_LIMIT: u64 = 64 * 1024;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const RAMFS_MAGIC: u64 = 0x8584_58f6;

#[derive(Clone, PartialEq, Eq)]
pub enum CredentialInputSource {
    Stdin,
    Fd(i32),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialInputContext {
    pub mode: DeploymentMode,
    pub allowed_owner_uids: BTreeSet<u32>,
}

pub struct CredentialMaterial(Zeroizing<Vec<u8>>);

impl CredentialMaterial {
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }
}

pub fn load_credential_inputs(
    declared_slots: &BTreeSet<String>,
    required_slots: &BTreeSet<String>,
    sources: &BTreeMap<String, CredentialInputSource>,
    context: &CredentialInputContext,
    stdin: &mut dyn Read,
) -> Result<BTreeMap<String, CredentialMaterial>> {
    if !required_slots.is_subset(declared_slots)
        || sources.keys().any(|slot| !declared_slots.contains(slot))
        || context.allowed_owner_uids.is_empty()
    {
        bail!("credential input does not match the declared deployment slots");
    }
    if sources
        .values()
        .any(|source| matches!(source, CredentialInputSource::Stdin))
        && required_slots.len() != 1
    {
        bail!("standard input is valid only when exactly one credential slot requires input");
    }

    let mut loaded = BTreeMap::new();
    for slot in required_slots {
        let source = match sources.get(slot) {
            Some(source) => source,
            None => continue,
        };
        let bytes = match source {
            CredentialInputSource::Stdin => read_bounded(stdin, "standard input")?,
            CredentialInputSource::Fd(fd) => {
                let mut file = open_inherited_fd(*fd)?;
                validate_descriptor(&file, context, false)?;
                read_bounded(&mut file, "credential file descriptor")?
            }
            CredentialInputSource::File(path) => {
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
                    .open(path)
                    .with_context(|| format!("open credential file {}", path.display()))?;
                validate_descriptor(&file, context, true)?;
                read_bounded(&mut file, "credential file")?
            }
        };
        loaded.insert(slot.clone(), CredentialMaterial(Zeroizing::new(bytes)));
    }
    Ok(loaded)
}

fn open_inherited_fd(fd: i32) -> Result<File> {
    if fd < 3 {
        bail!("credential file descriptor must be 3 or greater");
    }
    let proc_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    File::open(&proc_path).context("duplicate inherited credential file descriptor")
}

fn validate_descriptor(
    file: &File,
    context: &CredentialInputContext,
    named_file: bool,
) -> Result<()> {
    let metadata = file.metadata().context("inspect credential input")?;
    if metadata.file_type().is_file() {
        if metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || !context.allowed_owner_uids.contains(&metadata.uid())
        {
            bail!("credential file has unsafe filesystem authority");
        }
    } else if named_file || !metadata.file_type().is_fifo() {
        bail!("credential file descriptor must reference a regular file or private pipe");
    }
    if metadata.len() > CREDENTIAL_LIMIT {
        bail!("credential input exceeds the size limit");
    }
    if context.mode == DeploymentMode::Strong && metadata.file_type().is_file() {
        let filesystem =
            rustix::fs::fstatfs(file.as_fd()).context("inspect credential input filesystem")?;
        let filesystem_type = filesystem.f_type as u64;
        if filesystem_type != TMPFS_MAGIC && filesystem_type != RAMFS_MAGIC {
            bail!("strong-mode credential files must use an approved memory-backed filesystem");
        }
    }
    Ok(())
}

fn read_bounded(reader: &mut dyn Read, description: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(CREDENTIAL_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    if bytes.is_empty() || bytes.len() as u64 > CREDENTIAL_LIMIT || bytes.contains(&0) {
        bail!("credential input is empty, oversized, or malformed");
    }
    Ok(bytes)
}
