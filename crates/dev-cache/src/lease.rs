use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::root::RootHandle;
use crate::util::{now_unix, write_json_atomic};

pub struct RootLease {
    file: File,
    record: Option<(PathBuf, LeaseRecord)>,
}

pub struct ActiveLease {
    record: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LeaseMode {
    Observe,
    Maintain,
}

#[derive(Deserialize, Serialize)]
struct LeaseRecord {
    schema_version: u32,
    pid: u32,
    started_unix: u64,
    operation: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    resource_ids: Vec<String>,
}

impl RootLease {
    pub fn shared(root: &RootHandle, operation: &str) -> Result<Self> {
        let file = lock_file(root)?;
        FileExt::lock_shared(&file).context("acquire shared cache-root lease")?;
        let id = format!("{}-{}", std::process::id(), uuid::Uuid::new_v4().simple());
        let record = root.control().join("leases").join(format!("{id}.json"));
        // The held root lock excludes collection throughout setup. Publish only
        // the scoped activity record, durably, before releasing that lock.
        Ok(Self {
            file,
            record: Some((
                record,
                LeaseRecord {
                    schema_version: 1,
                    pid: std::process::id(),
                    started_unix: now_unix(),
                    operation: operation.to_owned(),
                    resource_ids: Vec::new(),
                },
            )),
        })
    }

    pub fn into_active(mut self, resource_ids: &[String]) -> Result<ActiveLease> {
        if resource_ids.is_empty() {
            bail!("an active routed lease requires at least one resource");
        }
        let (record_path, mut record) = self
            .record
            .take()
            .context("shared root lease has no activity record")?;
        record.resource_ids = resource_ids.to_vec();
        record.resource_ids.sort();
        record.resource_ids.dedup();
        write_json_atomic(&record_path, &record)?;
        let active = ActiveLease {
            record: Some(record_path),
        };
        FileExt::unlock(&self.file).context("release cache-root setup lease")?;
        Ok(active)
    }

    pub fn exclusive(root: &RootHandle) -> Result<Self> {
        Self::try_exclusive(root)?.context("cache root is busy with an active routed command")
    }

    pub fn try_exclusive(root: &RootHandle) -> Result<Option<Self>> {
        Self::try_exclusive_with_mode(root, LeaseMode::Maintain)
    }

    pub(crate) fn exclusive_read_only(root: &RootHandle) -> Result<Self> {
        Self::try_exclusive_read_only(root)?
            .context("cache root is busy with an active routed command")
    }

    pub(crate) fn try_exclusive_read_only(root: &RootHandle) -> Result<Option<Self>> {
        Self::try_exclusive_with_mode(root, LeaseMode::Observe)
    }

    fn try_exclusive_with_mode(root: &RootHandle, mode: LeaseMode) -> Result<Option<Self>> {
        let file = if mode == LeaseMode::Maintain {
            lock_file(root)?
        } else {
            open_lock_file(root, LeaseMode::Observe)
                .context("open existing cache-root coordination; if absent, explicitly run config init-root for this root before previewing collection")?
        };
        match file.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error).context("acquire exclusive cache-root lease"),
        }
        if mode == LeaseMode::Maintain {
            clean_stale_lease_records(root)?;
        }
        Ok(Some(Self { file, record: None }))
    }
}

impl Drop for RootLease {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

impl Drop for ActiveLease {
    fn drop(&mut self) {
        if let Some(path) = self.record.take() {
            let _ = fs::remove_file(path);
        }
    }
}

pub fn active_resource_ids(root: &RootHandle) -> Result<BTreeSet<String>> {
    active_resource_ids_with_mode(root, LeaseMode::Maintain)
}

pub(crate) fn observe_active_resource_ids(root: &RootHandle) -> Result<BTreeSet<String>> {
    active_resource_ids_with_mode(root, LeaseMode::Observe)
}

fn active_resource_ids_with_mode(root: &RootHandle, mode: LeaseMode) -> Result<BTreeSet<String>> {
    let mut active = BTreeSet::new();
    let directory = root.control().join("leases");
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let record: LeaseRecord = serde_json::from_slice(&fs::read(entry.path())?)
            .with_context(|| format!("parse active lease {}", entry.path().display()))?;
        if record.schema_version != 1 || record.pid == 0 || record.operation.is_empty() {
            bail!("invalid active lease {}", entry.path().display());
        }
        if !process_alive(record.pid) {
            if mode == LeaseMode::Maintain {
                fs::remove_file(entry.path())?;
            }
            continue;
        }
        if record.resource_ids.is_empty() {
            bail!(
                "active routed command {} has no resource scope",
                record.operation
            );
        }
        active.extend(record.resource_ids);
    }
    Ok(active)
}

pub(crate) fn prepare_root_lock(root: &RootHandle) -> Result<()> {
    let _file = lock_file(root)?;
    Ok(())
}

fn lock_file(root: &RootHandle) -> Result<File> {
    open_lock_file(root, LeaseMode::Maintain)
}

fn open_lock_file(root: &RootHandle, mode: LeaseMode) -> Result<File> {
    let path = root.control().join("root.lock");
    let mut options = OpenOptions::new();
    options
        .create(mode == LeaseMode::Maintain)
        .truncate(false)
        .read(true)
        .write(mode == LeaseMode::Maintain);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("open {}", path.display()))?;
    let metadata = file
        .metadata()
        .context("inspect cache-root coordination handle")?;
    if !metadata.is_file() {
        bail!("cache-root coordination is not a regular file");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("cache-root coordination is a reparse point");
        }
    }
    Ok(file)
}

fn clean_stale_lease_records(root: &RootHandle) -> Result<()> {
    let dir = root.control().join("leases");
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let record: LeaseRecord = serde_json::from_slice(&fs::read(entry.path())?)
                .with_context(|| format!("parse lease record {}", entry.path().display()))?;
            if record.schema_version != 1 || record.pid == 0 || record.operation.is_empty() {
                bail!("invalid lease record {}", entry.path().display());
            }
            if !process_alive(record.pid) {
                fs::remove_file(entry.path())?;
            }
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_alive(pid: u32) -> bool {
    PathBuf::from("/proc").join(pid.to_string()).exists()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn process_alive(_pid: u32) -> bool {
    true
}
