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
    record: Option<PathBuf>,
}

pub struct ActiveLease {
    record: Option<PathBuf>,
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
        let id = format!("{}-{}", std::process::id(), now_unix());
        let record = root.control().join("leases").join(format!("{id}.json"));
        write_json_atomic(
            &record,
            &LeaseRecord {
                schema_version: 1,
                pid: std::process::id(),
                started_unix: now_unix(),
                operation: operation.to_owned(),
                resource_ids: Vec::new(),
            },
        )?;
        Ok(Self {
            file,
            record: Some(record),
        })
    }

    pub fn into_active(mut self, resource_ids: &[String]) -> Result<ActiveLease> {
        if resource_ids.is_empty() {
            bail!("an active routed lease requires at least one resource");
        }
        let record_path = self
            .record
            .as_ref()
            .context("shared root lease has no activity record")?;
        let mut record: LeaseRecord =
            serde_json::from_slice(&fs::read(record_path)?).context("parse routed lease record")?;
        record.resource_ids = resource_ids.to_vec();
        record.resource_ids.sort();
        record.resource_ids.dedup();
        write_json_atomic(record_path, &record)?;
        FileExt::unlock(&self.file).context("release cache-root setup lease")?;
        Ok(ActiveLease {
            record: self.record.take(),
        })
    }

    pub fn exclusive(root: &RootHandle) -> Result<Self> {
        Self::try_exclusive(root)?.context("cache root is busy with an active routed command")
    }

    pub fn try_exclusive(root: &RootHandle) -> Result<Option<Self>> {
        let file = lock_file(root)?;
        match file.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error).context("acquire exclusive cache-root lease"),
        }
        clean_stale_lease_records(root)?;
        Ok(Some(Self { file, record: None }))
    }
}

impl Drop for RootLease {
    fn drop(&mut self) {
        if let Some(path) = self.record.take() {
            let _ = fs::remove_file(path);
        }
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
            fs::remove_file(entry.path())?;
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

fn lock_file(root: &RootHandle) -> Result<File> {
    let path = root.control().join("root.lock");
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("open {}", path.display()))
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
