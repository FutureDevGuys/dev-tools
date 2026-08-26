use std::fs::{self, File, OpenOptions};
use std::path::PathBuf;

use anyhow::{Context, Result};
use fs2::FileExt;
use serde::Serialize;

use crate::root::RootHandle;
use crate::util::{now_unix, write_json_atomic};

pub struct RootLease {
    file: File,
    record: Option<PathBuf>,
}

#[derive(Serialize)]
struct LeaseRecord {
    schema_version: u32,
    pid: u32,
    started_unix: u64,
    operation: String,
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
            },
        )?;
        Ok(Self {
            file,
            record: Some(record),
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
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}
