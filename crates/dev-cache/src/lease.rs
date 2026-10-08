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
        match FileExt::try_lock_shared(&file) {
            Ok(()) => {}
            Err(error) if lock_is_contended(&error) => {
                bail!("cache root is busy with exclusive maintenance; routed setup did not start")
            }
            Err(error) => return Err(error).context("acquire shared cache-root setup lease"),
        }
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
        Self::try_exclusive(root)?.context("cache root is busy with another coordinated operation")
    }

    pub fn try_exclusive(root: &RootHandle) -> Result<Option<Self>> {
        Self::try_exclusive_for_maintenance(root)
    }

    pub(crate) fn shared_read_only(root: &RootHandle) -> Result<Self> {
        Self::try_shared_read_only(root)?.context("cache root is busy with exclusive maintenance")
    }

    pub(crate) fn try_shared_read_only(root: &RootHandle) -> Result<Option<Self>> {
        let file = open_lock_file(root, LeaseMode::Observe)
            .context("open existing cache-root coordination; if absent, explicitly run config init-root for this root before previewing collection")?;
        match FileExt::try_lock_shared(&file) {
            Ok(()) => Ok(Some(Self { file, record: None })),
            Err(error) if lock_is_contended(&error) => Ok(None),
            Err(error) => Err(error).context("acquire shared cache-root observation lease"),
        }
    }

    fn try_exclusive_for_maintenance(root: &RootHandle) -> Result<Option<Self>> {
        let file = lock_file(root)?;
        match file.try_lock_exclusive() {
            Ok(()) => {}
            Err(error) if lock_is_contended(&error) => return Ok(None),
            Err(error) => return Err(error).context("acquire exclusive cache-root lease"),
        }
        clean_stale_lease_records(root)?;
        Ok(Some(Self { file, record: None }))
    }
}

// fs2 uses platform-specific contention codes (including Windows lock violation).
// A broad ErrorKind is insufficient there and can misclassify unrelated errors.
fn lock_is_contended(error: &std::io::Error) -> bool {
    matches!(
        (error.raw_os_error(), fs2::lock_contended_error().raw_os_error()),
        (Some(actual), Some(expected)) if actual == expected
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_contention_classification_uses_the_exact_native_code() {
        let expected = fs2::lock_contended_error();
        assert!(lock_is_contended(&expected));
        assert!(!lock_is_contended(&std::io::Error::other("unrelated")));
        assert!(!lock_is_contended(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));
        assert!(!lock_is_contended(&std::io::Error::from_raw_os_error(
            expected.raw_os_error().unwrap() + 1
        )));
    }

    #[test]
    fn observation_and_routed_setup_share_coordination_without_unscoped_records() {
        let temp = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
        let observation = RootLease::shared_read_only(&root).unwrap();
        let setup = RootLease::shared(&root, "preview-concurrent-setup").unwrap();
        assert!(RootLease::try_shared_read_only(&root).unwrap().is_some());
        assert!(RootLease::try_exclusive(&root).unwrap().is_none());
        assert_eq!(
            fs::read_dir(root.control().join("leases")).unwrap().count(),
            0
        );
        drop(setup);
        assert!(RootLease::try_exclusive(&root).unwrap().is_none());
        drop(observation);
        assert!(RootLease::try_exclusive(&root).unwrap().is_some());
    }

    #[test]
    fn routed_setup_returns_busy_while_exclusive_maintenance_is_still_held() {
        let temp = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
        let maintenance = RootLease::exclusive(&root).unwrap();
        assert!(RootLease::try_shared_read_only(&root).unwrap().is_none());
        let (send, receive) = std::sync::mpsc::channel();
        let worker_root = root.clone();
        let worker = std::thread::spawn(move || {
            let result = RootLease::shared(&worker_root, "contended-setup")
                .err()
                .map(|error| error.to_string());
            send.send(result).unwrap();
        });
        // A blocking regression is released and joined before this test fails.
        // The successful result must arrive before the exclusive lease is dropped.
        let result = receive.recv_timeout(std::time::Duration::from_secs(5));
        drop(maintenance);
        worker.join().unwrap();
        let message = result
            .expect("setup must not wait for maintenance to finish")
            .expect("contended setup must fail, never run without protection");
        assert!(message.contains("busy with exclusive maintenance"));
        assert_eq!(
            fs::read_dir(root.control().join("leases")).unwrap().count(),
            0
        );
        assert!(RootLease::shared(&root, "after-maintenance").is_ok());
    }
}
