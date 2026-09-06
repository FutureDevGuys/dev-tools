//! Monotonic retirement of Linux atomic-replacement document writers.
use crate::{ArtifactIdentity, AtomicDocument, DocumentAuthority, InstallationLock};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const SCHEMA: &str = "dev-tools-retired-atomic-document-v1";
const PREFIX: &str = ".dev-tools-retired-owned-";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
enum Origin {
    Existing,
    Absent,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    target: String,
    parent_device: u64,
    parent_inode: u64,
    stage: String,
    fence_device: u64,
    fence_inode: u64,
    mode: u32,
    limit: u64,
    origin: Origin,
    captured: Option<ArtifactIdentity>,
}

struct Retirement<'a, Lease = InstallationLock> {
    path: &'a Path,
    authority: &'a DocumentAuthority,
    parent_path: PathBuf,
    parent: File,
    key: String,
    record_path: PathBuf,
    record_authority: DocumentAuthority,
    _lock: Lease,
}

/// Recognized fenced history, not a durability acknowledgement or product
/// authentication. `captured: None` means explicitly retired empty history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredAtomicDocument {
    pub captured: Option<AtomicDocument>,
}

/// Read captured history without creating, locking, syncing or recovering.
/// `None` means the target has not reached a recognized retirement fence; it
/// does not grant permission to initialize history. An invalid existing record,
/// missing captured file, changed fence or changed recorded identity is an error.
/// A post-exchange interruption is readable before the writer has acknowledged
/// durability or recorded the captured digest. Callers must revalidate at their
/// mutation boundary and independently authenticate the returned document.
pub fn observe_retired_atomic_document(
    path: &Path,
    authority: &DocumentAuthority,
) -> Result<Option<RetiredAtomicDocument>> {
    validate_target(path, authority)?;
    let context = match Retirement::<()>::context(path, authority, false) {
        Ok(context) => context,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error),
    };
    let Some(original) =
        crate::read_atomic_document(&context.record_path, &context.record_authority)?
    else {
        return Ok(None);
    };
    let record: Record = serde_json::from_slice(&original.bytes)?;
    context.validate(&record, true)?;
    let stage = context.parent_path.join(&record.stage);
    let observed = if context.is_fence(path, &record)? {
        context.inspect_fence(path, &record)?;
        let captured = crate::read_atomic_document(&stage, authority)?;
        match (&record.origin, &captured) {
            (Origin::Existing, None) => bail!("captured retirement history is missing"),
            (Origin::Absent, Some(_)) => bail!("unexpected retirement history"),
            _ => {}
        }
        if record.captured.as_ref().is_some_and(|expected| {
            captured.as_ref().map(|document| &document.identity) != Some(expected)
        }) {
            bail!("captured retirement history changed");
        }
        Some(RetiredAtomicDocument { captured })
    } else {
        if record.captured.is_some() {
            bail!("completed retirement fence is missing");
        }
        context.inspect_fence(&stage, &record)?;
        let current = crate::read_atomic_document(path, authority)?;
        if record.origin == Origin::Existing && current.is_none() {
            bail!("required retirement history is missing");
        }
        None
    };
    let current = crate::read_atomic_document(&context.record_path, &context.record_authority)?;
    if current.as_ref().map(|document| &document.identity) != Some(&original.identity) {
        bail!("retirement changed during observation");
    }
    context.verify_parent()?;
    Ok(observed)
}

/// Retire an atomic-replacement document, retaining its final bytes for import.
///
/// Linux exchanges the final document with an exact journal-owned empty 0700
/// directory. This excludes old writers that replace the path using rename,
/// including already-prepared writes; it does not exclude in-place writers or
/// hostile same-owner mutation. The permanent record, lock, fence and captured
/// document must remain in place. Nothing is deleted or scanned for cleanup.
/// Products own ancestor trust and authentication of the returned bytes.
///
/// The parent must be owned by the supplied owner without group/other write
/// permission. Calls acquire a nonblocking per-target lease; callers holding
/// other locks must maintain one order. `allow_absent` permits an explicitly
/// new history only, never loss of a previously captured document. False also
/// rejects a prior retirement that recorded an absent history.
///
/// Success reports durable retirement/record change and the final captured
/// document, or no document for new history. Errors can follow mutation and
/// require explicit retry with the same authority, not rollback to old writers.
pub fn retire_atomic_document(
    path: &Path,
    authority: &DocumentAuthority,
    allow_absent: bool,
) -> Result<(bool, Option<AtomicDocument>)> {
    retire_with(path, authority, allow_absent, |_| Ok(()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Recorded,
    Prepared,
    Published,
}

fn retire_with(
    path: &Path,
    authority: &DocumentAuthority,
    allow_absent: bool,
    mut boundary: impl FnMut(Phase) -> Result<()>,
) -> Result<(bool, Option<AtomicDocument>)> {
    validate_target(path, authority)?;
    let retirement = Retirement::open(path, authority)?;
    let existing =
        crate::read_atomic_document(&retirement.record_path, &retirement.record_authority)?;
    let mut changed = false;
    let mut record = match existing {
        Some(document) => serde_json::from_slice::<Record>(&document.bytes)?,
        None => {
            let source = crate::read_atomic_document(path, authority)?;
            if source.is_none() && !allow_absent {
                bail!("required retirement history is missing");
            }
            let temporary = tempfile::Builder::new()
                .prefix(PREFIX)
                .tempdir_in(&retirement.parent_path)?;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
            let metadata = temporary.path().symlink_metadata()?;
            if metadata.uid() != authority.owner_uid {
                bail!("retirement fence owner differs");
            }
            let parent = retirement.parent.metadata()?;
            let record = Record {
                schema: SCHEMA.into(),
                target: retirement.key.clone(),
                parent_device: parent.dev(),
                parent_inode: parent.ino(),
                stage: temporary
                    .path()
                    .file_name()
                    .and_then(|n| n.to_str())
                    .context("invalid retirement stage")?
                    .into(),
                fence_device: metadata.dev(),
                fence_inode: metadata.ino(),
                mode: authority.mode,
                limit: authority.limit,
                origin: if source.is_some() {
                    Origin::Existing
                } else {
                    Origin::Absent
                },
                captured: None,
            };
            // Retain before the fallible write: a visible record followed by a
            // sync error must not lose its fence through a TempDir destructor.
            let stage = temporary.keep();
            File::open(stage)?.sync_all()?;
            retirement.save(&record)?;
            changed = true;
            record
        }
    };
    retirement.validate(&record, allow_absent)?;
    boundary(Phase::Recorded)?;
    let stage = retirement.parent_path.join(&record.stage);
    if !retirement.is_fence(path, &record)? {
        if record.captured.is_some() {
            bail!("completed retirement fence is missing");
        }
        retirement.require_fence(&stage, &record)?;
        let source = crate::read_atomic_document(path, authority)?;
        if record.origin == Origin::Existing && source.is_none() {
            bail!("required retirement history is missing");
        }
        if source.is_some() && record.origin == Origin::Absent {
            record.origin = Origin::Existing;
            retirement.save(&record)?;
        }
        retirement.verify_parent()?;
        let name = path.file_name().context("retirement target has no name")?;
        boundary(Phase::Prepared)?;
        if record.origin == Origin::Absent {
            match rustix::fs::renameat_with(
                &retirement.parent,
                record.stage.as_str(),
                &retirement.parent,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            ) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {
                    // A participating old writer may have published first.
                    // Bind that history durably before exchanging it.
                    crate::read_atomic_document(path, authority)?
                        .context("concurrent retirement history disappeared")?;
                    record.origin = Origin::Existing;
                    retirement.save(&record)?;
                    retirement.exchange(&record)?;
                }
                Err(error) => return Err(error.into()),
            }
        } else {
            retirement.exchange(&record)?;
        }
        changed = true;
    }
    retirement.require_fence(path, &record)?;
    retirement.parent.sync_all()?;
    boundary(Phase::Published)?;
    let captured = crate::read_atomic_document(&stage, authority)?;
    match (&record.origin, &captured) {
        (Origin::Existing, None) => bail!("captured retirement history is missing"),
        (Origin::Absent, Some(_)) => bail!("unexpected retirement history"),
        _ => {}
    }
    if let Some(document) = &captured {
        match &record.captured {
            Some(identity) if identity != &document.identity => {
                bail!("captured retirement history changed")
            }
            Some(_) => {}
            None => {
                record.captured = Some(document.identity.clone());
                retirement.save(&record)?;
                changed = true;
            }
        }
        // A successful retry acknowledges retained history durability too.
        crate::open_read_nofollow(&stage)?.sync_all()?;
    }
    retirement.verify_parent()?;
    retirement.parent.sync_all()?;
    Ok((changed, captured))
}

fn validate_target(path: &Path, authority: &DocumentAuthority) -> Result<()> {
    crate::validate_document_authority(authority)?;
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.as_os_str().len() > 4096
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|p| matches!(p, Component::CurDir | Component::ParentDir))
    {
        bail!("document retirement requires a normalized absolute target");
    }
    Ok(())
}

impl<'a> Retirement<'a, ()> {
    fn context(path: &'a Path, authority: &'a DocumentAuthority, create: bool) -> Result<Self> {
        let parent_path = path
            .parent()
            .context("retirement target has no parent")?
            .to_owned();
        let (parent, _) = if create {
            crate::open_durable_directory_chain(&parent_path)?
        } else {
            crate::open_directory_chain(&parent_path, false)?
        };
        let parent = File::from(parent);
        let metadata = parent.metadata()?;
        if metadata.uid() != authority.owner_uid || metadata.mode() & 0o022 != 0 {
            bail!("retirement parent has unsafe custody");
        }
        let mut hash = Sha256::new();
        hash.update(b"dev-tools-retired-document-target-v1\0");
        hash.update(path.as_os_str().as_bytes());
        let key = format!("{:x}", hash.finalize());
        let stem = format!(".dev-tools-retired-document-{key}");
        let retirement = Self {
            path,
            authority,
            record_path: parent_path.join(format!("{stem}.json")),
            parent_path,
            parent,
            key,
            record_authority: DocumentAuthority {
                owner_uid: authority.owner_uid,
                mode: 0o600,
                limit: 4096,
            },
            _lock: (),
        };
        Ok(retirement)
    }
}

impl<Lease> Retirement<'_, Lease> {
    fn verify_parent(&self) -> Result<()> {
        let (named, _) = crate::open_directory_chain(&self.parent_path, false)?;
        let named = rustix::fs::fstat(&named)?;
        let retained = self.parent.metadata()?;
        if named.st_dev != retained.dev()
            || named.st_ino != retained.ino()
            || named.st_uid != self.authority.owner_uid
            || named.st_mode & 0o022 != 0
        {
            bail!("retirement parent identity or custody changed");
        }
        Ok(())
    }

    fn validate(&self, record: &Record, allow_absent: bool) -> Result<()> {
        let parent = self.parent.metadata()?;
        if record.schema != SCHEMA
            || record.target != self.key
            || record.parent_device != parent.dev()
            || record.parent_inode != parent.ino()
            || record.mode != self.authority.mode
            || record.limit != self.authority.limit
            || !record.stage.starts_with(PREFIX)
            || record.stage.len() > 255
            || Path::new(&record.stage).file_name() != Some(std::ffi::OsStr::new(&record.stage))
            || (record.origin == Origin::Absent && (!allow_absent || record.captured.is_some()))
        {
            bail!("document retirement record authority differs");
        }
        self.verify_parent()
    }

    fn is_fence(&self, path: &Path, record: &Record) -> Result<bool> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        Ok(metadata.is_dir()
            && metadata.dev() == record.fence_device
            && metadata.ino() == record.fence_inode)
    }

    fn inspect_fence(&self, path: &Path, record: &Record) -> Result<File> {
        let directory = File::from(rustix::fs::openat(
            &self.parent,
            path.file_name().context("fence has no name")?,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        let metadata = directory.metadata()?;
        if metadata.dev() != record.fence_device
            || metadata.ino() != record.fence_inode
            || metadata.uid() != self.authority.owner_uid
            || metadata.mode() & 0o7777 != 0o700
            || fs::read_dir(path)?.next().is_some()
        {
            bail!("retirement fence custody or inventory changed");
        }
        Ok(directory)
    }
}

impl<'a> Retirement<'a> {
    fn open(path: &'a Path, authority: &'a DocumentAuthority) -> Result<Self> {
        let context = Retirement::<()>::context(path, authority, true)?;
        let lock = InstallationLock::open_with_owner(
            &context
                .parent_path
                .join(format!(".dev-tools-retired-document-{}.lock", context.key)),
            true,
            Some(authority.owner_uid),
            || {},
        )?
        .context("document retirement is busy")?;
        let retirement = Self {
            path: context.path,
            authority: context.authority,
            parent_path: context.parent_path,
            parent: context.parent,
            key: context.key,
            record_path: context.record_path,
            record_authority: context.record_authority,
            _lock: lock,
        };
        retirement.verify_parent()?;
        Ok(retirement)
    }

    fn require_fence(&self, path: &Path, record: &Record) -> Result<()> {
        self.inspect_fence(path, record)?.sync_all()?;
        Ok(())
    }

    fn save(&self, record: &Record) -> Result<()> {
        self.verify_parent()?;
        let current = crate::read_atomic_document(&self.record_path, &self.record_authority)?;
        crate::write_atomic_document(
            &self.record_path,
            &serde_json::to_vec(record)?,
            &self.record_authority,
            current.as_ref().map(|document| &document.identity),
        )?;
        Ok(())
    }

    fn exchange(&self, record: &Record) -> Result<()> {
        self.verify_parent()?;
        self.require_fence(&self.parent_path.join(&record.stage), record)?;
        rustix::fs::renameat_with(
            &self.parent,
            record.stage.as_str(),
            &self.parent,
            self.path
                .file_name()
                .context("retirement target has no name")?,
            rustix::fs::RenameFlags::EXCHANGE,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(root: &Path) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: root.metadata().unwrap().uid(),
            mode: 0o600,
            limit: 1024,
        }
    }

    #[test]
    fn absent_publication_losing_to_legacy_writer_preserves_that_history() {
        let root = tempfile::tempdir().unwrap();
        let auth = authority(root.path());
        let source = root.path().join("state");
        let (_, captured) = retire_with(&source, &auth, true, |phase| {
            if phase == Phase::Prepared {
                crate::write_atomic_document(&source, b"legacy won", &auth, None)?;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(captured.unwrap().bytes, b"legacy won");
        assert_eq!(
            retire_atomic_document(&source, &auth, false)
                .unwrap()
                .1
                .unwrap()
                .bytes,
            b"legacy won"
        );
    }

    #[test]
    fn crash_fixture() {
        let Some(root) = std::env::var_os("DEV_TOOLS_RETIREMENT_TEST_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        let requested = std::env::var("DEV_TOOLS_RETIREMENT_TEST_PHASE").unwrap();
        retire_with(&root.join("state"), &authority(&root), true, |phase| {
            if matches!(
                (requested.as_str(), phase),
                ("recorded", Phase::Recorded) | ("published", Phase::Published)
            ) {
                std::process::exit(74);
            }
            Ok(())
        })
        .unwrap();
        panic!("crash fixture unexpectedly completed");
    }

    #[test]
    fn native_process_exit_releases_lease_and_retains_recoverable_history() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        for phase in ["recorded", "published"] {
            for present in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let auth = authority(root.path());
                let source = root.path().join("state");
                if present {
                    crate::write_atomic_document(&source, b"history", &auth, None).unwrap();
                }
                let mut child = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "document_retirement::tests::crash_fixture"])
                    .env_clear()
                    .env("DEV_TOOLS_RETIREMENT_TEST_ROOT", root.path())
                    .env("DEV_TOOLS_RETIREMENT_TEST_PHASE", phase)
                    .current_dir(root.path())
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                let deadline = Instant::now() + Duration::from_secs(10);
                let status = loop {
                    if let Some(status) = child.try_wait().unwrap() {
                        break status;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        panic!("retirement child timed out");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                assert_eq!(status.code(), Some(74));
                let (record_path, _) = record(root.path());
                let before = fs::read(&record_path).unwrap();
                let observed = observe_retired_atomic_document(&source, &auth).unwrap();
                if phase == "published" {
                    assert_eq!(
                        observed.unwrap().captured.map(|d| d.bytes),
                        present.then(|| b"history".to_vec())
                    );
                } else {
                    assert!(observed.is_none());
                }
                assert_eq!(fs::read(record_path).unwrap(), before);
                let (_, captured) = retire_atomic_document(&source, &auth, true).unwrap();
                assert_eq!(
                    captured.map(|d| d.bytes),
                    present.then(|| b"history".to_vec())
                );
                assert!(!retire_atomic_document(&source, &auth, true).unwrap().0);
            }
        }
    }

    #[test]
    fn live_retirement_lease_excludes_reentry() {
        let root = tempfile::tempdir().unwrap();
        let auth = authority(root.path());
        let source = root.path().join("state");
        retire_with(&source, &auth, true, |phase| {
            if phase == Phase::Recorded {
                assert!(retire_atomic_document(&source, &auth, true).is_err());
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn observation_inside_writer_boundaries_never_finishes_the_record() {
        for present in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let auth = authority(root.path());
            let source = root.path().join("state");
            if present {
                crate::write_atomic_document(&source, b"history", &auth, None).unwrap();
            }
            retire_with(&source, &auth, true, |phase| {
                let (path, saved) = record(root.path());
                let before = fs::read(&path)?;
                let observed = observe_retired_atomic_document(&source, &auth)?;
                if phase == Phase::Published {
                    assert!(saved.captured.is_none());
                    assert_eq!(
                        observed.unwrap().captured.map(|document| document.bytes),
                        present.then(|| b"history".to_vec())
                    );
                } else {
                    assert!(observed.is_none());
                }
                assert_eq!(fs::read(path)?, before);
                Ok(())
            })
            .unwrap();
        }
    }

    fn record(root: &Path) -> (PathBuf, Record) {
        let path = fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                let name = p.file_name().unwrap().to_str().unwrap();
                name.starts_with(".dev-tools-retired-document-") && name.ends_with(".json")
            })
            .unwrap();
        let record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        (path, record)
    }

    #[test]
    fn captures_last_legacy_write_not_pre_record_snapshot() {
        for originally_present in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let auth = authority(root.path());
            let source = root.path().join("state");
            if originally_present {
                crate::write_atomic_document(&source, b"earlier", &auth, None).unwrap();
            }
            let (_, captured) = retire_with(&source, &auth, true, |phase| {
                if phase == Phase::Recorded {
                    let current = crate::read_atomic_document(&source, &auth)?;
                    crate::write_atomic_document(
                        &source,
                        b"last write",
                        &auth,
                        current.as_ref().map(|d| &d.identity),
                    )?;
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(captured.unwrap().bytes, b"last write");
            assert_eq!(
                retire_atomic_document(&source, &auth, false)
                    .unwrap()
                    .1
                    .unwrap()
                    .bytes,
                b"last write"
            );
        }
    }

    #[test]
    fn interrupted_publication_resumes_without_lowering_history() {
        for phase in [Phase::Recorded, Phase::Published] {
            for present in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let auth = authority(root.path());
                let source = root.path().join("state");
                if present {
                    crate::write_atomic_document(&source, b"history", &auth, None).unwrap();
                }
                assert!(retire_with(&source, &auth, true, |at| {
                    if at == phase {
                        bail!("injected boundary failure");
                    }
                    Ok(())
                })
                .is_err());
                let (_, captured) = retire_atomic_document(&source, &auth, true).unwrap();
                assert_eq!(
                    captured.map(|d| d.bytes),
                    present.then(|| b"history".to_vec())
                );
                assert!(!retire_atomic_document(&source, &auth, true).unwrap().0);
            }
        }
    }

    #[test]
    fn missing_or_changed_archive_never_becomes_empty_history() {
        for remove in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let auth = authority(root.path());
            let source = root.path().join("state");
            crate::write_atomic_document(&source, b"history", &auth, None).unwrap();
            retire_atomic_document(&source, &auth, false).unwrap();
            let (record_path, saved) = record(root.path());
            let before = fs::read(&record_path).unwrap();
            let archive = root.path().join(saved.stage);
            if remove {
                fs::remove_file(archive).unwrap();
            } else {
                let current = crate::read_atomic_document(&archive, &auth)
                    .unwrap()
                    .unwrap();
                crate::write_atomic_document(&archive, b"changed", &auth, Some(&current.identity))
                    .unwrap();
            }
            assert!(retire_atomic_document(&source, &auth, true).is_err());
            assert_eq!(fs::read(record_path).unwrap(), before);
            assert!(observe_retired_atomic_document(&source, &auth).is_err());
            assert!(source.is_dir());
        }
    }

    #[test]
    fn pending_existing_history_cannot_disappear() {
        let root = tempfile::tempdir().unwrap();
        let auth = authority(root.path());
        let source = root.path().join("state");
        crate::write_atomic_document(&source, b"history", &auth, None).unwrap();
        assert!(retire_with(&source, &auth, true, |_| {
            bail!("stop before exchange");
        })
        .is_err());
        fs::remove_file(&source).unwrap();
        assert!(retire_atomic_document(&source, &auth, true).is_err());
        assert!(!source.exists());
        assert!(observe_retired_atomic_document(&source, &auth).is_err());
    }

    #[test]
    fn changed_authority_or_fence_inventory_fails_without_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let auth = authority(root.path());
        let source = root.path().join("state");
        retire_atomic_document(&source, &auth, true).unwrap();
        let mut changed = auth.clone();
        changed.limit += 1;
        assert!(retire_atomic_document(&source, &changed, true).is_err());
        assert!(observe_retired_atomic_document(&source, &changed).is_err());
        let unknown = source.join("unknown");
        fs::write(&unknown, b"keep").unwrap();
        assert!(retire_atomic_document(&source, &auth, true).is_err());
        assert!(observe_retired_atomic_document(&source, &auth).is_err());
        assert_eq!(fs::read(unknown).unwrap(), b"keep");
    }

    #[test]
    fn malformed_record_and_replaced_fence_are_not_adopted() {
        for field in ["schema", "target", "parent_inode", "stage", "unknown"] {
            let root = tempfile::tempdir().unwrap();
            let auth = authority(root.path());
            let source = root.path().join("state");
            retire_atomic_document(&source, &auth, true).unwrap();
            let (record_path, _) = record(root.path());
            let mut value: serde_json::Value =
                serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
            value[field] = if field == "parent_inode" {
                serde_json::json!(0)
            } else {
                serde_json::json!("../foreign")
            };
            let altered = serde_json::to_vec(&value).unwrap();
            fs::write(&record_path, &altered).unwrap();
            assert!(retire_atomic_document(&source, &auth, true).is_err());
            assert!(observe_retired_atomic_document(&source, &auth).is_err());
            assert_eq!(fs::read(record_path).unwrap(), altered);
            assert!(source.is_dir());
        }
        let root = tempfile::tempdir().unwrap();
        let auth = authority(root.path());
        let source = root.path().join("state");
        retire_atomic_document(&source, &auth, true).unwrap();
        fs::rename(&source, root.path().join("retained-fence")).unwrap();
        fs::create_dir(&source).unwrap();
        assert!(retire_atomic_document(&source, &auth, true).is_err());
        assert!(observe_retired_atomic_document(&source, &auth).is_err());
        assert!(source.is_dir());
        assert!(root.path().join("retained-fence").is_dir());
    }

    #[test]
    fn unsafe_source_custody_is_rejected_before_retirement_record() {
        use std::os::unix::fs::symlink;
        for kind in ["symlink", "hardlink", "mode", "oversize"] {
            let root = tempfile::tempdir().unwrap();
            let auth = authority(root.path());
            let source = root.path().join("state");
            let other = root.path().join("other");
            crate::write_atomic_document(&other, b"history", &auth, None).unwrap();
            match kind {
                "symlink" => symlink(&other, &source).unwrap(),
                "hardlink" => fs::hard_link(&other, &source).unwrap(),
                "mode" => {
                    fs::copy(&other, &source).unwrap();
                    fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
                }
                _ => {
                    fs::copy(&other, &source).unwrap();
                    fs::write(&source, vec![0; 1025]).unwrap();
                }
            }
            assert!(retire_atomic_document(&source, &auth, true).is_err());
            assert_eq!(fs::read(other).unwrap(), b"history");
            assert!(!fs::read_dir(root.path()).unwrap().any(|e| {
                let name = e.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with(".dev-tools-retired-document-") && name.ends_with(".json")
            }));
        }
    }
}
