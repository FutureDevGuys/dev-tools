//! Journal-owned first-use directory publication on Linux.
use crate::{DocumentAuthority, InstallationLock};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

const SCHEMA: &str = "dev-tools-initial-directory-publication-v1";
const PREFIX: &str = ".dev-tools-initial-owned-";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    target: String,
    parent_device: u64,
    parent_inode: u64,
    stage: String,
    stage_device: u64,
    stage_inode: u64,
    document: String,
    limit: u64,
}

struct Publication {
    parent_path: PathBuf,
    parent: File,
    target_key: String,
    journal_path: PathBuf,
    authority: DocumentAuthority,
    _lock: InstallationLock,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    BeforeJournal,
    JournalPublished,
    ContentSynced,
    DirectoryPublished,
}

/// Publish a new private directory and recover this protocol's interrupted staging.
///
/// This Linux boundary requires mode 0700, document mode 0600, and a parent
/// owned by `authority.owner_uid` without group/other write permission, or a
/// root-owned sticky parent such as the system temporary directory. Callers
/// own ancestor trust. The per-target nonblocking lock is retained permanently;
/// cooperating callers must not unlink it or use another publication protocol
/// concurrently for the same target. No existing final directory is adopted or
/// replaced, even when a prior attempt published it before a durability error.
///
/// A durable journal binds the exact staged directory device/inode before any
/// document bytes are written. Retry removes only that directory's closed,
/// custody-checked inventory. Older unmarked temporary entries are never
/// scanned, adopted or removed. Death before journal publication can still leave
/// an empty unmarked directory or an atomic-journal temporary; these do not
/// block a new attempt and do not confer cleanup authority. This is a
/// cooperating-owner protocol, not isolation from the same filesystem owner.
/// Errors may follow publication or recovery and do not promise unchanged state.
pub fn publish_new_document_directory_recoverable(
    path: &Path,
    document_name: &str,
    bytes: &[u8],
    authority: &DocumentAuthority,
    mode: u32,
) -> Result<()> {
    publish_with(path, document_name, bytes, authority, mode, |_, _| Ok(()))
}

fn publish_with(
    path: &Path,
    document_name: &str,
    bytes: &[u8],
    authority: &DocumentAuthority,
    mode: u32,
    mut boundary: impl FnMut(&Path, Phase) -> Result<()>,
) -> Result<()> {
    crate::validate_document_authority(authority)?;
    if mode != 0o700
        || authority.mode != 0o600
        || bytes.is_empty()
        || bytes.len() as u64 > authority.limit
        || !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || !single_name(document_name)
    {
        bail!("initial private directory publication has invalid authority or bounds");
    }
    let publication = Publication::open(path, authority)?;
    publication.recover(document_name, authority.limit)?;
    crate::require_path_absent(path)?;
    let temporary = tempfile::Builder::new()
        .prefix(PREFIX)
        .tempdir_in(&publication.parent_path)
        .context("reserve initial publication directory")?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    let metadata = temporary.path().symlink_metadata()?;
    if metadata.uid() != authority.owner_uid {
        bail!("initial publication directory owner differs");
    }
    let parent_metadata = publication.parent.metadata()?;
    let journal = Journal {
        schema: SCHEMA.into(),
        target: publication.target_key.clone(),
        parent_device: parent_metadata.dev(),
        parent_inode: parent_metadata.ino(),
        stage: temporary
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .context("initial publication stage name is invalid")?
            .into(),
        stage_device: metadata.dev(),
        stage_inode: metadata.ino(),
        document: document_name.into(),
        limit: authority.limit,
    };
    boundary(temporary.path(), Phase::BeforeJournal)?;
    // Publication of this bounded record precedes writing any staged content.
    // Its atomic writer may leave an unmarked temporary on process death; no
    // recovery operation infers authority over such entries.
    crate::write_atomic_document(
        &publication.journal_path,
        &serde_json::to_vec(&journal)?,
        &publication.authority,
        None,
    )?;
    let staged_path = temporary.keep();
    boundary(&staged_path, Phase::JournalPublished)?;
    let mut document = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(staged_path.join(document_name))?;
    document.set_permissions(fs::Permissions::from_mode(0o600))?;
    document.write_all(bytes)?;
    document.sync_all()?;
    let directory = publication.open_stage(&journal)?;
    directory.sync_all()?;
    boundary(&staged_path, Phase::ContentSynced)?;
    publication.verify_parent()?;
    publication.open_stage(&journal)?;
    rustix::fs::renameat_with(
        &publication.parent,
        journal.stage.as_str(),
        &publication.parent,
        path.file_name().context("publication target has no name")?,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .context("publish journal-owned initial directory")?;
    publication.parent.sync_all()?;
    boundary(path, Phase::DirectoryPublished)?;
    publication.clear_journal()?;
    Ok(())
}

fn single_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && Path::new(name).file_name() == Some(std::ffi::OsStr::new(name))
        && !matches!(name, "." | "..")
}

impl Publication {
    fn open(path: &Path, authority: &DocumentAuthority) -> Result<Self> {
        let parent_path = path
            .parent()
            .context("publication target has no parent")?
            .to_owned();
        let (parent, _) = crate::open_durable_directory_chain(&parent_path)?;
        let parent = File::from(parent);
        let metadata = parent.metadata()?;
        if !parent_custody(metadata.uid(), metadata.mode(), authority.owner_uid) {
            bail!("initial publication parent has unsafe custody");
        }
        let mut digest = Sha256::new();
        digest.update(b"dev-tools-initial-directory-target-v1\0");
        digest.update(path.as_os_str().as_bytes());
        let target_key = format!("{:x}", digest.finalize());
        let stem = format!(".dev-tools-initial-{target_key}");
        let lock = InstallationLock::open_with_owner(
            &parent_path.join(format!("{stem}.lock")),
            true,
            Some(authority.owner_uid),
            || {},
        )?
        .context("initial directory publication is busy")?;
        let publication = Self {
            journal_path: parent_path.join(format!("{stem}.json")),
            parent_path,
            parent,
            target_key,
            authority: DocumentAuthority {
                owner_uid: authority.owner_uid,
                mode: 0o600,
                limit: 4096,
            },
            _lock: lock,
        };
        publication.verify_parent()?;
        Ok(publication)
    }

    fn verify_parent(&self) -> Result<()> {
        let (named, _) = crate::open_directory_chain(&self.parent_path, false)?;
        let named = rustix::fs::fstat(&named)?;
        let retained = self.parent.metadata()?;
        if named.st_dev != retained.dev()
            || named.st_ino != retained.ino()
            || !parent_custody(named.st_uid, named.st_mode, self.authority.owner_uid)
        {
            bail!("initial publication parent identity changed");
        }
        Ok(())
    }

    fn open_stage(&self, journal: &Journal) -> Result<File> {
        let directory = rustix::fs::openat(
            &self.parent,
            journal.stage.as_str(),
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let directory = File::from(directory);
        let metadata = directory.metadata()?;
        if metadata.dev() != journal.stage_device
            || metadata.ino() != journal.stage_inode
            || metadata.uid() != self.authority.owner_uid
            || metadata.mode() & 0o7777 != 0o700
        {
            bail!("journal-owned initial directory custody changed");
        }
        Ok(directory)
    }

    fn recover(&self, document_name: &str, limit: u64) -> Result<()> {
        let Some(document) = crate::read_atomic_document(&self.journal_path, &self.authority)?
        else {
            return Ok(());
        };
        let journal: Journal = serde_json::from_slice(&document.bytes)?;
        let parent = self.parent.metadata()?;
        if journal.schema != SCHEMA
            || journal.target != self.target_key
            || journal.parent_device != parent.dev()
            || journal.parent_inode != parent.ino()
            || journal.document != document_name
            || journal.limit != limit
            || !single_name(&journal.stage)
            || !journal.stage.starts_with(PREFIX)
        {
            bail!("initial publication journal authority differs");
        }
        self.verify_parent()?;
        let stage = self.parent_path.join(&journal.stage);
        match fs::symlink_metadata(&stage) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // It may already have been renamed to the final directory. No
                // final entry is modified or treated as a successful new install.
                return self.clear_journal();
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let directory = self.open_stage(&journal)?;
        let mut has_document = false;
        for entry in fs::read_dir(&stage)? {
            let entry = entry?;
            if entry.file_name() != std::ffi::OsStr::new(document_name) || has_document {
                bail!("initial publication directory contains an unowned entry");
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.is_file()
                || metadata.uid() != self.authority.owner_uid
                || metadata.mode() & 0o7777 & !0o600 != 0
                || metadata.nlink() != 1
                || metadata.len() > limit
            {
                bail!("initial publication document has invalid custody");
            }
            has_document = true;
        }
        self.open_stage(&journal)?;
        if has_document {
            rustix::fs::unlinkat(&directory, document_name, rustix::fs::AtFlags::empty())?;
            directory.sync_all()?;
        }
        rustix::fs::unlinkat(
            &self.parent,
            journal.stage.as_str(),
            rustix::fs::AtFlags::REMOVEDIR,
        )?;
        self.parent.sync_all()?;
        self.clear_journal()
    }

    fn clear_journal(&self) -> Result<()> {
        self.verify_parent()?;
        rustix::fs::unlinkat(
            &self.parent,
            self.journal_path
                .file_name()
                .context("journal has no filename")?,
            rustix::fs::AtFlags::empty(),
        )?;
        self.parent.sync_all()?;
        Ok(())
    }
}

fn parent_custody(owner: u32, mode: u32, expected_owner: u32) -> bool {
    (owner == expected_owner && mode & 0o022 == 0) || (owner == 0 && mode & 0o1000 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    fn authority(root: &Path) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: root.metadata().unwrap().uid(),
            mode: 0o600,
            limit: 1024,
        }
    }

    #[test]
    fn crash_fixture() {
        let Some(root) = std::env::var_os("DEV_TOOLS_INITIAL_PUBLICATION_TEST_ROOT") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        publish_with(
            &root.join("target"),
            "document.json",
            b"interrupted",
            &authority(&root),
            0o700,
            |_, phase| {
                let requested = std::env::var("DEV_TOOLS_INITIAL_PUBLICATION_TEST_PHASE")
                    .unwrap_or_else(|_| "content".into());
                if matches!(
                    (requested.as_str(), phase),
                    ("unmarked", Phase::BeforeJournal)
                        | ("journal", Phase::JournalPublished)
                        | ("content", Phase::ContentSynced)
                        | ("published", Phase::DirectoryPublished)
                ) {
                    std::process::exit(91);
                }
                Ok(())
            },
        )
        .unwrap();
        panic!("crash fixture unexpectedly completed");
    }

    #[test]
    fn retry_after_process_death_recovers_only_owned_initial_staging() {
        let temp = tempfile::tempdir().unwrap();
        let legacy = temp.path().join(".dev-tools-initial-legacy-unmarked");
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("unowned"), b"preserve").unwrap();
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "directory_publication::tests::crash_fixture",
                "--nocapture",
            ])
            .env("DEV_TOOLS_INITIAL_PUBLICATION_TEST_ROOT", temp.path())
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(91));
        assert!(!temp.path().join("target").exists());
        let interrupted: Vec<_> = fs::read_dir(temp.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.is_dir() && path != &legacy)
            .collect();
        assert_eq!(interrupted.len(), 1, "fixture must leave real staged bytes");
        publish_new_document_directory_recoverable(
            &temp.path().join("target"),
            "document.json",
            b"retry",
            &authority(temp.path()),
            0o700,
        )
        .unwrap();
        assert_eq!(
            fs::read(temp.path().join("target/document.json")).unwrap(),
            b"retry"
        );
        assert_eq!(fs::read(legacy.join("unowned")).unwrap(), b"preserve");
        assert!(
            !interrupted[0].exists(),
            "durably owned staging must be recovered"
        );
    }

    fn crash(root: &Path, phase: &str) {
        let result = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "directory_publication::tests::crash_fixture",
                "--nocapture",
            ])
            .env("DEV_TOOLS_INITIAL_PUBLICATION_TEST_ROOT", root)
            .env("DEV_TOOLS_INITIAL_PUBLICATION_TEST_PHASE", phase)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(91));
    }

    fn stage(root: &Path) -> PathBuf {
        fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_dir())
            .unwrap()
    }

    fn retry(root: &Path) -> Result<()> {
        publish_new_document_directory_recoverable(
            &root.join("target"),
            "document.json",
            b"retry",
            &authority(root),
            0o700,
        )
    }

    #[test]
    fn crash_boundaries_preserve_unmarked_entries_and_never_replace_published_state() {
        for phase in ["unmarked", "journal", "published"] {
            let temp = tempfile::tempdir().unwrap();
            crash(temp.path(), phase);
            let prior = stage(temp.path());
            let result = retry(temp.path());
            if phase == "published" {
                assert!(
                    result.is_err(),
                    "published state is never adopted as a new install"
                );
                assert_eq!(
                    fs::read(prior.join("document.json")).unwrap(),
                    b"interrupted"
                );
            } else {
                result.unwrap();
                assert_eq!(prior.exists(), phase == "unmarked");
                assert_eq!(
                    fs::read(temp.path().join("target/document.json")).unwrap(),
                    b"retry"
                );
            }
            assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "json")));
        }
    }

    #[test]
    fn recovery_rejects_unknown_inventory_and_payload_custody_before_deletion() {
        for kind in [
            "unknown",
            "symlink",
            "hardlink",
            "mode",
            "oversized",
            "directory",
        ] {
            let temp = tempfile::tempdir().unwrap();
            crash(temp.path(), "content");
            let staged = stage(temp.path());
            let path = staged.join("document.json");
            match kind {
                "unknown" => fs::write(staged.join("unknown"), b"preserve").unwrap(),
                "symlink" => {
                    fs::remove_file(&path).unwrap();
                    fs::write(temp.path().join("external"), b"preserve").unwrap();
                    std::os::unix::fs::symlink(temp.path().join("external"), &path).unwrap();
                }
                "hardlink" => fs::hard_link(&path, temp.path().join("external")).unwrap(),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "oversized" => fs::write(&path, vec![b'x'; 1025]).unwrap(),
                "directory" => {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(retry(temp.path()).is_err(), "must reject {kind}");
            assert!(staged.exists());
            assert!(fs::symlink_metadata(&path).is_ok(), "must preserve {kind}");
            assert!(!temp.path().join("target").exists());
        }
    }

    #[test]
    fn recovery_accepts_incomplete_owner_only_creation_before_permission_finalization() {
        for mode in [0o000, 0o200, 0o400, 0o600] {
            let temp = tempfile::tempdir().unwrap();
            crash(temp.path(), "journal");
            let staged = stage(temp.path());
            fs::write(staged.join("document.json"), b"partial").unwrap();
            fs::set_permissions(
                staged.join("document.json"),
                fs::Permissions::from_mode(mode),
            )
            .unwrap();
            retry(temp.path()).unwrap();
            assert!(!staged.exists());
            let final_document = temp.path().join("target/document.json");
            assert_eq!(fs::read(&final_document).unwrap(), b"retry");
            assert_eq!(final_document.metadata().unwrap().mode() & 0o7777, 0o600);
        }
    }

    #[test]
    fn recovery_binds_exact_directory_and_journal_authority() {
        for kind in [
            "inode", "target", "document", "limit", "schema", "parent", "extra",
        ] {
            let temp = tempfile::tempdir().unwrap();
            crash(temp.path(), "content");
            let staged = stage(temp.path());
            if kind == "inode" {
                fs::rename(&staged, temp.path().join("preserved-old")).unwrap();
                fs::create_dir(&staged).unwrap();
                fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
            } else {
                let journal = fs::read_dir(temp.path())
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.extension()
                            .is_some_and(|extension| extension == "json")
                    })
                    .unwrap();
                let mut value: serde_json::Value =
                    serde_json::from_slice(&fs::read(&journal).unwrap()).unwrap();
                match kind {
                    "target" => value["target"] = "wrong".into(),
                    "document" => value["document"] = "different".into(),
                    "limit" => value["limit"] = 1.into(),
                    "schema" => value["schema"] = "wrong".into(),
                    "parent" => value["parent_inode"] = 0.into(),
                    "extra" => value["unknown"] = true.into(),
                    _ => unreachable!(),
                }
                fs::write(journal, serde_json::to_vec(&value).unwrap()).unwrap();
            }
            assert!(retry(temp.path()).is_err(), "must reject {kind}");
            assert!(staged.exists(), "must preserve {kind}");
            assert!(!temp.path().join("target").exists());
        }
    }

    #[test]
    fn live_publication_lock_excludes_retry_and_final_collision_is_preserved() {
        let temp = tempfile::tempdir().unwrap();
        publish_with(
            &temp.path().join("target"),
            "document.json",
            b"first",
            &authority(temp.path()),
            0o700,
            |staged, phase| {
                if phase == Phase::ContentSynced {
                    assert!(retry(temp.path()).is_err());
                    assert_eq!(fs::read(staged.join("document.json")).unwrap(), b"first");
                }
                Ok(())
            },
        )
        .unwrap();
        assert!(retry(temp.path()).is_err());
        assert_eq!(
            fs::read(temp.path().join("target/document.json")).unwrap(),
            b"first"
        );
    }

    #[test]
    fn invalid_bounds_and_parent_custody_do_not_publish() {
        for kind in [
            "empty",
            "oversized",
            "document-mode",
            "directory-mode",
            "name",
            "parent-mode",
            "normalized",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let mut authority = authority(temp.path());
            let mut bytes = b"valid".to_vec();
            let mut mode = 0o700;
            let mut name = "document.json";
            let mut path = temp.path().join("target");
            match kind {
                "empty" => bytes.clear(),
                "oversized" => bytes.resize(1025, b'x'),
                "document-mode" => authority.mode = 0o644,
                "directory-mode" => mode = 0o755,
                "name" => name = "../escape",
                "parent-mode" => {
                    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o777)).unwrap()
                }
                "normalized" => path = PathBuf::from(format!("{}/./target", temp.path().display())),
                _ => unreachable!(),
            }
            assert!(
                publish_new_document_directory_recoverable(&path, name, &bytes, &authority, mode)
                    .is_err(),
                "must reject {kind}"
            );
            assert_eq!(
                fs::read_dir(temp.path()).unwrap().count(),
                0,
                "must not stage {kind}"
            );
        }
        assert!(parent_custody(1000, 0o40755, 1000));
        assert!(parent_custody(0, 0o41777, 1000));
        assert!(!parent_custody(1001, 0o41777, 1000));
        assert!(!parent_custody(0, 0o40777, 1000));
    }

    #[test]
    fn root_owned_sticky_parent_keeps_the_publication_lock_user_owned() {
        let parent = Path::new("/tmp");
        let metadata = parent.metadata().unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_ne!(metadata.mode() & 0o1000, 0);
        let target = tempfile::Builder::new()
            .prefix("dev-tools-initial-test-")
            .tempdir_in(parent)
            .unwrap();
        let authority = authority(target.path());
        fs::remove_dir(target.path()).unwrap();
        let publication = Publication::open(target.path(), &authority).unwrap();
        let lock_path = publication.journal_path.with_extension("lock");
        assert_eq!(lock_path.metadata().unwrap().uid(), authority.owner_uid);
        assert_eq!(lock_path.metadata().unwrap().mode() & 0o7777, 0o600);
        drop(publication);
        publish_new_document_directory_recoverable(
            target.path(),
            "document.json",
            b"private",
            &authority,
            0o700,
        )
        .unwrap();
        assert_eq!(
            fs::read(target.path().join("document.json")).unwrap(),
            b"private"
        );
        // This unique test target has no remaining users. The production
        // protocol deliberately retains the lock for future participating calls.
        fs::remove_file(lock_path).unwrap();
    }
}
