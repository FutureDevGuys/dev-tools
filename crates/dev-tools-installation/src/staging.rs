//! Explicitly reserved, lease-protected quarantine. Never installation authority.
use crate::{
    publish_new_document_directory, read_atomic_document, DocumentAuthority, InstallationLock,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, Metadata, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const MARKER: &str = "staging-reservation-v1.json";
const LOCK: &str = "staging.lock";
const PAYLOAD: &str = "payload";
const SCHEMA: &str = "dev-tools-staging-reservation-v1";

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Reservation {
    schema: String,
    target: [u8; 32],
}

/// Linux quarantine reservation bound to a caller-owned target identifier.
/// Callers own trusted ancestor selection and release authentication.
/// The reserved directory is dedicated to this protocol, never an installation
/// or cache directory containing other data. Its stable lock is never removed.
#[derive(Clone)]
pub struct StagingArea {
    path: PathBuf,
    owner: u32,
    target: [u8; 32],
}

/// A live exclusive staging reservation. Dropping closes the payload and lease;
/// it deliberately leaves residual bytes for the next explicit acquisition.
/// Callers must settle all work using the payload before releasing this lease,
/// and must not retain cloned file descriptors beyond its lifetime. This is a
/// cooperating-process contract, not isolation from the same filesystem owner.
pub struct StagingLease {
    file: File,
    path: PathBuf,
    _lock: InstallationLock,
    area: StagingArea,
    directory: File,
}

enum PrivatePublication<'a> {
    NoClobber,
    Document {
        expected_current: Option<&'a crate::ArtifactIdentity>,
        limit: u64,
    },
}

impl StagingArea {
    pub fn new(path: PathBuf, owner: u32, target: [u8; 32]) -> Result<Self> {
        if !path.is_absolute()
            || path.file_name().is_none()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            bail!("staging root must be absolute and normalized");
        }
        Ok(Self {
            path,
            owner,
            target,
        })
    }

    /// Explicit first use; never adopts or replaces an existing directory.
    /// Publication uses the shared durable no-clobber directory primitive.
    /// Interrupted initial publication can leave an unpublished temporary
    /// directory; this protocol never infers ownership of those sibling entries.
    pub fn initialize(&self) -> Result<()> {
        let bytes =
            serde_json::to_vec(&self.reservation()).context("encode staging reservation")?;
        publish_new_document_directory(&self.path, MARKER, &bytes, &self.authority(), 0o700)
    }

    /// Explicit first use with journal-owned initial-directory recovery.
    /// Requires the parent custody of
    /// [`crate::publish_new_document_directory_recoverable`]. The older
    /// initializer and all existing reservation bytes remain unchanged.
    pub fn initialize_recoverable(&self) -> Result<()> {
        let bytes =
            serde_json::to_vec(&self.reservation()).context("encode staging reservation")?;
        crate::publish_new_document_directory_recoverable(
            &self.path,
            MARKER,
            &bytes,
            &self.authority(),
            0o700,
        )
    }

    /// Nonblocking acquisition, followed by cleanup of a reserved abandoned
    /// payload and creation of an empty private payload. Busy returns `None`.
    /// Neither successful acquisition nor the reservation authenticates bytes.
    /// Failures can leave recoverable reserved payload state; callers must inspect
    /// and reacquire explicitly, never assume a failed operation made no change.
    pub fn try_acquire(&self) -> Result<Option<StagingLease>> {
        let directory = self.inspect()?;
        self.inspect_entries()?;
        let Some(lock) = InstallationLock::try_acquire(&self.path.join(LOCK))? else {
            return Ok(None);
        };
        self.verify_directory(&directory)?;
        self.inspect_entries()?;
        let path = self.path.join(PAYLOAD);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                self.verify_payload(&metadata)?;
                // Reservation, native lease and exact custody together authorize
                // this fixed entry. No glob, timestamp or PID grants deletion.
                rustix::fs::unlinkat(&directory, PAYLOAD, rustix::fs::AtFlags::empty())
                    .context("remove abandoned staging payload")?;
                directory.sync_all().context("sync staging cleanup")?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect staging payload"),
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)
            .context("create staging payload")?;
        self.verify_payload(&file.metadata()?)?;
        Ok(Some(StagingLease {
            file,
            path,
            _lock: lock,
            area: self.clone(),
            directory,
        }))
    }

    fn reservation(&self) -> Reservation {
        Reservation {
            schema: SCHEMA.into(),
            target: self.target,
        }
    }

    fn authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.owner,
            mode: 0o600,
            limit: 1024,
        }
    }

    fn inspect(&self) -> Result<File> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&self.path)
            .context("open staging reservation")?;
        self.verify_directory(&directory)?;
        Ok(directory)
    }

    fn verify_directory(&self, directory: &File) -> Result<()> {
        let retained = directory
            .metadata()
            .context("inspect retained staging directory")?;
        let named = fs::symlink_metadata(&self.path).context("inspect staging directory")?;
        if !named.is_dir()
            || named.dev() != retained.dev()
            || named.ino() != retained.ino()
            || named.uid() != self.owner
            || named.mode() & 0o7777 != 0o700
        {
            bail!("staging directory custody changed");
        }
        let document = read_atomic_document(&self.path.join(MARKER), &self.authority())?
            .context("staging reservation is missing")?;
        let reservation: Reservation =
            serde_json::from_slice(&document.bytes).context("decode staging reservation")?;
        if reservation != self.reservation() {
            bail!("staging reservation authority differs");
        }
        Ok(())
    }

    fn inspect_entries(&self) -> Result<()> {
        // There are at most three protocol entries. Stop at the first unknown
        // name instead of collecting a potentially unbounded directory listing.
        for entry in fs::read_dir(&self.path).context("inspect staging entries")? {
            let name = entry.context("inspect staging entry")?.file_name();
            if name != MARKER && name != LOCK && name != PAYLOAD {
                bail!("staging directory contains an unowned entry");
            }
        }
        Ok(())
    }

    fn verify_payload(&self, metadata: &Metadata) -> Result<()> {
        if !metadata.is_file()
            || metadata.uid() != self.owner
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            bail!("staging payload has invalid custody");
        }
        Ok(())
    }
}

impl StagingLease {
    /// Publish a bounded private document from this reservation. Callers serialize
    /// competing destination writers and retain ancestor trust and authentication.
    /// Existing equal content is unchanged; otherwise replacement requires the
    /// exact expected current identity. Failure may follow durable publication.
    /// The parent must already be private (0700), caller-owned and on the same
    /// filesystem. Documents remain single-link 0600 regular files. The limit
    /// must be nonzero and at most 256 MiB. Success, including equal content,
    /// removes this reservation's payload; failed work can be recovered by its
    /// next explicit acquisition. Expected identity is not a monotonic generation.
    pub fn publish_private_document(
        self,
        destination: &Path,
        expected_payload: &crate::ArtifactIdentity,
        expected_current: Option<&crate::ArtifactIdentity>,
        limit: u64,
    ) -> Result<bool> {
        self.publish_private(
            destination,
            expected_payload,
            PrivatePublication::Document {
                expected_current,
                limit,
            },
        )
    }

    /// Publish exact caller-approved private bytes without replacing any entry.
    /// The destination parent must already be private and caller-owned, on the
    /// same filesystem. Callers own its trusted ancestors and authentication.
    /// Success syncs the payload and both directories. An error after rename can
    /// leave the destination published; inspect before deciding on another action.
    pub fn publish_private_noclobber(
        self,
        destination: &Path,
        expected: &crate::ArtifactIdentity,
    ) -> Result<()> {
        self.publish_private(destination, expected, PrivatePublication::NoClobber)
            .map(|_| ())
    }

    fn publish_private(
        self,
        destination: &Path,
        expected: &crate::ArtifactIdentity,
        publication: PrivatePublication<'_>,
    ) -> Result<bool> {
        if let PrivatePublication::Document { limit, .. } = &publication {
            crate::validate_document_authority(&DocumentAuthority {
                owner_uid: self.area.owner,
                mode: 0o600,
                limit: *limit,
            })?;
            if expected.length == 0 || expected.length > *limit {
                bail!("reserved document content is empty or exceeds its bound");
            }
        }
        if !destination.is_absolute()
            || destination
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            bail!("staging destination must be absolute and normalized");
        }
        let parent = destination
            .parent()
            .context("staging destination has no parent")?;
        let name = destination
            .file_name()
            .context("staging destination has no filename")?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(parent)
            .context("open staging destination directory")?;
        let retained = directory
            .metadata()
            .context("inspect staging destination directory")?;
        let source = self.directory.metadata()?;
        if retained.uid() != self.area.owner
            || retained.mode() & 0o7777 != 0o700
            || retained.dev() != source.dev()
            || retained.ino() == source.ino()
        {
            bail!("staging destination directory has invalid custody");
        }
        self.verify_payload_identity()?;
        crate::copy_verified_artifact_to_staging(
            &self.path,
            &DocumentAuthority {
                owner_uid: self.area.owner,
                mode: 0o600,
                limit: expected.length,
            },
            expected,
            &mut std::io::sink(),
        )?;
        self.file
            .sync_all()
            .context("sync staging publication payload")?;
        self.verify_payload_identity()?;
        let named =
            fs::symlink_metadata(parent).context("reinspect staging destination directory")?;
        if !named.is_dir()
            || named.dev() != retained.dev()
            || named.ino() != retained.ino()
            || named.uid() != self.area.owner
            || named.mode() & 0o7777 != 0o700
        {
            bail!("staging destination directory identity changed");
        }
        let replace = match publication {
            PrivatePublication::NoClobber => false,
            PrivatePublication::Document {
                expected_current,
                limit,
            } => {
                let current = read_atomic_document(
                    destination,
                    &DocumentAuthority {
                        owner_uid: self.area.owner,
                        mode: 0o600,
                        limit,
                    },
                )?;
                if current
                    .as_ref()
                    .is_some_and(|current| current.identity == *expected)
                {
                    self.cleanup()?;
                    return Ok(false);
                }
                match (&current, expected_current) {
                    (None, None) => {}
                    (Some(current), Some(expected)) if current.identity == *expected => {}
                    (None, Some(_)) => bail!("reserved document disappeared before replacement"),
                    (Some(_), None) => {
                        bail!("reserved document already exists with different content")
                    }
                    (Some(_), Some(_)) => bail!("reserved document changed before replacement"),
                }
                current.is_some()
            }
        };
        rustix::fs::renameat_with(
            &self.directory,
            PAYLOAD,
            &directory,
            name,
            if replace {
                rustix::fs::RenameFlags::empty()
            } else {
                rustix::fs::RenameFlags::NOREPLACE
            },
        )
        .context("publish private staging payload")?;
        // Persist the new name before persisting removal of the old one. No
        // hard-link or cross-device copy fallback creates a second payload.
        directory.sync_all().context("sync staging destination")?;
        self.directory
            .sync_all()
            .context("sync published staging reservation")?;
        Ok(true)
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicit fallible cleanup before releasing the lease.
    pub fn cleanup(self) -> Result<()> {
        self.verify_payload_identity()?;
        rustix::fs::unlinkat(&self.directory, PAYLOAD, rustix::fs::AtFlags::empty())
            .context("remove completed staging payload")?;
        self.directory.sync_all().context("sync staging cleanup")?;
        Ok(())
    }

    fn verify_payload_identity(&self) -> Result<()> {
        self.area.verify_directory(&self.directory)?;
        self.area.inspect_entries()?;
        let retained = self
            .file
            .metadata()
            .context("inspect retained staging payload")?;
        let named = fs::symlink_metadata(&self.path).context("inspect staging payload")?;
        self.area.verify_payload(&retained)?;
        self.area.verify_payload(&named)?;
        if retained.dev() != named.dev() || retained.ino() != named.ino() {
            bail!("staging payload identity changed");
        }
        Ok(())
    }
}
