//! Disposable content-addressed bytes, never release or installation authority.
use crate::private_directory::PrivateDirectory;
use dev_tools_installation::{
    copy_verified_artifact_to_staging, ArtifactIdentity, DocumentAuthority, StagingArea,
};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const ERROR: &str = "artifact cache is unavailable or invalid";
pub(super) struct Store {
    directory: PrivateDirectory,
}

impl Store {
    pub fn new(root: PathBuf, owner: u32) -> Result<Self, String> {
        Ok(Self {
            directory: PrivateDirectory::new(root, owner).map_err(|_| ERROR)?,
        })
    }
    fn path(&self, identity: &ArtifactIdentity) -> Result<PathBuf, String> {
        if identity.length == 0
            || identity.length > 256 * 1024 * 1024
            || identity.sha256.len() != 64
            || !identity
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ERROR.into());
        }
        Ok(self
            .directory
            .path
            .join(format!("{}-{}.artifact", identity.sha256, identity.length)))
    }

    fn authority(&self, mode: u32) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.directory.owner,
            mode,
            limit: 256 * 1024 * 1024,
        }
    }

    fn publication_area(&self, identity: &ArtifactIdentity) -> Result<StagingArea, String> {
        let destination = self.path(identity)?;
        let parent = PrivateDirectory::new(
            self.directory.path.join(".publication-staging-v1"),
            self.directory.owner,
        )
        .map_err(|_| ERROR)?;
        parent.ensure().map_err(|_| ERROR)?;
        let name = destination.file_name().ok_or(ERROR)?;
        let path = parent.path.join(name);
        let mut digest = Sha256::new();
        digest.update(b"artifact-update-cache-publication-v1\0");
        let root = self.directory.path.as_os_str().as_bytes();
        digest.update((root.len() as u64).to_be_bytes());
        digest.update(root);
        digest.update(self.directory.owner.to_be_bytes());
        digest.update(identity.sha256.as_bytes());
        digest.update(identity.length.to_be_bytes());
        let area = StagingArea::new(path.clone(), self.directory.owner, digest.finalize().into())
            .map_err(|_| ERROR)?;
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                area.initialize_recoverable().map_err(|_| ERROR)?
            }
            Err(_) => return Err(ERROR.into()),
            Ok(_) => {}
        }
        Ok(area)
    }

    pub fn stage(
        &self,
        identity: &ArtifactIdentity,
        writer: &mut impl Write,
    ) -> Result<bool, String> {
        let path = self.path(identity)?;
        if !self.directory.inspect().map_err(|_| ERROR)? {
            return Ok(false);
        }
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(ERROR.into()),
            Ok(_) => {}
        }
        copy_verified_artifact_to_staging(&path, &self.authority(0o600), identity, writer)
            .map_err(|_| ERROR)?;
        Ok(true)
    }

    pub fn save_executable(
        &self,
        source: &Path,
        identity: &ArtifactIdentity,
    ) -> Result<bool, String> {
        let destination = self.path(identity)?;
        if self.stage(identity, &mut std::io::sink())? {
            return Ok(false);
        }
        self.directory.ensure().map_err(|_| ERROR)?;
        let area = self.publication_area(identity)?;
        let mut temporary = area.try_acquire().map_err(|_| ERROR)?.ok_or(ERROR)?;
        // A publisher may have completed between preflight and acquisition.
        if self.stage(identity, &mut std::io::sink())? {
            temporary.cleanup().map_err(|_| ERROR)?;
            return Ok(false);
        }
        copy_verified_artifact_to_staging(
            source,
            &self.authority(0o755),
            identity,
            temporary.file_mut(),
        )
        .map_err(|_| ERROR)?;
        // Never replace a concurrent publication or drift. A caller can inspect
        // final state after failure; failure is not permission for blind retry.
        if !self.directory.inspect().map_err(|_| ERROR)? {
            return Err(ERROR.into());
        }
        temporary
            .publish_private_noclobber(&destination, identity)
            .map_err(|_| ERROR)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    #[test]
    fn failed_cache_copy_leaves_only_reserved_payload_and_retry_recovers_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let store = Store::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let source = temp.path().join("executable");
        std::fs::write(&source, b"approved").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        let identity = ArtifactIdentity::from_file(&source, 1024).unwrap();
        std::fs::write(&source, b"tampered").unwrap();
        assert!(store.save_executable(&source, &identity).is_err());
        let destination = store.path(&identity).unwrap();
        let reservation = root
            .join(".publication-staging-v1")
            .join(destination.file_name().unwrap());
        assert!(reservation.join("staging-reservation-v1.json").is_file());
        assert_eq!(
            std::fs::read(reservation.join("payload")).unwrap(),
            b"tampered"
        );
        assert!(!destination.exists());
        std::fs::write(root.join("old-unmarked-temporary"), b"unowned").unwrap();
        std::fs::write(&source, b"approved").unwrap();
        assert!(store.save_executable(&source, &identity).unwrap());
        assert_eq!(std::fs::read(&destination).unwrap(), b"approved");
        assert!(!reservation.join("payload").exists());
        assert_eq!(
            std::fs::read(root.join("old-unmarked-temporary")).unwrap(),
            b"unowned"
        );
    }

    #[test]
    fn cache_publication_excludes_live_payloads_and_refuses_unknown_reservations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let store = Store::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let source = temp.path().join("executable");
        std::fs::write(&source, b"approved").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        let identity = ArtifactIdentity::from_file(&source, 1024).unwrap();
        store.directory.ensure().unwrap();
        let area = store.publication_area(&identity).unwrap();
        let mut live = area.try_acquire().unwrap().unwrap();
        live.file_mut().write_all(b"live copy").unwrap();
        assert!(store.save_executable(&source, &identity).is_err());
        assert_eq!(std::fs::read(live.path()).unwrap(), b"live copy");
        assert!(!store.path(&identity).unwrap().exists());
        // Distinct content gets its own lease, not a global publication lock.
        let other = temp.path().join("other");
        std::fs::write(&other, b"other approved").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
        let other_identity = ArtifactIdentity::from_file(&other, 1024).unwrap();
        assert!(store.save_executable(&other, &other_identity).unwrap());
        let unknown = live.path().parent().unwrap().join("unowned");
        std::fs::write(&unknown, b"leave untouched").unwrap();
        drop(live);
        assert!(store.save_executable(&source, &identity).is_err());
        assert_eq!(std::fs::read(&unknown).unwrap(), b"leave untouched");
        assert_eq!(
            std::fs::read(unknown.parent().unwrap().join("payload")).unwrap(),
            b"live copy"
        );
    }

    #[test]
    fn cache_roundtrip_is_bounded_private_and_never_repairs_corruption() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let store = Store::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let source = temp.path().join("executable");
        std::fs::write(&source, b"inert signed bytes").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o755)).unwrap();
        let identity = ArtifactIdentity::from_file(&source, 1024).unwrap();
        let mut copied = Vec::new();
        assert!(!store.stage(&identity, &mut copied).unwrap());
        assert!(copied.is_empty() && !root.exists());
        assert!(store.save_executable(&source, &identity).unwrap());
        assert!(!store.save_executable(&source, &identity).unwrap());
        assert!(store.stage(&identity, &mut copied).unwrap());
        assert_eq!(copied, b"inert signed bytes");
        let entries: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(entries.len(), 2);
        let path = &store.path(&identity).unwrap();
        assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
        std::fs::write(path, b"corrupt").unwrap();
        assert!(store.stage(&identity, &mut Vec::new()).is_err());
        assert!(store.save_executable(&source, &identity).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"corrupt");
        std::fs::remove_file(path).unwrap();
        std::os::unix::fs::symlink(&source, path).unwrap();
        assert!(store.stage(&identity, &mut Vec::new()).is_err());
        assert!(store.save_executable(&source, &identity).is_err());
        assert_eq!(std::fs::read(source).unwrap(), b"inert signed bytes");
    }
}
