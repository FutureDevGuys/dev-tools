//! Linux private-directory custody shared by configuration, caches and ledgers.
use dev_tools_installation::ensure_owned_directory;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

pub(super) struct PrivateDirectory {
    pub path: PathBuf,
    pub owner: u32,
}

impl PrivateDirectory {
    pub fn new(path: PathBuf, owner: u32) -> Result<Self, ()> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        {
            return Err(());
        }
        Ok(Self { path, owner })
    }

    // Other users must not control a rename boundary. Root-owned sticky
    // temporary ancestors are allowed; the final directory remains private.
    pub fn inspect(&self) -> Result<bool, ()> {
        inspect_directory(&self.path, self.owner, 0o700)
    }

    pub fn ensure(&self) -> Result<(), ()> {
        self.inspect()?;
        ensure_owned_directory(&self.path, self.owner, 0o700).map_err(|_| ())?;
        if !self.inspect()? {
            return Err(());
        }
        Ok(())
    }

    pub fn publish_document(
        &self,
        name: &str,
        bytes: &[u8],
        authority: &dev_tools_installation::DocumentAuthority,
    ) -> Result<(), ()> {
        if self.inspect()? {
            return Err(());
        }
        dev_tools_installation::publish_new_document_directory(
            &self.path, name, bytes, authority, 0o700,
        )
        .map_err(|_| ())?;
        if !self.inspect()? {
            return Err(());
        }
        Ok(())
    }

    // The caller holds this cache's stable writer lock throughout publication.
    pub fn publish_cache_entry(
        &self,
        name: &str,
        bytes: &[u8],
        authority: &dev_tools_installation::DocumentAuthority,
        expected_current: Option<&dev_tools_installation::ArtifactIdentity>,
    ) -> Result<bool, ()> {
        if Path::new(name).file_name() != Some(std::ffi::OsStr::new(name))
            || name.len() > 255
            || matches!(name, "cache.lock" | ".publication-staging-v1")
            || authority.owner_uid != self.owner
            || authority.mode != 0o600
            || authority.limit > 256 * 1024 * 1024
            || bytes.is_empty()
            || bytes.len() as u64 > authority.limit
            || !self.inspect()?
        {
            return Err(());
        }
        let parent = PrivateDirectory::new(self.path.join(".publication-staging-v1"), self.owner)?;
        parent.ensure()?;
        let path = parent.path.join(name);
        let mut digest = Sha256::new();
        digest.update(b"artifact-update-metadata-publication-v1\0");
        let root = self.path.as_os_str().as_bytes();
        digest.update((root.len() as u64).to_be_bytes());
        digest.update(root);
        digest.update(self.owner.to_be_bytes());
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        let area = dev_tools_installation::StagingArea::new(
            path.clone(),
            self.owner,
            digest.finalize().into(),
        )
        .map_err(|_| ())?;
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                area.initialize().map_err(|_| ())?
            }
            Err(_) => return Err(()),
            Ok(_) => {}
        }
        let mut lease = area.try_acquire().map_err(|_| ())?.ok_or(())?;
        lease.file_mut().write_all(bytes).map_err(|_| ())?;
        let identity = dev_tools_installation::ArtifactIdentity {
            length: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        };
        lease
            .publish_private_document(
                &self.path.join(name),
                &identity,
                expected_current,
                authority.limit,
            )
            .map_err(|_| ())
    }
}

pub(super) fn inspect_directory(root: &Path, owner: u32, mode: u32) -> Result<bool, ()> {
    if !root.is_absolute()
        || mode & !0o777 != 0
        || root
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err(());
    }
    let mut path = PathBuf::new();
    for component in root.components() {
        path.push(component);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(_) => return Err(()),
        };
        let sticky_root = metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir()
            || ![0, owner].contains(&metadata.uid())
            || (metadata.mode() & 0o022 != 0 && !sticky_root)
            || (path == root && (metadata.uid() != owner || metadata.mode() & 0o777 != mode))
        {
            return Err(());
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dev_tools_installation::{ArtifactIdentity, DocumentAuthority};

    #[test]
    fn metadata_reservations_cannot_be_reused_for_another_root_or_entry() {
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().metadata().unwrap().uid();
        let first = PrivateDirectory::new(temp.path().join("first"), owner).unwrap();
        let second = PrivateDirectory::new(temp.path().join("second"), owner).unwrap();
        let authority = DocumentAuthority {
            owner_uid: owner,
            mode: 0o600,
            limit: 1024,
        };
        for directory in [&first, &second] {
            directory.ensure().unwrap();
            directory
                .publish_cache_entry("entry.cache", b"original", &authority, None)
                .unwrap();
        }
        let source = first.path.join(".publication-staging-v1/entry.cache");
        let marker = "staging-reservation-v1.json";
        std::fs::copy(
            source.join(marker),
            second
                .path
                .join(".publication-staging-v1/entry.cache")
                .join(marker),
        )
        .unwrap();
        assert!(second
            .publish_cache_entry("entry.cache", b"new", &authority, None)
            .is_err());
        assert_eq!(
            std::fs::read(second.path.join("entry.cache")).unwrap(),
            b"original"
        );
        std::fs::rename(
            source,
            first.path.join(".publication-staging-v1/other.cache"),
        )
        .unwrap();
        assert!(first
            .publish_cache_entry("other.cache", b"new", &authority, None)
            .is_err());
        assert!(!first.path.join("other.cache").exists());
    }

    #[test]
    fn cache_publication_reserves_its_payload_and_preserves_existing_document() {
        let temp = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::new(
            temp.path().join("cache"),
            temp.path().metadata().unwrap().uid(),
        )
        .unwrap();
        directory.ensure().unwrap();
        let authority = DocumentAuthority {
            owner_uid: directory.owner,
            mode: 0o600,
            limit: 1024,
        };
        assert!(directory
            .publish_cache_entry("entry.cache", b"first", &authority, None)
            .unwrap());
        let path = directory.path.join("entry.cache");
        let expected = ArtifactIdentity::from_file(&path, 1024).unwrap();
        let reservation = directory.path.join(".publication-staging-v1/entry.cache");
        assert!(reservation.join("staging-reservation-v1.json").exists());
        assert!(!reservation.join("payload").exists());
        assert!(directory
            .publish_cache_entry("entry.cache", b"replacement", &authority, Some(&expected))
            .unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert!(!directory
            .publish_cache_entry("entry.cache", b"replacement", &authority, Some(&expected))
            .unwrap());
        assert!(!reservation.join("payload").exists());
        assert!(directory
            .publish_cache_entry("entry.cache", b"stale", &authority, Some(&expected))
            .is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        assert_eq!(
            std::fs::read(reservation.join("payload")).unwrap(),
            b"stale"
        );
        // A subsequent explicit save recovers only the reservation-owned payload.
        assert!(!directory
            .publish_cache_entry("entry.cache", b"replacement", &authority, Some(&expected))
            .unwrap());
        assert!(!reservation.join("payload").exists());
    }
}
