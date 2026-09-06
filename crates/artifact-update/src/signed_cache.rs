//! Bounded original signed-document storage; callers own lifetime and authority.
//! Discovery uses disposable cache roots; retained installation evidence uses
//! durable data roots. Neither use replaces the separate acceptance ledger.
use crate::private_directory::PrivateDirectory;
use dev_tools_installation::{
    read_atomic_document, write_atomic_document, DocumentAuthority, InstallationLock,
};
use dev_tools_release::ReleaseMetadata;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const HEADER_LIMIT: usize = 4096;
const DOCUMENT_LIMIT: usize = 512 * 1024;
const SCHEMA: &str = "artifact-update-signed-metadata-v1";
const ERROR: &str = "signed metadata cache is unavailable or invalid";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    key: String,
    checked_at: u64,
    root_length: usize,
}

pub(super) struct Snapshot {
    pub metadata: ReleaseMetadata,
    pub checked_at: u64,
}

impl Snapshot {
    pub fn is_fresh(&self, now: u64) -> bool {
        now.checked_sub(self.checked_at)
            .is_some_and(|age| age <= dev_tools_update::MAX_CACHE_AGE_SECONDS)
    }
}

pub(super) struct Store {
    directory: PrivateDirectory,
}

impl Store {
    pub fn new(root: PathBuf, owner: u32) -> Result<Self, String> {
        Ok(Self {
            directory: PrivateDirectory::new(root, owner).map_err(|_| ERROR)?,
        })
    }

    fn path(&self, key: &str) -> Result<PathBuf, String> {
        if key.len() != 64 || !key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(ERROR.into());
        }
        Ok(self.directory.path.join(format!("{key}.cache")))
    }

    fn authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.directory.owner,
            mode: 0o600,
            limit: (HEADER_LIMIT + 1 + 2 * DOCUMENT_LIMIT) as u64,
        }
    }

    pub fn load(&self, key: &str) -> Result<Option<Snapshot>, String> {
        let path = self.path(key)?;
        if !self.directory.inspect().map_err(|_| ERROR)? {
            return Ok(None);
        }
        let Some(document) = read_atomic_document(&path, &self.authority()).map_err(|_| ERROR)?
        else {
            return Ok(None);
        };
        let split = document
            .bytes
            .iter()
            .take(HEADER_LIMIT + 1)
            .position(|byte| *byte == b'\n')
            .ok_or(ERROR)?;
        let header: Header = serde_json::from_slice(&document.bytes[..split]).map_err(|_| ERROR)?;
        let body = &document.bytes[split + 1..];
        if header.schema != SCHEMA
            || header.key != key
            || header.root_length == 0
            || header.root_length > DOCUMENT_LIMIT
            || header.root_length >= body.len()
            || body.len() - header.root_length > DOCUMENT_LIMIT
        {
            return Err(ERROR.into());
        }
        Ok(Some(Snapshot {
            metadata: ReleaseMetadata {
                root: body[..header.root_length].to_vec(),
                manifest: body[header.root_length..].to_vec(),
            },
            checked_at: header.checked_at,
        }))
    }

    pub fn save(
        &self,
        key: &str,
        metadata: &ReleaseMetadata,
        checked_at: u64,
    ) -> Result<bool, String> {
        self.save_document(key, metadata, checked_at, false)
    }

    /// Disposable discovery metadata only; retained evidence uses `save`.
    pub fn save_cache(
        &self,
        key: &str,
        metadata: &ReleaseMetadata,
        checked_at: u64,
    ) -> Result<bool, String> {
        self.save_document(key, metadata, checked_at, true)
    }

    fn save_document(
        &self,
        key: &str,
        metadata: &ReleaseMetadata,
        checked_at: u64,
        recoverable_cache: bool,
    ) -> Result<bool, String> {
        let path = self.path(key)?;
        if metadata.root.is_empty()
            || metadata.manifest.is_empty()
            || metadata.root.len() > DOCUMENT_LIMIT
            || metadata.manifest.len() > DOCUMENT_LIMIT
        {
            return Err(ERROR.into());
        }
        let mut bytes = serde_json::to_vec(&Header {
            schema: SCHEMA.into(),
            key: key.into(),
            checked_at,
            root_length: metadata.root.len(),
        })
        .map_err(|_| ERROR)?;
        if bytes.len() > HEADER_LIMIT {
            return Err(ERROR.into());
        }
        bytes.push(b'\n');
        bytes.extend_from_slice(&metadata.root);
        bytes.extend_from_slice(&metadata.manifest);
        self.directory.ensure().map_err(|_| ERROR)?;
        let _lock = InstallationLock::try_acquire(&self.directory.path.join("cache.lock"))
            .map_err(|_| ERROR)?
            .ok_or("signed metadata cache is busy")?;
        let current = read_atomic_document(&path, &self.authority()).map_err(|_| ERROR)?;
        if recoverable_cache {
            return self
                .directory
                .publish_cache_entry(
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .ok_or(ERROR)?,
                    &bytes,
                    &self.authority(),
                    current.as_ref().map(|document| &document.identity),
                )
                .map_err(|_| ERROR.into());
        }
        write_atomic_document(
            &path,
            &bytes,
            &self.authority(),
            current.as_ref().map(|document| &document.identity),
        )
        .map_err(|_| ERROR.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn original_documents_roundtrip_without_status_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let store = Store::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let key = "a".repeat(64);
        assert!(store.load(&key).unwrap().is_none());
        assert!(!root.exists());
        let metadata = ReleaseMetadata {
            root: b"original\nroot bytes".to_vec(),
            manifest: b"original\nmanifest bytes".to_vec(),
        };
        assert!(store.save_cache(&key, &metadata, 100).unwrap());
        assert!(root
            .join(".publication-staging-v1")
            .join(format!("{key}.cache"))
            .join("staging-reservation-v1.json")
            .exists());
        assert!(!store.save_cache(&key, &metadata, 100).unwrap());
        let before = std::fs::metadata(store.path(&key).unwrap())
            .unwrap()
            .modified()
            .unwrap();
        let snapshot = store
            .load(&key)
            .unwrap()
            .expect("saved signed metadata must be readable");
        assert_eq!(snapshot.metadata, metadata);
        assert!(snapshot.is_fresh(100));
        assert!(snapshot.is_fresh(86500));
        assert!(!snapshot.is_fresh(86501));
        assert!(!snapshot.is_fresh(99));
        assert_eq!(
            std::fs::metadata(store.path(&key).unwrap())
                .unwrap()
                .modified()
                .unwrap(),
            before
        );
        assert!(store.load(&"b".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn cache_recovery_is_explicit_and_does_not_change_retained_evidence() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().metadata().unwrap().uid();
        let store = Store::new(temp.path().join("cache"), owner).unwrap();
        let evidence = Store::new(temp.path().join("evidence"), owner).unwrap();
        let key = "a".repeat(64);
        let metadata = ReleaseMetadata {
            root: b"root".to_vec(),
            manifest: b"manifest".to_vec(),
        };
        evidence.save(&key, &metadata, 100).unwrap();
        assert!(!evidence
            .directory
            .path
            .join(".publication-staging-v1")
            .exists());
        store.save_cache(&key, &metadata, 100).unwrap();
        assert_eq!(
            std::fs::read(store.path(&key).unwrap()).unwrap(),
            std::fs::read(evidence.path(&key).unwrap()).unwrap()
        );
        let reservation = store
            .directory
            .path
            .join(".publication-staging-v1")
            .join(format!("{key}.cache"));
        let payload = reservation.join("payload");
        std::fs::write(&payload, b"interrupted publication").unwrap();
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(store.load(&key).unwrap().unwrap().metadata, metadata);
        assert_eq!(std::fs::read(&payload).unwrap(), b"interrupted publication");
        let lock = InstallationLock::try_acquire(&reservation.join("staging.lock"))
            .unwrap()
            .unwrap();
        assert!(store.save_cache(&key, &metadata, 101).is_err());
        assert_eq!(std::fs::read(&payload).unwrap(), b"interrupted publication");
        drop(lock);
        let unknown = reservation.join("unknown");
        std::fs::write(&unknown, b"preserve").unwrap();
        assert!(store.save_cache(&key, &metadata, 101).is_err());
        assert_eq!(std::fs::read(&unknown).unwrap(), b"preserve");
        assert_eq!(std::fs::read(&payload).unwrap(), b"interrupted publication");
        assert_eq!(store.load(&key).unwrap().unwrap().checked_at, 100);
        std::fs::remove_file(unknown).unwrap();
        assert!(!store.save_cache(&key, &metadata, 100).unwrap());
        assert!(!payload.exists());
        assert!(store.save_cache(&key, &metadata, 101).unwrap());
        assert_eq!(store.load(&key).unwrap().unwrap().checked_at, 101);
    }

    #[test]
    fn rejects_invalid_framing_context_and_linked_storage() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        let store = Store::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let key = "a".repeat(64);
        assert!(store.load("../escape").is_err());
        let metadata = ReleaseMetadata {
            root: b"root".to_vec(),
            manifest: b"manifest".to_vec(),
        };
        store.save(&key, &metadata, 100).unwrap();
        let path = store.path(&key).unwrap();
        let original = std::fs::read(&path).unwrap();
        let header = |root_length: usize| {
            serde_json::json!({
                "schema": SCHEMA, "key": key, "checked_at": 100, "root_length": root_length
            })
        };
        for invalid in [
            header(0),
            header(usize::MAX),
            header(DOCUMENT_LIMIT + 1),
            serde_json::json!({"schema": SCHEMA, "key": "b".repeat(64), "checked_at": 100, "root_length": 4}),
            serde_json::json!({"schema": SCHEMA, "key": key, "checked_at": 100, "root_length": 4, "extra": true}),
        ] {
            let mut bytes = serde_json::to_vec(&invalid).unwrap();
            bytes.extend_from_slice(b"\nrootmanifest");
            std::fs::write(&path, bytes).unwrap();
            assert!(store.load(&key).is_err());
        }
        std::fs::write(&path, vec![b' '; HEADER_LIMIT + 2]).unwrap();
        assert!(store.load(&key).is_err());
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load(&key).is_err());
        std::fs::remove_file(&path).unwrap();
        let target = temp.path().join("untouched");
        std::fs::write(&target, b"untouched").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(store.load(&key).is_err());
        assert!(store.save(&key, &metadata, 100).is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"untouched");
        let linked_root = temp.path().join("linked");
        std::os::unix::fs::symlink(root, &linked_root).unwrap();
        let linked = Store::new(linked_root, temp.path().metadata().unwrap().uid()).unwrap();
        assert!(linked.load(&key).is_err());
        assert!(linked.save(&key, &metadata, 100).is_err());
    }
}
