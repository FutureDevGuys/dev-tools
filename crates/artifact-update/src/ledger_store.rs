use crate::private_directory::PrivateDirectory;
use dev_tools_installation::{
    read_atomic_document, write_atomic_document, ArtifactIdentity, DocumentAuthority,
    InstallationLock,
};
use dev_tools_update::artifact::ArtifactRecord;
use dev_tools_update::manifest_ledger::{ManifestLedger, MANIFEST_LEDGER_LIMIT};
use std::ffi::OsStr;
use std::path::PathBuf;

const ERROR: &str = "release ledger is unavailable or has invalid custody";
const CONFLICT: &str = "release ledger precondition changed";

fn state_path(
    authority: [u8; 32],
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Result<PathBuf, String> {
    let root = match xdg_state_home.filter(|value| !value.is_empty()) {
        Some(root) => PathBuf::from(root),
        None => PathBuf::from(
            home.filter(|value| !value.is_empty())
                .ok_or("native state directory is unavailable")?,
        )
        .join(".local/state"),
    };
    if !root.is_absolute()
        || root.components().any(|part| {
            matches!(
                part,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err("native state root must be absolute and normalized".into());
    }
    let key: String = authority.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(root.join("artifact-update/release-ledgers-v1").join(key))
}

pub(super) enum LedgerExpectation {
    /// An approved first-use decision, never an implicit missing-file fallback.
    FirstUse,
    Current(ArtifactIdentity),
}

pub(super) struct LedgerStore {
    directory: PrivateDirectory,
}

impl LedgerStore {
    pub fn for_record(record: &ArtifactRecord) -> Result<Self, String> {
        let authority = ManifestLedger::new(record)
            .map_err(|_| ERROR)?
            .authority_id();
        let root = state_path(
            authority,
            std::env::var_os("XDG_STATE_HOME").as_deref(),
            std::env::var_os("HOME").as_deref(),
        )?;
        Self::new(root, rustix::process::geteuid().as_raw())
    }

    pub fn new(root: PathBuf, owner: u32) -> Result<Self, String> {
        Ok(Self {
            directory: PrivateDirectory::new(root, owner).map_err(|_| ERROR)?,
        })
    }

    fn authority(&self) -> DocumentAuthority {
        DocumentAuthority {
            owner_uid: self.directory.owner,
            mode: 0o600,
            limit: MANIFEST_LEDGER_LIMIT as u64,
        }
    }

    pub fn load(
        &self,
        record: &ArtifactRecord,
    ) -> Result<Option<(ManifestLedger, ArtifactIdentity)>, String> {
        if !self.directory.inspect().map_err(|_| ERROR)? {
            return Ok(None);
        }
        let document =
            read_atomic_document(&self.directory.path.join("ledger.json"), &self.authority())
                .map_err(|_| ERROR)?
                .ok_or(CONFLICT)?;
        let ledger = ManifestLedger::from_bytes(&document.bytes, record).map_err(|_| ERROR)?;
        Ok(Some((ledger, document.identity)))
    }

    pub fn recover_initial_publication(&self) -> Result<bool, String> {
        self.directory
            .recover_publication("ledger.json", &self.authority())
            .map_err(|_| ERROR.into())
    }

    /// The callback performs only in-memory verification/state changes, never
    /// network I/O. Success is returned only after the atomic document commits.
    pub fn transaction<T>(
        &self,
        record: &ArtifactRecord,
        expected: LedgerExpectation,
        operation: impl FnOnce(&mut ManifestLedger) -> Result<T, String>,
    ) -> Result<(T, bool), String> {
        match expected {
            LedgerExpectation::FirstUse => {
                if self.directory.inspect().map_err(|_| ERROR)? {
                    return Err(CONFLICT.into());
                }
                let mut ledger = ManifestLedger::new(record).map_err(|_| ERROR)?;
                let value = operation(&mut ledger)?;
                let bytes = ledger.to_bytes().map_err(|_| ERROR)?;
                self.directory
                    .publish_document("ledger.json", &bytes, &self.authority())
                    .map_err(|_| CONFLICT)?;
                Ok((value, true))
            }
            LedgerExpectation::Current(identity) => {
                if !self.directory.inspect().map_err(|_| ERROR)? {
                    return Err(CONFLICT.into());
                }
                let _lock = InstallationLock::try_acquire(&self.directory.path.join("ledger.lock"))
                    .map_err(|_| ERROR)?
                    .ok_or("release ledger is busy")?;
                let path = self.directory.path.join("ledger.json");
                let current = read_atomic_document(&path, &self.authority())
                    .map_err(|_| ERROR)?
                    .ok_or(CONFLICT)?;
                if current.identity != identity {
                    return Err(CONFLICT.into());
                }
                let mut ledger =
                    ManifestLedger::from_bytes(&current.bytes, record).map_err(|_| ERROR)?;
                let value = operation(&mut ledger)?;
                let bytes = ledger.to_bytes().map_err(|_| ERROR)?;
                let changed =
                    write_atomic_document(&path, &bytes, &self.authority(), Some(&identity))
                        .map_err(|_| ERROR)?;
                Ok((value, changed))
            }
        }
    }

    /// Hold unchanged accepted state through bounded local installation work.
    /// The callback cannot mutate this ledger. Lock order is ledger, then
    /// installation, then retained-evidence storage; never acquire this guard
    /// from a callback already holding either downstream lock. No network or
    /// external commands may run in the callback.
    pub fn with_current<T>(
        &self,
        record: &ArtifactRecord,
        expected: &ArtifactIdentity,
        operation: impl FnOnce(&ManifestLedger) -> Result<T, String>,
    ) -> Result<T, String> {
        if !self.directory.inspect().map_err(|_| ERROR)? {
            return Err(CONFLICT.into());
        }
        let _lock = InstallationLock::try_acquire(&self.directory.path.join("ledger.lock"))
            .map_err(|_| ERROR)?
            .ok_or("release ledger is busy")?;
        let (ledger, identity) = self.load(record)?.ok_or(CONFLICT)?;
        if &identity != expected {
            return Err(CONFLICT.into());
        }
        operation(&ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dev_tools_update::artifact::ArtifactCatalog;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn retained_authority_guard_holds_current_ledger_without_rewriting_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ledger");
        let store = LedgerStore::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        let (_, identity) = store.load(record).unwrap().unwrap();
        let original = std::fs::read(root.join("ledger.json")).unwrap();
        let held = InstallationLock::acquire(&root.join("ledger.lock")).unwrap();
        let mut ran = false;
        let result = store.with_current(record, &identity, |_| {
            ran = true;
            Ok(())
        });
        assert!(
            result.is_err(),
            "busy ledger must not admit activation work"
        );
        assert!(!ran);
        drop(held);
        store
            .with_current(record, &identity, |ledger| {
                assert_eq!(ledger.to_bytes().unwrap(), original);
                assert!(InstallationLock::try_acquire(&root.join("ledger.lock"))
                    .unwrap()
                    .is_none());
                Ok(())
            })
            .unwrap();
        assert_eq!(std::fs::read(root.join("ledger.json")).unwrap(), original);
        assert!(InstallationLock::try_acquire(&root.join("ledger.lock"))
            .unwrap()
            .is_some());
        let wrong = ArtifactIdentity {
            length: identity.length + 1,
            ..identity.clone()
        };
        assert!(store
            .with_current(record, &wrong, |_| -> Result<(), String> {
                panic!("stale guard callback")
            })
            .is_err());
        assert!(store
            .with_current(record, &identity, |_| Err::<(), _>(
                "failed local work".into()
            ))
            .is_err());
        assert_eq!(std::fs::read(root.join("ledger.json")).unwrap(), original);
        assert!(InstallationLock::try_acquire(&root.join("ledger.lock"))
            .unwrap()
            .is_some());
    }

    fn catalog() -> ArtifactCatalog {
        ArtifactCatalog::parse(r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "static-manifest", url = "https://example.invalid/stable.json" }
version = { type = "semver-tag" }
verification = { type = "signed-manifest", root = "https://example.invalid/root.json", trusted_root_public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", product = "example", target = "linux-x86_64", artifact_url = "https://example.invalid/tool" }
selectors = [{ type = "exact", pattern = "tool" }]
"#).unwrap()
    }

    #[test]
    fn durable_state_path_uses_native_root_and_stable_authority() {
        let catalog = catalog();
        let authority = ManifestLedger::new(catalog.get("example").unwrap())
            .unwrap()
            .authority_id();
        let suffix = "artifact-update/release-ledgers-v1/428d172207370ee0ef6d2f419c526d17b76f739b176d798c39dc9cead14280aa";
        assert_eq!(
            state_path(
                authority,
                Some(OsStr::new("/state")),
                Some(OsStr::new("relative"))
            )
            .unwrap(),
            PathBuf::from("/state").join(suffix)
        );
        for xdg in [None, Some(OsStr::new(""))] {
            assert_eq!(
                state_path(authority, xdg, Some(OsStr::new("/home/example"))).unwrap(),
                PathBuf::from("/home/example/.local/state").join(suffix)
            );
        }
        for invalid in ["relative", "/state/../elsewhere"] {
            assert!(state_path(
                authority,
                Some(OsStr::new(invalid)),
                Some(OsStr::new("/home/example"))
            )
            .is_err());
            assert!(state_path(authority, None, Some(OsStr::new(invalid))).is_err());
        }
        for home in [None, Some(OsStr::new(""))] {
            assert!(state_path(authority, None, home).is_err());
        }
    }

    #[test]
    fn first_use_does_not_adopt_an_intervening_directory() {
        use std::os::unix::fs::DirBuilderExt;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ledger");
        let store = LedgerStore::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let catalog = catalog();
        assert!(store
            .transaction(
                catalog.get("example").unwrap(),
                LedgerExpectation::FirstUse,
                |_| {
                    std::fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&root)
                        .unwrap();
                    Ok(())
                }
            )
            .is_err());
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn busy_or_stale_ledger_never_runs_the_acceptance_callback() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ledger");
        let store = LedgerStore::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        let (_, identity) = store.load(record).unwrap().unwrap();
        let path = root.join("ledger.json");
        let original = std::fs::read(&path).unwrap();
        let held_lock = InstallationLock::try_acquire(&root.join("ledger.lock"))
            .unwrap()
            .unwrap();
        let mut callback_ran = false;
        assert_eq!(
            store
                .transaction(record, LedgerExpectation::Current(identity.clone()), |_| {
                    callback_ran = true;
                    Ok(())
                })
                .unwrap_err(),
            "release ledger is busy"
        );
        assert!(!callback_ran);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        drop(held_lock);

        // A separately published, valid representation changes document identity
        // even when the acceptance state has the same meaning.
        let mut replacement = original.clone();
        replacement.push(b'\n');
        write_atomic_document(&path, &replacement, &store.authority(), Some(&identity)).unwrap();
        assert!(store.load(record).is_ok());
        assert_eq!(
            store
                .transaction(record, LedgerExpectation::Current(identity), |_| {
                    callback_ran = true;
                    Ok(())
                })
                .unwrap_err(),
            CONFLICT
        );
        assert!(!callback_ran);
        assert_eq!(std::fs::read(&path).unwrap(), replacement);
    }

    #[test]
    fn ledger_transactions_require_exact_preconditions_and_explicit_first_use() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("ledger");
        let store = LedgerStore::new(root.clone(), temp.path().metadata().unwrap().uid()).unwrap();
        let catalog = catalog();
        let record = catalog.get("example").unwrap();
        assert!(store.load(record).unwrap().is_none());
        assert!(!root.exists());
        let (_, changed) = store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .unwrap();
        assert!(changed);
        let (_, identity) = store.load(record).unwrap().unwrap();
        let bytes = std::fs::read(root.join("ledger.json")).unwrap();
        assert!(
            !store
                .transaction(
                    record,
                    LedgerExpectation::Current(identity.clone()),
                    |_| Ok(())
                )
                .unwrap()
                .1
        );
        assert!(store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .is_err());
        assert!(store
            .transaction(record, LedgerExpectation::Current(identity.clone()), |_| {
                Err::<(), _>("failed verification".into())
            })
            .is_err());
        assert_eq!(std::fs::read(root.join("ledger.json")).unwrap(), bytes);
        std::fs::remove_file(root.join("ledger.json")).unwrap();
        assert!(store.load(record).is_err());
        assert!(store
            .transaction(record, LedgerExpectation::Current(identity), |_| Ok(()))
            .is_err());
        assert!(store
            .transaction(record, LedgerExpectation::FirstUse, |_| Ok(()))
            .is_err());
    }
}
