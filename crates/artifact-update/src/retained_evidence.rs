//! Receipt-bound release evidence is durable data, not the discovery cache.
use dev_tools_installation::ArtifactIdentity;
use dev_tools_update::{artifact::ArtifactRecord, manifest_ledger::ManifestLedger};
use sha2::{Digest, Sha256};

const ERROR: &str = "retained release evidence is unavailable or invalid";

pub(super) fn key(version: &str, identity: &ArtifactIdentity) -> String {
    let mut hash = Sha256::new();
    for value in [
        "artifact-update-retained-evidence-v1",
        version,
        &identity.sha256,
    ] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.update(identity.length.to_be_bytes());
    format!("{:x}", hash.finalize())
}

pub(super) fn verify(
    store: &crate::signed_cache::Store,
    record: &ArtifactRecord,
    version: &str,
    identity: &ArtifactIdentity,
    ledger: impl FnOnce() -> Result<ManifestLedger, String>,
) -> Result<bool, String> {
    let Some(snapshot) = store.load(&key(version, identity)).map_err(|_| ERROR)? else {
        return Ok(false);
    };
    let verified = ledger()?
        .verify_retained_metadata(record, &snapshot.metadata)
        .map_err(|_| ERROR)?;
    if verified.version.to_string() != version
        || verified.artifact_length != identity.length
        || verified.artifact_sha256 != identity.sha256
    {
        return Err(ERROR.into());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn retained_evidence_binds_receipt_identity_and_requires_durable_acceptance() {
        let (catalog, metadata) = crate::signed_check_tests::fixture(2, "1.2.3");
        let record = catalog.get("example").unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("retained");
        let store =
            crate::signed_cache::Store::new(root.clone(), temp.path().metadata().unwrap().uid())
                .unwrap();
        let identity = ArtifactIdentity {
            length: 42,
            sha256: "b".repeat(64),
        };
        let version = "1.2.3";
        assert!(!verify(&store, record, version, &identity, || panic!(
            "absent proof must not inspect ledger"
        ))
        .unwrap());
        assert!(!root.exists());
        let mut ledger = ManifestLedger::new(record).unwrap();
        ledger.accept(record, &metadata).unwrap();
        store.save(&key(version, &identity), &metadata, 0).unwrap();
        assert!(verify(&store, record, version, &identity, || Ok(ledger.clone())).unwrap());
        assert!(
            verify(&store, record, version, &identity, || ManifestLedger::new(
                record
            )
            .map_err(|_| ERROR.into()))
            .is_err()
        );
        assert!(verify(&store, record, version, &identity, || Err(ERROR.into())).is_err());
        for (version, identity) in [
            ("1.2.2", identity.clone()),
            (
                version,
                ArtifactIdentity {
                    length: 43,
                    ..identity.clone()
                },
            ),
            (
                version,
                ArtifactIdentity {
                    sha256: "c".repeat(64),
                    ..identity.clone()
                },
            ),
        ] {
            // A filename is no proof: put valid metadata under an incompatible
            // receipt-derived key and require verification to reject it.
            store.save(&key(version, &identity), &metadata, 0).unwrap();
            assert!(verify(&store, record, version, &identity, || Ok(ledger.clone())).is_err());
        }
    }
}
