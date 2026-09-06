use super::*;
use dev_tools_release::{
    build_signed_envelope, build_unsigned_product_manifest, build_unsigned_root_document,
    release_key_id, root_key_id, EnvelopeSignature, ManifestArtifact, ProductManifestSpec,
    ReleaseMetadata, RootDocumentSpec, RootReleaseKey,
};
use ed25519_dalek::{Signer, SigningKey};
use std::os::unix::fs::MetadataExt;

pub(super) fn fixture(generation: u64, version: &str) -> (ArtifactCatalog, ReleaseMetadata) {
    fixture_with_identity(generation, version, 42, "b".repeat(64), "", None)
}

pub(super) fn installation_fixture(
    generation: u64,
    version: &str,
    bytes: &[u8],
    root: &std::path::Path,
) -> (ArtifactCatalog, ReleaseMetadata) {
    installation_fixture_with_rotation(generation, version, bytes, root, None)
}

pub(super) fn installation_fixture_with_rotation(
    generation: u64,
    version: &str,
    bytes: &[u8],
    root: &std::path::Path,
    revoke_old: Option<bool>,
) -> (ArtifactCatalog, ReleaseMetadata) {
    use sha2::{Digest, Sha256};
    let installation = format!(
        "installation = {{ type = \"versioned-binary\", data_root = {}, bin_dir = {}, artifact_name = \"tool\", aliases = [\"example\"] }}",
        serde_json::to_string(&root.join("data")).unwrap(),
        serde_json::to_string(&root.join("bin")).unwrap(),
    );
    fixture_with_identity(
        generation,
        version,
        bytes.len() as u64,
        format!("{:x}", Sha256::digest(bytes)),
        &installation,
        revoke_old,
    )
}

fn fixture_with_identity(
    generation: u64,
    version: &str,
    length: u64,
    sha256: String,
    installation: &str,
    revoke_old: Option<bool>,
) -> (ArtifactCatalog, ReleaseMetadata) {
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let target = if installation.is_empty() {
        "linux-x86_64".to_owned()
    } else {
        format!("linux-{}", std::env::consts::ARCH)
    };
    let release_key = SigningKey::from_bytes(&[if revoke_old.is_some() { 9 } else { 8 }; 32]);
    let hex = |key: &SigningKey| {
        key.verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let root_public = hex(&root_key);
    let release_public = hex(&release_key);
    let mut release_keys = vec![RootReleaseKey {
        public_key: release_public.clone(),
        revoked: false,
    }];
    if let Some(revoked) = revoke_old {
        release_keys.push(RootReleaseKey {
            public_key: hex(&SigningKey::from_bytes(&[8; 32])),
            revoked,
        });
    }
    let unsigned_root = build_unsigned_root_document(&RootDocumentSpec {
        generation: if revoke_old.is_some() { 2 } else { 1 },
        release_keys,
    })
    .unwrap();
    let root = build_signed_envelope(
        &unsigned_root,
        &[EnvelopeSignature {
            key_id: root_key_id(&root_public).unwrap(),
            signature: root_key.sign(&unsigned_root).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let unsigned = build_unsigned_product_manifest(&ProductManifestSpec {
        product: "example".into(),
        generation,
        version: version.into(),
        source_commit: "a".repeat(40),
        artifacts: vec![ManifestArtifact {
            target: target.clone(),
            url: "https://example.invalid/tool".into(),
            length,
            sha256,
        }],
    })
    .unwrap();
    let manifest = build_signed_envelope(
        &unsigned,
        &[EnvelopeSignature {
            key_id: release_key_id(&release_public).unwrap(),
            signature: release_key.sign(&unsigned).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    let catalog = ArtifactCatalog::parse(&format!(r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = {{ type = "static-manifest", url = "https://example.invalid/stable.json" }}
version = {{ type = "semver-tag" }}
verification = {{ type = "signed-manifest", root = "https://example.invalid/root.json", trusted_root_public_key = "{root_public}", product = "example", target = "{target}", artifact_url = "https://example.invalid/tool" }}
selectors = [{{ type = "exact", pattern = "tool" }}]
{installation}
"#)).unwrap();
    (catalog, ReleaseMetadata { root, manifest })
}

#[test]
fn signed_check_reports_only_durably_accepted_metadata() {
    let (catalog, metadata) = fixture(2, "1.2.3");
    let record = catalog.get("example").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("ledger");
    let store = ledger_store::LedgerStore::new(root.clone(), temp.path().metadata().unwrap().uid())
        .unwrap();
    let mut network = false;
    let mut called = false;
    let absent = check_signed_with_fetch(
        record,
        &store,
        &mut network,
        || {
            called = true;
            Ok(metadata.clone())
        },
        |_| Ok(false),
    );
    assert!(matches!(absent, Err((_, 3))));
    assert!(!called && !network && !root.exists());
    store
        .transaction(
            record,
            ledger_store::LedgerExpectation::FirstUse,
            |_| Ok(()),
        )
        .unwrap();
    let empty = std::fs::read(root.join("ledger.json")).unwrap();
    let accepted = check_signed_with_fetch(
        record,
        &store,
        &mut network,
        || Ok(metadata.clone()),
        |_| Ok(false),
    )
    .unwrap_or_else(|error| panic!("{error:?}"));
    assert!(
        matches!(accepted, CheckedRelease::Authenticated { version, generation: 2, changed: true, .. } if version == "1.2.3")
    );
    assert!(network);
    let bytes = std::fs::read(root.join("ledger.json")).unwrap();
    assert_ne!(bytes, empty);
    let (mut persisted, _) = store.load(record).unwrap().unwrap();
    assert!(!persisted.accept(record, &metadata).unwrap().1);
    let replay = check_signed_with_fetch(
        record,
        &store,
        &mut network,
        || Ok(metadata.clone()),
        |_| Ok(false),
    );
    assert!(matches!(
        replay,
        Ok(CheckedRelease::Authenticated { changed: false, .. })
    ));
    let cache_only = check_signed_with_fetch(
        record,
        &store,
        &mut network,
        || Ok(metadata.clone()),
        |_| Ok(true),
    );
    assert!(
        matches!(
            cache_only,
            Ok(CheckedRelease::Authenticated { changed: false, .. })
        ),
        "cache timestamp refresh must not report a ledger change"
    );
    let (_, older) = fixture(1, "1.2.2");
    let rejected =
        check_signed_with_fetch(record, &store, &mut network, || Ok(older), |_| Ok(false));
    assert!(matches!(rejected, Err((_, 4))));
    assert_eq!(std::fs::read(root.join("ledger.json")).unwrap(), bytes);
    let failed = check_signed_with_fetch(
        record,
        &store,
        &mut network,
        || Err(DiscoveryError::Unavailable),
        |_| Ok(false),
    );
    assert!(matches!(failed, Err((_, 1))));
    assert_eq!(std::fs::read(root.join("ledger.json")).unwrap(), bytes);

    // Successful retrieval cannot hide a state change during network I/O.
    let raced = check_signed_with_fetch(
        record,
        &store,
        &mut network,
        || {
            let mut changed = bytes.clone();
            changed.push(b'\n');
            std::fs::write(root.join("ledger.json"), changed).unwrap();
            Ok(metadata)
        },
        |_| Ok(false),
    );
    assert!(matches!(raced, Err((_, 4))));
}

#[test]
fn signed_status_requires_current_ledger_and_never_mutates_it() {
    let (catalog, metadata) = fixture(2, "1.2.3");
    let record = catalog.get("example").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let owner = temp.path().metadata().unwrap().uid();
    let ledger_root = temp.path().join("ledger");
    let ledger = ledger_store::LedgerStore::new(ledger_root.clone(), owner).unwrap();
    let cache_root = temp.path().join("cache");
    let cache = signed_cache::Store::new(cache_root.clone(), owner).unwrap();
    let key = signed_metadata_key(b"config", "example");
    cache.save(&key, &metadata, 100).unwrap();
    let inspect = |now| signed_status_row("example", record, &ledger, &cache, &key, now);
    let row = inspect(100).unwrap();
    assert_eq!(row["trust"], "requires-initialization");
    assert!(!ledger_root.exists(), "cache must never initialize trust");
    ledger
        .transaction(
            record,
            ledger_store::LedgerExpectation::FirstUse,
            |_| Ok(()),
        )
        .unwrap();
    assert!(
        inspect(100).is_err(),
        "valid but unaccepted metadata is not status authority"
    );
    let mut network = false;
    check_signed_with_fetch(
        record,
        &ledger,
        &mut network,
        || Ok(metadata.clone()),
        |metadata| cache.save(&key, metadata, 100),
    )
    .unwrap_or_else(|error| panic!("{error:?}"));
    let original = std::fs::read(ledger_root.join("ledger.json")).unwrap();
    let modified = std::fs::metadata(ledger_root.join("ledger.json"))
        .unwrap()
        .modified()
        .unwrap();
    for (now, freshness, available) in [
        (100, "fresh", true),
        (86500, "fresh", true),
        (86501, "stale", false),
        (99, "stale", false),
    ] {
        let row = inspect(now).unwrap();
        assert_eq!(row["outcome"], "unknown");
        assert_eq!(row["cache_freshness"], freshness);
        assert_eq!(row["installation_authorized"], false);
        assert_eq!(row.get("available_version").is_some(), available);
        if available {
            assert_eq!(row["available_version"], "1.2.3");
        }
    }
    assert_eq!(
        std::fs::metadata(ledger_root.join("ledger.json"))
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
    assert_eq!(
        std::fs::read(ledger_root.join("ledger.json")).unwrap(),
        original
    );
    let (_, older) = fixture(1, "1.2.2");
    cache.save(&key, &older, 100).unwrap();
    assert!(inspect(100).is_err());
    let (_, newer) = fixture(3, "1.2.4");
    cache.save(&key, &newer, 100).unwrap();
    assert!(inspect(100).is_err());
    let mut forged = metadata.clone();
    forged.manifest[0] = b'!';
    cache.save(&key, &forged, 100).unwrap();
    assert!(inspect(100).is_err());
    std::fs::remove_file(cache_root.join(format!("{key}.cache"))).unwrap();
    assert_eq!(inspect(100).unwrap()["cache_freshness"], "absent");
    assert_eq!(
        std::fs::read(ledger_root.join("ledger.json")).unwrap(),
        original
    );
}

#[test]
fn failed_cache_publication_preserves_advanced_ledger() {
    let (catalog, metadata) = fixture(2, "1.2.3");
    let record = catalog.get("example").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let store = ledger_store::LedgerStore::new(
        temp.path().join("ledger"),
        temp.path().metadata().unwrap().uid(),
    )
    .unwrap();
    store
        .transaction(
            record,
            ledger_store::LedgerExpectation::FirstUse,
            |_| Ok(()),
        )
        .unwrap();
    let result = check_signed_with_fetch(
        record,
        &store,
        &mut false,
        || Ok(metadata.clone()),
        |_| Err("injected cache publication failure".into()),
    );
    assert!(matches!(result, Err((_, 1))));
    let (mut ledger, _) = store.load(record).unwrap().unwrap();
    assert!(!ledger.accept(record, &metadata).unwrap().1);
    let (_, older) = fixture(1, "1.2.2");
    assert!(ledger.accept(record, &older).is_err());
}
