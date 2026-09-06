use dev_tools_release::{
    build_signed_envelope, build_unsigned_product_manifest, build_unsigned_root_document,
    release_key_id, root_key_id, EnvelopeSignature, ManifestArtifact, ProductManifestSpec,
    ReleaseMetadata, RootDocumentSpec, RootReleaseKey,
};
use dev_tools_update::{artifact::ArtifactCatalog, discovery::verify_static_manifest_metadata};
use ed25519_dalek::{Signer, SigningKey};

fn fixture() -> (String, ReleaseMetadata) {
    fixture_version(2, "1.2.3")
}

#[test]
fn direct_authority_import_preserves_high_water_and_serialized_identity() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, current) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let authority = record.release_authority().unwrap();
    let mut incumbent = ManifestLedger::new(record).unwrap();
    incumbent.accept(record, &current).unwrap();
    let before = incumbent.to_bytes().unwrap();
    let encoded: serde_json::Value = serde_json::from_slice(&before).unwrap();
    let state = serde_json::from_value(encoded["state"].clone()).unwrap();
    let mut imported = ManifestLedger::import_release_state(&authority, state).unwrap();
    let (_, old) = fixture_version(1, "1.2.2");
    assert!(
        imported.accept(record, &old).is_err(),
        "import discarded accepted high water"
    );
    assert_eq!(imported.to_bytes().unwrap(), before);
    assert_eq!(imported.authority_id(), incumbent.authority_id());
}

#[test]
fn direct_authority_verification_matches_catalog_contract_and_reapplies_policy() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, current) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let authority = record.release_authority().unwrap();
    let mut direct = ManifestLedger::import_release_state(&authority, Default::default()).unwrap();
    let mut incumbent = ManifestLedger::new(record).unwrap();
    assert_eq!(direct.to_bytes().unwrap(), incumbent.to_bytes().unwrap());
    assert_eq!(
        direct
            .accept_release_metadata(&authority, &current)
            .unwrap(),
        incumbent.accept(record, &current).unwrap()
    );
    let original = direct.to_bytes().unwrap();
    assert_eq!(original, incumbent.to_bytes().unwrap());
    let mut restored = ManifestLedger::from_bytes_with_authority(&original, &authority).unwrap();
    assert!(
        !restored
            .accept_release_metadata(&authority, &current)
            .unwrap()
            .1
    );
    let (_, older) = fixture_version(1, "1.2.2");
    assert_eq!(
        restored
            .verify_retained_with_authority(&authority, &older)
            .unwrap(),
        incumbent.verify_retained_metadata(record, &older).unwrap()
    );
    assert!(restored
        .accept_release_metadata(&authority, &older)
        .is_err());
    let (_, future) = fixture_version(3, "1.2.4");
    assert!(restored
        .verify_retained_with_authority(&authority, &future)
        .is_err());
    let mut changed_url = authority.clone();
    changed_url.artifact_url =
        dev_tools_release::ArtifactUrlPolicy::Exact("https://other.invalid/application".into());
    let mut changed_schema = authority.clone();
    changed_schema.accepted_manifest_schemas = vec!["dev-tools-product-v1".into()];
    let mut changed_protocol = authority.clone();
    changed_protocol.engine_protocol += 1;
    let mut changed_key = authority.clone();
    changed_key.trusted_root_key = "00".repeat(32);
    for changed in [changed_url, changed_schema, changed_protocol, changed_key] {
        // Each policy change is checked by the verifier, not supplied by the
        // imported high-water fields or frozen into an acceptance shortcut.
        assert!(restored
            .accept_release_metadata(&changed, &current)
            .is_err());
        assert!(restored
            .verify_retained_with_authority(&changed, &older)
            .is_err());
    }
    let mut wrong_product = authority.clone();
    wrong_product.product = "another".into();
    assert!(ManifestLedger::from_bytes_with_authority(&original, &wrong_product).is_err());
    assert!(restored
        .accept_release_metadata(&wrong_product, &current)
        .is_err());
    let mut tampered = current.clone();
    tampered.manifest[0] = b'!';
    assert!(restored
        .accept_release_metadata(&authority, &tampered)
        .is_err());
    assert!(restored
        .verify_retained_with_authority(&authority, &tampered)
        .is_err());
    assert_eq!(restored.to_bytes().unwrap(), original);
}

#[test]
fn direct_authority_import_rejects_partial_history_and_ambiguous_stream_names() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, current) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let authority = record.release_authority().unwrap();
    let mut incumbent = ManifestLedger::new(record).unwrap();
    incumbent.accept(record, &current).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&incumbent.to_bytes().unwrap()).unwrap();
    let state: dev_tools_release::ReleaseState =
        serde_json::from_value(value["state"].clone()).unwrap();
    for field in [
        "accepted_root_generation",
        "accepted_generation",
        "accepted_root_sha256",
        "accepted_manifest_sha256",
        "accepted_binary_sha256",
        "accepted_version",
    ] {
        let mut invalid = serde_json::to_value(&state).unwrap();
        invalid[field] = if field.ends_with("generation") {
            serde_json::json!(0)
        } else {
            serde_json::Value::Null
        };
        let invalid = serde_json::from_value(invalid).unwrap();
        assert!(ManifestLedger::import_release_state(&authority, invalid).is_err());
    }
    for name in ["", "example\0other", "example\nother"] {
        let mut invalid = authority.clone();
        invalid.product = name.into();
        assert!(ManifestLedger::import_release_state(&invalid, state.clone()).is_err());
        invalid = authority.clone();
        invalid.target = name.into();
        assert!(ManifestLedger::import_release_state(&invalid, state.clone()).is_err());
    }
    let mut oversized = authority.clone();
    oversized.product = "x".repeat(4096);
    assert!(ManifestLedger::import_release_state(&oversized, state).is_err());
}

fn fixture_version(generation: u64, version: &str) -> (String, ReleaseMetadata) {
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[8; 32]);
    let hex = |key: &SigningKey| {
        key.verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    let root_public = hex(&root_key);
    let release_public = hex(&release_key);
    let unsigned_root = build_unsigned_root_document(&RootDocumentSpec {
        generation: 1,
        release_keys: vec![RootReleaseKey {
            public_key: release_public.clone(),
            revoked: false,
        }],
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
            target: "linux-x86_64".into(),
            url: "https://example.invalid/application".into(),
            length: 42,
            sha256: "b".repeat(64),
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
    let config = format!(
        r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "local-name"
kind = "native-binary"
[artifacts.source]
type = "static-manifest"
url = "https://example.invalid/stable.json"
[artifacts.version]
type = "semver-tag"
[artifacts.verification]
type = "signed-manifest"
root = "https://example.invalid/root.json"
trusted_root_public_key = "{root_public}"
product = "example"
target = "linux-x86_64"
artifact_url = "https://example.invalid/application"
[[artifacts.selectors]]
type = "exact"
pattern = "application"
"#
    );
    (config, ReleaseMetadata { root, manifest })
}

#[test]
fn retained_metadata_requires_accepted_root_without_rewinding_online_state() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, current) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let (_, older) = fixture_version(1, "1.2.2");
    let mut ledger = ManifestLedger::new(record).unwrap();
    assert!(
        ledger.verify_retained_metadata(record, &older).is_err(),
        "first-use ledger must not authorize retained metadata"
    );
    ledger.accept(record, &current).unwrap();
    let before = ledger.to_bytes().unwrap();
    assert_eq!(
        ledger
            .verify_retained_metadata(record, &older)
            .unwrap()
            .version
            .to_string(),
        "1.2.2"
    );
    assert!(ledger.accept(record, &older).is_err());
    for (generation, version) in [(3, "1.2.4"), (1, "2.0.0"), (2, "1.2.2")] {
        let (_, invalid) = fixture_version(generation, version);
        assert!(ledger.verify_retained_metadata(record, &invalid).is_err());
    }
    assert_eq!(ledger.to_bytes().unwrap(), before);
}

#[test]
fn retained_metadata_rechecks_signers_against_the_exact_accepted_root() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, current) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let (_, older) = fixture_version(1, "1.2.2");
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let new_key = SigningKey::from_bytes(&[9; 32]);
    let public = new_key
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    for revoked in [false, true] {
        let root: serde_json::Value = serde_json::from_slice(&current.root).unwrap();
        // Retain the existing signer explicitly, optionally revoked, and add the
        // replacement signer used by the newly accepted current manifest.
        let old_public = SigningKey::from_bytes(&[8; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let unsigned = build_unsigned_root_document(&RootDocumentSpec {
            generation: 2,
            release_keys: vec![
                RootReleaseKey {
                    public_key: old_public,
                    revoked,
                },
                RootReleaseKey {
                    public_key: public.clone(),
                    revoked: false,
                },
            ],
        })
        .unwrap();
        let root_bytes = build_signed_envelope(
            &unsigned,
            &[EnvelopeSignature {
                key_id: root["signatures"][0]["key_id"].as_str().unwrap().into(),
                signature: root_key.sign(&unsigned).to_bytes().to_vec(),
            }],
        )
        .unwrap();
        let manifest: serde_json::Value = serde_json::from_slice(&current.manifest).unwrap();
        let unsigned = serde_json::to_vec(&manifest["signed"]).unwrap();
        let manifest = build_signed_envelope(
            &unsigned,
            &[EnvelopeSignature {
                key_id: release_key_id(&public).unwrap(),
                signature: new_key.sign(&unsigned).to_bytes().to_vec(),
            }],
        )
        .unwrap();
        let mut ledger = ManifestLedger::new(record).unwrap();
        ledger
            .accept(
                record,
                &ReleaseMetadata {
                    root: root_bytes.clone(),
                    manifest,
                },
            )
            .unwrap();
        let before = ledger.to_bytes().unwrap();
        assert!(
            ledger.verify_retained_metadata(record, &older).is_err(),
            "superseded signed root must not bypass current key policy"
        );
        assert!(ledger
            .verify_retained_with_authority(&record.release_authority().unwrap(), &older)
            .is_err());
        let refreshed = ReleaseMetadata {
            root: root_bytes,
            manifest: older.manifest.clone(),
        };
        assert_eq!(
            ledger.verify_retained_metadata(record, &refreshed).is_ok(),
            !revoked
        );
        assert_eq!(
            ledger
                .verify_retained_with_authority(&record.release_authority().unwrap(), &refreshed)
                .is_ok(),
            !revoked
        );
        assert_eq!(ledger.to_bytes().unwrap(), before);
    }
}

#[test]
fn signed_prerelease_cannot_advance_stable_acceptance() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, stable) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let mut ledger = ManifestLedger::new(record).unwrap();
    ledger.accept(record, &stable).unwrap();
    let original = ledger.to_bytes().unwrap();
    let (_, mut prerelease) = fixture_version(3, "1.2.4");
    let mut envelope: serde_json::Value = serde_json::from_slice(&prerelease.manifest).unwrap();
    envelope["signed"]["version"] = serde_json::json!("1.2.4-rc.1");
    let unsigned = serde_json::to_vec(&envelope["signed"]).unwrap();
    let key = SigningKey::from_bytes(&[8; 32]);
    prerelease.manifest = build_signed_envelope(
        &unsigned,
        &[EnvelopeSignature {
            key_id: envelope["signatures"][0]["key_id"].as_str().unwrap().into(),
            signature: key.sign(&unsigned).to_bytes().to_vec(),
        }],
    )
    .unwrap();
    assert!(dev_tools_release::verify_release_metadata(
        &prerelease,
        &record.release_authority().unwrap()
    )
    .is_ok());
    assert!(verify_static_manifest_metadata(record, &prerelease).is_err());
    assert!(ledger.accept(record, &prerelease).is_err());
    assert!(ledger
        .accept_release_metadata(&record.release_authority().unwrap(), &prerelease)
        .is_err());
    assert!(ledger
        .verify_retained_with_authority(&record.release_authority().unwrap(), &prerelease)
        .is_err());
    assert_eq!(ledger.to_bytes().unwrap(), original);
}

#[test]
fn ledger_authority_id_ignores_local_names_urls_and_accepted_generations() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, metadata) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let mut ledger = ManifestLedger::new(record).unwrap();
    let identity = ledger.authority_id();
    let root_key = record.release_authority().unwrap().trusted_root_key;
    ledger.accept(record, &metadata).unwrap();
    assert_eq!(ledger.authority_id(), identity);
    let restored = ManifestLedger::from_bytes(&ledger.to_bytes().unwrap(), record).unwrap();
    assert_eq!(restored.authority_id(), identity);

    for changed in [
        config.replace("local-name", "renamed"),
        config.replace("example.invalid", "mirror.invalid"),
        config.replace("pattern = \"application\"", "pattern = \"different\""),
        config.replace(&root_key, &root_key.to_uppercase()),
    ] {
        let changed = ArtifactCatalog::parse(&changed).unwrap();
        let (_, record) = changed.iter().next().unwrap();
        assert_eq!(
            ManifestLedger::new(record).unwrap().authority_id(),
            identity
        );
    }
    for changed in [
        config.replace("product = \"example\"", "product = \"other\""),
        config.replace("linux-x86_64", "linux-aarch64"),
        config.replace(
            &root_key,
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        ),
    ] {
        let changed = ArtifactCatalog::parse(&changed).unwrap();
        let (_, record) = changed.iter().next().unwrap();
        assert_ne!(
            ManifestLedger::new(record).unwrap().authority_id(),
            identity
        );
    }
    let vector = ArtifactCatalog::parse(&config.replace(
        &root_key,
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ))
    .unwrap();
    let id = ManifestLedger::new(vector.get("local-name").unwrap())
        .unwrap()
        .authority_id();
    // Independently computed with the system SHA-256 utility over the public
    // v1 preimage documented on authority_id; this freezes durable key encoding.
    assert_eq!(
        id.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        "428d172207370ee0ef6d2f419c526d17b76f739b176d798c39dc9cead14280aa"
    );
}

#[test]
fn manifest_ledger_binds_authority_and_preserves_rollback_state() {
    use dev_tools_update::manifest_ledger::ManifestLedger;
    let (config, metadata) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let record = catalog.get("local-name").unwrap();
    let mut ledger = ManifestLedger::new(record).unwrap();
    assert!(ledger.accept(record, &metadata).unwrap().1);
    assert!(!ledger.accept(record, &metadata).unwrap().1);
    let original = ledger.to_bytes().unwrap();
    let document: serde_json::Value = serde_json::from_slice(&original).unwrap();
    for mutation in 0..5 {
        let mut invalid = document.clone();
        match mutation {
            0 => invalid["unexpected"] = serde_json::json!(true),
            1 => invalid["schema"] = serde_json::json!("other-v1"),
            2 => invalid["state"]["accepted_binary_sha256"] = serde_json::Value::Null,
            3 => invalid["authority"]["target"] = serde_json::json!("windows-x86_64"),
            _ => invalid["authority"]["trusted_root_key"][0] = serde_json::json!(0),
        }
        assert!(
            ManifestLedger::from_bytes(&serde_json::to_vec(&invalid).unwrap(), record).is_err()
        );
    }
    assert!(ManifestLedger::from_bytes(&vec![b' '; 4097], record).is_err());
    let mut restored = ManifestLedger::from_bytes(&original, record).unwrap();
    let (_, older) = fixture_version(1, "1.2.2");
    assert!(restored.accept(record, &older).is_err());
    assert_eq!(restored.to_bytes().unwrap(), original);
    let renamed = ArtifactCatalog::parse(
        &config
            .replace("id = \"local-name\"", "id = \"new-name\"")
            .replace("/stable.json", "/new-location.json"),
    )
    .unwrap();
    assert!(ManifestLedger::from_bytes(&original, renamed.get("new-name").unwrap()).is_ok());
    let other =
        ArtifactCatalog::parse(&config.replace("product = \"example\"", "product = \"different\""))
            .unwrap();
    assert!(ManifestLedger::from_bytes(&original, other.get("local-name").unwrap()).is_err());
    let (_, newer) = fixture_version(3, "1.2.4");
    assert!(restored.accept(record, &newer).unwrap().1);
}

#[test]
fn static_metadata_rejects_other_sources_and_check_only_policy() {
    let (config, metadata) = fixture();
    let github = config.replace(
        "type = \"static-manifest\"\nurl = \"https://example.invalid/stable.json\"",
        "type = \"github\"\nowner = \"example\"\nrepository = \"example\"",
    );
    let catalog = ArtifactCatalog::parse(&github).unwrap();
    assert!(
        verify_static_manifest_metadata(catalog.get("local-name").unwrap(), &metadata).is_err()
    );
    let start = config.find("[artifacts.verification]").unwrap();
    let end = config.find("[[artifacts.selectors]]").unwrap();
    let check_only = format!(
        "{}[artifacts.verification]\ntype = \"check-only\"\n{}",
        &config[..start],
        &config[end..]
    );
    let catalog = ArtifactCatalog::parse(&check_only).unwrap();
    assert!(
        verify_static_manifest_metadata(catalog.get("local-name").unwrap(), &metadata).is_err()
    );
}

#[test]
fn static_metadata_authenticates_only_explicit_local_authority() {
    let (config, metadata) = fixture();
    let catalog = ArtifactCatalog::parse(&config).unwrap();
    let verified =
        verify_static_manifest_metadata(catalog.get("local-name").unwrap(), &metadata).unwrap();
    assert_eq!(verified.product, "example");
    assert_eq!(verified.version.to_string(), "1.2.3");
    assert_eq!(
        verified.source_commit.as_deref(),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    for (from, to) in [
        ("product = \"example\"", "product = \"other\""),
        ("target = \"linux-x86_64\"", "target = \"windows-x86_64\""),
        (
            "artifact_url = \"https://example.invalid/application\"",
            "artifact_url = \"https://example.invalid/other\"",
        ),
    ] {
        let changed = ArtifactCatalog::parse(&config.replace(from, to)).unwrap();
        assert!(
            verify_static_manifest_metadata(changed.get("local-name").unwrap(), &metadata).is_err()
        );
    }
    let mut tampered = metadata;
    tampered.manifest = String::from_utf8(tampered.manifest)
        .unwrap()
        .replace("1.2.3", "1.2.4")
        .into_bytes();
    assert!(
        verify_static_manifest_metadata(catalog.get("local-name").unwrap(), &tampered).is_err()
    );
}
