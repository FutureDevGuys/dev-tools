use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

struct Fixture {
    _env: std::sync::MutexGuard<'static, ()>,
    root: tempfile::TempDir,
    paths: Paths,
    authority: ReleaseAuthority,
    original_home: Option<std::ffi::OsString>,
    original_state: Option<std::ffi::OsString>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn signed(value: Value, key: &SigningKey, key_id: &str) -> Vec<u8> {
    let signature = key.sign(&serde_jcs::to_vec(&value).unwrap());
    serde_json::to_vec(&json!({
        "signed": value,
        "signatures": [{"key_id":key_id, "signature":BASE64.encode(signature.to_bytes())}]
    }))
    .unwrap()
}

impl Fixture {
    fn new() -> Self {
        let guard = crate::test_support::env_guard();
        let root = tempfile::tempdir().unwrap();
        let original_home = env::var_os("HOME");
        let original_state = env::var_os("XDG_STATE_HOME");
        env::set_var("HOME", root.path());
        env::set_var("XDG_STATE_HOME", root.path().join("state"));
        let paths = Paths::resolve(Product::DevCache).unwrap();
        let mut authority = release_authority(Product::DevCache);
        authority.trusted_root_key =
            hex(&SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes());
        Self {
            _env: guard,
            root,
            paths,
            authority,
            original_home,
            original_state,
        }
    }

    fn bundle(&self, version: &str, generation: u64) -> OfflineBundlePaths {
        let directory = self
            .root
            .path()
            .join(format!("bundle-{version}-{generation}"));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let root_key = SigningKey::from_bytes(&[81; 32]);
        let key = SigningKey::from_bytes(&[82; 32]);
        let public = hex(&key.verifying_key().to_bytes());
        let root_id = dev_tools_release::root_key_id(&self.authority.trusted_root_key).unwrap();
        let release_id = dev_tools_release::release_key_id(&public).unwrap();
        let artifact = format!("#!/bin/sh\nprintf '%s\\n' 'dev-cache {version}'\n");
        let root = json!({"schema":"dev-tools-root-v1","generation":1,
            "release_keys":[{"key_id":release_id,"public_key":public,"revoked":false}]});
        let manifest = json!({"schema":"dev-tools-product-v2","product":"dev-cache",
            "generation":generation,"version":version,"engine_protocol":1,
            "source_commit":"a".repeat(40),"artifacts":{"linux-x86_64":{
                "url":format!("https://github.com/FutureDevGuys/dev-tools/releases/download/dev-cache%2Fv{version}/dev-cache-{version}-linux-x86_64"),
                "length":artifact.len(),"sha256":sha256_hex(artifact.as_bytes())}}});
        let paths = OfflineBundlePaths {
            root_document: directory.join("dev-tools-root.json"),
            manifest: directory.join("dev-cache-stable.json"),
            artifact: directory.join(format!("dev-cache-{version}-linux-x86_64")),
        };
        fs::write(&paths.root_document, signed(root, &root_key, &root_id)).unwrap();
        fs::write(&paths.manifest, signed(manifest, &key, &release_id)).unwrap();
        fs::write(&paths.artifact, artifact).unwrap();
        for path in [&paths.root_document, &paths.manifest, &paths.artifact] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        paths
    }

    fn install(&self, bundle: &OfflineBundlePaths) -> Result<Activation> {
        install_with_authority(Product::DevCache, &self.paths, bundle, &self.authority)
    }

    fn assert_not_activated(&self) {
        assert!(!self.paths.public_binary.exists());
        assert!(!self
            .paths
            .product_root
            .join("installation-receipt-v1.json")
            .exists());
        assert!(!self.paths.state.exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for (name, value) in [
            ("HOME", &self.original_home),
            ("XDG_STATE_HOME", &self.original_state),
        ] {
            match value {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
    }
}

fn alter_signed(path: &Path, is_root: bool, change: impl FnOnce(&mut Value)) {
    let mut envelope: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    change(&mut envelope["signed"]);
    let key = SigningKey::from_bytes(&[if is_root { 81 } else { 82 }; 32]);
    let public = hex(&key.verifying_key().to_bytes());
    let id = if is_root {
        dev_tools_release::root_key_id(&public)
    } else {
        dev_tools_release::release_key_id(&public)
    }
    .unwrap();
    fs::write(path, signed(envelope["signed"].clone(), &key, &id)).unwrap();
}

#[test]
fn offline_signed_bundle_installs_repeats_upgrades_and_rolls_back() {
    let f = Fixture::new();
    let prior = f.bundle("0.1.10", 11);
    let candidate = f.bundle("0.1.11", 12);
    assert!(f.install(&prior).unwrap().changed);
    let state_before = fs::read(&f.paths.state).unwrap();
    assert!(!f.install(&prior).unwrap().changed);
    assert_eq!(fs::read(&f.paths.state).unwrap(), state_before);
    assert!(load_state(&f.paths)
        .unwrap()
        .last_successful_check_unix
        .is_none());
    assert!(f.install(&candidate).unwrap().changed);
    assert!(!f.install(&candidate).unwrap().changed);
    assert_eq!(
        fs::read(&f.paths.public_binary).unwrap(),
        fs::read(&candidate.artifact).unwrap()
    );
    assert_eq!(
        rollback(Product::DevCache).unwrap().version.as_deref(),
        Some("0.1.10")
    );
    assert!(f.install(&prior).is_err());
    assert_eq!(
        rollback(Product::DevCache).unwrap().version.as_deref(),
        Some("0.1.11")
    );
    assert_eq!(load_state(&f.paths).unwrap().accepted_generation, 12);
    assert!(!f.install(&candidate).unwrap().changed);
}

#[test]
fn offline_signed_bundle_preserves_freshness_and_metadata_only_no_change() {
    let f = Fixture::new();
    let first = f.bundle("0.1.10", 11);
    f.install(&first).unwrap();
    let mut state = load_state(&f.paths).unwrap();
    state.last_successful_check_unix = Some(12345);
    save_state(&f.paths, &state).unwrap();
    let next = f.bundle("0.1.10", 12);
    assert!(!f.install(&next).unwrap().changed);
    let state = load_state(&f.paths).unwrap();
    assert_eq!(state.last_successful_check_unix, Some(12345));
    assert_eq!(state.accepted_generation, 12);
    assert!(!f.install(&next).unwrap().changed);
    assert!(!f.paths.root_cache.exists());
    assert!(!f.paths.manifest_cache.exists());
}

#[test]
fn offline_signed_bundle_rejects_invalid_signed_authority_before_activation() {
    for case in [
        "schema",
        "source",
        "product",
        "target",
        "protocol",
        "url",
        "length",
        "hash",
        "prerelease",
        "unknown",
        "revoked",
        "signature",
        "root-signature",
    ] {
        let f = Fixture::new();
        let b = f.bundle("0.1.11", 12);
        match case {
            "revoked" => alter_signed(&b.root_document, true, |v| {
                v["release_keys"][0]["revoked"] = json!(true)
            }),
            "signature" | "root-signature" => {
                let path = if case == "signature" {
                    &b.manifest
                } else {
                    &b.root_document
                };
                let mut v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
                v["signatures"][0]["signature"] = json!(BASE64.encode([0_u8; 64]));
                fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
            }
            _ => alter_signed(&b.manifest, false, |v| match case {
                "schema" => v["schema"] = json!("dev-tools-product-v1"),
                "source" => {
                    v.as_object_mut().unwrap().remove("source_commit");
                }
                "product" => v["product"] = json!("skills-sync"),
                "target" => {
                    let a = v["artifacts"]["linux-x86_64"].take();
                    v["artifacts"] = json!({"linux-aarch64":a});
                }
                "protocol" => v["engine_protocol"] = json!(2),
                "url" => {
                    v["artifacts"]["linux-x86_64"]["url"] =
                        json!("https://example.invalid/artifact")
                }
                "length" => v["artifacts"]["linux-x86_64"]["length"] = json!(1),
                "hash" => v["artifacts"]["linux-x86_64"]["sha256"] = json!("0".repeat(64)),
                "prerelease" => v["version"] = json!("0.1.11-rc.1"),
                "unknown" => v["command"] = json!("arbitrary"),
                _ => unreachable!(),
            }),
        }
        assert!(f.install(&b).is_err(), "{case}");
        f.assert_not_activated();
    }
}

#[test]
fn offline_signed_bundle_rejects_rollback_and_equivocation_before_recovery() {
    for case in [
        "generation",
        "version",
        "root-generation",
        "root-equivocation",
        "manifest-equivocation",
        "version-equivocation",
    ] {
        let f = Fixture::new();
        let first = f.bundle("0.1.10", 11);
        // Accept root generation two, allowing an independently valid older root fixture.
        alter_signed(&first.root_document, true, |v| v["generation"] = json!(2));
        f.install(&first).unwrap();
        let b = f.bundle(if case == "version" { "0.1.9" } else { "0.1.10" }, 12);
        alter_signed(&b.root_document, true, |v| v["generation"] = json!(2));
        match case {
            "generation" => alter_signed(&b.manifest, false, |v| v["generation"] = json!(10)),
            "root-generation" => {
                alter_signed(&b.root_document, true, |v| v["generation"] = json!(1))
            }
            "root-equivocation" => alter_signed(&b.root_document, true, |v| {
                let key = SigningKey::from_bytes(&[83; 32]);
                let public = hex(&key.verifying_key().to_bytes());
                v["release_keys"].as_array_mut().unwrap().push(json!({"key_id":dev_tools_release::release_key_id(&public).unwrap(),"public_key":public,"revoked":false}));
            }),
            "manifest-equivocation" => alter_signed(&b.manifest, false, |v| {
                v["generation"] = json!(11);
                v["source_commit"] = json!("b".repeat(40));
            }),
            "version-equivocation" => {
                let mut bytes = fs::read(&b.artifact).unwrap();
                bytes.extend_from_slice(b"# other bytes\n");
                fs::write(&b.artifact, &bytes).unwrap();
                alter_signed(&b.manifest, false, |v| {
                    v["artifacts"]["linux-x86_64"]["length"] = json!(bytes.len());
                    v["artifacts"]["linux-x86_64"]["sha256"] = json!(sha256_hex(&bytes));
                });
            }
            _ => {}
        }
        // A missing owned alias would be repaired by admitted recovery; rejection must precede it.
        fs::remove_file(&f.paths.public_binary).unwrap();
        let before = fs::read(&f.paths.state).unwrap();
        assert!(f.install(&b).is_err(), "{case}");
        assert!(!f.paths.public_binary.exists(), "{case}");
        assert_eq!(fs::read(&f.paths.state).unwrap(), before, "{case}");
    }
}

#[test]
fn offline_signed_bundle_rejects_unsafe_and_bounded_inputs() {
    for case in [
        "relative",
        "parent",
        "missing",
        "empty",
        "oversize-metadata",
        "oversize-artifact",
        "symlink",
        "parent-symlink",
        "hardlink",
        "writable",
        "special-mode",
        "parent-writable",
        "directory",
        "special-file",
        "tampered",
    ] {
        let f = Fixture::new();
        let mut b = f.bundle("0.1.11", 12);
        match case {
            "relative" => b.artifact = PathBuf::from("relative"),
            "parent" => b.artifact = b.artifact.parent().unwrap().join("../artifact"),
            "missing" => {
                fs::remove_file(&b.artifact).unwrap();
            }
            "empty" => fs::write(&b.artifact, []).unwrap(),
            "oversize-metadata" => File::options()
                .write(true)
                .open(&b.manifest)
                .unwrap()
                .set_len(METADATA_LIMIT + 1)
                .unwrap(),
            "oversize-artifact" => File::options()
                .write(true)
                .open(&b.artifact)
                .unwrap()
                .set_len(ARTIFACT_LIMIT + 1)
                .unwrap(),
            "symlink" => {
                let original = b.artifact.with_extension("original");
                fs::rename(&b.artifact, &original).unwrap();
                symlink(original, &b.artifact).unwrap();
            }
            "parent-symlink" => {
                let linked = f.root.path().join("linked");
                symlink(b.artifact.parent().unwrap(), &linked).unwrap();
                b.artifact = linked.join(b.artifact.file_name().unwrap());
            }
            "hardlink" => fs::hard_link(&b.artifact, b.artifact.with_extension("linked")).unwrap(),
            "writable" => {
                fs::set_permissions(&b.artifact, fs::Permissions::from_mode(0o666)).unwrap()
            }
            "special-mode" => {
                fs::set_permissions(&b.artifact, fs::Permissions::from_mode(0o4700)).unwrap()
            }
            "parent-writable" => fs::set_permissions(
                b.artifact.parent().unwrap(),
                fs::Permissions::from_mode(0o777),
            )
            .unwrap(),
            "directory" => {
                fs::remove_file(&b.artifact).unwrap();
                fs::create_dir(&b.artifact).unwrap();
            }
            "special-file" => b.artifact = PathBuf::from("/dev/null"),
            "tampered" => fs::write(&b.artifact, b"different").unwrap(),
            _ => unreachable!(),
        }
        assert!(f.install(&b).is_err(), "{case}");
        f.assert_not_activated();
    }
}

#[test]
fn offline_signed_bundle_keeps_external_commands_and_rejects_busy_writer() {
    let f = Fixture::new();
    let b = f.bundle("0.1.11", 12);
    create_private_dir(&f.paths.bin_dir).unwrap();
    fs::write(&f.paths.public_binary, b"external tool").unwrap();
    let result = f.install(&b).unwrap();
    assert!(!result.changed);
    assert!(!result.managed);
    assert_eq!(fs::read(&f.paths.public_binary).unwrap(), b"external tool");
    assert!(!f.paths.product_root.exists());
    fs::remove_file(&f.paths.public_binary).unwrap();
    dev_tools_installation::ensure_owned_directory(&f.paths.product_root, current_uid(), 0o700)
        .unwrap();
    let lease = acquire_release_writer(&f.paths).unwrap();
    let error = f.install(&b).unwrap_err();
    assert!(error.downcast_ref::<ReleaseMutationBusy>().is_some());
    f.assert_not_activated();
    drop(lease);
    assert!(f.install(&b).unwrap().changed);
}

#[test]
fn offline_signed_bundle_resumes_after_accepted_history_before_activation() {
    let f = Fixture::new();
    let b = f.bundle("0.1.11", 12);
    let prepared = prepare(Product::DevCache, &f.paths, &b, &f.authority).unwrap();
    assert_eq!(load_state(&f.paths).unwrap().accepted_generation, 12);
    assert!(!f.paths.public_binary.exists());
    assert!(acquire_release_writer(&f.paths).is_err());
    drop(prepared);
    let prior = f.bundle("0.1.10", 11);
    assert!(f.install(&prior).is_err());
    assert!(!f.paths.public_binary.exists());
    assert!(f.install(&b).unwrap().changed);
    assert!(!f.install(&b).unwrap().changed);
}

#[test]
fn offline_signed_bundle_snapshot_cannot_be_substituted_after_acceptance() {
    let f = Fixture::new();
    let b = f.bundle("0.1.11", 12);
    let prepared = prepare(Product::DevCache, &f.paths, &b, &f.authority).unwrap();
    let exact = fs::read(&b.artifact).unwrap();
    fs::write(
        &b.artifact,
        b"changed original path after verified snapshot",
    )
    .unwrap();
    assert!(prepared.activate().unwrap().changed);
    assert_eq!(fs::read(&f.paths.public_binary).unwrap(), exact);
    assert!(f.install(&b).is_err());
}

#[test]
fn offline_signed_bundle_rejects_cached_source_tampering_before_activation() {
    let f = Fixture::new();
    let b = f.bundle("0.1.11", 12);
    let prepared = prepare(Product::DevCache, &f.paths, &b, &f.authority).unwrap();
    fs::write(&prepared.cached_artifact, b"changed cached source").unwrap();
    assert!(prepared.activate().is_err());
    assert!(!f.paths.public_binary.exists());
    assert_eq!(load_state(&f.paths).unwrap().accepted_generation, 12);
    assert!(f.install(&b).is_err());
}

#[test]
fn offline_signed_bundle_recovers_receipt_commit_before_state_publication() {
    let f = Fixture::new();
    let prior = f.bundle("0.1.10", 11);
    f.install(&prior).unwrap();
    let b = f.bundle("0.1.11", 12);
    let mut prepared = prepare(Product::DevCache, &f.paths, &b, &f.authority).unwrap();
    activate_verified_source(
        prepared.product,
        prepared.paths,
        &mut prepared.state,
        &prepared.verified,
        &prepared.cached_artifact,
    )
    .unwrap();
    // Simulated interruption: durable receipt is new, observation fields are old.
    drop(prepared);
    let before = load_state(&f.paths).unwrap();
    assert_eq!(before.accepted_generation, 12);
    assert_eq!(before.active_version.as_deref(), Some("0.1.10"));
    assert!(f.install(&b).unwrap().changed);
    assert_eq!(
        load_state(&f.paths).unwrap().active_version.as_deref(),
        Some("0.1.11")
    );
    assert!(!f.install(&b).unwrap().changed);
}

#[test]
fn offline_signed_bundle_recovers_both_installation_journal_boundaries() {
    for committed in [false, true] {
        let f = Fixture::new();
        let prior = f.bundle("0.1.10", 11);
        let b = f.bundle("0.1.11", 12);
        f.install(&prior).unwrap();
        let layout = shared_installation_layout(Product::DevCache, &f.paths).unwrap();
        let first = verify_versioned_installation(&layout).unwrap();
        f.install(&b).unwrap();
        let next = verify_versioned_installation(&layout).unwrap();
        let journal = f.paths.product_root.join("installation-transition-v1.json");
        fs::write(
            &journal,
            serde_json::to_vec(
                &json!({"schema":"dev-tools-versioned-transition-v1","prior":first,"next":next}),
            )
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        if !committed {
            fs::write(
                f.paths.product_root.join("installation-receipt-v1.json"),
                serde_json::to_vec(&first).unwrap(),
            )
            .unwrap();
        }
        assert!(f.install(&b).unwrap().changed);
        assert!(!journal.exists());
        assert!(!f.install(&b).unwrap().changed);
        assert_eq!(
            rollback(Product::DevCache).unwrap().version.as_deref(),
            Some("0.1.10")
        );
    }
}

#[test]
fn offline_signed_bundle_failed_health_keeps_prior_receipt_and_monotonic_history() {
    let f = Fixture::new();
    let prior = f.bundle("0.1.10", 11);
    f.install(&prior).unwrap();
    let b = f.bundle("0.1.11", 12);
    let bad = b"#!/bin/sh\nexit 1\n";
    fs::write(&b.artifact, bad).unwrap();
    alter_signed(&b.manifest, false, |v| {
        v["artifacts"]["linux-x86_64"]["length"] = json!(bad.len());
        v["artifacts"]["linux-x86_64"]["sha256"] = json!(sha256_hex(bad));
    });
    let receipt = fs::read(f.paths.product_root.join("installation-receipt-v1.json")).unwrap();
    assert!(f.install(&b).is_err());
    assert_eq!(
        fs::read(f.paths.product_root.join("installation-receipt-v1.json")).unwrap(),
        receipt
    );
    assert_eq!(
        fs::read(&f.paths.public_binary).unwrap(),
        fs::read(&prior.artifact).unwrap()
    );
    assert_eq!(load_state(&f.paths).unwrap().accepted_generation, 12);
    assert!(f.install(&prior).is_err());
}

#[test]
fn offline_signed_bundle_continued_writer_never_blesses_intervening_history() {
    let f = Fixture::new();
    let b = f.bundle("0.1.11", 12);
    let prepared = prepare(Product::DevCache, &f.paths, &b, &f.authority).unwrap();
    let mut other = load_state(&f.paths).unwrap();
    other.last_successful_check_unix = Some(999);
    let bytes = serde_json::to_vec_pretty(&other).unwrap();
    fs::write(&f.paths.state, &bytes).unwrap();
    assert!(prepared.writer.save(&prepared.state).is_err());
    assert_eq!(fs::read(&f.paths.state).unwrap(), bytes);
    assert!(acquire_release_writer(&f.paths).is_ok());
}

#[test]
fn offline_signed_bundle_rejects_lost_history_without_repair_or_downgrade() {
    for reset in [false, true] {
        let f = Fixture::new();
        let candidate = f.bundle("0.1.11", 12);
        let prior = f.bundle("0.1.10", 11);
        f.install(&candidate).unwrap();
        let receipt_path = f.paths.product_root.join("installation-receipt-v1.json");
        let receipt = fs::read(&receipt_path).unwrap();
        if reset {
            fs::write(
                &f.paths.state,
                serde_json::to_vec(&ReleaseState::default()).unwrap(),
            )
            .unwrap();
        } else {
            fs::remove_file(&f.paths.state).unwrap();
        }
        let original = fs::read(&f.paths.state).ok();
        fs::remove_file(&f.paths.public_binary).unwrap();
        assert!(f.install(&prior).is_err());
        assert!(f.install(&candidate).is_err());
        assert!(!f.paths.public_binary.exists());
        assert_eq!(fs::read(&receipt_path).unwrap(), receipt);
        assert_eq!(fs::read(&f.paths.state).ok(), original);
    }
}

#[test]
fn offline_signed_bundle_production_entrypoint_has_no_fixture_trust_override() {
    let f = Fixture::new();
    let candidate = f.bundle("0.1.11", 12);
    assert!(install(Product::DevCache, &candidate).is_err());
    f.assert_not_activated();
}

#[test]
fn offline_signed_bundle_recovers_first_install_journals_and_owned_alias() {
    for committed in [false, true] {
        let f = Fixture::new();
        let b = f.bundle("0.1.11", 12);
        f.install(&b).unwrap();
        let layout = shared_installation_layout(Product::DevCache, &f.paths).unwrap();
        let next = verify_versioned_installation(&layout).unwrap();
        let journal = f.paths.product_root.join("installation-transition-v1.json");
        fs::write(
            &journal,
            serde_json::to_vec(&json!({
                "schema":"dev-tools-versioned-transition-v1", "prior":null, "next":next
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        if !committed {
            fs::remove_file(f.paths.product_root.join("installation-receipt-v1.json")).unwrap();
        }
        let mut state = load_state(&f.paths).unwrap();
        state.active_version = None;
        state.previous_version = None;
        save_state(&f.paths, &state).unwrap();
        assert!(f.install(&b).unwrap().changed);
        assert!(!journal.exists());
        assert!(!f.install(&b).unwrap().changed);
        fs::remove_file(&f.paths.public_binary).unwrap();
        assert!(f.install(&b).unwrap().changed);
        assert!(!f.install(&b).unwrap().changed);
    }
}

#[test]
fn offline_signed_bundle_acceptance_failure_ends_writer_without_forgetting_publication() {
    for published in [false, true] {
        let f = Fixture::new();
        let b = f.bundle("0.1.11", 12);
        let metadata = ReleaseMetadata {
            root: fs::read(&b.root_document).unwrap(),
            manifest: fs::read(&b.manifest).unwrap(),
        };
        let verified =
            project_verified_manifest(verify_release_metadata(&metadata, &f.authority).unwrap());
        dev_tools_installation::ensure_owned_directory(&f.paths.product_root, current_uid(), 0o700)
            .unwrap();
        let (writer, mut state) = ReleaseStateWriter::begin(&f.paths).unwrap();
        accept_manifest_metadata(&mut state, &verified).unwrap();
        let result = writer.publish_and_continue(&state, |path, bytes, authority, expected| {
            if published {
                dev_tools_installation::write_atomic_document(path, bytes, authority, expected)?;
            }
            anyhow::bail!("injected publication failure with uncertain progress")
        });
        assert!(result.is_err());
        assert!(acquire_release_writer(&f.paths).is_ok());
        assert!(!f.paths.public_binary.exists());
        assert_eq!(
            load_state(&f.paths).unwrap().accepted_generation,
            if published { 12 } else { 0 }
        );
        let prior = f.bundle("0.1.10", 11);
        if published {
            assert!(f.install(&prior).is_err());
        }
        assert!(f.install(&b).unwrap().changed);
        assert!(!f.install(&b).unwrap().changed);
    }
}
