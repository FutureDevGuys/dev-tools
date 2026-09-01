use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use dev_tools_release::{
    accept_verified_release, fetch_https, select_stable_release_assets, verify_artifact_bytes,
    verify_release_bytes, verify_release_metadata, ArtifactUrlPolicy, HttpsPolicy,
    ReleaseAuthority, ReleaseBundle, ReleaseMetadata, ReleaseState,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::Duration;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn signed(value: Value, key_id: &str, key: &SigningKey) -> Vec<u8> {
    let canonical = serde_jcs::to_vec(&value).unwrap();
    serde_json::to_vec(&json!({
        "signed": value,
        "signatures": [{
            "key_id": key_id,
            "signature": BASE64.encode(key.sign(&canonical).to_bytes()),
        }],
    }))
    .unwrap()
}

fn fixture(schema: &str, source_commit: Option<&str>) -> (ReleaseBundle, ReleaseAuthority) {
    let root_key = SigningKey::from_bytes(&[7; 32]);
    let release_key = SigningKey::from_bytes(&[9; 32]);
    let root = signed(
        json!({
            "schema": "dev-tools-root-v1",
            "generation": 3,
            "release_keys": [{
                "key_id": "release-test",
                "public_key": hex(&release_key.verifying_key().to_bytes()),
                "revoked": false,
            }],
        }),
        "root-test",
        &root_key,
    );
    let artifact = b"signed product fixture".to_vec();
    let expected_url = "https://github.com/FutureDevGuys/dev-tools/releases/download/product%2Fv1.2.3/product-1.2.3-linux-x86_64";
    let mut manifest = json!({
        "schema": schema,
        "product": "product",
        "generation": 11,
        "version": "1.2.3",
        "engine_protocol": 1,
        "artifacts": {
            "linux-x86_64": {
                "url": expected_url,
                "length": artifact.len(),
                "sha256": format!("{:x}", Sha256::digest(&artifact)),
            }
        },
    });
    if let Some(commit) = source_commit {
        manifest["source_commit"] = Value::String(commit.into());
    }
    let manifest = signed(manifest, "release-test", &release_key);
    (
        ReleaseBundle {
            root,
            manifest,
            artifact,
        },
        ReleaseAuthority {
            trusted_root_key: hex(&root_key.verifying_key().to_bytes()),
            product: "product".into(),
            accepted_manifest_schemas: vec![schema.into()],
            target: "linux-x86_64".into(),
            artifact_url: ArtifactUrlPolicy::Exact(expected_url.into()),
            require_source_commit: source_commit.is_some(),
            engine_protocol: 1,
        },
    )
}

#[test]
fn verifies_v1_and_source_bound_v2_without_weakening_either_contract() {
    let (v1, v1_authority) = fixture("dev-tools-product-v1", None);
    let verified = verify_release_bytes(&v1, &v1_authority).unwrap();
    assert_eq!(verified.source_commit, None);
    assert_eq!(verified.version.to_string(), "1.2.3");

    let (v2, v2_authority) = fixture("dev-auth-product-v2", Some(&"a".repeat(40)));
    let verified = verify_release_bytes(&v2, &v2_authority).unwrap();
    assert_eq!(verified.source_commit.as_deref(), Some(&*"a".repeat(40)));

    let (unsigned_source, mut strict_authority) = fixture("dev-tools-product-v1", None);
    strict_authority.require_source_commit = true;
    assert!(verify_release_bytes(&unsigned_source, &strict_authority).is_err());
}

#[test]
fn rejects_revoked_keys_wrong_urls_and_artifact_changes() {
    let (mut bundle, authority) = fixture("dev-auth-product-v2", Some(&"b".repeat(40)));
    bundle.artifact.push(0);
    assert!(verify_release_bytes(&bundle, &authority).is_err());

    let (bundle, mut wrong_url) = fixture("dev-auth-product-v2", Some(&"b".repeat(40)));
    wrong_url.artifact_url = ArtifactUrlPolicy::Exact("https://example.invalid/wrong".into());
    assert!(verify_release_bytes(&bundle, &wrong_url).is_err());
}

#[test]
fn metadata_can_be_authenticated_before_the_artifact_is_downloaded() {
    let (bundle, authority) = fixture("dev-tools-product-v1", None);
    let verified = verify_release_metadata(
        &ReleaseMetadata {
            root: bundle.root.clone(),
            manifest: bundle.manifest.clone(),
        },
        &authority,
    )
    .unwrap();
    verify_artifact_bytes(&verified, &bundle.artifact).unwrap();

    let mut changed = bundle.artifact;
    changed.push(0);
    assert!(verify_artifact_bytes(&verified, &changed).is_err());
}

#[test]
fn stable_selection_is_product_scoped_and_rejects_prereleases() {
    let releases = serde_json::to_vec(&json!([
        {
            "tag_name": "product/v1.2.3-beta.1",
            "draft": false,
            "prerelease": false,
            "assets": []
        },
        {
            "tag_name": "other/v9.0.0",
            "draft": false,
            "prerelease": false,
            "assets": []
        },
        {
            "tag_name": "product/v1.2.2",
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "dev-tools-root.json", "browser_download_url": "https://github.com/root-old"},
                {"name": "product-stable.json", "browser_download_url": "https://github.com/manifest-old"}
            ]
        },
        {
            "tag_name": "product/v1.2.3",
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "dev-tools-root.json", "browser_download_url": "https://github.com/root"},
                {"name": "product-stable.json", "browser_download_url": "https://github.com/manifest"}
            ]
        }
    ])).unwrap();

    let selected = select_stable_release_assets(
        &releases,
        "product",
        "dev-tools-root.json",
        "product-stable.json",
    )
    .unwrap();
    assert_eq!(selected.version.to_string(), "1.2.3");
    assert_eq!(selected.root_url, "https://github.com/root");
    assert_eq!(selected.manifest_url, "https://github.com/manifest");
}

#[test]
fn https_transport_rejects_untrusted_origins_before_network_access() {
    let policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from(["api.github.com".into()]),
        max_redirects: 3,
        timeout: Duration::from_secs(30),
        user_agent: "dev-tools-release-test".into(),
    };
    assert!(fetch_https("http://api.github.com/releases", &policy, 1024, None).is_err());
    assert!(fetch_https("https://example.invalid/releases", &policy, 1024, None).is_err());
    assert!(fetch_https("https://api.github.com/releases", &policy, 0, None).is_err());
    assert!(fetch_https(
        "https://api.github.com/releases",
        &policy,
        1024,
        Some("bad\nheader")
    )
    .is_err());
}

#[test]
fn release_state_rejects_rollback_and_equivocation() {
    let (bundle, authority) = fixture("dev-auth-product-v2", Some(&"c".repeat(40)));
    let verified = verify_release_bytes(&bundle, &authority).unwrap();
    let mut state = ReleaseState::default();
    assert!(accept_verified_release(&mut state, &verified).unwrap());
    assert!(!accept_verified_release(&mut state, &verified).unwrap());

    let mut rollback = verified.clone();
    rollback.manifest_generation -= 1;
    assert!(accept_verified_release(&mut state, &rollback).is_err());

    let mut equivocation = verified.clone();
    equivocation.manifest_sha256 = "d".repeat(64);
    assert!(accept_verified_release(&mut state, &equivocation).is_err());

    let mut version_rollback = verified;
    version_rollback.manifest_generation += 1;
    version_rollback.version = semver::Version::parse("1.2.2").unwrap();
    assert!(accept_verified_release(&mut state, &version_rollback).is_err());
}
