use crate::release_manifest::VerifiedDevAuthRelease;
use anyhow::{bail, Context, Result};
use dev_tools_release::{
    accept_verified_release, accept_verified_release_at, cache_verified_release, fetch_https,
    load_cached_release, load_release_state_at, select_stable_release_assets,
    verify_artifact_bytes, verify_release_metadata, ArtifactUrlPolicy, CachedRelease, HttpsPolicy,
    ReleaseAuthority, ReleaseMetadata, ReleaseState, VerifiedRelease,
};
use semver::Version;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

const RELEASES_URL: &str =
    "https://api.github.com/repos/FutureDevGuys/dev-tools/releases?per_page=100";
const METADATA_LIMIT: u64 = 512 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const TRUSTED_ROOT: &str = include_str!("../trust/root-public-key.txt");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedStableRelease {
    pub verified: VerifiedDevAuthRelease,
    pub directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableReleaseStorage {
    pub state_path: PathBuf,
    pub cache_root: PathBuf,
    pub owner_uid: u32,
}

pub fn native_release_storage(mode: crate::setup::InstallMode) -> Result<StableReleaseStorage> {
    let (root, owner_uid) = match mode {
        crate::setup::InstallMode::Strong => (PathBuf::from("/var/lib/dev-auth/releases"), 0),
        crate::setup::InstallMode::UserOnly => {
            let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())?
                .context("effective native account does not exist")?;
            (
                user.dir.join(".local/state/dev-auth/releases"),
                user.uid.as_raw(),
            )
        }
    };
    Ok(StableReleaseStorage {
        state_path: root.join("accepted.json"),
        cache_root: root.join("cache"),
        owner_uid,
    })
}

pub fn stage_latest_stable_release(
    storage: &StableReleaseStorage,
    offline: bool,
) -> Result<StagedStableRelease> {
    validate_storage(storage)?;
    if offline {
        return load_offline_release(storage);
    }
    stage_latest_stable_release_inner(storage)
}

pub fn stage_verified_release_from_paths(
    storage: &StableReleaseStorage,
    root_path: &Path,
    manifest_path: &Path,
    artifact_path: &Path,
) -> Result<StagedStableRelease> {
    stage_verified_release_from_paths_with_authority(
        storage,
        &release_authority()?,
        root_path,
        manifest_path,
        artifact_path,
    )
}

fn stage_verified_release_from_paths_with_authority(
    storage: &StableReleaseStorage,
    authority: &ReleaseAuthority,
    root_path: &Path,
    manifest_path: &Path,
    artifact_path: &Path,
) -> Result<StagedStableRelease> {
    let metadata = ReleaseMetadata {
        root: crate::release_manifest::read_public_file(
            root_path,
            METADATA_LIMIT,
            "root document",
        )?,
        manifest: crate::release_manifest::read_public_file(
            manifest_path,
            METADATA_LIMIT,
            "release manifest",
        )?,
    };
    let artifact = crate::release_manifest::read_public_file(
        artifact_path,
        ARTIFACT_LIMIT,
        "release artifact",
    )?;
    stage_verified_release_bundle(storage, authority, &metadata, &artifact)
}

pub fn require_accepted_release(
    storage: &StableReleaseStorage,
    release: &VerifiedDevAuthRelease,
) -> Result<()> {
    load_exact_accepted_release(storage, release).map(|_| ())
}

/// Reload the expected accepted release from the authenticated canonical cache.
///
/// The paths in `expected` are not trusted as cache authority. The returned
/// paths always identify the receipt-checked entry beneath `storage.cache_root`.
pub fn load_exact_accepted_release(
    storage: &StableReleaseStorage,
    expected: &VerifiedDevAuthRelease,
) -> Result<StagedStableRelease> {
    load_exact_accepted_release_with_authority(storage, expected, &retained_release_authority()?)
}

fn stage_latest_stable_release_inner(
    storage: &StableReleaseStorage,
) -> Result<StagedStableRelease> {
    let policy = release_https_policy();
    let releases = fetch_https(RELEASES_URL, &policy, METADATA_LIMIT, None)?;
    let selected = select_stable_release_assets(
        &releases.bytes,
        "dev-auth",
        "dev-tools-root.json",
        "dev-auth-stable.json",
    )?;
    let root = fetch_https(&selected.root_url, &policy, METADATA_LIMIT, None)?;
    let manifest = fetch_https(&selected.manifest_url, &policy, METADATA_LIMIT, None)?;
    let authority = release_authority()?;
    let metadata = ReleaseMetadata {
        root: root.bytes,
        manifest: manifest.bytes,
    };
    let verified = verify_release_metadata(&metadata, &authority)?;
    require_new_release_schema(&verified)?;
    if verified.version != selected.version
        || verified.artifact_length == 0
        || verified.artifact_length > ARTIFACT_LIMIT
    {
        bail!("selected stable release and signed manifest disagree");
    }
    let artifact = fetch_https(
        &verified.artifact_url,
        &policy,
        verified.artifact_length,
        None,
    )?;
    stage_verified_release_bundle(storage, &authority, &metadata, &artifact.bytes)
}

fn stage_verified_release_bundle(
    storage: &StableReleaseStorage,
    authority: &ReleaseAuthority,
    metadata: &ReleaseMetadata,
    artifact: &[u8],
) -> Result<StagedStableRelease> {
    validate_storage(storage)?;
    let verified = verify_release_metadata(metadata, authority)?;
    require_new_release_schema(&verified)?;
    if !verified.version.pre.is_empty() {
        bail!("explicit release bundle is not a stable release");
    }
    verify_artifact_bytes(&verified, artifact)?;
    preflight_accepted_state(storage, &verified)?;
    let cached = cache_verified_release(
        &storage.cache_root,
        authority,
        metadata,
        artifact,
        storage.owner_uid,
    )?;
    accept_verified_release_at(&storage.state_path, storage.owner_uid, &verified)?;
    cached_release_result(cached)
}

fn release_https_policy() -> HttpsPolicy {
    HttpsPolicy {
        allowed_hosts: BTreeSet::from([
            "api.github.com".into(),
            "github.com".into(),
            "objects.githubusercontent.com".into(),
            "github-releases.githubusercontent.com".into(),
            "release-assets.githubusercontent.com".into(),
        ]),
        max_redirects: 3,
        timeout: Duration::from_secs(30),
        user_agent: format!("dev-auth/{}", env!("CARGO_PKG_VERSION")),
    }
}

fn release_authority() -> Result<ReleaseAuthority> {
    Ok(ReleaseAuthority {
        trusted_root_key: TRUSTED_ROOT.trim().into(),
        product: "dev-auth".into(),
        accepted_manifest_schemas: vec![
            "dev-tools-product-v2".into(),
            "dev-auth-product-v2".into(),
        ],
        target: crate::release_manifest::target_id()?,
        artifact_url: ArtifactUrlPolicy::GitHubRelease {
            owner: "FutureDevGuys".into(),
            repository: "dev-tools".into(),
        },
        require_source_commit: true,
        engine_protocol: 1,
    })
}

fn retained_release_authority() -> Result<ReleaseAuthority> {
    let authority = release_authority()?;
    // These readers require an exact match with the already accepted ledger;
    // compatibility must never expand online discovery or new bundle intake.
    Ok(authority)
}

fn require_new_release_schema(release: &VerifiedRelease) -> Result<()> {
    if release.manifest_schema == "dev-tools-product-v2"
        || (release.product == "dev-auth"
            && release.version.to_string() == "0.3.11"
            && release.manifest_schema == "dev-auth-product-v2")
    {
        Ok(())
    } else {
        bail!("legacy release is outside the Dev Auth 0.3.11 signer bootstrap");
    }
}

fn validate_storage(storage: &StableReleaseStorage) -> Result<()> {
    if !storage.state_path.is_absolute()
        || !storage.cache_root.is_absolute()
        || storage.state_path == Path::new("/")
        || storage.cache_root == Path::new("/")
        || storage.state_path.starts_with(&storage.cache_root)
    {
        bail!("stable release storage is invalid");
    }
    Ok(())
}

fn preflight_accepted_state(
    storage: &StableReleaseStorage,
    verified: &VerifiedRelease,
) -> Result<()> {
    let mut state = load_release_state_at(&storage.state_path, storage.owner_uid)?;
    accept_verified_release(&mut state, verified)?;
    Ok(())
}

fn load_offline_release(storage: &StableReleaseStorage) -> Result<StagedStableRelease> {
    let authority = retained_release_authority()?;
    load_accepted_release_with_authority(storage, &authority)
}

fn load_accepted_release_with_authority(
    storage: &StableReleaseStorage,
    authority: &ReleaseAuthority,
) -> Result<StagedStableRelease> {
    validate_storage(storage)?;
    let state = load_release_state_at(&storage.state_path, storage.owner_uid)?;
    let version = state
        .accepted_version
        .as_deref()
        .context("offline release resolution has no previously accepted version")?;
    let version = Version::parse(version).context("parse accepted offline release version")?;
    let cached = load_cached_release(&storage.cache_root, authority, &version, storage.owner_uid)?;
    require_cached_state_match(&state, &cached.verified)?;
    cached_release_result(cached)
}

fn load_exact_accepted_release_with_authority(
    storage: &StableReleaseStorage,
    expected: &VerifiedDevAuthRelease,
    authority: &ReleaseAuthority,
) -> Result<StagedStableRelease> {
    validate_storage(storage)?;
    let state = load_release_state_at(&storage.state_path, storage.owner_uid)?;
    require_expected_state_match(&state, expected)?;
    let version =
        Version::parse(&expected.version).context("parse expected accepted release version")?;
    let cached = load_cached_release(&storage.cache_root, authority, &version, storage.owner_uid)?;
    require_cached_state_match(&state, &cached.verified)?;
    let accepted = cached_release_result(cached)?;
    if accepted.verified != *expected {
        bail!("canonical cached release does not match the expected release identity");
    }
    Ok(accepted)
}

fn require_expected_state_match(
    state: &ReleaseState,
    expected: &VerifiedDevAuthRelease,
) -> Result<()> {
    if state.accepted_root_generation != expected.root_generation
        || state.accepted_root_sha256.as_deref() != Some(expected.root_sha256.as_str())
        || state.accepted_generation != expected.manifest_generation
        || state.accepted_manifest_sha256.as_deref() != Some(expected.manifest_sha256.as_str())
        || state.accepted_version.as_deref() != Some(expected.version.as_str())
        || state.accepted_binary_sha256.as_deref() != Some(expected.artifact_sha256.as_str())
    {
        bail!("setup plan release is no longer the exact accepted stable release");
    }
    Ok(())
}

fn require_cached_state_match(state: &ReleaseState, verified: &VerifiedRelease) -> Result<()> {
    if state.accepted_root_generation != verified.root_generation
        || state.accepted_root_sha256.as_deref() != Some(verified.root_sha256.as_str())
        || state.accepted_generation != verified.manifest_generation
        || state.accepted_manifest_sha256.as_deref() != Some(verified.manifest_sha256.as_str())
        || state.accepted_version.as_deref() != Some(verified.version.to_string().as_str())
        || state.accepted_binary_sha256.as_deref() != Some(verified.artifact_sha256.as_str())
    {
        bail!("offline cached release does not match the accepted release state");
    }
    Ok(())
}

fn cached_release_result(cached: CachedRelease) -> Result<StagedStableRelease> {
    let source_commit = cached
        .verified
        .source_commit
        .clone()
        .context("verified dev-auth release has no source commit")?;
    let directory = cached
        .artifact_path
        .parent()
        .context("cached dev-auth release has no directory")?
        .to_path_buf();
    Ok(StagedStableRelease {
        verified: VerifiedDevAuthRelease {
            schema: "dev-auth-verified-release-v1".into(),
            root_path: cached.root_path,
            manifest_path: cached.manifest_path,
            root_generation: cached.verified.root_generation,
            manifest_generation: cached.verified.manifest_generation,
            version: cached.verified.version.to_string(),
            source_commit,
            target: cached.verified.target,
            artifact_path: cached.artifact_path,
            artifact_url: cached.verified.artifact_url,
            artifact_length: cached.verified.artifact_length,
            artifact_sha256: cached.verified.artifact_sha256,
            root_sha256: cached.verified.root_sha256,
            manifest_sha256: cached.verified.manifest_sha256,
        },
        directory,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    #[derive(Serialize)]
    struct TestEnvelope<T> {
        signed: T,
        signatures: Vec<TestSignature>,
    }

    #[derive(Serialize)]
    struct TestSignature {
        key_id: String,
        signature: String,
    }

    #[derive(Serialize)]
    struct TestRoot {
        schema: String,
        generation: u64,
        release_keys: Vec<TestReleaseKey>,
    }

    #[derive(Serialize)]
    struct TestReleaseKey {
        key_id: String,
        public_key: String,
        revoked: bool,
    }

    #[derive(Serialize)]
    struct TestManifest {
        schema: String,
        product: String,
        generation: u64,
        version: String,
        source_commit: String,
        engine_protocol: u32,
        artifacts: BTreeMap<String, TestArtifact>,
    }

    #[derive(Serialize)]
    struct TestArtifact {
        url: String,
        length: u64,
        sha256: String,
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn envelope<T: Serialize>(signed: T, key_id: &str, key: &SigningKey) -> Vec<u8> {
        let signature = BASE64.encode(key.sign(&serde_jcs::to_vec(&signed).unwrap()).to_bytes());
        serde_json::to_vec(&TestEnvelope {
            signed,
            signatures: vec![TestSignature {
                key_id: key_id.into(),
                signature,
            }],
        })
        .unwrap()
    }

    fn release_fixture() -> (ReleaseAuthority, ReleaseMetadata, Vec<u8>) {
        release_fixture_at("0.3.11")
    }

    fn release_fixture_at(version: &str) -> (ReleaseAuthority, ReleaseMetadata, Vec<u8>) {
        let root_key = SigningKey::from_bytes(&[7; 32]);
        let release_key = SigningKey::from_bytes(&[9; 32]);
        let release_id =
            dev_tools_release::release_key_id(&hex(&release_key.verifying_key().to_bytes()))
                .unwrap();
        let target = "linux-x86_64";
        let artifact = b"authenticated local release fixture".to_vec();
        let root = envelope(
            TestRoot {
                schema: "dev-tools-root-v1".into(),
                generation: 7,
                release_keys: vec![TestReleaseKey {
                    key_id: release_id.clone(),
                    public_key: hex(&release_key.verifying_key().to_bytes()),
                    revoked: false,
                }],
            },
            "root-test",
            &root_key,
        );
        let manifest = envelope(
            TestManifest {
                schema: "dev-auth-product-v2".into(),
                product: "dev-auth".into(),
                generation: 19,
                version: version.into(),
                source_commit: "a".repeat(40),
                engine_protocol: 1,
                artifacts: BTreeMap::from([(
                    target.into(),
                    TestArtifact {
                        url: format!("https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv{version}/dev-auth-{version}-{target}"),
                        length: artifact.len() as u64,
                        sha256: format!("{:x}", Sha256::digest(&artifact)),
                    },
                )]),
            },
            &release_id,
            &release_key,
        );
        (
            ReleaseAuthority {
                trusted_root_key: hex(&root_key.verifying_key().to_bytes()),
                product: "dev-auth".into(),
                accepted_manifest_schemas: vec!["dev-auth-product-v2".into()],
                target: target.into(),
                artifact_url: ArtifactUrlPolicy::GitHubRelease {
                    owner: "FutureDevGuys".into(),
                    repository: "dev-tools".into(),
                },
                require_source_commit: true,
                engine_protocol: 1,
            },
            ReleaseMetadata { root, manifest },
            artifact,
        )
    }

    #[test]
    fn online_authority_limits_legacy_to_source_bound_bootstrap_manifest() {
        let authority = release_authority().unwrap();
        assert_eq!(
            authority.accepted_manifest_schemas,
            ["dev-tools-product-v2", "dev-auth-product-v2"]
        );
        assert!(authority.require_source_commit);
        assert_eq!(authority.product, "dev-auth");
    }

    #[test]
    fn predecessor_schema_is_readable_only_as_exact_accepted_cache() {
        let root = tempfile::tempdir().unwrap();
        let storage = StableReleaseStorage {
            state_path: root.path().join("state.json"),
            cache_root: root.path().join("cache"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        };
        let (previous_authority, metadata, artifact) = release_fixture_at("0.3.10");
        let mut online = release_authority().unwrap();
        online.trusted_root_key = previous_authority.trusted_root_key.clone();
        online.target = previous_authority.target.clone();
        let mut identity = verify_release_metadata(&metadata, &online).unwrap();
        assert!(require_new_release_schema(&identity).is_err());
        for version in ["0.3.10", "0.3.12", "0.3.11+other"] {
            identity.version = Version::parse(version).unwrap();
            assert!(require_new_release_schema(&identity).is_err());
        }

        assert!(stage_verified_release_bundle(&storage, &online, &metadata, &artifact).is_err());
        // Model bytes accepted by the predecessor, not a new legacy intake.
        let cached = cache_verified_release(
            &storage.cache_root,
            &previous_authority,
            &metadata,
            &artifact,
            storage.owner_uid,
        )
        .unwrap();
        accept_verified_release_at(&storage.state_path, storage.owner_uid, &cached.verified)
            .unwrap();
        let previous = cached_release_result(cached).unwrap();
        let mut retained = retained_release_authority().unwrap();
        retained.trusted_root_key = previous_authority.trusted_root_key;
        retained.target = previous_authority.target;
        assert_eq!(
            load_accepted_release_with_authority(&storage, &retained).unwrap(),
            previous,
        );
        let mut substituted = previous.verified;
        substituted.manifest_sha256 = "b".repeat(64);
        assert!(
            load_exact_accepted_release_with_authority(&storage, &substituted, &retained,).is_err()
        );
    }

    #[test]
    fn release_storage_is_absolute_bounded_and_nonoverlapping() {
        let root = tempfile::tempdir().unwrap();
        let storage = StableReleaseStorage {
            state_path: root.path().join("state.json"),
            cache_root: root.path().join("cache"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        };
        assert!(validate_storage(&storage).is_ok());
        let overlapping = StableReleaseStorage {
            state_path: storage.cache_root.join("state.json"),
            ..storage
        };
        assert!(validate_storage(&overlapping).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn authenticated_local_release_is_cached_accepted_and_reloadable() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let storage = StableReleaseStorage {
            state_path: root.path().join("state.json"),
            cache_root: root.path().join("cache"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        };
        let (authority, metadata, artifact) = release_fixture();
        let root_real = root.path().join("root-real.json");
        let root_path = root.path().join("root.json");
        let manifest_path = root.path().join("manifest.json");
        let artifact_path = root.path().join("artifact");
        std::fs::write(&root_real, &metadata.root).unwrap();
        std::fs::write(&manifest_path, &metadata.manifest).unwrap();
        std::fs::write(&artifact_path, &artifact).unwrap();
        symlink(&root_real, &root_path).unwrap();
        assert!(stage_verified_release_from_paths_with_authority(
            &storage,
            &authority,
            &root_path,
            &manifest_path,
            &artifact_path,
        )
        .is_err());
        std::fs::remove_file(&root_path).unwrap();
        std::fs::write(&root_path, &metadata.root).unwrap();

        let staged = stage_verified_release_from_paths_with_authority(
            &storage,
            &authority,
            &root_path,
            &manifest_path,
            &artifact_path,
        )
        .unwrap();
        assert_eq!(staged.verified.version, "0.3.11");
        assert_eq!(staged.verified.manifest_generation, 19);
        assert!(staged.verified.root_path.starts_with(&storage.cache_root));
        assert!(staged
            .verified
            .manifest_path
            .starts_with(&storage.cache_root));
        assert!(staged
            .verified
            .artifact_path
            .starts_with(&storage.cache_root));
        assert_eq!(
            stage_verified_release_from_paths_with_authority(
                &storage,
                &authority,
                &root_path,
                &manifest_path,
                &artifact_path,
            )
            .unwrap(),
            staged
        );
        let state = load_release_state_at(&storage.state_path, storage.owner_uid).unwrap();
        let cached = load_cached_release(
            &storage.cache_root,
            &authority,
            &Version::parse("0.3.11").unwrap(),
            storage.owner_uid,
        )
        .unwrap();
        require_cached_state_match(&state, &cached.verified).unwrap();
        assert_eq!(cached_release_result(cached).unwrap(), staged);

        let copied_artifact = root.path().join("copied-artifact");
        std::fs::write(&copied_artifact, &artifact).unwrap();
        let mut expected = staged.verified.clone();
        expected.artifact_path = copied_artifact;
        assert!(
            load_exact_accepted_release_with_authority(&storage, &expected, &authority).is_err()
        );

        let mut mismatched = staged.verified.clone();
        mismatched.source_commit = "b".repeat(40);
        assert!(
            load_exact_accepted_release_with_authority(&storage, &mismatched, &authority,).is_err()
        );

        let mut tampered_state = state;
        tampered_state.accepted_binary_sha256 = Some("0".repeat(64));
        std::fs::write(
            &storage.state_path,
            serde_jcs::to_vec(&tampered_state).unwrap(),
        )
        .unwrap();
        assert!(
            load_exact_accepted_release_with_authority(&storage, &staged.verified, &authority)
                .is_err()
        );

        let mut changed = artifact.clone();
        changed.push(0);
        std::fs::write(&artifact_path, changed).unwrap();
        assert!(stage_verified_release_from_paths_with_authority(
            &storage,
            &authority,
            &root_path,
            &manifest_path,
            &artifact_path,
        )
        .is_err());
    }
}
