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

#[derive(Debug)]
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

pub fn require_accepted_release(
    storage: &StableReleaseStorage,
    release: &VerifiedDevAuthRelease,
) -> Result<()> {
    validate_storage(storage)?;
    let state = load_release_state_at(&storage.state_path, storage.owner_uid)?;
    if state.accepted_root_generation != release.root_generation
        || state.accepted_root_sha256.as_deref() != Some(release.root_sha256.as_str())
        || state.accepted_generation != release.manifest_generation
        || state.accepted_manifest_sha256.as_deref() != Some(release.manifest_sha256.as_str())
        || state.accepted_version.as_deref() != Some(release.version.as_str())
        || state.accepted_binary_sha256.as_deref() != Some(release.artifact_sha256.as_str())
    {
        bail!("setup plan release is no longer the exact accepted stable release");
    }
    Ok(())
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
    verify_artifact_bytes(&verified, &artifact.bytes)?;
    preflight_accepted_state(storage, &verified)?;
    let cached = cache_verified_release(
        &storage.cache_root,
        &authority,
        &metadata,
        &artifact.bytes,
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
        accepted_manifest_schemas: vec!["dev-auth-product-v2".into()],
        target: crate::release_manifest::target_id()?,
        artifact_url: ArtifactUrlPolicy::GitHubRelease {
            owner: "FutureDevGuys".into(),
            repository: "dev-tools".into(),
        },
        require_source_commit: true,
        engine_protocol: 1,
    })
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
    let state = load_release_state_at(&storage.state_path, storage.owner_uid)?;
    let version = state
        .accepted_version
        .as_deref()
        .context("offline release resolution has no previously accepted version")?;
    let version = Version::parse(version).context("parse accepted offline release version")?;
    let cached = load_cached_release(
        &storage.cache_root,
        &release_authority()?,
        &version,
        storage.owner_uid,
    )?;
    require_cached_state_match(&state, &cached.verified)?;
    cached_release_result(cached)
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
}
