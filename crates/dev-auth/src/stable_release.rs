use crate::release_manifest::VerifiedDevAuthRelease;
use anyhow::{anyhow, bail, Context, Result};
use dev_tools_installation::{
    read_atomic_document, write_atomic_document, DocumentAuthority, InstallationLock,
};
use dev_tools_release::{
    accept_verified_release, accept_verified_release_at, cache_verified_release, fetch_https,
    load_cached_release, load_release_state_at, observe_cached_release,
    select_stable_release_assets, verify_artifact_bytes, verify_release_metadata,
    ArtifactUrlPolicy, CachedRelease, HttpsPolicy, ReleaseAuthority, ReleaseMetadata, ReleaseState,
    VerifiedRelease,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RELEASES_URL: &str =
    "https://api.github.com/repos/FutureDevGuys/dev-tools/releases?per_page=100";
const METADATA_LIMIT: u64 = 512 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const TRUSTED_ROOT: &str = include_str!("../trust/root-public-key.txt");
const OBSERVATION_SCHEMA: &str = "dev-auth-stable-release-observation-v1";
// serde_json encodes Vec<u8> as bounded decimal arrays (at most four bytes
// per input byte, including separators), not as base64 strings.
const OBSERVATION_LIMIT: u64 = 8 * METADATA_LIMIT + 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseObservationFailureKind {
    Network,
    Authenticity,
    Authority,
    Operational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseObservationFailure {
    kind: ReleaseObservationFailureKind,
}

impl ReleaseObservationFailure {
    pub fn kind(self) -> ReleaseObservationFailureKind {
        self.kind
    }

    fn new(kind: ReleaseObservationFailureKind) -> Self {
        Self { kind }
    }
}

impl fmt::Display for ReleaseObservationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ReleaseObservationFailureKind::Network => "stable release network request failed",
            ReleaseObservationFailureKind::Authenticity => "stable release signature is invalid",
            ReleaseObservationFailureKind::Authority => "stable release authority is invalid",
            ReleaseObservationFailureKind::Operational => "stable release observation failed",
        })
    }
}

impl std::error::Error for ReleaseObservationFailure {}

#[derive(Debug)]
struct ReleaseNetworkFailure;

impl fmt::Display for ReleaseNetworkFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("stable release transport failed")
    }
}

impl std::error::Error for ReleaseNetworkFailure {}

#[derive(Debug)]
struct ReleaseAuthenticityFailure;

impl fmt::Display for ReleaseAuthenticityFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("stable release authentication failed")
    }
}

impl std::error::Error for ReleaseAuthenticityFailure {}

/// Signed metadata is observed independently of the artifact and of the
/// accepted installation generation. The timestamp is freshness evidence only;
/// it is never release or installation authority.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableReleaseObservation {
    schema: String,
    checked_at_unix: u64,
    metadata: ReleaseMetadataDocument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseMetadataDocument {
    root: Vec<u8>,
    manifest: Vec<u8>,
}

impl StableReleaseObservation {
    pub fn checked_at_unix(&self) -> u64 {
        self.checked_at_unix
    }

    pub fn verified(&self) -> Result<VerifiedRelease> {
        self.verified_with_authority(&release_authority()?)
    }

    fn verified_with_authority(&self, authority: &ReleaseAuthority) -> Result<VerifiedRelease> {
        if self.schema != OBSERVATION_SCHEMA || self.checked_at_unix == 0 {
            bail!("stable release observation is invalid");
        }
        let metadata = self.metadata();
        let verified = verify_release_metadata(&metadata, authority)?;
        require_new_release_schema(&verified)?;
        if !verified.version.pre.is_empty() {
            bail!("stable release observation is not a stable version");
        }
        Ok(verified)
    }

    fn metadata(&self) -> ReleaseMetadata {
        ReleaseMetadata {
            root: self.metadata.root.clone(),
            manifest: self.metadata.manifest.clone(),
        }
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableReleaseObservationStorage {
    pub path: PathBuf,
    pub owner_uid: u32,
}

/// Per-account, disposable release metadata for ordinary status and check.
/// It is deliberately separate from the root-owned accepted-release ledger.
pub fn native_user_observation_storage() -> Result<StableReleaseObservationStorage> {
    let project = directories::ProjectDirs::from("", "", "dev-auth")
        .context("the native account has no cache directory")?;
    let path = project
        .cache_dir()
        .join("stable-release-observation-v1.json");
    if !path.is_absolute() {
        bail!("native release observation cache is not absolute");
    }
    Ok(StableReleaseObservationStorage {
        path,
        owner_uid: nix::unistd::Uid::effective().as_raw(),
    })
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

/// Explicit metadata-only network boundary. No artifact bytes are requested,
/// accepted as executable, or published by this operation.
pub fn check_latest_stable_release(
    storage: &StableReleaseStorage,
) -> Result<StableReleaseObservation> {
    validate_storage(storage)?;
    let observation = fetch_latest_stable_observation()?;
    preflight_accepted_state(storage, &observation.verified()?)?;
    save_release_observation(storage, &observation)?;
    Ok(observation)
}

pub fn check_user_stable_release_classified(
    storage: &StableReleaseObservationStorage,
) -> std::result::Result<StableReleaseObservation, ReleaseObservationFailure> {
    validate_observation_storage(storage)
        .map_err(|_| ReleaseObservationFailure::new(ReleaseObservationFailureKind::Authority))?;
    let observation =
        fetch_latest_stable_observation().map_err(classify_observation_fetch_failure)?;
    observation
        .verified()
        .map_err(|_| ReleaseObservationFailure::new(ReleaseObservationFailureKind::Authenticity))?;
    save_release_observation_at(
        &storage.path,
        storage.owner_uid,
        &observation,
        &release_authority().map_err(|_| {
            ReleaseObservationFailure::new(ReleaseObservationFailureKind::Operational)
        })?,
    )
    .map_err(classify_observation_storage_failure)?;
    Ok(observation)
}

fn classify_observation_fetch_failure(error: anyhow::Error) -> ReleaseObservationFailure {
    ReleaseObservationFailure::new(if error.is::<ReleaseNetworkFailure>() {
        ReleaseObservationFailureKind::Network
    } else if error.is::<ReleaseAuthenticityFailure>() {
        ReleaseObservationFailureKind::Authenticity
    } else {
        ReleaseObservationFailureKind::Authority
    })
}

fn classify_observation_storage_failure(error: anyhow::Error) -> ReleaseObservationFailure {
    let kind = if error.chain().any(|cause| cause.is::<std::io::Error>()) {
        ReleaseObservationFailureKind::Operational
    } else {
        ReleaseObservationFailureKind::Authority
    };
    ReleaseObservationFailure::new(kind)
}

fn fetch_latest_stable_observation() -> Result<StableReleaseObservation> {
    let checked_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("read stable release observation time")?
        .as_secs();
    if checked_at_unix == 0 {
        bail!("stable release observation time is invalid");
    }
    let policy = release_https_policy();
    let releases = fetch_https(RELEASES_URL, &policy, METADATA_LIMIT, None)
        .map_err(|_| anyhow!(ReleaseNetworkFailure))?;
    let selected = select_stable_release_with_detail_fallback(&releases.bytes, |id| {
        let url = format!("https://api.github.com/repos/FutureDevGuys/dev-tools/releases/{id}");
        Ok(fetch_https(&url, &policy, METADATA_LIMIT, None)
            .map_err(|_| anyhow!(ReleaseNetworkFailure))?
            .bytes)
    })?;
    let observation = StableReleaseObservation {
        schema: OBSERVATION_SCHEMA.into(),
        checked_at_unix,
        metadata: ReleaseMetadataDocument {
            root: fetch_https(&selected.root_url, &policy, METADATA_LIMIT, None)
                .map_err(|_| anyhow!(ReleaseNetworkFailure))?
                .bytes,
            manifest: fetch_https(&selected.manifest_url, &policy, METADATA_LIMIT, None)
                .map_err(|_| anyhow!(ReleaseNetworkFailure))?
                .bytes,
        },
    };
    let verified = observation
        .verified()
        .map_err(|_| anyhow!(ReleaseAuthenticityFailure))?;
    if verified.version != selected.version {
        return Err(anyhow!(ReleaseAuthenticityFailure));
    }
    Ok(observation)
}

#[derive(Deserialize)]
struct GithubReleaseIdentity {
    id: u64,
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

fn latest_stable_release_identity(bytes: &[u8]) -> Result<(u64, String, Version)> {
    let releases: Vec<GithubReleaseIdentity> =
        serde_json::from_slice(bytes).context("decode stable release index identity")?;
    releases
        .into_iter()
        .filter(|release| !release.draft && !release.prerelease && release.id > 0)
        .filter_map(|release| {
            let version = Version::parse(release.tag_name.strip_prefix("dev-auth/v")?).ok()?;
            version
                .pre
                .is_empty()
                .then_some((release.id, release.tag_name, version))
        })
        .max_by(|left, right| left.2.cmp(&right.2))
        .context("no stable Dev Auth release identity is published")
}

fn select_stable_release_with_detail_fallback(
    releases: &[u8],
    mut fetch_detail: impl FnMut(u64) -> Result<Vec<u8>>,
) -> Result<dev_tools_release::SelectedReleaseAssets> {
    let (id, tag, version) = latest_stable_release_identity(releases)?;
    let select = |bytes: &[u8]| {
        select_stable_release_assets(
            bytes,
            "dev-auth",
            "dev-tools-root.json",
            "dev-auth-stable.json",
        )
    };
    if let Ok(selected) = select(releases) {
        if selected.version == version {
            return Ok(selected);
        }
        bail!("release index selected a different stable version");
    }
    let detail_bytes = fetch_detail(id)?;
    let detail: GithubReleaseIdentity =
        serde_json::from_slice(&detail_bytes).context("decode stable release detail identity")?;
    if detail.id != id || detail.tag_name != tag || detail.draft || detail.prerelease {
        bail!("stable release detail does not match the selected release identity");
    }
    let detail_value: serde_json::Value =
        serde_json::from_slice(&detail_bytes).context("decode stable release detail")?;
    let singleton = serde_json::to_vec(&vec![detail_value])?;
    let selected = select(&singleton)?;
    if selected.version != version {
        bail!("stable release detail selected a different version");
    }
    Ok(selected)
}

/// A local status read must authenticate the cached bytes again. An absent
/// observation is unknown, not an implicit network check or currentness claim.
pub fn load_release_observation(
    storage: &StableReleaseStorage,
) -> Result<Option<StableReleaseObservation>> {
    load_release_observation_with_authority(storage, &release_authority()?)
}

pub fn load_user_release_observation_classified(
    storage: &StableReleaseObservationStorage,
) -> std::result::Result<Option<StableReleaseObservation>, ReleaseObservationFailure> {
    validate_observation_storage(storage)
        .map_err(|_| ReleaseObservationFailure::new(ReleaseObservationFailureKind::Authority))?;
    let observation = read_unverified_observation_at(&storage.path, storage.owner_uid)
        .map_err(classify_observation_storage_failure)?;
    if let Some(observation) = &observation {
        observation.verified().map_err(|_| {
            ReleaseObservationFailure::new(ReleaseObservationFailureKind::Authenticity)
        })?;
    }
    Ok(observation)
}

fn load_release_observation_with_authority(
    storage: &StableReleaseStorage,
    authority: &ReleaseAuthority,
) -> Result<Option<StableReleaseObservation>> {
    validate_storage(storage)?;
    let observation = load_release_observation_at(
        &storage.cache_root.join("observation-v1.json"),
        storage.owner_uid,
        authority,
    )?;
    if let Some(observation) = &observation {
        preflight_accepted_state(storage, &observation.verified_with_authority(authority)?)?;
    }
    Ok(observation)
}

fn load_release_observation_at(
    path: &Path,
    owner_uid: u32,
    authority: &ReleaseAuthority,
) -> Result<Option<StableReleaseObservation>> {
    let observation = read_unverified_observation_at(path, owner_uid)?;
    if let Some(observation) = &observation {
        observation.verified_with_authority(authority)?;
    }
    Ok(observation)
}

fn read_unverified_observation_at(
    path: &Path,
    owner_uid: u32,
) -> Result<Option<StableReleaseObservation>> {
    let Some(document) = read_atomic_document(path, &observation_authority(owner_uid))? else {
        return Ok(None);
    };
    let observation: StableReleaseObservation =
        serde_json::from_slice(&document.bytes).context("decode stable release observation")?;
    Ok(Some(observation))
}

/// Fetches payload bytes only for the exact signed observation selected by
/// update planning. A later metadata check cannot substitute another version
/// or reset the observation's original freshness time.
pub fn prepare_observed_release(
    storage: &StableReleaseStorage,
    observation: &StableReleaseObservation,
) -> Result<StagedStableRelease> {
    validate_storage(storage)?;
    let verified = observation.verified()?;
    if verified.artifact_length == 0 || verified.artifact_length > ARTIFACT_LIMIT {
        bail!("signed stable release artifact length is invalid");
    }
    let metadata = observation.metadata();
    let artifact = fetch_https(
        &verified.artifact_url,
        &release_https_policy(),
        verified.artifact_length,
        None,
    )?;
    let staged =
        stage_verified_release_bundle(storage, &release_authority()?, &metadata, &artifact.bytes)?;
    if staged.verified.version != verified.version.to_string()
        || staged.verified.artifact_sha256 != verified.artifact_sha256
        || staged.verified.manifest_sha256 != verified.manifest_sha256
        || staged.verified.root_sha256 != verified.root_sha256
    {
        bail!("prepared release differs from the checked stable release");
    }
    Ok(staged)
}

/// Check disposable artifact availability without creating a cache entry or
/// accepting a release. Setup mutation rechecks the accepted ledger and exact
/// artifact custody independently before installation.
pub fn observe_prepared_release(
    storage: &StableReleaseStorage,
    observation: &StableReleaseObservation,
) -> Result<Option<StagedStableRelease>> {
    observe_prepared_release_with_authority(storage, observation, &release_authority()?)
}

fn observe_prepared_release_with_authority(
    storage: &StableReleaseStorage,
    observation: &StableReleaseObservation,
    authority: &ReleaseAuthority,
) -> Result<Option<StagedStableRelease>> {
    validate_storage(storage)?;
    let verified = observation.verified_with_authority(authority)?;
    let cached = observe_cached_release(
        &storage.cache_root,
        authority,
        &verified.version,
        storage.owner_uid,
    )?;
    cached
        .map(|cached| {
            if cached.verified != verified {
                bail!("cached artifact differs from the observed stable release");
            }
            cached_release_result(cached)
        })
        .transpose()
}

fn save_release_observation(
    storage: &StableReleaseStorage,
    observation: &StableReleaseObservation,
) -> Result<()> {
    save_release_observation_with_authority(storage, observation, &release_authority()?)
}

fn save_release_observation_with_authority(
    storage: &StableReleaseStorage,
    observation: &StableReleaseObservation,
    release_authority: &ReleaseAuthority,
) -> Result<()> {
    validate_storage(storage)?;
    save_release_observation_at(
        &storage.cache_root.join("observation-v1.json"),
        storage.owner_uid,
        observation,
        release_authority,
    )
}

fn save_release_observation_at(
    path: &Path,
    owner_uid: u32,
    observation: &StableReleaseObservation,
    release_authority: &ReleaseAuthority,
) -> Result<()> {
    observation.verified_with_authority(release_authority)?;
    let _lock = InstallationLock::acquire(&path.with_extension("lock"))?;
    let authority = observation_authority(owner_uid);
    let current = read_atomic_document(path, &authority)?;
    if let Some(current) = &current {
        let prior: StableReleaseObservation = serde_json::from_slice(&current.bytes)
            .context("decode current stable release observation")?;
        prior.verified_with_authority(release_authority)?;
        if prior.checked_at_unix > observation.checked_at_unix {
            return Ok(());
        }
        if prior.checked_at_unix == observation.checked_at_unix
            && (prior.metadata.root != observation.metadata.root
                || prior.metadata.manifest != observation.metadata.manifest)
        {
            bail!("stable release observations conflict at one check time");
        }
    }
    let bytes = serde_jcs::to_vec(observation).context("encode stable release observation")?;
    write_atomic_document(
        path,
        &bytes,
        &authority,
        current.as_ref().map(|document| &document.identity),
    )?;
    Ok(())
}

fn observation_authority(owner_uid: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid,
        mode: 0o600,
        limit: OBSERVATION_LIMIT,
    }
}

fn validate_observation_storage(storage: &StableReleaseObservationStorage) -> Result<()> {
    if !storage.path.is_absolute()
        || storage.path == Path::new("/")
        || storage.path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        bail!("stable release observation storage is invalid");
    }
    Ok(())
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
    let observation = check_latest_stable_release(storage)?;
    prepare_observed_release(storage, &observation)
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
    fn metadata_observation_is_local_authenticated_and_payload_free() {
        let root = tempfile::tempdir().unwrap();
        let storage = StableReleaseStorage {
            state_path: root.path().join("accepted.json"),
            cache_root: root.path().join("cache"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        };
        let (authority, metadata, _) = release_fixture();
        assert!(
            load_release_observation_with_authority(&storage, &authority)
                .unwrap()
                .is_none()
        );
        assert!(
            !storage.cache_root.exists(),
            "status must not create cache state"
        );
        let observation = StableReleaseObservation {
            schema: OBSERVATION_SCHEMA.into(),
            checked_at_unix: 100,
            metadata: ReleaseMetadataDocument {
                root: metadata.root,
                manifest: metadata.manifest,
            },
        };
        assert_eq!(
            observation
                .verified_with_authority(&authority)
                .unwrap()
                .version,
            Version::parse("0.3.11").unwrap()
        );
        save_release_observation_with_authority(&storage, &observation, &authority).unwrap();
        let loaded = load_release_observation_with_authority(&storage, &authority)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.checked_at_unix(), 100);
        assert_eq!(loaded.metadata().manifest, observation.metadata().manifest);
        assert!(!storage.cache_root.join("artifact").exists());
        assert!(!storage.cache_root.join("release-cache.lock").exists());

        let mut older = observation.clone();
        older.checked_at_unix = 99;
        save_release_observation_with_authority(&storage, &older, &authority).unwrap();
        assert_eq!(
            load_release_observation_with_authority(&storage, &authority)
                .unwrap()
                .unwrap()
                .checked_at_unix(),
            100
        );

        let path = storage.cache_root.join("observation-v1.json");
        let mut tampered: StableReleaseObservation =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        tampered.metadata.manifest[0] ^= 1;
        std::fs::write(&path, serde_jcs::to_vec(&tampered).unwrap()).unwrap();
        assert!(load_release_observation_with_authority(&storage, &authority).is_err());
    }

    #[test]
    fn release_id_fallback_is_bound_to_the_latest_stable_identity() {
        let list = serde_json::to_vec(&serde_json::json!([
            {"id": 14, "tag_name": "dev-auth/v0.4.0", "draft": false, "prerelease": false, "assets": []},
            {"id": 13, "tag_name": "dev-auth/v0.3.11", "draft": false, "prerelease": false, "assets": []},
            {"id": 15, "tag_name": "dev-auth/v0.5.0-rc.1", "draft": false, "prerelease": true, "assets": []}
        ]))
        .unwrap();
        let detail = serde_json::to_vec(&serde_json::json!({
            "id": 14,
            "tag_name": "dev-auth/v0.4.0",
            "draft": false,
            "prerelease": false,
            "assets": [
                {"name": "dev-tools-root.json", "browser_download_url": "https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv0.4.0/dev-tools-root.json"},
                {"name": "dev-auth-stable.json", "browser_download_url": "https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv0.4.0/dev-auth-stable.json"}
            ]
        }))
        .unwrap();
        let selected = select_stable_release_with_detail_fallback(&list, |id| {
            assert_eq!(id, 14);
            Ok(detail.clone())
        })
        .unwrap();
        assert_eq!(selected.version, Version::parse("0.4.0").unwrap());
        let direct_list = serde_json::to_vec(&serde_json::json!([serde_json::from_slice::<
            serde_json::Value,
        >(&detail)
        .unwrap()]))
        .unwrap();
        assert!(
            select_stable_release_with_detail_fallback(&direct_list, |_| {
                panic!("complete list assets must not fetch a release detail")
            })
            .is_ok()
        );
        let mut wrong: serde_json::Value = serde_json::from_slice(&detail).unwrap();
        wrong["id"] = serde_json::json!(999);
        assert!(select_stable_release_with_detail_fallback(&list, |_| {
            Ok(serde_json::to_vec(&wrong).unwrap())
        })
        .is_err());
        wrong["id"] = serde_json::json!(14);
        wrong["tag_name"] = serde_json::json!("dev-auth/v0.3.11");
        assert!(select_stable_release_with_detail_fallback(&list, |_| {
            Ok(serde_json::to_vec(&wrong).unwrap())
        })
        .is_err());
    }

    #[test]
    fn observation_failure_categories_are_fixed_and_value_free() {
        assert_eq!(
            classify_observation_fetch_failure(anyhow!(ReleaseNetworkFailure)).kind(),
            ReleaseObservationFailureKind::Network
        );
        assert_eq!(
            classify_observation_fetch_failure(anyhow!(ReleaseAuthenticityFailure)).kind(),
            ReleaseObservationFailureKind::Authenticity
        );
        assert_eq!(
            classify_observation_fetch_failure(anyhow!("malformed release index")).kind(),
            ReleaseObservationFailureKind::Authority
        );
        assert_eq!(
            classify_observation_storage_failure(
                std::io::Error::from(std::io::ErrorKind::ReadOnlyFilesystem,).into()
            )
            .kind(),
            ReleaseObservationFailureKind::Operational
        );
        assert_eq!(
            classify_observation_storage_failure(anyhow!("unsafe custody")).kind(),
            ReleaseObservationFailureKind::Authority
        );
    }

    #[test]
    fn user_observation_cache_is_independent_of_accepted_installation_ledger() {
        let root = tempfile::tempdir().unwrap();
        let storage = StableReleaseObservationStorage {
            path: root.path().join("account-cache/observation.json"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        };
        validate_observation_storage(&storage).unwrap();
        let (authority, metadata, _) = release_fixture();
        let observation = StableReleaseObservation {
            schema: OBSERVATION_SCHEMA.into(),
            checked_at_unix: 123,
            metadata: ReleaseMetadataDocument {
                root: metadata.root,
                manifest: metadata.manifest,
            },
        };
        assert!(
            read_unverified_observation_at(&storage.path, storage.owner_uid)
                .unwrap()
                .is_none()
        );
        assert!(!storage.path.parent().unwrap().exists());
        save_release_observation_at(&storage.path, storage.owner_uid, &observation, &authority)
            .unwrap();
        let loaded =
            load_release_observation_at(&storage.path, storage.owner_uid, &authority).unwrap();
        assert_eq!(loaded.unwrap().checked_at_unix(), 123);
        assert!(!root.path().join("accepted.json").exists());
        assert!(!root.path().join("release-cache.lock").exists());
    }

    #[test]
    fn offline_artifact_availability_requires_matching_signed_cached_bytes() {
        let root = tempfile::tempdir().unwrap();
        let storage = StableReleaseStorage {
            state_path: root.path().join("accepted.json"),
            cache_root: root.path().join("cache"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        };
        let (authority, metadata, artifact) = release_fixture();
        let observation = StableReleaseObservation {
            schema: OBSERVATION_SCHEMA.into(),
            checked_at_unix: 123,
            metadata: ReleaseMetadataDocument {
                root: metadata.root.clone(),
                manifest: metadata.manifest.clone(),
            },
        };
        assert!(
            observe_prepared_release_with_authority(&storage, &observation, &authority)
                .unwrap()
                .is_none()
        );
        assert!(!storage.cache_root.exists());
        let staged =
            stage_verified_release_bundle(&storage, &authority, &metadata, &artifact).unwrap();
        assert_eq!(
            observe_prepared_release_with_authority(&storage, &observation, &authority)
                .unwrap()
                .unwrap()
                .verified,
            staged.verified
        );
    }

    #[test]
    #[ignore = "explicit signed GitHub metadata observation; requires network access"]
    fn public_stable_observation_fetches_metadata_without_an_artifact() {
        let root = tempfile::tempdir().unwrap();
        let storage = StableReleaseObservationStorage {
            path: root.path().join("stable-release-observation-v1.json"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        };
        let observation = check_user_stable_release_classified(&storage).unwrap();
        assert_eq!(observation.verified().unwrap().product, "dev-auth");
        assert_eq!(
            load_user_release_observation_classified(&storage)
                .unwrap()
                .unwrap()
                .checked_at_unix(),
            observation.checked_at_unix()
        );
        let entries = std::fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 2, "only observation and its stable lock");
        assert!(!root.path().join("accepted.json").exists());
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
