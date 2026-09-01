use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use ureq::ResponseExt;

const METADATA_LIMIT: usize = 512 * 1024;
const ARTIFACT_LIMIT: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseBundle {
    pub root: Vec<u8>,
    pub manifest: Vec<u8>,
    pub artifact: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseMetadata {
    pub root: Vec<u8>,
    pub manifest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAuthority {
    pub trusted_root_key: String,
    pub product: String,
    pub accepted_manifest_schemas: Vec<String>,
    pub target: String,
    pub artifact_url: ArtifactUrlPolicy,
    pub require_source_commit: bool,
    pub engine_protocol: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactUrlPolicy {
    Exact(String),
    GitHubRelease { owner: String, repository: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub root_generation: u64,
    pub root_sha256: String,
    pub manifest_generation: u64,
    pub manifest_sha256: String,
    pub manifest_schema: String,
    pub product: String,
    pub version: Version,
    pub source_commit: Option<String>,
    pub target: String,
    pub artifact_url: String,
    pub artifact_length: u64,
    pub artifact_sha256: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseState {
    pub accepted_root_generation: u64,
    pub accepted_root_sha256: Option<String>,
    pub accepted_generation: u64,
    pub accepted_manifest_sha256: Option<String>,
    pub accepted_version: Option<String>,
    pub accepted_binary_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedReleaseAssets {
    pub version: Version,
    pub root_url: String,
    pub manifest_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsPolicy {
    pub allowed_hosts: BTreeSet<String>,
    pub max_redirects: u32,
    pub timeout: Duration,
    pub user_agent: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsResponse {
    pub bytes: Vec<u8>,
    pub etag: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseCandidate {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedEnvelope<T> {
    signed: T,
    signatures: Vec<DocumentSignature>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DocumentSignature {
    key_id: String,
    signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootDocument {
    schema: String,
    generation: u64,
    release_keys: Vec<ReleaseKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseKey {
    key_id: String,
    public_key: String,
    #[serde(default)]
    revoked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductManifest {
    schema: String,
    product: String,
    generation: u64,
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source_commit: Option<String>,
    engine_protocol: u32,
    artifacts: BTreeMap<String, ArtifactIdentity>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    url: String,
    length: u64,
    sha256: String,
}

pub fn verify_release_bytes(
    bundle: &ReleaseBundle,
    authority: &ReleaseAuthority,
) -> Result<VerifiedRelease> {
    let verified = verify_release_metadata(
        &ReleaseMetadata {
            root: bundle.root.clone(),
            manifest: bundle.manifest.clone(),
        },
        authority,
    )?;
    verify_artifact_bytes(&verified, &bundle.artifact)?;
    Ok(verified)
}

pub fn verify_release_metadata(
    metadata: &ReleaseMetadata,
    authority: &ReleaseAuthority,
) -> Result<VerifiedRelease> {
    validate_authority(authority)?;
    require_bounded(&metadata.root, METADATA_LIMIT, "root document")?;
    require_bounded(&metadata.manifest, METADATA_LIMIT, "release manifest")?;

    let root: SignedEnvelope<RootDocument> =
        serde_json::from_slice(&metadata.root).context("parse trusted root document")?;
    if root.signed.schema != "dev-tools-root-v1" || root.signed.generation == 0 {
        bail!("release root document has an unsupported contract");
    }
    verify_any_signature(&root, &parse_public_key(&authority.trusted_root_key)?)
        .context("verify release root document")?;

    let manifest: SignedEnvelope<ProductManifest> =
        serde_json::from_slice(&metadata.manifest).context("parse product release manifest")?;
    verify_release_signature(&manifest, &root.signed)?;
    validate_manifest(&manifest.signed, authority)?;
    let artifact = manifest
        .signed
        .artifacts
        .get(&authority.target)
        .context("release manifest has no artifact for the selected target")?;
    Ok(VerifiedRelease {
        root_generation: root.signed.generation,
        root_sha256: sha256_hex(&metadata.root),
        manifest_generation: manifest.signed.generation,
        manifest_sha256: sha256_hex(&metadata.manifest),
        manifest_schema: manifest.signed.schema,
        product: manifest.signed.product,
        version: Version::parse(&manifest.signed.version).context("parse product version")?,
        source_commit: manifest.signed.source_commit,
        target: authority.target.clone(),
        artifact_url: artifact.url.clone(),
        artifact_length: artifact.length,
        artifact_sha256: artifact.sha256.clone(),
    })
}

pub fn verify_artifact_bytes(verified: &VerifiedRelease, artifact: &[u8]) -> Result<()> {
    require_bounded(artifact, ARTIFACT_LIMIT, "release artifact")?;
    if verified.artifact_length != artifact.len() as u64
        || verified.artifact_sha256 != sha256_hex(artifact)
    {
        bail!("release artifact does not match the signed manifest");
    }
    Ok(())
}

pub fn select_stable_release_assets(
    releases_json: &[u8],
    product: &str,
    root_asset_name: &str,
    manifest_asset_name: &str,
) -> Result<SelectedReleaseAssets> {
    require_bounded(releases_json, METADATA_LIMIT, "release index")?;
    if product.is_empty() || root_asset_name.is_empty() || manifest_asset_name.is_empty() {
        bail!("stable release selection is incomplete");
    }
    let releases: Vec<ReleaseCandidate> =
        serde_json::from_slice(releases_json).context("parse stable release index")?;
    let prefix = format!("{product}/v");
    let (version, release) = releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let version = Version::parse(release.tag_name.strip_prefix(&prefix)?).ok()?;
            version.pre.is_empty().then_some((version, release))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .with_context(|| format!("no stable {product} release is published"))?;
    let find_asset = |name: &str| -> Result<String> {
        let matches = release
            .assets
            .iter()
            .filter(|asset| asset.name == name)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!(
                "release {} does not contain exactly one required asset {name}",
                release.tag_name
            );
        }
        let url = &matches[0].browser_download_url;
        if !url.starts_with("https://") {
            bail!("stable release asset URL must use HTTPS");
        }
        Ok(url.clone())
    };
    Ok(SelectedReleaseAssets {
        version,
        root_url: find_asset(root_asset_name)?,
        manifest_url: find_asset(manifest_asset_name)?,
    })
}

pub fn fetch_https(
    url: &str,
    policy: &HttpsPolicy,
    limit: u64,
    etag: Option<&str>,
) -> Result<HttpsResponse> {
    validate_https_request(url, policy, limit)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(policy.max_redirects)
        .max_redirects_will_error(true)
        .save_redirect_history(true)
        .timeout_global(Some(policy.timeout))
        .user_agent(policy.user_agent.clone())
        .build()
        .into();
    let mut request = agent.get(url).header(
        "Accept",
        if url.starts_with("https://api.github.com/") {
            "application/vnd.github+json"
        } else {
            "application/octet-stream"
        },
    );
    if let Some(etag) = etag {
        if etag.is_empty() || etag.contains(['\r', '\n', '\0']) {
            bail!("release ETag is invalid");
        }
        request = request.header("If-None-Match", etag);
    }
    let mut response = request.call().with_context(|| format!("GET {url}"))?;
    if response.status().as_u16() == 304 {
        bail!("release response was not modified");
    }
    if !response.status().is_success() {
        bail!("GET {url} returned HTTP {}", response.status());
    }
    if let Some(history) = response.get_redirect_history() {
        for uri in history {
            if uri.scheme_str() != Some("https")
                || !policy
                    .allowed_hosts
                    .contains(uri.host().unwrap_or_default())
            {
                bail!("release request traversed an untrusted redirect");
            }
        }
    }
    let final_uri = response.get_uri();
    if final_uri.scheme_str() != Some("https")
        || !policy
            .allowed_hosts
            .contains(final_uri.host().unwrap_or_default())
    {
        bail!("release request resolved to an untrusted origin");
    }
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .with_context(|| format!("read bounded response from {url}"))?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        bail!("release response is empty or exceeds its size bound");
    }
    Ok(HttpsResponse { bytes, etag })
}

fn validate_https_request(url: &str, policy: &HttpsPolicy, limit: u64) -> Result<()> {
    if limit == 0 || limit as usize > ARTIFACT_LIMIT {
        bail!("release response size bound is invalid");
    }
    if policy.allowed_hosts.is_empty()
        || policy.max_redirects > 5
        || policy.timeout.is_zero()
        || policy.timeout > Duration::from_secs(120)
        || policy.user_agent.is_empty()
        || policy.user_agent.len() > 256
        || policy.user_agent.contains(['\r', '\n', '\0'])
    {
        bail!("release HTTPS policy is invalid");
    }
    let parsed: ureq::http::Uri = url.parse().context("parse release URL")?;
    if parsed.scheme_str() != Some("https")
        || !policy
            .allowed_hosts
            .contains(parsed.host().unwrap_or_default())
    {
        bail!("release URL is outside the allowed HTTPS origins");
    }
    Ok(())
}

pub fn accept_verified_release(
    state: &mut ReleaseState,
    verified: &VerifiedRelease,
) -> Result<bool> {
    if verified.root_generation < state.accepted_root_generation {
        bail!("release root generation rollback detected");
    }
    if verified.root_generation == state.accepted_root_generation
        && state.accepted_root_generation != 0
        && state
            .accepted_root_sha256
            .as_ref()
            .is_some_and(|accepted| accepted != &verified.root_sha256)
    {
        bail!("release root equivocation detected");
    }
    if verified.manifest_generation < state.accepted_generation {
        bail!("release manifest generation rollback detected");
    }
    if verified.manifest_generation == state.accepted_generation
        && state.accepted_generation != 0
        && state
            .accepted_manifest_sha256
            .as_ref()
            .is_some_and(|accepted| accepted != &verified.manifest_sha256)
    {
        bail!("release manifest equivocation detected");
    }
    if state
        .accepted_version
        .as_ref()
        .map(|accepted| Version::parse(accepted).context("parse accepted release version"))
        .transpose()?
        .is_some_and(|accepted| verified.version < accepted)
    {
        bail!("release version rollback detected");
    }
    let verified_version = verified.version.to_string();
    let changed = state.accepted_root_generation != verified.root_generation
        || state.accepted_root_sha256.as_ref() != Some(&verified.root_sha256)
        || state.accepted_generation != verified.manifest_generation
        || state.accepted_manifest_sha256.as_ref() != Some(&verified.manifest_sha256)
        || state.accepted_version.as_deref() != Some(verified_version.as_str())
        || state.accepted_binary_sha256.as_ref() != Some(&verified.artifact_sha256);
    state.accepted_root_generation = verified.root_generation;
    state.accepted_root_sha256 = Some(verified.root_sha256.clone());
    state.accepted_generation = verified.manifest_generation;
    state.accepted_manifest_sha256 = Some(verified.manifest_sha256.clone());
    state.accepted_version = Some(verified_version);
    state.accepted_binary_sha256 = Some(verified.artifact_sha256.clone());
    Ok(changed)
}

fn validate_authority(authority: &ReleaseAuthority) -> Result<()> {
    if authority.product.is_empty()
        || authority.target.is_empty()
        || authority.engine_protocol == 0
        || authority.accepted_manifest_schemas.is_empty()
    {
        bail!("release authority is incomplete");
    }
    let schemas = authority
        .accepted_manifest_schemas
        .iter()
        .collect::<BTreeSet<_>>();
    if schemas.len() != authority.accepted_manifest_schemas.len()
        || authority
            .accepted_manifest_schemas
            .iter()
            .any(|schema| schema.is_empty())
    {
        bail!("release authority manifest schemas are invalid");
    }
    match &authority.artifact_url {
        ArtifactUrlPolicy::Exact(url) if !url.starts_with("https://") => {
            bail!("expected release artifact URL must use HTTPS")
        }
        ArtifactUrlPolicy::Exact(_) => {}
        ArtifactUrlPolicy::GitHubRelease { owner, repository }
            if !valid_github_component(owner) || !valid_github_component(repository) =>
        {
            bail!("GitHub release authority is invalid")
        }
        ArtifactUrlPolicy::GitHubRelease { .. } => {}
    }
    parse_public_key(&authority.trusted_root_key)?;
    Ok(())
}

fn validate_manifest(manifest: &ProductManifest, authority: &ReleaseAuthority) -> Result<()> {
    if !authority
        .accepted_manifest_schemas
        .iter()
        .any(|schema| schema == &manifest.schema)
        || manifest.product != authority.product
        || manifest.generation == 0
        || manifest.engine_protocol != authority.engine_protocol
        || manifest.artifacts.len() != 1
    {
        bail!("release manifest has an unsupported contract");
    }
    Version::parse(&manifest.version).context("parse product manifest version")?;
    match &manifest.source_commit {
        Some(commit) if valid_hex(commit, 40) => {}
        Some(_) => bail!("release manifest source commit is invalid"),
        None if authority.require_source_commit => {
            bail!("release manifest does not bind a source commit")
        }
        None => {}
    }
    let artifact = manifest
        .artifacts
        .get(&authority.target)
        .context("release manifest has no artifact for the selected target")?;
    let expected_url = match &authority.artifact_url {
        ArtifactUrlPolicy::Exact(url) => url.clone(),
        ArtifactUrlPolicy::GitHubRelease { owner, repository } => format!(
            "https://github.com/{owner}/{repository}/releases/download/{}%2Fv{}/{}-{}-{}",
            manifest.product,
            manifest.version,
            manifest.product,
            manifest.version,
            authority.target
        ),
    };
    if artifact.url != expected_url
        || artifact.length == 0
        || artifact.length as usize > ARTIFACT_LIMIT
        || !valid_hex(&artifact.sha256, 64)
    {
        bail!("release manifest artifact identity is invalid");
    }
    Ok(())
}

fn verify_release_signature(
    manifest: &SignedEnvelope<ProductManifest>,
    root: &RootDocument,
) -> Result<()> {
    let canonical = serde_jcs::to_vec(&manifest.signed).context("canonicalize release manifest")?;
    for signature in &manifest.signatures {
        let Some(key) = root
            .release_keys
            .iter()
            .find(|key| key.key_id == signature.key_id && !key.revoked)
        else {
            continue;
        };
        if verify_signature(
            &parse_public_key(&key.public_key)?,
            &canonical,
            &signature.signature,
        )
        .is_ok()
        {
            return Ok(());
        }
    }
    bail!("release manifest has no valid authorized signature")
}

fn verify_any_signature<T: Serialize>(
    envelope: &SignedEnvelope<T>,
    key: &VerifyingKey,
) -> Result<()> {
    let canonical = serde_jcs::to_vec(&envelope.signed).context("canonicalize signed document")?;
    if envelope
        .signatures
        .iter()
        .any(|candidate| verify_signature(key, &canonical, &candidate.signature).is_ok())
    {
        return Ok(());
    }
    bail!("signed document has no valid trusted signature")
}

fn verify_signature(key: &VerifyingKey, message: &[u8], encoded: &str) -> Result<()> {
    let bytes = BASE64.decode(encoded).context("decode Ed25519 signature")?;
    let signature = Signature::try_from(bytes.as_slice()).context("parse Ed25519 signature")?;
    key.verify_strict(message, &signature)
        .context("verify Ed25519 signature")
}

fn parse_public_key(encoded: &str) -> Result<VerifyingKey> {
    if !valid_hex(encoded, 64) {
        bail!("release public key is invalid");
    }
    let bytes = (0..encoded.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("release public key length is invalid"))?;
    VerifyingKey::from_bytes(&bytes).context("parse release public key")
}

fn require_bounded(bytes: &[u8], limit: usize, label: &str) -> Result<()> {
    if bytes.is_empty() || bytes.len() > limit {
        bail!("{label} exceeds its public size contract");
    }
    Ok(())
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_github_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
