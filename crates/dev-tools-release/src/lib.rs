use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use ureq::ResponseExt;

use dev_tools_installation::{
    read_atomic_document, write_atomic_document, DocumentAuthority, InstallationLock,
};

const METADATA_LIMIT: usize = 512 * 1024;
const ARTIFACT_LIMIT: usize = 256 * 1024 * 1024;
const MAX_MANIFEST_ARTIFACTS: usize = 16;
const CRATE_PACKAGE_LIMIT: usize = 10 * 1024 * 1024;
const MAX_CRATE_SET_PACKAGES: usize = 64;
const CRATES_IO_INDEX_LIMIT: u64 = 1024 * 1024;
const CRATES_IO_CONFIG_LIMIT: u64 = 64 * 1024;
pub const CRATE_SET_AUTHORITY: &str = "dev-tools-shared-crates";

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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRelease {
    pub verified: VerifiedRelease,
    pub root_path: PathBuf,
    pub manifest_path: PathBuf,
    pub artifact_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CachedReleaseReceipt {
    schema: String,
    verified: VerifiedRelease,
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
pub struct VerifiedRoot {
    pub generation: u64,
    pub sha256: String,
    pub active_release_keys: usize,
    pub revoked_release_keys: usize,
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
struct ReleaseCandidate {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Deserialize)]
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
struct CrateSetDocument {
    schema: String,
    authority: String,
    generation: u64,
    source_commit: String,
    registry: String,
    packages: BTreeMap<String, CratePackageIdentity>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CratePackageIdentity {
    version: String,
    length: u64,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedProductManifest {
    pub schema: String,
    pub product: String,
    pub generation: u64,
    pub version: Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedReleaseDocument {
    pub schema: String,
    pub authority: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CratePackageSpec {
    pub name: String,
    pub version: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateSetSpec {
    pub generation: u64,
    pub source_commit: String,
    pub registry: String,
    pub packages: Vec<CratePackageSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateSetMetadata {
    pub root: Vec<u8>,
    pub manifest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateSetAuthority {
    pub trusted_root_key: String,
    pub registry: String,
    pub source_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCratePackage {
    pub version: Version,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCrateSet {
    pub root_generation: u64,
    pub root_sha256: String,
    pub manifest_generation: u64,
    pub manifest_sha256: String,
    pub schema: String,
    pub authority: String,
    pub source_commit: String,
    pub registry: String,
    pub packages: BTreeMap<String, VerifiedCratePackage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRegistryCrate {
    pub name: String,
    pub version: Version,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryCrateStatus {
    Absent,
    Verified(VerifiedRegistryCrate),
}

#[derive(Debug, Deserialize)]
struct CratesIoConfig {
    dl: String,
    api: String,
    #[serde(default, rename = "auth-required")]
    auth_required: bool,
}

#[derive(Debug, Deserialize)]
struct CratesIoIndexEntry {
    name: String,
    vers: String,
    cksum: String,
    yanked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestArtifact {
    pub target: String,
    pub url: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductManifestSpec {
    pub product: String,
    pub generation: u64,
    pub version: String,
    pub source_commit: String,
    pub artifacts: Vec<ManifestArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootReleaseKey {
    pub public_key: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootDocumentSpec {
    pub generation: u64,
    pub release_keys: Vec<RootReleaseKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSignature {
    pub key_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    url: String,
    length: u64,
    sha256: String,
}

/// Constructs the sole source-bound product-manifest representation written by
/// native release tooling. The returned bytes are RFC 8785 canonical JSON and
/// are therefore the exact bytes presented to the release-signing authority.
pub fn build_unsigned_product_manifest(spec: &ProductManifestSpec) -> Result<Vec<u8>> {
    if !valid_product_id(&spec.product)
        || spec.generation == 0
        || !valid_lower_hex(&spec.source_commit, 40)
        || spec.artifacts.is_empty()
        || spec.artifacts.len() > MAX_MANIFEST_ARTIFACTS
    {
        bail!("product manifest specification is invalid");
    }
    let version = Version::parse(&spec.version).context("parse product manifest version")?;
    if !version.pre.is_empty() || version.to_string() != spec.version {
        bail!("product manifest version is not canonical stable semantic version");
    }
    let mut artifacts = BTreeMap::new();
    for artifact in &spec.artifacts {
        let identity = ArtifactIdentity {
            url: artifact.url.clone(),
            length: artifact.length,
            sha256: artifact.sha256.clone(),
        };
        validate_artifact_identity(&artifact.target, &identity)
            .context("product manifest artifact identity is invalid")?;
        if artifacts
            .insert(artifact.target.clone(), identity)
            .is_some()
        {
            bail!("product manifest target is duplicated");
        }
    }
    let manifest = ProductManifest {
        schema: "dev-tools-product-v2".into(),
        product: spec.product.clone(),
        generation: spec.generation,
        version: spec.version.clone(),
        source_commit: Some(spec.source_commit.clone()),
        engine_protocol: 1,
        artifacts,
    };
    let bytes = serde_jcs::to_vec(&manifest).context("canonicalize product manifest")?;
    validate_unsigned_product_manifest(&bytes)?;
    Ok(bytes)
}

/// Constructs a canonical authorization inventory of exact registry package bytes
/// and their declared source identity.
///
/// This document authenticates what may be published; it does not perform the
/// externally irreversible registry upload.
pub fn build_unsigned_crate_set(spec: &CrateSetSpec) -> Result<Vec<u8>> {
    if spec.generation == 0
        || !valid_lower_hex(&spec.source_commit, 40)
        || spec.registry != "crates-io"
        || spec.packages.is_empty()
        || spec.packages.len() > MAX_CRATE_SET_PACKAGES
    {
        bail!("crate-set specification is invalid");
    }
    let mut packages = BTreeMap::new();
    for package in &spec.packages {
        let identity = CratePackageIdentity {
            version: package.version.clone(),
            length: package.length,
            sha256: package.sha256.clone(),
        };
        validate_crate_package_identity(&package.name, &identity)
            .context("crate-set package identity is invalid")?;
        if packages.insert(package.name.clone(), identity).is_some() {
            bail!("crate-set package is duplicated");
        }
    }
    let document = CrateSetDocument {
        schema: "dev-tools-crate-set-v1".into(),
        authority: CRATE_SET_AUTHORITY.into(),
        generation: spec.generation,
        source_commit: spec.source_commit.clone(),
        registry: spec.registry.clone(),
        packages,
    };
    let bytes = serde_jcs::to_vec(&document).context("canonicalize crate set")?;
    validate_unsigned_crate_set(&bytes)?;
    Ok(bytes)
}

/// Constructs the exact canonical root payload signed by offline root keys.
pub fn build_unsigned_root_document(spec: &RootDocumentSpec) -> Result<Vec<u8>> {
    if spec.generation == 0 || spec.release_keys.is_empty() || spec.release_keys.len() > 32 {
        bail!("root document specification is invalid");
    }
    let mut identities = BTreeSet::new();
    let mut release_keys = Vec::with_capacity(spec.release_keys.len());
    for key in &spec.release_keys {
        let verifying_key = parse_release_public_key(&key.public_key)
            .context("parse root-authorized release public key")?;
        let key_id = key_id("release", verifying_key.as_bytes());
        if !identities.insert(key_id.clone()) {
            bail!("root document release key is duplicated");
        }
        release_keys.push(ReleaseKey {
            key_id,
            public_key: key.public_key.clone(),
            revoked: key.revoked,
        });
    }
    if release_keys.iter().all(|key| key.revoked) {
        bail!("root document must authorize at least one active release key");
    }
    release_keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    serde_jcs::to_vec(&RootDocument {
        schema: "dev-tools-root-v1".into(),
        generation: spec.generation,
        release_keys,
    })
    .context("canonicalize root document")
}

/// Wraps one canonical JSON payload in a deterministic signed envelope.
pub fn build_signed_envelope(unsigned: &[u8], signatures: &[EnvelopeSignature]) -> Result<Vec<u8>> {
    require_bounded(unsigned, METADATA_LIMIT, "unsigned signed payload")?;
    if signatures.is_empty() || signatures.len() > 8 {
        bail!("signed envelope has an invalid signature count");
    }
    let signed: serde_json::Value =
        serde_json::from_slice(unsigned).context("parse unsigned signed payload")?;
    if serde_jcs::to_vec(&signed).context("canonicalize unsigned signed payload")? != unsigned {
        bail!("unsigned signed payload is not canonical JSON");
    }
    let mut seen = BTreeSet::new();
    let mut rows = Vec::with_capacity(signatures.len());
    for signature in signatures {
        if !valid_key_id(&signature.key_id)
            || signature.signature.len() != ed25519_dalek::SIGNATURE_LENGTH
            || !seen.insert(signature.key_id.clone())
        {
            bail!("signed envelope signature is invalid or duplicated");
        }
        rows.push(DocumentSignature {
            key_id: signature.key_id.clone(),
            signature: BASE64.encode(&signature.signature),
        });
    }
    rows.sort_by(|left, right| left.key_id.cmp(&right.key_id));
    let mut bytes = serde_jcs::to_vec(&SignedEnvelope {
        signed,
        signatures: rows,
    })
    .context("canonicalize signed envelope")?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn release_key_id(public_key: &str) -> Result<String> {
    let key = parse_release_public_key(public_key)?;
    Ok(key_id("release", key.as_bytes()))
}

pub fn root_key_id(public_key: &str) -> Result<String> {
    let key = parse_release_public_key(public_key)?;
    Ok(key_id("root", key.as_bytes()))
}

/// Validates the exact canonical bytes that the release tooling signs.
///
/// This deliberately validates only the shared manifest contract. Product-specific
/// URL, target, and source authority remains the verifier's responsibility.
pub fn validate_unsigned_product_manifest(input: &[u8]) -> Result<UnsignedProductManifest> {
    require_bounded(input, METADATA_LIMIT, "unsigned release manifest")?;
    let manifest: ProductManifest =
        serde_json::from_slice(input).context("parse unsigned release manifest")?;
    let canonical =
        serde_jcs::to_vec(&manifest).context("canonicalize unsigned release manifest")?;
    if canonical != input {
        bail!("unsigned release manifest is not canonical JSON");
    }
    if !valid_product_id(&manifest.product)
        || manifest.generation == 0
        || manifest.engine_protocol != 1
        || manifest.artifacts.is_empty()
        || manifest.artifacts.len() > MAX_MANIFEST_ARTIFACTS
    {
        bail!("unsigned release manifest has an unsupported contract");
    }
    validate_manifest_schema(&manifest)
        .context("unsigned release manifest has an unsupported schema")?;
    let version = Version::parse(&manifest.version).context("parse product manifest version")?;
    if !version.pre.is_empty() {
        bail!("unsigned release manifest version is not stable");
    }
    for (target, artifact) in &manifest.artifacts {
        validate_artifact_identity(target, artifact)
            .context("unsigned release manifest artifact identity is invalid")?;
    }
    Ok(UnsignedProductManifest {
        schema: manifest.schema,
        product: manifest.product,
        generation: manifest.generation,
        version,
    })
}

/// Validates any canonical document admitted by the release-signing operation
/// and returns its policy authority without exposing schema-specific contents.
pub fn validate_unsigned_release_document(input: &[u8]) -> Result<UnsignedReleaseDocument> {
    require_bounded(input, METADATA_LIMIT, "unsigned release document")?;
    let value: serde_json::Value =
        serde_json::from_slice(input).context("parse unsigned release document")?;
    if serde_jcs::to_vec(&value).context("canonicalize unsigned release document")? != input {
        bail!("unsigned release document is not canonical JSON");
    }
    match value.get("schema").and_then(serde_json::Value::as_str) {
        Some("dev-tools-crate-set-v1") => {
            let document = validate_unsigned_crate_set(input)?;
            Ok(UnsignedReleaseDocument {
                schema: document.schema,
                authority: document.authority,
                generation: document.generation,
            })
        }
        Some(_) => {
            let manifest = validate_unsigned_product_manifest(input)?;
            Ok(UnsignedReleaseDocument {
                schema: manifest.schema,
                authority: manifest.product,
                generation: manifest.generation,
            })
        }
        None => bail!("unsigned release document has no schema"),
    }
}

/// Authenticates a signed crate inventory against the release root and its exact
/// declared source, registry, and policy authority.
pub fn verify_crate_set_metadata(
    metadata: &CrateSetMetadata,
    authority: &CrateSetAuthority,
) -> Result<VerifiedCrateSet> {
    if authority.registry != "crates-io" || !valid_lower_hex(&authority.source_commit, 40) {
        bail!("crate-set authority is invalid");
    }
    require_bounded(&metadata.root, METADATA_LIMIT, "root document")?;
    require_bounded(&metadata.manifest, METADATA_LIMIT, "crate-set manifest")?;
    let root = parse_and_verify_root(&metadata.root, &authority.trusted_root_key)?;
    let envelope: SignedEnvelope<CrateSetDocument> =
        serde_json::from_slice(&metadata.manifest).context("parse signed crate set")?;
    verify_release_signature(&envelope, &root.signed)?;
    let canonical = serde_jcs::to_vec(&envelope.signed).context("canonicalize signed crate set")?;
    let document = validate_unsigned_crate_set(&canonical)?;
    if document.authority != CRATE_SET_AUTHORITY
        || document.registry != authority.registry
        || document.source_commit != authority.source_commit
    {
        bail!("signed crate set is outside the selected authority");
    }
    let packages = document
        .packages
        .into_iter()
        .map(|(name, identity)| {
            let version =
                Version::parse(&identity.version).context("parse crate package version")?;
            Ok((
                name,
                VerifiedCratePackage {
                    version,
                    length: identity.length,
                    sha256: identity.sha256,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(VerifiedCrateSet {
        root_generation: root.signed.generation,
        root_sha256: sha256_hex(&metadata.root),
        manifest_generation: document.generation,
        manifest_sha256: sha256_hex(&metadata.manifest),
        schema: document.schema,
        authority: document.authority,
        source_commit: document.source_commit,
        registry: document.registry,
        packages,
    })
}

/// Verifies exact package bytes against one authenticated crate-set entry.
pub fn verify_crate_package_bytes(
    set: &VerifiedCrateSet,
    name: &str,
    version: &str,
    bytes: &[u8],
) -> Result<()> {
    require_bounded(bytes, CRATE_PACKAGE_LIMIT, "crate package")?;
    let package = set
        .packages
        .get(name)
        .context("crate package is absent from the authenticated set")?;
    if package.version.to_string() != version
        || package.length != bytes.len() as u64
        || package.sha256 != sha256_hex(bytes)
    {
        bail!("crate package bytes do not match the authenticated set");
    }
    Ok(())
}

/// Anonymously authenticates every package in a signed crate set against the
/// crates.io sparse index and the exact downloaded registry bytes.
pub fn verify_crates_io_package_set(set: &VerifiedCrateSet) -> Result<Vec<VerifiedRegistryCrate>> {
    let (index_policy, artifact_policy) = crates_io_https_policies();
    verify_crates_io_package_set_with_fetch(set, |url, limit| {
        let policy = crates_io_policy_for_url(url, &index_policy, &artifact_policy)?;
        Ok(fetch_https(url, policy, limit, None)?.bytes)
    })
}

/// Inspects one package version without credentials and distinguishes a truly
/// absent sparse-index entry from an authenticated published package.
pub fn inspect_crates_io_package(
    set: &VerifiedCrateSet,
    name: &str,
) -> Result<RegistryCrateStatus> {
    let (index_policy, artifact_policy) = crates_io_https_policies();
    inspect_crates_io_package_with_fetch(set, name, |url, limit| {
        let policy = crates_io_policy_for_url(url, &index_policy, &artifact_policy)?;
        if url.starts_with("https://index.crates.io/") {
            Ok(fetch_optional_https(url, policy, limit)?.map(|response| response.bytes))
        } else {
            Ok(Some(fetch_https(url, policy, limit, None)?.bytes))
        }
    })
}

fn crates_io_https_policies() -> (HttpsPolicy, HttpsPolicy) {
    let index_policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from(["index.crates.io".into()]),
        max_redirects: 3,
        timeout: Duration::from_secs(30),
        user_agent: concat!("dev-tools-release/", env!("CARGO_PKG_VERSION")).into(),
    };
    let artifact_policy = HttpsPolicy {
        allowed_hosts: BTreeSet::from(["static.crates.io".into()]),
        ..index_policy.clone()
    };
    (index_policy, artifact_policy)
}

fn crates_io_policy_for_url<'a>(
    url: &str,
    index: &'a HttpsPolicy,
    artifact: &'a HttpsPolicy,
) -> Result<&'a HttpsPolicy> {
    if url.starts_with("https://index.crates.io/") {
        Ok(index)
    } else if url.starts_with("https://static.crates.io/") {
        Ok(artifact)
    } else {
        bail!("crates.io verification URL is outside the fixed registry authority");
    }
}

fn verify_crates_io_package_set_with_fetch<F>(
    set: &VerifiedCrateSet,
    mut fetch: F,
) -> Result<Vec<VerifiedRegistryCrate>>
where
    F: FnMut(&str, u64) -> Result<Vec<u8>>,
{
    let mut verified = Vec::with_capacity(set.packages.len());
    for name in set.packages.keys() {
        let status = inspect_crates_io_package_with_fetch(set, name, |url, limit| {
            Ok(Some(fetch(url, limit)?))
        })?;
        match status {
            RegistryCrateStatus::Verified(package) => verified.push(package),
            RegistryCrateStatus::Absent => {
                bail!("crates.io index does not contain the package version")
            }
        }
    }
    Ok(verified)
}

fn inspect_crates_io_package_with_fetch<F>(
    set: &VerifiedCrateSet,
    name: &str,
    mut fetch: F,
) -> Result<RegistryCrateStatus>
where
    F: FnMut(&str, u64) -> Result<Option<Vec<u8>>>,
{
    if set.authority != CRATE_SET_AUTHORITY || set.registry != "crates-io" {
        bail!("crate set is outside the crates.io verification authority");
    }
    let package = set
        .packages
        .get(name)
        .context("crate is absent from the authenticated set")?;
    let config_bytes = fetch(
        "https://index.crates.io/config.json",
        CRATES_IO_CONFIG_LIMIT,
    )
    .context("fetch crates.io registry configuration")?
    .context("crates.io registry configuration is absent")?;
    let config: CratesIoConfig =
        serde_json::from_slice(&config_bytes).context("parse crates.io registry configuration")?;
    if config.api != "https://crates.io" || config.auth_required {
        bail!("crates.io registry configuration is unsupported");
    }
    let index_url = crates_io_index_url(name)?;
    let Some(index) = fetch(&index_url, CRATES_IO_INDEX_LIMIT)
        .with_context(|| format!("fetch crates.io index entry for {name}"))?
    else {
        return Ok(RegistryCrateStatus::Absent);
    };
    let Some(entry) = crates_io_index_entry(name, package, &index)? else {
        return Ok(RegistryCrateStatus::Absent);
    };
    if entry.yanked || entry.cksum != package.sha256 || !valid_lower_hex(&entry.cksum, 64) {
        bail!("crates.io index package identity does not match the authenticated set");
    }
    let download_url = crates_io_download_url(&config.dl, name, package)?;
    let bytes = fetch(&download_url, package.length)
        .with_context(|| format!("download crates.io package {name}"))?
        .context("crates.io package download is absent")?;
    verify_crate_package_bytes(set, name, &package.version.to_string(), &bytes)?;
    Ok(RegistryCrateStatus::Verified(VerifiedRegistryCrate {
        name: name.into(),
        version: package.version.clone(),
        length: package.length,
        sha256: package.sha256.clone(),
    }))
}

fn crates_io_index_entry(
    expected_name: &str,
    expected: &VerifiedCratePackage,
    input: &[u8],
) -> Result<Option<CratesIoIndexEntry>> {
    require_bounded(
        input,
        CRATES_IO_INDEX_LIMIT as usize,
        "crates.io index entry",
    )?;
    let version = expected.version.to_string();
    let mut selected = None;
    for line in input
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let entry: CratesIoIndexEntry =
            serde_json::from_slice(line).context("parse crates.io index record")?;
        if entry.name == expected_name && entry.vers == version && selected.replace(entry).is_some()
        {
            bail!("crates.io index contains a duplicate package version");
        }
    }
    Ok(selected)
}

fn crates_io_index_url(name: &str) -> Result<String> {
    if !valid_product_id(name) {
        bail!("crate name is invalid for the crates.io sparse index");
    }
    let prefix = match name.len() {
        1 => "1".into(),
        2 => "2".into(),
        3 => format!("3/{}", &name[..1]),
        _ => format!("{}/{}", &name[..2], &name[2..4]),
    };
    Ok(format!("https://index.crates.io/{prefix}/{name}"))
}

fn crates_io_download_url(
    template: &str,
    name: &str,
    package: &VerifiedCratePackage,
) -> Result<String> {
    let prefix = match name.len() {
        1 => "1".into(),
        2 => "2".into(),
        3 => format!("3/{}", &name[..1]),
        _ => format!("{}/{}", &name[..2], &name[2..4]),
    };
    let version = package.version.to_string();
    let has_marker = [
        "{crate}",
        "{version}",
        "{prefix}",
        "{lowerprefix}",
        "{sha256-checksum}",
    ]
    .iter()
    .any(|marker| template.contains(marker));
    let mut url = template
        .replace("{crate}", name)
        .replace("{version}", &version)
        .replace("{prefix}", &prefix)
        .replace("{lowerprefix}", &prefix.to_ascii_lowercase())
        .replace("{sha256-checksum}", &package.sha256);
    if !has_marker {
        url = format!("{}/{name}/{version}/download", url.trim_end_matches('/'));
    }
    let parsed: ureq::http::Uri = url.parse().context("parse crates.io download URL")?;
    if parsed.scheme_str() != Some("https")
        || parsed.host() != Some("static.crates.io")
        || parsed.port_u16().is_some_and(|port| port != 443)
        || url.contains(['{', '}', '\r', '\n', '\0'])
    {
        bail!("crates.io download URL is outside the fixed registry authority");
    }
    Ok(url)
}

fn validate_unsigned_crate_set(input: &[u8]) -> Result<CrateSetDocument> {
    require_bounded(input, METADATA_LIMIT, "unsigned crate set")?;
    let document: CrateSetDocument =
        serde_json::from_slice(input).context("parse unsigned crate set")?;
    if serde_jcs::to_vec(&document).context("canonicalize unsigned crate set")? != input {
        bail!("unsigned crate set is not canonical JSON");
    }
    if document.schema != "dev-tools-crate-set-v1"
        || document.authority != CRATE_SET_AUTHORITY
        || document.generation == 0
        || !valid_lower_hex(&document.source_commit, 40)
        || document.registry != "crates-io"
        || document.packages.is_empty()
        || document.packages.len() > MAX_CRATE_SET_PACKAGES
    {
        bail!("unsigned crate set has an unsupported contract");
    }
    for (name, identity) in &document.packages {
        validate_crate_package_identity(name, identity)
            .context("unsigned crate-set package identity is invalid")?;
    }
    Ok(document)
}

fn validate_crate_package_identity(name: &str, identity: &CratePackageIdentity) -> Result<()> {
    if !valid_product_id(name)
        || identity.length == 0
        || identity.length > CRATE_PACKAGE_LIMIT as u64
        || !valid_lower_hex(&identity.sha256, 64)
    {
        bail!("crate package identity is invalid");
    }
    let version = Version::parse(&identity.version).context("parse crate package version")?;
    if !version.pre.is_empty() || version.to_string() != identity.version {
        bail!("crate package version is not canonical stable semantic version");
    }
    Ok(())
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
    let releases = verify_release_set_metadata(metadata, authority)?;
    releases
        .into_iter()
        .find(|release| release.target == authority.target)
        .context("release manifest has no artifact for the selected target")
}

/// Verifies one signed manifest and returns every authenticated target
/// projection in deterministic target order.
pub fn verify_release_set_metadata(
    metadata: &ReleaseMetadata,
    authority: &ReleaseAuthority,
) -> Result<Vec<VerifiedRelease>> {
    validate_authority(authority)?;
    require_bounded(&metadata.root, METADATA_LIMIT, "root document")?;
    require_bounded(&metadata.manifest, METADATA_LIMIT, "release manifest")?;

    let root = parse_and_verify_root(&metadata.root, &authority.trusted_root_key)?;

    let manifest: SignedEnvelope<ProductManifest> =
        serde_json::from_slice(&metadata.manifest).context("parse product release manifest")?;
    verify_release_signature(&manifest, &root.signed)?;
    validate_manifest(&manifest.signed, authority)?;
    if matches!(authority.artifact_url, ArtifactUrlPolicy::Exact(_))
        && manifest.signed.artifacts.len() != 1
    {
        bail!("exact artifact URL authority cannot admit a multi-target manifest");
    }
    let root_sha256 = sha256_hex(&metadata.root);
    let manifest_sha256 = sha256_hex(&metadata.manifest);
    let version = Version::parse(&manifest.signed.version).context("parse product version")?;
    Ok(manifest
        .signed
        .artifacts
        .into_iter()
        .map(|(target, artifact)| VerifiedRelease {
            root_generation: root.signed.generation,
            root_sha256: root_sha256.clone(),
            manifest_generation: manifest.signed.generation,
            manifest_sha256: manifest_sha256.clone(),
            manifest_schema: manifest.signed.schema.clone(),
            product: manifest.signed.product.clone(),
            version: version.clone(),
            source_commit: manifest.signed.source_commit.clone(),
            target,
            artifact_url: artifact.url,
            artifact_length: artifact.length,
            artifact_sha256: artifact.sha256,
        })
        .collect())
}

pub fn verify_root_bytes(root: &[u8], trusted_root_key: &str) -> Result<VerifiedRoot> {
    let envelope = parse_and_verify_root(root, trusted_root_key)?;
    Ok(VerifiedRoot {
        generation: envelope.signed.generation,
        sha256: sha256_hex(root),
        active_release_keys: envelope
            .signed
            .release_keys
            .iter()
            .filter(|key| !key.revoked)
            .count(),
        revoked_release_keys: envelope
            .signed
            .release_keys
            .iter()
            .filter(|key| key.revoked)
            .count(),
    })
}

/// Authenticates a root document and returns the public key for one active
/// routine release-signing identity.
pub fn authorized_release_public_key(
    root: &[u8],
    trusted_root_key: &str,
    release_key_id: &str,
) -> Result<String> {
    let envelope = parse_and_verify_root(root, trusted_root_key)?;
    envelope
        .signed
        .release_keys
        .into_iter()
        .find(|key| key.key_id == release_key_id && !key.revoked)
        .map(|key| key.public_key)
        .context("release key is not active in the authenticated root")
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
    fetch_https_response(url, policy, limit, etag, false)?
        .context("release response was unexpectedly absent")
}

fn fetch_optional_https(
    url: &str,
    policy: &HttpsPolicy,
    limit: u64,
) -> Result<Option<HttpsResponse>> {
    fetch_https_response(url, policy, limit, None, true)
}

fn fetch_https_response(
    url: &str,
    policy: &HttpsPolicy,
    limit: u64,
    etag: Option<&str>,
    allow_not_found: bool,
) -> Result<Option<HttpsResponse>> {
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
    if response.status().as_u16() == 304 {
        bail!("release response was not modified");
    }
    if allow_not_found && response.status().as_u16() == 404 {
        return Ok(None);
    }
    if !response.status().is_success() {
        bail!("GET {url} returned HTTP {}", response.status());
    }
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = read_bounded_body(response.body_mut(), limit)
        .with_context(|| format!("read bounded response from {url}"))?;
    Ok(Some(HttpsResponse { bytes, etag }))
}

fn read_bounded_body(body: &mut ureq::Body, limit: u64) -> Result<Vec<u8>> {
    // ureq's reader treats consuming exactly its configured limit as an error
    // because `read_to_end` performs one final EOF probe. Read at most one byte
    // beyond our authenticated bound, then enforce the actual inclusive bound
    // ourselves.
    let transport_limit = limit
        .checked_add(1)
        .context("release response size bound overflowed")?;
    let bytes = body
        .with_config()
        .limit(transport_limit)
        .read_to_vec()
        .context("read bounded release response body")?;
    if bytes.is_empty() || bytes.len() as u64 > limit {
        bail!("release response is empty or exceeds its size bound");
    }
    Ok(bytes)
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

pub fn load_release_state_at(path: &Path, owner_uid: u32) -> Result<ReleaseState> {
    let authority = release_state_authority(owner_uid);
    let Some(document) = read_atomic_document(path, &authority)? else {
        return Ok(ReleaseState::default());
    };
    serde_json::from_slice(&document.bytes).context("parse persisted release state")
}

pub fn accept_verified_release_at(
    path: &Path,
    owner_uid: u32,
    verified: &VerifiedRelease,
) -> Result<bool> {
    if !path.is_absolute() {
        bail!("persisted release state path must be absolute");
    }
    let lock_path = path.with_extension("lock");
    let _lock = InstallationLock::acquire(&lock_path)?;
    let authority = release_state_authority(owner_uid);
    let current = read_atomic_document(path, &authority)?;
    let mut state = current
        .as_ref()
        .map(|document| {
            serde_json::from_slice(&document.bytes).context("parse persisted release state")
        })
        .transpose()?
        .unwrap_or_default();
    let changed = accept_verified_release(&mut state, verified)?;
    if changed {
        let bytes = serde_jcs::to_vec(&state).context("serialize persisted release state")?;
        write_atomic_document(
            path,
            &bytes,
            &authority,
            current.as_ref().map(|document| &document.identity),
        )?;
    }
    Ok(changed)
}

pub fn cache_verified_release(
    cache_root: &Path,
    authority: &ReleaseAuthority,
    metadata: &ReleaseMetadata,
    artifact: &[u8],
    owner_uid: u32,
) -> Result<CachedRelease> {
    if !cache_root.is_absolute() {
        bail!("verified release cache root must be absolute");
    }
    let verified = verify_release_metadata(metadata, authority)?;
    verify_artifact_bytes(&verified, artifact)?;
    let _lock = InstallationLock::acquire(&cache_root.join("release-cache.lock"))?;
    let directory = cache_directory(
        cache_root,
        &verified.product,
        &verified.version,
        &verified.target,
    );
    ensure_release_cache_directory(&directory, owner_uid)?;
    let metadata_authority = DocumentAuthority {
        owner_uid,
        mode: 0o600,
        limit: METADATA_LIMIT as u64,
    };
    let artifact_authority = DocumentAuthority {
        owner_uid,
        mode: 0o700,
        limit: ARTIFACT_LIMIT as u64,
    };
    write_atomic_document(
        &directory.join("root.json"),
        &metadata.root,
        &metadata_authority,
        None,
    )?;
    write_atomic_document(
        &directory.join("manifest.json"),
        &metadata.manifest,
        &metadata_authority,
        None,
    )?;
    write_atomic_document(
        &directory.join("artifact"),
        artifact,
        &artifact_authority,
        None,
    )?;
    let receipt = CachedReleaseReceipt {
        schema: "dev-tools-release-cache-v1".into(),
        verified: verified.clone(),
    };
    write_atomic_document(
        &directory.join("receipt.json"),
        &serde_jcs::to_vec(&receipt).context("serialize verified release cache receipt")?,
        &metadata_authority,
        None,
    )?;
    std::fs::File::open(&directory)
        .context("open verified release cache entry")?
        .sync_all()
        .context("sync verified release cache entry")?;
    let cached = load_cached_release_unlocked(cache_root, authority, &verified.version, owner_uid)?;
    if cached.verified != verified {
        bail!("verified release cache contains an equivocal release identity");
    }
    Ok(cached)
}

pub fn load_cached_release(
    cache_root: &Path,
    authority: &ReleaseAuthority,
    version: &Version,
    owner_uid: u32,
) -> Result<CachedRelease> {
    if !cache_root.is_absolute() {
        bail!("verified release cache root must be absolute");
    }
    let _lock = InstallationLock::acquire(&cache_root.join("release-cache.lock"))?;
    load_cached_release_unlocked(cache_root, authority, version, owner_uid)
}

fn load_cached_release_unlocked(
    cache_root: &Path,
    authority: &ReleaseAuthority,
    version: &Version,
    owner_uid: u32,
) -> Result<CachedRelease> {
    let directory = cache_directory(cache_root, &authority.product, version, &authority.target);
    let metadata_authority = DocumentAuthority {
        owner_uid,
        mode: 0o600,
        limit: METADATA_LIMIT as u64,
    };
    let artifact_authority = DocumentAuthority {
        owner_uid,
        mode: 0o700,
        limit: ARTIFACT_LIMIT as u64,
    };
    let root_path = directory.join("root.json");
    let manifest_path = directory.join("manifest.json");
    let artifact_path = directory.join("artifact");
    let receipt_path = directory.join("receipt.json");
    let root = read_atomic_document(&root_path, &metadata_authority)?
        .context("cached release root is absent")?;
    let manifest = read_atomic_document(&manifest_path, &metadata_authority)?
        .context("cached release manifest is absent")?;
    let artifact = read_atomic_document(&artifact_path, &artifact_authority)?
        .context("cached release artifact is absent")?;
    let receipt = read_atomic_document(&receipt_path, &metadata_authority)?
        .context("cached release receipt is absent")?;
    let receipt: CachedReleaseReceipt =
        serde_json::from_slice(&receipt.bytes).context("parse cached release receipt")?;
    if receipt.schema != "dev-tools-release-cache-v1" {
        bail!("cached release receipt has an unsupported contract");
    }
    let verified = verify_release_bytes(
        &ReleaseBundle {
            root: root.bytes,
            manifest: manifest.bytes,
            artifact: artifact.bytes,
        },
        authority,
    )?;
    if verified.version != *version || verified != receipt.verified {
        bail!("cached release receipt does not match its authenticated bytes");
    }
    Ok(CachedRelease {
        verified,
        root_path,
        manifest_path,
        artifact_path,
    })
}

fn release_state_authority(owner_uid: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid,
        mode: 0o600,
        limit: 64 * 1024,
    }
}

fn cache_directory(cache_root: &Path, product: &str, version: &Version, target: &str) -> PathBuf {
    let key = sha256_hex(format!("{product}\0{version}\0{target}").as_bytes());
    cache_root.join(format!("release-{key}"))
}

fn ensure_release_cache_directory(path: &Path, owner_uid: u32) -> Result<()> {
    #[cfg(not(unix))]
    let _ = owner_uid;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                bail!("verified release cache entry is not a directory");
            }
            #[cfg(unix)]
            if metadata.uid() != owner_uid || metadata.mode() & 0o777 != 0o700 {
                bail!("verified release cache entry has unsafe filesystem authority");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(path).context("reserve verified release cache entry")?;
            #[cfg(unix)]
            {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                    .context("protect verified release cache entry")?;
                if fs::metadata(path)?.uid() != owner_uid {
                    std::os::unix::fs::chown(path, Some(owner_uid), None)
                        .context("set verified release cache entry owner")?;
                }
            }
        }
        Err(error) => return Err(error).context("inspect verified release cache entry"),
    }
    Ok(())
}

fn parse_and_verify_root(
    bytes: &[u8],
    trusted_root_key: &str,
) -> Result<SignedEnvelope<RootDocument>> {
    require_bounded(bytes, METADATA_LIMIT, "root document")?;
    let root: SignedEnvelope<RootDocument> =
        serde_json::from_slice(bytes).context("parse trusted root document")?;
    validate_root_document(&root.signed)?;
    if root.signatures.is_empty() || root.signatures.len() > 8 {
        bail!("release root document signatures are invalid");
    }
    verify_any_signature(&root, &parse_release_public_key(trusted_root_key)?)
        .context("verify release root document")?;
    Ok(root)
}

fn validate_root_document(root: &RootDocument) -> Result<()> {
    if root.schema != "dev-tools-root-v1"
        || root.generation == 0
        || root.release_keys.is_empty()
        || root.release_keys.len() > 32
    {
        bail!("release root document has an unsupported contract");
    }
    let mut identities = BTreeSet::new();
    for key in &root.release_keys {
        let verifying_key = parse_release_public_key(&key.public_key)
            .context("parse root-authorized release public key")?;
        if key.key_id != key_id("release", verifying_key.as_bytes())
            || !identities.insert(key.key_id.clone())
        {
            bail!("release root key identity is invalid or duplicated");
        }
    }
    if root.release_keys.iter().all(|key| key.revoked) {
        bail!("release root document has no active release key");
    }
    Ok(())
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
    parse_release_public_key(&authority.trusted_root_key)?;
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
        || manifest.artifacts.is_empty()
        || manifest.artifacts.len() > MAX_MANIFEST_ARTIFACTS
    {
        bail!("release manifest has an unsupported contract");
    }
    validate_manifest_schema(manifest).context("release manifest has an unsupported schema")?;
    Version::parse(&manifest.version).context("parse product manifest version")?;
    match &manifest.source_commit {
        Some(commit) if valid_hex(commit, 40) => {}
        Some(_) => bail!("release manifest source commit is invalid"),
        None if authority.require_source_commit => {
            bail!("release manifest does not bind a source commit")
        }
        None => {}
    }
    for (target, artifact) in &manifest.artifacts {
        validate_artifact_identity(target, artifact)
            .context("release manifest artifact identity is invalid")?;
        if let ArtifactUrlPolicy::GitHubRelease { owner, repository } = &authority.artifact_url {
            let artifact_name = native_artifact_name(&manifest.product, &manifest.version, target);
            let expected_url = format!(
                "https://github.com/{owner}/{repository}/releases/download/{}%2Fv{}/{artifact_name}",
                manifest.product, manifest.version
            );
            if artifact.url != expected_url {
                bail!("release manifest artifact identity is invalid");
            }
        }
    }
    let artifact = manifest
        .artifacts
        .get(&authority.target)
        .context("release manifest has no artifact for the selected target")?;
    let expected_url = match &authority.artifact_url {
        ArtifactUrlPolicy::Exact(url) => url.clone(),
        ArtifactUrlPolicy::GitHubRelease { owner, repository } => {
            let artifact_name =
                native_artifact_name(&manifest.product, &manifest.version, &authority.target);
            format!(
                "https://github.com/{owner}/{repository}/releases/download/{}%2Fv{}/{artifact_name}",
                manifest.product, manifest.version
            )
        }
    };
    if artifact.url != expected_url {
        bail!("release manifest artifact identity is invalid");
    }
    Ok(())
}

fn validate_manifest_schema(manifest: &ProductManifest) -> Result<()> {
    match (
        manifest.schema.as_str(),
        manifest.product.as_str(),
        manifest.source_commit.as_deref(),
        manifest.artifacts.len(),
    ) {
        ("dev-tools-product-v1", product, None, 1) if product != "dev-auth" => Ok(()),
        ("dev-auth-product-v2", "dev-auth", Some(commit), 1) if valid_hex(commit, 40) => Ok(()),
        ("dev-tools-product-v2", _, Some(commit), _) if valid_hex(commit, 40) => Ok(()),
        _ => bail!("release manifest schema is unsupported"),
    }
}

fn validate_artifact_identity(target: &str, artifact: &ArtifactIdentity) -> Result<()> {
    if !valid_release_target(target)
        || !artifact.url.starts_with("https://")
        || artifact.length == 0
        || artifact.length as usize > ARTIFACT_LIMIT
        || !valid_hex(&artifact.sha256, 64)
    {
        bail!("release artifact identity is invalid");
    }
    Ok(())
}

fn native_artifact_name(product: &str, version: &str, target: &str) -> String {
    let executable_suffix = if target.starts_with("windows-") {
        ".exe"
    } else {
        ""
    };
    format!("{product}-{version}-{target}{executable_suffix}")
}

fn verify_release_signature<T: Serialize>(
    manifest: &SignedEnvelope<T>,
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
            &parse_release_public_key(&key.public_key)?,
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

pub fn parse_release_public_key(encoded: &str) -> Result<VerifyingKey> {
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

fn key_id(prefix: &str, public_key: &[u8]) -> String {
    let digest = sha256_hex(public_key);
    format!("{prefix}-{}", &digest[..16])
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_product_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_release_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
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

#[cfg(test)]
mod tests {
    use super::{
        inspect_crates_io_package_with_fetch, read_bounded_body, sha256_hex,
        verify_crates_io_package_set_with_fetch, RegistryCrateStatus, VerifiedCratePackage,
        VerifiedCrateSet, CRATE_SET_AUTHORITY,
    };
    use semver::Version;
    use std::collections::BTreeMap;

    #[test]
    fn bounded_body_accepts_the_exact_authenticated_length() {
        let mut exact = ureq::Body::builder().data(b"exact".to_vec());
        assert_eq!(read_bounded_body(&mut exact, 5).unwrap(), b"exact");

        let mut oversized = ureq::Body::builder().data(b"larger".to_vec());
        assert!(read_bounded_body(&mut oversized, 5).is_err());
    }

    #[test]
    fn crates_io_verification_matches_the_signed_index_and_download_bytes() {
        let package_bytes = b"authenticated crate bytes";
        let set = crate_set(package_bytes);
        let checksum = sha256_hex(package_bytes);
        let mut requests = Vec::new();

        let verified = verify_crates_io_package_set_with_fetch(&set, |url, limit| {
            requests.push((url.to_owned(), limit));
            match url {
                "https://index.crates.io/config.json" => Ok(
                    br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#
                        .to_vec(),
                ),
                "https://index.crates.io/de/v-/dev-tools-command" => Ok(format!(
                    "{{\"name\":\"dev-tools-command\",\"vers\":\"0.1.0\",\"cksum\":\"{checksum}\",\"yanked\":false}}\n"
                )
                .into_bytes()),
                "https://static.crates.io/crates/dev-tools-command/0.1.0/download" => {
                    Ok(package_bytes.to_vec())
                }
                _ => panic!("unexpected URL: {url}"),
            }
        })
        .unwrap();

        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].name, "dev-tools-command");
        assert_eq!(verified[0].version, Version::parse("0.1.0").unwrap());
        assert_eq!(verified[0].length, package_bytes.len() as u64);
        assert_eq!(verified[0].sha256, checksum);
        assert_eq!(
            requests,
            vec![
                (
                    "https://index.crates.io/config.json".into(),
                    super::CRATES_IO_CONFIG_LIMIT,
                ),
                (
                    "https://index.crates.io/de/v-/dev-tools-command".into(),
                    super::CRATES_IO_INDEX_LIMIT,
                ),
                (
                    "https://static.crates.io/crates/dev-tools-command/0.1.0/download".into(),
                    package_bytes.len() as u64,
                ),
            ]
        );
    }

    #[test]
    fn crates_io_verification_rejects_index_identity_before_download() {
        let package_bytes = b"authenticated crate bytes";
        let set = crate_set(package_bytes);
        let mut downloaded = false;

        let error = verify_crates_io_package_set_with_fetch(&set, |url, _| match url {
            "https://index.crates.io/config.json" => Ok(
                br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#
                    .to_vec(),
            ),
            "https://index.crates.io/de/v-/dev-tools-command" => Ok(format!(
                "{{\"name\":\"dev-tools-command\",\"vers\":\"0.1.0\",\"cksum\":\"{}\",\"yanked\":false}}\n",
                "0".repeat(64)
            )
            .into_bytes()),
            _ => {
                downloaded = true;
                Ok(package_bytes.to_vec())
            }
        })
        .unwrap_err();

        assert!(error.to_string().contains("identity does not match"));
        assert!(!downloaded);
    }

    #[test]
    fn crates_io_verification_rejects_yanked_or_duplicate_versions() {
        let package_bytes = b"authenticated crate bytes";
        let set = crate_set(package_bytes);
        let checksum = sha256_hex(package_bytes);
        for index in [
            format!(
                "{{\"name\":\"dev-tools-command\",\"vers\":\"0.1.0\",\"cksum\":\"{checksum}\",\"yanked\":true}}\n"
            ),
            format!(
                "{{\"name\":\"dev-tools-command\",\"vers\":\"0.1.0\",\"cksum\":\"{checksum}\",\"yanked\":false}}\n{{\"name\":\"dev-tools-command\",\"vers\":\"0.1.0\",\"cksum\":\"{checksum}\",\"yanked\":false}}\n"
            ),
        ] {
            let error = verify_crates_io_package_set_with_fetch(&set, |url, _| match url {
                "https://index.crates.io/config.json" => Ok(
                    br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#
                        .to_vec(),
                ),
                "https://index.crates.io/de/v-/dev-tools-command" => {
                    Ok(index.as_bytes().to_vec())
                }
                _ => panic!("download must not start for rejected index state"),
            })
            .unwrap_err();
            assert!(
                error.to_string().contains("identity does not match")
                    || error.to_string().contains("duplicate package version")
            );
        }
    }

    #[test]
    fn crates_io_verification_rejects_an_untrusted_download_authority() {
        let package_bytes = b"authenticated crate bytes";
        let set = crate_set(package_bytes);
        let checksum = sha256_hex(package_bytes);

        let error = verify_crates_io_package_set_with_fetch(&set, |url, _| match url {
            "https://index.crates.io/config.json" => Ok(
                br#"{"dl":"https://packages.example.invalid/{crate}/{version}","api":"https://crates.io"}"#
                    .to_vec(),
            ),
            "https://index.crates.io/de/v-/dev-tools-command" => Ok(format!(
                "{{\"name\":\"dev-tools-command\",\"vers\":\"0.1.0\",\"cksum\":\"{checksum}\",\"yanked\":false}}\n"
            )
            .into_bytes()),
            _ => panic!("download must not start for an untrusted authority"),
        })
        .unwrap_err();

        assert!(error.to_string().contains("fixed registry authority"));
    }

    #[test]
    fn crates_io_inspection_distinguishes_an_absent_index_entry() {
        let set = crate_set(b"authenticated crate bytes");

        let status =
            inspect_crates_io_package_with_fetch(&set, "dev-tools-command", |url, _| match url {
                "https://index.crates.io/config.json" => Ok(Some(
                    br#"{"dl":"https://static.crates.io/crates","api":"https://crates.io"}"#
                        .to_vec(),
                )),
                "https://index.crates.io/de/v-/dev-tools-command" => Ok(None),
                _ => panic!("download must not start for an absent index entry"),
            })
            .unwrap();

        assert_eq!(status, RegistryCrateStatus::Absent);
    }

    fn crate_set(package_bytes: &[u8]) -> VerifiedCrateSet {
        VerifiedCrateSet {
            root_generation: 1,
            root_sha256: "1".repeat(64),
            manifest_generation: 1,
            manifest_sha256: "2".repeat(64),
            schema: "dev-tools-crate-set-v1".into(),
            authority: CRATE_SET_AUTHORITY.into(),
            source_commit: "3".repeat(40),
            registry: "crates-io".into(),
            packages: BTreeMap::from([(
                "dev-tools-command".into(),
                VerifiedCratePackage {
                    version: Version::parse("0.1.0").unwrap(),
                    length: package_bytes.len() as u64,
                    sha256: sha256_hex(package_bytes),
                },
            )]),
        }
    }
}
