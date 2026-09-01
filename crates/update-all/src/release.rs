use crate::IntegrityFailure;
use anyhow::{bail, Context, Result};
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(test)]
use base64::Engine as _;
#[cfg(unix)]
use dev_tools_installation::{
    adopt_versioned_installation, apply_versioned_installation, rollback_versioned_installation,
    verify_versioned_installation, ArtifactIdentity, VersionedAdoption, VersionedInstallRequest,
    VersionedLayout, VersionedReceipt,
};
use dev_tools_release::{
    accept_verified_release, select_stable_release_assets, verify_release_metadata,
    ArtifactUrlPolicy, ReleaseAuthority, ReleaseMetadata, ReleaseState as SharedReleaseState,
    VerifiedRelease as SharedVerifiedRelease,
};
#[cfg(test)]
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq::ResponseExt;
use wait_timeout::ChildExt;

const ENGINE_PROTOCOL: u32 = 1;
const RELEASES_URL: &str =
    "https://api.github.com/repos/FutureDevGuys/dev-tools/releases?per_page=100";
const METADATA_LIMIT: u64 = 512 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60;
const MAX_JITTER_SECS: u64 = 30 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Product {
    UpdateAll,
    DevCache,
    SyncConfigs,
    SkillsSync,
}

impl Product {
    pub(crate) const ALL: [Self; 4] = [
        Self::UpdateAll,
        Self::DevCache,
        Self::SyncConfigs,
        Self::SkillsSync,
    ];

    pub(crate) fn id(self) -> &'static str {
        match self {
            Self::UpdateAll => "update-all",
            Self::DevCache => "dev-cache",
            Self::SyncConfigs => "sync-configs",
            Self::SkillsSync => "skills-sync",
        }
    }

    fn executable_name(self) -> String {
        if cfg!(windows) && self != Self::SyncConfigs {
            format!("{}.exe", self.id())
        } else {
            self.id().to_string()
        }
    }

    fn health_args(self) -> &'static [&'static str] {
        &["--version"]
    }

    fn from_id(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|product| product.id() == value)
            .with_context(|| format!("unsupported release product {value}"))
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedEnvelope<T> {
    pub signed: T,
    pub signatures: Vec<DocumentSignature>,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DocumentSignature {
    pub key_id: String,
    pub signature: String,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootDocument {
    pub schema: String,
    pub generation: u64,
    pub release_keys: Vec<ReleaseKey>,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReleaseKey {
    pub key_id: String,
    pub public_key: String,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProductManifest {
    pub schema: String,
    pub product: String,
    pub generation: u64,
    pub version: String,
    pub engine_protocol: u32,
    pub artifacts: BTreeMap<String, Artifact>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Artifact {
    pub url: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseState {
    accepted_root_generation: u64,
    accepted_root_sha256: Option<String>,
    accepted_generation: u64,
    accepted_version: Option<String>,
    accepted_manifest_sha256: Option<String>,
    accepted_binary_sha256: Option<String>,
    active_version: Option<String>,
    previous_version: Option<String>,
    last_successful_check_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Status {
    pub product: Product,
    pub installed_version: Option<String>,
    pub engine_version: String,
    pub previous_version: Option<String>,
    pub managed: bool,
    pub last_successful_check_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Check {
    pub product: Product,
    pub installed_version: Option<String>,
    pub latest_version: String,
    pub update_available: bool,
    pub target: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Activation {
    pub product: Product,
    pub version: Option<String>,
    pub changed: bool,
    pub managed: bool,
    pub outcome: String,
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct VerifiedManifest {
    root_generation: u64,
    root_sha256: String,
    manifest: ProductManifest,
    artifact: Artifact,
    manifest_sha256: String,
}

#[derive(Debug)]
struct FetchResult {
    bytes: Vec<u8>,
    etag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubAsset>,
}

#[derive(Debug, Deserialize)]
struct GitHubAsset {
    name: String,
    browser_download_url: String,
}

pub(crate) fn status(product: Product) -> Result<Status> {
    let paths = Paths::resolve(product)?;
    let state = load_state(&paths)?;
    Ok(Status {
        product,
        installed_version: state.active_version.clone(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        previous_version: state.previous_version,
        managed: is_managed_install(&paths),
        last_successful_check_unix: state.last_successful_check_unix,
    })
}

pub(crate) fn check(product: Product) -> Result<Check> {
    let paths = Paths::resolve(product)?;
    let mut state = load_state(&paths)?;
    let verified = fetch_verified_manifest(product, &paths, &state)?;
    accept_manifest_metadata(&mut state, &verified)?;
    state.last_successful_check_unix = Some(now_unix());
    save_state(&paths, &state)?;
    check_from_verified(product, &state, &verified)
}

pub(crate) fn update(product: Product) -> Result<Activation> {
    let paths = Paths::resolve(product)?;
    if paths.public_binary.exists() && !is_managed_install(&paths) {
        return Ok(externally_managed(product, &paths));
    }
    let mut state = load_state(&paths)?;
    #[cfg(unix)]
    adopt_legacy_installation(product, &paths, &mut state)?;
    let verified = fetch_verified_manifest(product, &paths, &state)?;
    accept_manifest_metadata(&mut state, &verified)?;
    if activation_is_current(&paths, &state, &verified)? {
        state.last_successful_check_unix = Some(now_unix());
        save_state(&paths, &state)?;
        return Ok(Activation {
            product,
            version: Some(verified.manifest.version.clone()),
            changed: false,
            managed: true,
            outcome: "no_op".into(),
            path: Some(version_binary(&paths, &verified.manifest.version)),
        });
    }
    if activate_retained_verified(product, &paths, &mut state, &verified)? {
        state.last_successful_check_unix = Some(now_unix());
        save_state(&paths, &state)?;
        return Ok(Activation {
            product,
            version: Some(verified.manifest.version.clone()),
            changed: true,
            managed: true,
            outcome: "updated".into(),
            path: Some(version_binary(&paths, &verified.manifest.version)),
        });
    }
    let bytes = fetch_artifact(&verified.artifact)?;
    verify_artifact(&bytes, &verified.artifact)?;
    let activation = activate(product, &paths, &mut state, &verified, &bytes)?;
    state.last_successful_check_unix = Some(now_unix());
    save_state(&paths, &state)?;
    Ok(activation)
}

fn activation_is_current(
    paths: &Paths,
    state: &ReleaseState,
    verified: &VerifiedManifest,
) -> Result<bool> {
    let version = &verified.manifest.version;
    if state.active_version.as_ref() != Some(version) || !is_managed_install(paths) {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        let receipt = verify_versioned_installation(&shared_installation_layout(
            Product::from_id(&verified.manifest.product)?,
            paths,
        )?)?;
        return Ok(receipt.active_version == *version
            && receipt.active_identity.length == verified.artifact.length
            && receipt.active_identity.sha256 == verified.artifact.sha256.to_ascii_lowercase());
    }
    #[cfg(not(unix))]
    {
        let target = version_binary(paths, version);
        if !target.is_file()
            || sha256_file(&target)? != verified.artifact.sha256
            || sha256_file(&paths.public_binary)? != verified.artifact.sha256
        {
            return Ok(false);
        }
        Ok(true)
    }
}

fn activate_retained_verified(
    product: Product,
    paths: &Paths,
    state: &mut ReleaseState,
    verified: &VerifiedManifest,
) -> Result<bool> {
    let version = &verified.manifest.version;
    let target = version_binary(paths, version);
    if !target.is_file() || sha256_file(&target)? != verified.artifact.sha256 {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        let identity = artifact_identity(&verified.artifact);
        let receipt = activate_existing_shared(product, paths, version, &identity)?;
        synchronize_installation_state(state, &receipt);
        return Ok(true);
    }
    #[cfg(not(unix))]
    {
        let previous = state.active_version.clone();
        activate_link(product, paths, version)?;
        state.previous_version = previous.filter(|value| value != version);
        state.active_version = Some(version.clone());
        prune_versions(paths, state)?;
        Ok(true)
    }
}

pub(crate) fn install(product: Product) -> Result<Activation> {
    update(product)
}

pub(crate) fn update_if_installed(product: Product) -> Result<Activation> {
    let paths = Paths::resolve(product)?;
    if !paths.public_binary.exists() {
        return Ok(Activation {
            product,
            version: None,
            changed: false,
            managed: false,
            outcome: "not_applicable".into(),
            path: None,
        });
    }
    update(product)
}

pub(crate) fn rollback(product: Product) -> Result<Activation> {
    let paths = Paths::resolve(product)?;
    let mut state = load_state(&paths)?;
    #[cfg(unix)]
    {
        adopt_legacy_installation(product, &paths, &mut state)?;
        let report = rollback_versioned_installation(
            &shared_installation_layout(product, &paths)?,
            |candidate| {
                let version = candidate
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|value| value.to_str())
                    .context("rollback candidate has no version directory")?;
                verify_candidate_health(product, candidate, version)
            },
        )?;
        synchronize_installation_state(&mut state, &report.receipt);
        save_state(&paths, &state)?;
        return Ok(Activation {
            product,
            version: Some(report.receipt.active_version.clone()),
            changed: report.changed,
            managed: true,
            outcome: "rolled_back".into(),
            path: Some(version_binary(&paths, &report.receipt.active_version)),
        });
    }
    #[cfg(not(unix))]
    {
        let previous = state.previous_version.clone().with_context(|| {
            format!(
                "no retained {} version is available for rollback",
                product.id()
            )
        })?;
        let binary = version_binary(&paths, &previous);
        if !binary.is_file() {
            bail!("retained rollback binary is missing: {}", binary.display());
        }
        activate_link(product, &paths, &previous)?;
        let old_active = state.active_version.replace(previous.clone());
        state.previous_version = old_active;
        save_state(&paths, &state)?;
        Ok(Activation {
            product,
            version: Some(previous),
            changed: true,
            managed: true,
            outcome: "rolled_back".into(),
            path: Some(binary),
        })
    }
}

pub(crate) fn maybe_auto_update() -> Result<Option<Activation>> {
    let product = Product::UpdateAll;
    let paths = Paths::resolve(product)?;
    if !is_managed_install(&paths) {
        return Ok(None);
    }
    let state = load_state(&paths)?;
    if !check_due(&state) {
        return Ok(None);
    }
    match update(product) {
        Ok(activation) => Ok(Some(activation)),
        Err(err) if err.downcast_ref::<IntegrityFailure>().is_some() => Err(err),
        Err(err) => {
            crate::ua_errln!("warning: automatic update check unavailable: {err:#}");
            Ok(None)
        }
    }
}

fn check_from_verified(
    product: Product,
    state: &ReleaseState,
    verified: &VerifiedManifest,
) -> Result<Check> {
    let latest = Version::parse(&verified.manifest.version).context("parse release version")?;
    let installed = state
        .active_version
        .as_deref()
        .map(Version::parse)
        .transpose()
        .context("parse installed version")?;
    Ok(Check {
        product,
        installed_version: state.active_version.clone(),
        latest_version: verified.manifest.version.clone(),
        update_available: installed.is_none_or(|installed| latest > installed),
        target: target_id(),
    })
}

fn check_due(state: &ReleaseState) -> bool {
    let Some(last) = state.last_successful_check_unix else {
        return true;
    };
    let seed = state
        .accepted_binary_sha256
        .as_deref()
        .and_then(|value| value.get(0..8))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .unwrap_or(0);
    now_unix().saturating_sub(last) >= CHECK_INTERVAL_SECS + (seed % (MAX_JITTER_SECS + 1))
}

fn fetch_verified_manifest(
    product: Product,
    paths: &Paths,
    state: &ReleaseState,
) -> Result<VerifiedManifest> {
    let (root_url, manifest_url) = resolve_release_urls(product)?;
    let root_bytes = fetch_cached(
        &root_url,
        &paths.root_cache,
        &paths.root_etag,
        METADATA_LIMIT,
    )?;
    let manifest_bytes = fetch_cached(
        &manifest_url,
        &paths.manifest_cache,
        &paths.manifest_etag,
        METADATA_LIMIT,
    )?;
    let verified = verify_release_metadata(
        &ReleaseMetadata {
            root: root_bytes,
            manifest: manifest_bytes,
        },
        &ReleaseAuthority {
            trusted_root_key: env!("UPDATE_ALL_TRUST_ROOT_PUBLIC_KEY").into(),
            product: product.id().into(),
            accepted_manifest_schemas: vec!["dev-tools-product-v1".into()],
            target: target_id(),
            artifact_url: ArtifactUrlPolicy::GitHubRelease {
                owner: "FutureDevGuys".into(),
                repository: "dev-tools".into(),
            },
            require_source_commit: false,
            engine_protocol: ENGINE_PROTOCOL,
        },
    )
    .map_err(|error| {
        IntegrityFailure(format!("authenticated release metadata failed: {error:#}"))
    })?;
    let artifact = Artifact {
        url: verified.artifact_url,
        length: verified.artifact_length,
        sha256: verified.artifact_sha256,
    };
    let manifest = ProductManifest {
        schema: verified.manifest_schema,
        product: verified.product,
        generation: verified.manifest_generation,
        version: verified.version.to_string(),
        engine_protocol: ENGINE_PROTOCOL,
        artifacts: BTreeMap::from([(target_id(), artifact.clone())]),
    };
    Ok(VerifiedManifest {
        root_generation: verified.root_generation,
        root_sha256: verified.root_sha256,
        manifest,
        artifact,
        manifest_sha256: verified.manifest_sha256,
    })
}

#[cfg(test)]
fn verify_root(envelope: &SignedEnvelope<RootDocument>) -> Result<()> {
    if envelope.signed.schema != "dev-tools-root-v1" {
        return integrity("unsupported root document schema");
    }
    let key = parse_public_key(env!("UPDATE_ALL_TRUST_ROOT_PUBLIC_KEY"))?;
    verify_any_signature(envelope, &key)
}

#[cfg(test)]
fn verify_product_manifest(
    envelope: &SignedEnvelope<ProductManifest>,
    root: &RootDocument,
) -> Result<()> {
    let signed = serde_jcs::to_vec(&envelope.signed).context("canonicalize product manifest")?;
    for signature in &envelope.signatures {
        let Some(key) = root
            .release_keys
            .iter()
            .find(|key| key.key_id == signature.key_id && !key.revoked)
        else {
            continue;
        };
        let verifying_key = parse_public_key(&key.public_key)?;
        if verify_signature(&verifying_key, &signed, &signature.signature).is_ok() {
            return Ok(());
        }
    }
    integrity("product manifest has no valid signature from an authorized release key")
}

#[cfg(test)]
fn verify_any_signature<T: Serialize>(
    envelope: &SignedEnvelope<T>,
    key: &VerifyingKey,
) -> Result<()> {
    let signed = serde_jcs::to_vec(&envelope.signed).context("canonicalize signed document")?;
    for signature in &envelope.signatures {
        if verify_signature(key, &signed, &signature.signature).is_ok() {
            return Ok(());
        }
    }
    integrity("root document signature is invalid")
}

#[cfg(test)]
fn verify_signature(key: &VerifyingKey, message: &[u8], encoded: &str) -> Result<()> {
    let bytes = BASE64
        .decode(encoded.trim())
        .context("decode Ed25519 signature")?;
    let signature = Signature::try_from(bytes.as_slice()).context("parse Ed25519 signature")?;
    key.verify_strict(message, &signature)
        .context("verify Ed25519 signature")
}

#[cfg(test)]
fn parse_public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes = decode_hex(encoded).context("decode Ed25519 public key")?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&array).context("parse Ed25519 public key")
}

#[cfg(test)]
fn validate_manifest(product: Product, manifest: &ProductManifest) -> Result<()> {
    if manifest.schema != "dev-tools-product-v1" {
        return integrity("unsupported product manifest schema");
    }
    if manifest.product != product.id() {
        return integrity("product manifest names a different product");
    }
    if manifest.engine_protocol != ENGINE_PROTOCOL {
        return integrity("product manifest requires an unsupported engine protocol");
    }
    Version::parse(&manifest.version).context("parse product manifest version")?;
    Ok(())
}

fn accept_manifest_metadata(state: &mut ReleaseState, verified: &VerifiedManifest) -> Result<()> {
    let mut shared = SharedReleaseState {
        accepted_root_generation: state.accepted_root_generation,
        accepted_root_sha256: state.accepted_root_sha256.clone(),
        accepted_generation: state.accepted_generation,
        accepted_version: state.accepted_version.clone(),
        accepted_manifest_sha256: state.accepted_manifest_sha256.clone(),
        accepted_binary_sha256: state.accepted_binary_sha256.clone(),
    };
    accept_verified_release(
        &mut shared,
        &SharedVerifiedRelease {
            root_generation: verified.root_generation,
            root_sha256: verified.root_sha256.clone(),
            manifest_generation: verified.manifest.generation,
            manifest_sha256: verified.manifest_sha256.clone(),
            manifest_schema: verified.manifest.schema.clone(),
            product: verified.manifest.product.clone(),
            version: Version::parse(&verified.manifest.version)
                .context("parse offered release version")?,
            source_commit: None,
            target: target_id(),
            artifact_url: verified.artifact.url.clone(),
            artifact_length: verified.artifact.length,
            artifact_sha256: verified.artifact.sha256.clone(),
        },
    )
    .map_err(|error| IntegrityFailure(format!("release state rejected metadata: {error:#}")))?;
    state.accepted_root_generation = shared.accepted_root_generation;
    state.accepted_root_sha256 = shared.accepted_root_sha256;
    state.accepted_generation = shared.accepted_generation;
    state.accepted_version = shared.accepted_version;
    state.accepted_manifest_sha256 = shared.accepted_manifest_sha256;
    state.accepted_binary_sha256 = shared.accepted_binary_sha256;
    Ok(())
}

fn fetch_artifact(artifact: &Artifact) -> Result<Vec<u8>> {
    let fetched = https_get(&artifact.url, None, artifact.length.saturating_add(1))?;
    Ok(fetched.bytes)
}

fn verify_artifact(bytes: &[u8], artifact: &Artifact) -> Result<()> {
    if bytes.len() as u64 != artifact.length {
        return integrity("downloaded artifact length does not match the signed manifest");
    }
    if sha256_hex(bytes) != artifact.sha256.to_ascii_lowercase() {
        return integrity("downloaded artifact hash does not match the signed manifest");
    }
    Ok(())
}

fn activate(
    product: Product,
    paths: &Paths,
    state: &mut ReleaseState,
    verified: &VerifiedManifest,
    bytes: &[u8],
) -> Result<Activation> {
    let version = &verified.manifest.version;
    let target = version_binary(paths, version);
    #[cfg(unix)]
    {
        let staged = paths
            .product_root
            .join("cache")
            .join(format!(".{}.candidate", product.id()));
        atomic_write(&staged, bytes, true)?;
        let identity = artifact_identity(&verified.artifact);
        let report = apply_versioned_installation(
            &VersionedInstallRequest {
                layout: shared_installation_layout(product, paths)?,
                version: version.clone(),
                source: staged.clone(),
                identity,
                aliases: vec![paths.executable_name.clone()],
            },
            |candidate| verify_candidate_health(product, candidate, version),
        );
        let _ = fs::remove_file(staged);
        let report = report?;
        synchronize_installation_state(state, &report.receipt);
        return Ok(Activation {
            product,
            version: Some(version.clone()),
            changed: report.changed,
            managed: true,
            outcome: if report.changed { "updated" } else { "no_op" }.into(),
            path: Some(target),
        });
    }
    #[cfg(not(unix))]
    {
        if target.is_file() && sha256_file(&target)? == verified.artifact.sha256 {
            activate_link(product, paths, version)?;
            state.active_version = Some(version.clone());
            return Ok(Activation {
                product,
                version: Some(version.clone()),
                changed: false,
                managed: true,
                outcome: "no_op".into(),
                path: Some(target),
            });
        }
        let parent = target.parent().context("version binary has no parent")?;
        create_private_dir(parent)?;
        atomic_write(&target, bytes, true)?;
        verify_candidate_health(product, &target, version)?;
        let previous = state.active_version.clone();
        activate_link(product, paths, version)?;
        state.previous_version = previous.filter(|value| value != version);
        state.active_version = Some(version.clone());
        prune_versions(paths, state)?;
        Ok(Activation {
            product,
            version: Some(version.clone()),
            changed: true,
            managed: true,
            outcome: "updated".into(),
            path: Some(target),
        })
    }
}

fn activate_link(product: Product, paths: &Paths, version: &str) -> Result<()> {
    let binary = version_binary(paths, version);
    if !binary.is_file() {
        bail!(
            "cannot activate missing release binary: {}",
            binary.display()
        );
    }
    create_private_dir(&paths.product_root)?;
    create_private_dir(&paths.bin_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let current_tmp = paths.product_root.join(".current.tmp");
        let _ = fs::remove_file(&current_tmp);
        symlink(paths.versions.join(version), &current_tmp)
            .context("create atomic current-version link")?;
        fs::rename(&current_tmp, &paths.current).context("activate current-version link")?;

        let public_tmp = paths.bin_dir.join(format!(".{}.tmp", product.id()));
        let _ = fs::remove_file(&public_tmp);
        symlink(paths.current.join(product.id()), &public_tmp)
            .context("create public command link")?;
        if paths.public_binary.exists() || fs::symlink_metadata(&paths.public_binary).is_ok() {
            fs::remove_file(&paths.public_binary).context("replace public command link")?;
        }
        fs::rename(&public_tmp, &paths.public_binary).context("activate public command link")?;
    }
    #[cfg(windows)]
    {
        let staged = paths.bin_dir.join(format!("{}.next.exe", product.id()));
        fs::copy(&binary, &staged).context("stage update-all replacement")?;
        let backup = paths.bin_dir.join(format!("{}.previous.exe", product.id()));
        if paths.public_binary.is_file() {
            let _ = fs::remove_file(&backup);
            fs::rename(&paths.public_binary, &backup)
                .context("retain prior update-all executable")?;
        }
        if let Err(error) = fs::rename(&staged, &paths.public_binary) {
            if backup.is_file() && !paths.public_binary.exists() {
                let _ = fs::rename(&backup, &paths.public_binary);
            }
            crate::ua_errln!(
                "{} activation deferred: close running processes and retry ({error})",
                product.id()
            );
            return Err(crate::Deferred.into());
        }
    }
    Ok(())
}

fn verify_candidate_health(product: Product, binary: &Path, expected_version: &str) -> Result<()> {
    let mut child = Command::new(binary)
        .args(product.health_args())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("launch candidate release {}", binary.display()))?;
    if child.wait_timeout(Duration::from_secs(10))?.is_none() {
        let _ = child.kill();
        let _ = child.wait();
        return integrity("candidate release health check timed out");
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return integrity("candidate release health check failed");
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("{} {expected_version}", product.id());
    if !stdout.lines().any(|line| line.starts_with(&expected)) {
        return integrity("candidate release reported an unexpected version");
    }
    Ok(())
}

fn prune_versions(paths: &Paths, state: &ReleaseState) -> Result<()> {
    let mut keep = vec![
        state.active_version.as_deref(),
        state.previous_version.as_deref(),
    ];
    keep.retain(Option::is_some);
    if !paths.versions.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&paths.versions).context("read retained product versions")? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.file_type()?.is_dir() && !keep.iter().any(|value| *value == Some(name.as_str())) {
            fs::remove_dir_all(entry.path()).with_context(|| format!("prune release {name}"))?;
        }
    }
    Ok(())
}

fn fetch_cached(url: &str, cache: &Path, etag_path: &Path, limit: u64) -> Result<Vec<u8>> {
    let etag = fs::read_to_string(etag_path).ok();
    match https_get(url, etag.as_deref().map(str::trim), limit) {
        Ok(fetched) => {
            atomic_write(cache, &fetched.bytes, false)?;
            if let Some(etag) = fetched.etag {
                atomic_write(etag_path, etag.as_bytes(), false)?;
            }
            Ok(fetched.bytes)
        }
        Err(err) if err.to_string().contains("not modified") && cache.is_file() => {
            fs::read(cache).with_context(|| format!("read cached metadata {}", cache.display()))
        }
        Err(err) => Err(err),
    }
}

fn https_get(url: &str, etag: Option<&str>, limit: u64) -> Result<FetchResult> {
    if !url.starts_with("https://") {
        return integrity("release URL must use HTTPS");
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .http_status_as_error(false)
        .max_redirects(3)
        .max_redirects_will_error(true)
        .save_redirect_history(true)
        .timeout_global(Some(Duration::from_secs(30)))
        .user_agent(format!("update-all/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut request = agent.get(url).header("Accept", accept_media_type(url));
    if let Some(etag) = etag {
        request = request.header("If-None-Match", etag);
    }
    let mut response = request.call().with_context(|| format!("GET {url}"))?;
    if response.status().as_u16() == 304 {
        bail!("not modified");
    }
    if !response.status().is_success() {
        bail!("GET {url} returned HTTP {}", response.status());
    }
    if let Some(history) = response.get_redirect_history() {
        for uri in history {
            if uri.scheme_str() != Some("https")
                || !allowed_release_host(uri.host().unwrap_or_default())
            {
                return integrity("release request traversed an untrusted redirect");
            }
        }
    }
    let final_host = response.get_uri().host().unwrap_or_default();
    if !allowed_release_host(final_host) {
        return integrity("release request redirected to an untrusted host");
    }
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .with_context(|| format!("read bounded response from {url}"))?;
    Ok(FetchResult { bytes, etag })
}

fn accept_media_type(url: &str) -> &'static str {
    if url.starts_with("https://api.github.com/") {
        "application/vnd.github+json"
    } else {
        "application/octet-stream"
    }
}

fn allowed_release_host(host: &str) -> bool {
    matches!(
        host,
        "api.github.com"
            | "github.com"
            | "objects.githubusercontent.com"
            | "github-releases.githubusercontent.com"
            | "release-assets.githubusercontent.com"
    )
}

fn resolve_release_urls(product: Product) -> Result<(String, String)> {
    match (
        env::var("DEV_TOOLS_ROOT_URL").ok(),
        env::var("DEV_TOOLS_MANIFEST_URL").ok(),
    ) {
        (Some(root), Some(manifest)) => return Ok((root, manifest)),
        (None, None) => {}
        _ => bail!("DEV_TOOLS_ROOT_URL and DEV_TOOLS_MANIFEST_URL must be set together"),
    }

    let releases_url =
        env::var("DEV_TOOLS_RELEASES_URL").unwrap_or_else(|_| RELEASES_URL.to_string());
    let bytes = https_get(&releases_url, None, METADATA_LIMIT)?.bytes;
    let selected = select_stable_release_assets(
        &bytes,
        product.id(),
        "dev-tools-root.json",
        &format!("{}-stable.json", product.id()),
    )?;
    Ok((selected.root_url, selected.manifest_url))
}

fn select_release_urls(releases: &[GitHubRelease], product: Product) -> Result<(String, String)> {
    let prefix = format!("{}/v", product.id());
    let selected = releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let version = release.tag_name.strip_prefix(&prefix)?;
            Version::parse(version)
                .ok()
                .map(|version| (version, release))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, release)| release)
        .with_context(|| format!("no stable {} release is published", product.id()))?;
    let asset_url = |name: &str| {
        selected
            .assets
            .iter()
            .find(|asset| asset.name == name)
            .map(|asset| asset.browser_download_url.clone())
            .with_context(|| {
                format!(
                    "release {} is missing required asset {name}",
                    selected.tag_name
                )
            })
    };
    Ok((
        asset_url("dev-tools-root.json")?,
        asset_url(&format!("{}-stable.json", product.id()))?,
    ))
}

fn is_managed_install(paths: &Paths) -> bool {
    fs::canonicalize(&paths.public_binary).is_ok_and(|path| path.starts_with(&paths.product_root))
}

fn externally_managed(product: Product, paths: &Paths) -> Activation {
    Activation {
        product,
        version: None,
        changed: false,
        managed: false,
        outcome: "externally_managed".into(),
        path: Some(paths.public_binary.clone()),
    }
}

fn target_id() -> String {
    let os = match env::consts::OS {
        "macos" => "macos",
        value => value,
    };
    let arch = match env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        value => value,
    };
    format!("{os}-{arch}")
}

fn version_binary(paths: &Paths, version: &str) -> PathBuf {
    paths.versions.join(version).join(&paths.executable_name)
}

#[cfg(unix)]
fn shared_installation_layout(product: Product, paths: &Paths) -> Result<VersionedLayout> {
    use std::os::unix::fs::MetadataExt;

    let mut authority_path = paths.product_root.as_path();
    let owner_uid = loop {
        match fs::symlink_metadata(authority_path) {
            Ok(metadata) => break metadata.uid(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                authority_path = authority_path
                    .parent()
                    .context("managed product root has no existing authority ancestor")?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "inspect installation authority {}",
                        authority_path.display()
                    )
                });
            }
        }
    };
    Ok(VersionedLayout {
        product: product.id().into(),
        data_root: paths.product_root.clone(),
        bin_dir: paths.bin_dir.clone(),
        artifact_name: paths.executable_name.clone(),
        owner_uid,
        directory_mode: 0o700,
    })
}

#[cfg(unix)]
fn adopt_legacy_installation(
    product: Product,
    paths: &Paths,
    state: &mut ReleaseState,
) -> Result<()> {
    let layout = shared_installation_layout(product, paths)?;
    if fs::symlink_metadata(paths.product_root.join("installation-receipt-v1.json")).is_ok() {
        verify_versioned_installation(&layout)?;
        return Ok(());
    }
    let Some(version) = state.active_version.as_deref() else {
        return Ok(());
    };
    let artifact = version_binary(paths, version);
    let identity = ArtifactIdentity::from_file(&artifact, ARTIFACT_LIMIT)?;
    if state
        .accepted_binary_sha256
        .as_deref()
        .is_some_and(|approved| approved != identity.sha256)
    {
        bail!("legacy managed artifact does not match authenticated release state");
    }
    let expected_current = paths.versions.join(version);
    let expected_public = paths.current.join(product.id());
    let current_present = verify_optional_legacy_symlink(&paths.current, &expected_current)?;
    let public_present = verify_optional_legacy_symlink(&paths.public_binary, &expected_public)?;
    verify_candidate_health(product, &artifact, version)?;
    if public_present {
        fs::remove_file(&paths.public_binary).context("detach legacy public command pointer")?;
    }
    if current_present {
        fs::remove_file(&paths.current).context("detach legacy current-version pointer")?;
    }
    adopt_versioned_installation(
        &VersionedAdoption {
            layout,
            version: version.into(),
            identity,
            aliases: vec![paths.executable_name.clone()],
        },
        |candidate| verify_candidate_health(product, candidate, version),
    )?;
    Ok(())
}

#[cfg(unix)]
fn verify_optional_legacy_symlink(path: &Path, expected: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() && fs::read_link(path)? == expected => {
            Ok(true)
        }
        Ok(_) => bail!("legacy managed installation pointer does not match authenticated state"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect legacy managed installation pointer"),
    }
}

#[cfg(unix)]
fn artifact_identity(artifact: &Artifact) -> ArtifactIdentity {
    ArtifactIdentity {
        length: artifact.length,
        sha256: artifact.sha256.to_ascii_lowercase(),
    }
}

#[cfg(unix)]
fn activate_existing_shared(
    product: Product,
    paths: &Paths,
    version: &str,
    identity: &ArtifactIdentity,
) -> Result<VersionedReceipt> {
    let layout = shared_installation_layout(product, paths)?;
    let receipt_path = paths.product_root.join("installation-receipt-v1.json");
    if fs::symlink_metadata(receipt_path).is_ok() {
        return Ok(apply_versioned_installation(
            &VersionedInstallRequest {
                layout,
                version: version.into(),
                source: version_binary(paths, version),
                identity: identity.clone(),
                aliases: vec![paths.executable_name.clone()],
            },
            |candidate| verify_candidate_health(product, candidate, version),
        )?
        .receipt);
    }
    Ok(adopt_versioned_installation(
        &VersionedAdoption {
            layout,
            version: version.into(),
            identity: identity.clone(),
            aliases: vec![paths.executable_name.clone()],
        },
        |candidate| verify_candidate_health(product, candidate, version),
    )?
    .receipt)
}

#[cfg(unix)]
fn synchronize_installation_state(state: &mut ReleaseState, receipt: &VersionedReceipt) {
    state.active_version = Some(receipt.active_version.clone());
    state.previous_version = receipt.previous_version.clone();
}

fn load_state(paths: &Paths) -> Result<ReleaseState> {
    if !paths.state.is_file() {
        return Ok(ReleaseState::default());
    }
    let bytes = fs::read(&paths.state).context("read update-all release state")?;
    parse_json(&bytes, "release state")
}

fn save_state(paths: &Paths, state: &ReleaseState) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(state).context("serialize release state")?;
    atomic_write(&paths.state, &bytes, false)
}

fn parse_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    serde_json::from_slice(bytes).with_context(|| format!("parse {label}"))
}

#[cfg(test)]
fn parse_trusted_json<T: for<'de> Deserialize<'de>>(bytes: &[u8], label: &str) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|error| IntegrityFailure(format!("invalid {label}: {error}")).into())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        bail!("hex value has odd length");
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).context("parse hex byte"))
        .collect()
}

fn atomic_write(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let parent = path.parent().context("managed path has no parent")?;
    create_private_dir(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file"),
        std::process::id()
    ));
    let mut file = File::create(&temp).with_context(|| format!("create {}", temp.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &temp,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o600 }),
        )?;
    }
    fs::rename(&temp, path).with_context(|| format!("activate {}", path.display()))
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn integrity<T>(message: impl Into<String>) -> Result<T> {
    Err(IntegrityFailure(message.into()).into())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[derive(Debug)]
struct Paths {
    product_root: PathBuf,
    versions: PathBuf,
    current: PathBuf,
    state: PathBuf,
    root_cache: PathBuf,
    root_etag: PathBuf,
    manifest_cache: PathBuf,
    manifest_etag: PathBuf,
    bin_dir: PathBuf,
    public_binary: PathBuf,
    executable_name: String,
}

impl Paths {
    fn resolve(product: Product) -> Result<Self> {
        let home = env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })
            .map(PathBuf::from)
            .context("home directory is unavailable")?;
        let state_home = if cfg!(windows) {
            env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join("AppData/Local"))
        } else {
            env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| home.join(".local/state"))
        };
        let bin_dir = if cfg!(windows) {
            state_home.join("dev-tools/bin")
        } else {
            home.join(".local/bin")
        };
        let product_root = state_home.join("dev-tools/products").join(product.id());
        let cache = product_root.join("cache");
        let executable_name = product.executable_name();
        Ok(Self {
            versions: product_root.join("versions"),
            current: product_root.join("current"),
            state: product_root.join("state.json"),
            root_cache: cache.join("root.json"),
            root_etag: cache.join("root.etag"),
            manifest_cache: cache.join("manifest.json"),
            manifest_etag: cache.join("manifest.etag"),
            public_binary: bin_dir.join(&executable_name),
            bin_dir,
            product_root,
            executable_name,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn envelope<T: Clone + Serialize>(
        signed: T,
        key_id: &str,
        key: &SigningKey,
    ) -> SignedEnvelope<T> {
        let bytes = serde_jcs::to_vec(&signed).unwrap();
        SignedEnvelope {
            signed,
            signatures: vec![DocumentSignature {
                key_id: key_id.to_string(),
                signature: BASE64.encode(key.sign(&bytes).to_bytes()),
            }],
        }
    }

    fn github_release(tag: &str, draft: bool, prerelease: bool) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.into(),
            draft,
            prerelease,
            assets: vec![
                GitHubAsset {
                    name: "dev-tools-root.json".into(),
                    browser_download_url: format!("https://github.com/root/{tag}"),
                },
                GitHubAsset {
                    name: "dev-cache-stable.json".into(),
                    browser_download_url: format!("https://github.com/manifest/{tag}"),
                },
            ],
        }
    }

    #[test]
    fn product_release_resolution_uses_latest_stable_matching_tag() {
        let releases = vec![
            github_release("dev-cache/v1.2.0", false, false),
            github_release("dev-cache/v9.0.0", true, false),
            github_release("dev-cache/v8.0.0", false, true),
            github_release("update-all/v7.0.0", false, false),
            github_release("dev-cache/v1.10.0", false, false),
        ];
        let (root, manifest) = select_release_urls(&releases, Product::DevCache).unwrap();
        assert!(root.ends_with("dev-cache/v1.10.0"));
        assert!(manifest.ends_with("dev-cache/v1.10.0"));
    }

    #[test]
    fn authorized_manifest_signature_is_accepted() {
        let release = SigningKey::from_bytes(&[7_u8; 32]);
        let root = RootDocument {
            schema: "dev-tools-root-v1".into(),
            generation: 3,
            release_keys: vec![ReleaseKey {
                key_id: "release-1".into(),
                public_key: release
                    .verifying_key()
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                revoked: false,
            }],
        };
        let manifest = ProductManifest {
            schema: "dev-tools-product-v1".into(),
            product: Product::UpdateAll.id().into(),
            generation: 4,
            version: "1.2.3".into(),
            engine_protocol: ENGINE_PROTOCOL,
            artifacts: BTreeMap::new(),
        };
        verify_product_manifest(&envelope(manifest, "release-1", &release), &root).unwrap();
    }

    #[test]
    fn dual_signed_root_document_accepts_each_rotation_key() {
        let current = SigningKey::from_bytes(&[2_u8; 32]);
        let next = SigningKey::from_bytes(&[3_u8; 32]);
        let document = RootDocument {
            schema: "dev-tools-root-v1".into(),
            generation: 2,
            release_keys: Vec::new(),
        };
        let bytes = serde_jcs::to_vec(&document).unwrap();
        let envelope = SignedEnvelope {
            signed: document,
            signatures: [&current, &next]
                .into_iter()
                .map(|key| DocumentSignature {
                    key_id: "root-transition".into(),
                    signature: BASE64.encode(key.sign(&bytes).to_bytes()),
                })
                .collect(),
        };

        verify_any_signature(&envelope, &current.verifying_key()).unwrap();
        verify_any_signature(&envelope, &next.verifying_key()).unwrap();
    }

    #[test]
    fn revoked_release_key_is_rejected() {
        let release = SigningKey::from_bytes(&[9_u8; 32]);
        let root = RootDocument {
            schema: "dev-tools-root-v1".into(),
            generation: 3,
            release_keys: vec![ReleaseKey {
                key_id: "release-1".into(),
                public_key: release
                    .verifying_key()
                    .to_bytes()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
                revoked: true,
            }],
        };
        let manifest = ProductManifest {
            schema: "dev-tools-product-v1".into(),
            product: Product::UpdateAll.id().into(),
            generation: 4,
            version: "1.2.3".into(),
            engine_protocol: ENGINE_PROTOCOL,
            artifacts: BTreeMap::new(),
        };
        let err =
            verify_product_manifest(&envelope(manifest, "release-1", &release), &root).unwrap_err();
        assert!(err.downcast_ref::<IntegrityFailure>().is_some());
    }

    #[test]
    fn rollback_and_equivocation_are_rejected() {
        let verified = |generation, version: &str, hash: &str| VerifiedManifest {
            root_generation: 1,
            root_sha256: "root".into(),
            manifest: ProductManifest {
                schema: "dev-tools-product-v1".into(),
                product: Product::UpdateAll.id().into(),
                generation,
                version: version.into(),
                engine_protocol: ENGINE_PROTOCOL,
                artifacts: BTreeMap::new(),
            },
            artifact: Artifact {
                url: "https://github.com/example".into(),
                length: 1,
                sha256: "00".repeat(32),
            },
            manifest_sha256: hash.into(),
        };
        let mut state = ReleaseState::default();
        accept_manifest_metadata(&mut state, &verified(5, "2.0.0", "a")).unwrap();
        assert!(accept_manifest_metadata(&mut state, &verified(4, "2.1.0", "b")).is_err());
        assert!(accept_manifest_metadata(&mut state, &verified(5, "2.0.0", "b")).is_err());
        assert!(accept_manifest_metadata(&mut state, &verified(6, "1.9.0", "c")).is_err());
    }

    #[test]
    fn artifact_integrity_requires_exact_length_and_hash() {
        let bytes = b"release";
        let artifact = Artifact {
            url: "https://github.com/example".into(),
            length: bytes.len() as u64,
            sha256: sha256_hex(bytes),
        };
        verify_artifact(bytes, &artifact).unwrap();
        assert!(verify_artifact(b"release!", &artifact).is_err());
    }

    #[test]
    fn github_release_discovery_requests_json_while_assets_request_bytes() {
        assert_eq!(
            accept_media_type("https://api.github.com/repos/example/releases"),
            "application/vnd.github+json"
        );
        assert_eq!(
            accept_media_type("https://github.com/example/releases/download/tag/artifact"),
            "application/octet-stream"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_authenticated_artifact_repairs_activation_without_a_download() {
        let temp = tempfile::tempdir().unwrap();
        let product_root = temp.path().join("products/update-all");
        let bin_dir = temp.path().join("bin");
        let paths = Paths {
            versions: product_root.join("versions"),
            current: product_root.join("current"),
            state: product_root.join("state.json"),
            root_cache: product_root.join("cache/root.json"),
            root_etag: product_root.join("cache/root.etag"),
            manifest_cache: product_root.join("cache/manifest.json"),
            manifest_etag: product_root.join("cache/manifest.etag"),
            public_binary: bin_dir.join("update-all"),
            bin_dir,
            product_root,
            executable_name: "update-all".into(),
        };
        let version = "1.2.3";
        let target = version_binary(&paths, version);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        crate::test_support::write_executable(
            &target,
            "#!/bin/sh\nprintf '%s\\n' 'update-all 1.2.3 profile=release'\n",
        )
        .unwrap();
        let bytes = fs::read(&target).unwrap();
        let verified = VerifiedManifest {
            root_generation: 1,
            root_sha256: "root".into(),
            manifest: ProductManifest {
                schema: "dev-tools-product-v1".into(),
                product: Product::UpdateAll.id().into(),
                generation: 1,
                version: version.into(),
                engine_protocol: ENGINE_PROTOCOL,
                artifacts: BTreeMap::new(),
            },
            artifact: Artifact {
                url: "https://github.com/example".into(),
                length: bytes.len() as u64,
                sha256: sha256_hex(&bytes),
            },
            manifest_sha256: "manifest".into(),
        };
        let mut state = ReleaseState::default();

        assert!(
            activate_retained_verified(Product::UpdateAll, &paths, &mut state, &verified).unwrap()
        );
        assert!(activation_is_current(&paths, &state, &verified).unwrap());
        assert_eq!(fs::canonicalize(paths.public_binary).unwrap(), target);
    }

    #[cfg(unix)]
    #[test]
    fn legacy_layout_is_adopted_by_the_shared_installation_authority() {
        let temp = tempfile::tempdir().unwrap();
        let product_root = temp.path().join("products/update-all");
        let bin_dir = temp.path().join("bin");
        let paths = Paths {
            versions: product_root.join("versions"),
            current: product_root.join("current"),
            state: product_root.join("state.json"),
            root_cache: product_root.join("cache/root.json"),
            root_etag: product_root.join("cache/root.etag"),
            manifest_cache: product_root.join("cache/manifest.json"),
            manifest_etag: product_root.join("cache/manifest.etag"),
            public_binary: bin_dir.join("update-all"),
            bin_dir,
            product_root,
            executable_name: "update-all".into(),
        };
        let version = "1.2.3";
        let target = version_binary(&paths, version);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        crate::test_support::write_executable(
            &target,
            "#!/bin/sh\nprintf '%s\\n' 'update-all 1.2.3 profile=release'\n",
        )
        .unwrap();
        activate_link(Product::UpdateAll, &paths, version).unwrap();
        let identity =
            dev_tools_installation::ArtifactIdentity::from_file(&target, ARTIFACT_LIMIT).unwrap();
        let mut state = ReleaseState {
            active_version: Some(version.into()),
            accepted_binary_sha256: Some(identity.sha256.clone()),
            ..ReleaseState::default()
        };

        adopt_legacy_installation(Product::UpdateAll, &paths, &mut state).unwrap();

        let receipt = dev_tools_installation::verify_versioned_installation(
            &shared_installation_layout(Product::UpdateAll, &paths).unwrap(),
        )
        .unwrap();
        assert_eq!(receipt.active_version, version);
        assert_eq!(receipt.active_identity, identity);
        assert_eq!(receipt.aliases, vec!["update-all"]);
        assert_eq!(fs::canonicalize(paths.public_binary).unwrap(), target);
        assert!(!paths.current.exists());
    }

    #[cfg(unix)]
    #[test]
    fn candidate_health_requires_the_signed_version() {
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("update-all");
        crate::test_support::write_executable(
            &binary,
            "#!/bin/sh\nprintf '%s\\n' 'update-all 1.2.3 profile=release'\n",
        )
        .unwrap();
        verify_candidate_health(Product::UpdateAll, &binary, "1.2.3").unwrap();
        let err = verify_candidate_health(Product::UpdateAll, &binary, "1.2.4").unwrap_err();
        assert!(err.downcast_ref::<IntegrityFailure>().is_some());
    }
}
