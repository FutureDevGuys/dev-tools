use crate::IntegrityFailure;
use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
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

const PRODUCT: &str = "update-all";
const ENGINE_PROTOCOL: u32 = 1;
const ROOT_URL: &str =
    "https://github.com/FutureDevGuys/dev-tools/releases/latest/download/dev-tools-root.json";
const MANIFEST_URL: &str =
    "https://github.com/FutureDevGuys/dev-tools/releases/latest/download/update-all-stable.json";
const METADATA_LIMIT: u64 = 512 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const CHECK_INTERVAL_SECS: u64 = 6 * 60 * 60;
const MAX_JITTER_SECS: u64 = 30 * 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedEnvelope<T> {
    pub signed: T,
    pub signatures: Vec<DocumentSignature>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DocumentSignature {
    pub key_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootDocument {
    pub schema: String,
    pub generation: u64,
    pub release_keys: Vec<ReleaseKey>,
}

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
    pub installed_version: Option<String>,
    pub running_version: String,
    pub previous_version: Option<String>,
    pub managed: bool,
    pub last_successful_check_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Check {
    pub installed_version: Option<String>,
    pub latest_version: String,
    pub update_available: bool,
    pub target: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Activation {
    pub version: String,
    pub changed: bool,
    pub path: PathBuf,
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

pub(crate) fn status() -> Result<Status> {
    let paths = Paths::resolve()?;
    let state = load_state(&paths)?;
    Ok(Status {
        installed_version: state.active_version.clone(),
        running_version: env!("CARGO_PKG_VERSION").to_string(),
        previous_version: state.previous_version,
        managed: is_managed_install(&paths),
        last_successful_check_unix: state.last_successful_check_unix,
    })
}

pub(crate) fn check() -> Result<Check> {
    let paths = Paths::resolve()?;
    let mut state = load_state(&paths)?;
    let verified = fetch_verified_manifest(&paths, &state)?;
    accept_root_metadata(&mut state, &verified);
    accept_manifest_metadata(&mut state, &verified)?;
    state.last_successful_check_unix = Some(now_unix());
    save_state(&paths, &state)?;
    check_from_verified(&state, &verified)
}

pub(crate) fn update() -> Result<Activation> {
    let paths = Paths::resolve()?;
    let mut state = load_state(&paths)?;
    let verified = fetch_verified_manifest(&paths, &state)?;
    accept_root_metadata(&mut state, &verified);
    accept_manifest_metadata(&mut state, &verified)?;
    let bytes = fetch_artifact(&verified.artifact)?;
    verify_artifact(&bytes, &verified.artifact)?;
    let activation = activate(&paths, &mut state, &verified, &bytes)?;
    state.last_successful_check_unix = Some(now_unix());
    save_state(&paths, &state)?;
    Ok(activation)
}

pub(crate) fn install() -> Result<Activation> {
    update()
}

pub(crate) fn rollback() -> Result<Activation> {
    let paths = Paths::resolve()?;
    let mut state = load_state(&paths)?;
    let previous = state
        .previous_version
        .clone()
        .context("no retained update-all version is available for rollback")?;
    let binary = version_binary(&paths, &previous);
    if !binary.is_file() {
        bail!("retained rollback binary is missing: {}", binary.display());
    }
    activate_link(&paths, &previous)?;
    let old_active = state.active_version.replace(previous.clone());
    state.previous_version = old_active;
    save_state(&paths, &state)?;
    Ok(Activation {
        version: previous,
        changed: true,
        path: binary,
    })
}

pub(crate) fn maybe_auto_update() -> Result<Option<Activation>> {
    let paths = Paths::resolve()?;
    if !is_managed_install(&paths) {
        return Ok(None);
    }
    let state = load_state(&paths)?;
    if !check_due(&state) {
        return Ok(None);
    }
    match update() {
        Ok(activation) => Ok(Some(activation)),
        Err(err) if err.downcast_ref::<IntegrityFailure>().is_some() => Err(err),
        Err(err) => {
            crate::ua_errln!("warning: automatic update check unavailable: {err:#}");
            Ok(None)
        }
    }
}

fn check_from_verified(state: &ReleaseState, verified: &VerifiedManifest) -> Result<Check> {
    let latest = Version::parse(&verified.manifest.version).context("parse release version")?;
    let installed_raw = state
        .active_version
        .as_deref()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let installed = Version::parse(installed_raw).context("parse installed version")?;
    Ok(Check {
        installed_version: state
            .active_version
            .clone()
            .or_else(|| Some(installed_raw.to_string())),
        latest_version: verified.manifest.version.clone(),
        update_available: latest > installed,
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

fn fetch_verified_manifest(paths: &Paths, state: &ReleaseState) -> Result<VerifiedManifest> {
    let root_bytes = fetch_cached(
        &root_url(),
        &paths.root_cache,
        &paths.root_etag,
        METADATA_LIMIT,
    )?;
    let root: SignedEnvelope<RootDocument> = parse_trusted_json(&root_bytes, "root document")?;
    verify_root(&root)?;
    let root_hash = sha256_hex(&root_bytes);
    if root.signed.generation < state.accepted_root_generation {
        return integrity("root document generation is older than trusted state");
    }
    if root.signed.generation == state.accepted_root_generation
        && state
            .accepted_root_sha256
            .as_ref()
            .is_some_and(|accepted| accepted != &root_hash)
    {
        return integrity("root document equivocation detected");
    }

    let manifest_bytes = fetch_cached(
        &manifest_url(),
        &paths.manifest_cache,
        &paths.manifest_etag,
        METADATA_LIMIT,
    )?;
    let envelope: SignedEnvelope<ProductManifest> =
        parse_trusted_json(&manifest_bytes, "product manifest")?;
    verify_product_manifest(&envelope, &root.signed)?;
    validate_manifest(&envelope.signed)?;
    let artifact = envelope
        .signed
        .artifacts
        .get(&target_id())
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("release does not provide target {}", target_id()))?;
    if artifact.length > ARTIFACT_LIMIT {
        return integrity("artifact length exceeds the supported limit");
    }
    Ok(VerifiedManifest {
        root_generation: root.signed.generation,
        root_sha256: root_hash,
        manifest: envelope.signed,
        artifact,
        manifest_sha256: sha256_hex(&manifest_bytes),
    })
}

fn verify_root(envelope: &SignedEnvelope<RootDocument>) -> Result<()> {
    if envelope.signed.schema != "dev-tools-root-v1" {
        return integrity("unsupported root document schema");
    }
    let key = parse_public_key(include_str!("../trust/root-public-key.txt").trim())?;
    verify_any_signature(envelope, "root", &key)
}

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

fn verify_any_signature<T: Serialize>(
    envelope: &SignedEnvelope<T>,
    expected_key_id: &str,
    key: &VerifyingKey,
) -> Result<()> {
    let signed = serde_jcs::to_vec(&envelope.signed).context("canonicalize signed document")?;
    for signature in &envelope.signatures {
        if signature.key_id == expected_key_id
            && verify_signature(key, &signed, &signature.signature).is_ok()
        {
            return Ok(());
        }
    }
    integrity("root document signature is invalid")
}

fn verify_signature(key: &VerifyingKey, message: &[u8], encoded: &str) -> Result<()> {
    let bytes = BASE64
        .decode(encoded.trim())
        .context("decode Ed25519 signature")?;
    let signature = Signature::try_from(bytes.as_slice()).context("parse Ed25519 signature")?;
    key.verify_strict(message, &signature)
        .context("verify Ed25519 signature")
}

fn parse_public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes = decode_hex(encoded).context("decode Ed25519 public key")?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&array).context("parse Ed25519 public key")
}

fn validate_manifest(manifest: &ProductManifest) -> Result<()> {
    if manifest.schema != "dev-tools-product-v1" {
        return integrity("unsupported product manifest schema");
    }
    if manifest.product != PRODUCT {
        return integrity("product manifest names a different product");
    }
    if manifest.engine_protocol != ENGINE_PROTOCOL {
        return integrity("product manifest requires an unsupported engine protocol");
    }
    Version::parse(&manifest.version).context("parse product manifest version")?;
    Ok(())
}

fn accept_manifest_metadata(state: &mut ReleaseState, verified: &VerifiedManifest) -> Result<()> {
    let generation = verified.manifest.generation;
    if generation < state.accepted_generation {
        return integrity("product manifest generation rollback detected");
    }
    if generation == state.accepted_generation {
        if let Some(hash) = &state.accepted_manifest_sha256 {
            if hash != &verified.manifest_sha256 {
                return integrity("product manifest equivocation detected");
            }
        }
    }
    if let Some(current) = &state.accepted_version {
        let accepted = Version::parse(current).context("parse trusted release version")?;
        let offered =
            Version::parse(&verified.manifest.version).context("parse offered release version")?;
        if offered < accepted {
            return integrity("product version rollback detected");
        }
    }
    state.accepted_generation = generation;
    state.accepted_version = Some(verified.manifest.version.clone());
    state.accepted_manifest_sha256 = Some(verified.manifest_sha256.clone());
    state.accepted_binary_sha256 = Some(verified.artifact.sha256.clone());
    Ok(())
}

fn accept_root_metadata(state: &mut ReleaseState, verified: &VerifiedManifest) {
    state.accepted_root_generation = verified.root_generation;
    state.accepted_root_sha256 = Some(verified.root_sha256.clone());
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
    paths: &Paths,
    state: &mut ReleaseState,
    verified: &VerifiedManifest,
    bytes: &[u8],
) -> Result<Activation> {
    let version = &verified.manifest.version;
    let target = version_binary(paths, version);
    if target.is_file() && sha256_file(&target)? == verified.artifact.sha256 {
        activate_link(paths, version)?;
        state.active_version = Some(version.clone());
        return Ok(Activation {
            version: version.clone(),
            changed: false,
            path: target,
        });
    }
    let parent = target.parent().context("version binary has no parent")?;
    create_private_dir(parent)?;
    atomic_write(&target, bytes, true)?;
    verify_candidate_health(&target, version)?;
    let previous = state.active_version.clone();
    activate_link(paths, version)?;
    state.previous_version = previous.filter(|value| value != version);
    state.active_version = Some(version.clone());
    prune_versions(paths, state)?;
    Ok(Activation {
        version: version.clone(),
        changed: true,
        path: target,
    })
}

fn activate_link(paths: &Paths, version: &str) -> Result<()> {
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

        let public_tmp = paths.bin_dir.join(".update-all.tmp");
        let _ = fs::remove_file(&public_tmp);
        symlink(paths.current.join(PRODUCT), &public_tmp).context("create public command link")?;
        if paths.public_binary.exists() || fs::symlink_metadata(&paths.public_binary).is_ok() {
            let backup = paths.product_root.join("pre-managed-update-all");
            if !backup.exists()
                && !fs::symlink_metadata(&paths.public_binary)?
                    .file_type()
                    .is_symlink()
            {
                fs::rename(&paths.public_binary, &backup)
                    .context("retain pre-managed update-all binary")?;
            } else {
                fs::remove_file(&paths.public_binary).context("replace public command link")?;
            }
        }
        fs::rename(&public_tmp, &paths.public_binary).context("activate public command link")?;
    }
    #[cfg(windows)]
    {
        let staged = paths.bin_dir.join("update-all.next.exe");
        fs::copy(&binary, &staged).context("stage update-all replacement")?;
        let backup = paths.bin_dir.join("update-all.previous.exe");
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
                "update-all activation deferred: close running update-all processes and retry ({error})"
            );
            return Err(crate::Deferred.into());
        }
    }
    Ok(())
}

fn verify_candidate_health(binary: &Path, expected_version: &str) -> Result<()> {
    let mut child = Command::new(binary)
        .arg("--version")
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
    let expected = format!("update-all {expected_version}");
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
    for entry in fs::read_dir(&paths.versions).context("read retained update-all versions")? {
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
    let mut request = agent.get(url).header("Accept", "application/octet-stream");
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

fn allowed_release_host(host: &str) -> bool {
    matches!(
        host,
        "github.com" | "objects.githubusercontent.com" | "github-releases.githubusercontent.com"
    )
}

fn root_url() -> String {
    env::var("UPDATE_ALL_ROOT_URL").unwrap_or_else(|_| ROOT_URL.to_string())
}

fn manifest_url() -> String {
    env::var("UPDATE_ALL_MANIFEST_URL").unwrap_or_else(|_| MANIFEST_URL.to_string())
}

fn is_managed_install(paths: &Paths) -> bool {
    let Ok(current) = env::current_exe() else {
        return false;
    };
    current.starts_with(&paths.product_root)
        || fs::canonicalize(current).is_ok_and(|path| path.starts_with(&paths.product_root))
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
    paths.versions.join(version).join(if cfg!(windows) {
        "update-all.exe"
    } else {
        PRODUCT
    })
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
}

impl Paths {
    fn resolve() -> Result<Self> {
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
        let product_root = state_home.join("update-all/self");
        let cache = product_root.join("cache");
        Ok(Self {
            versions: product_root.join("versions"),
            current: product_root.join("current"),
            state: product_root.join("state.json"),
            root_cache: cache.join("root.json"),
            root_etag: cache.join("root.etag"),
            manifest_cache: cache.join("manifest.json"),
            manifest_etag: cache.join("manifest.etag"),
            public_binary: bin_dir.join(if cfg!(windows) {
                "update-all.exe"
            } else {
                PRODUCT
            }),
            bin_dir,
            product_root,
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
            product: PRODUCT.into(),
            generation: 4,
            version: "1.2.3".into(),
            engine_protocol: ENGINE_PROTOCOL,
            artifacts: BTreeMap::new(),
        };
        verify_product_manifest(&envelope(manifest, "release-1", &release), &root).unwrap();
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
            product: PRODUCT.into(),
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
                product: PRODUCT.into(),
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
        verify_candidate_health(&binary, "1.2.3").unwrap();
        let err = verify_candidate_health(&binary, "1.2.4").unwrap_err();
        assert!(err.downcast_ref::<IntegrityFailure>().is_some());
    }
}
