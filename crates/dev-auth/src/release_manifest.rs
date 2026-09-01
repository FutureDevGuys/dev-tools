use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const METADATA_LIMIT: u64 = 512 * 1024;
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;
const TRUSTED_ROOT: &str = include_str!("../trust/root-public-key.txt");

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedEnvelope<T> {
    signed: T,
    signatures: Vec<DocumentSignature>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DocumentSignature {
    key_id: String,
    signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RootDocument {
    schema: String,
    generation: u64,
    release_keys: Vec<ReleaseKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReleaseKey {
    key_id: String,
    public_key: String,
    #[serde(default)]
    revoked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DevAuthManifest {
    schema: String,
    product: String,
    generation: u64,
    version: String,
    source_commit: String,
    engine_protocol: u32,
    artifacts: BTreeMap<String, ArtifactIdentity>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArtifactIdentity {
    url: String,
    length: u64,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDevAuthRelease {
    pub schema: String,
    pub root_path: PathBuf,
    pub manifest_path: PathBuf,
    pub root_generation: u64,
    pub manifest_generation: u64,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub artifact_path: PathBuf,
    pub artifact_url: String,
    pub artifact_length: u64,
    pub artifact_sha256: String,
    pub root_sha256: String,
    pub manifest_sha256: String,
}

struct ReleasePaths<'a> {
    root: &'a Path,
    manifest: &'a Path,
    artifact: &'a Path,
}

pub fn verify_dev_auth_release(
    root_path: &Path,
    manifest_path: &Path,
    artifact_path: &Path,
) -> Result<VerifiedDevAuthRelease> {
    let root = read_public_file(root_path, METADATA_LIMIT, "root document")?;
    let manifest = read_public_file(manifest_path, METADATA_LIMIT, "release manifest")?;
    let artifact = read_public_file(artifact_path, ARTIFACT_LIMIT, "release artifact")?;
    verify_release_documents(
        &root,
        &manifest,
        ReleasePaths {
            root: root_path,
            manifest: manifest_path,
            artifact: artifact_path,
        },
        &artifact,
        TRUSTED_ROOT.trim(),
        &target_id()?,
    )
}

fn verify_release_documents(
    root_bytes: &[u8],
    manifest_bytes: &[u8],
    paths: ReleasePaths<'_>,
    artifact_bytes: &[u8],
    trusted_root: &str,
    target: &str,
) -> Result<VerifiedDevAuthRelease> {
    let root: SignedEnvelope<RootDocument> =
        serde_json::from_slice(root_bytes).context("parse trusted root document")?;
    if root.signed.schema != "dev-tools-root-v1" || root.signed.generation == 0 {
        bail!("release root document has an unsupported contract");
    }
    verify_any_signature(&root, &parse_public_key(trusted_root)?)
        .context("verify release root document")?;

    let manifest: SignedEnvelope<DevAuthManifest> =
        serde_json::from_slice(manifest_bytes).context("parse dev-auth release manifest")?;
    verify_release_signature(&manifest, &root.signed)?;
    validate_manifest(&manifest.signed, target)?;
    let artifact = manifest
        .signed
        .artifacts
        .get(target)
        .context("release manifest has no artifact for this platform")?;
    if artifact.length != artifact_bytes.len() as u64
        || artifact.sha256 != format!("{:x}", Sha256::digest(artifact_bytes))
    {
        bail!("release artifact does not match the signed manifest");
    }

    Ok(VerifiedDevAuthRelease {
        schema: "dev-auth-verified-release-v1".into(),
        root_path: paths.root.to_path_buf(),
        manifest_path: paths.manifest.to_path_buf(),
        root_generation: root.signed.generation,
        manifest_generation: manifest.signed.generation,
        version: manifest.signed.version,
        source_commit: manifest.signed.source_commit,
        target: target.to_owned(),
        artifact_path: paths.artifact.to_path_buf(),
        artifact_url: artifact.url.clone(),
        artifact_length: artifact.length,
        artifact_sha256: artifact.sha256.clone(),
        root_sha256: format!("{:x}", Sha256::digest(root_bytes)),
        manifest_sha256: format!("{:x}", Sha256::digest(manifest_bytes)),
    })
}

fn validate_manifest(manifest: &DevAuthManifest, target: &str) -> Result<()> {
    if manifest.schema != "dev-auth-product-v2"
        || manifest.product != "dev-auth"
        || manifest.engine_protocol != 1
        || manifest.generation == 0
        || !valid_version(&manifest.version)
        || !valid_hex(&manifest.source_commit, 40)
        || manifest.artifacts.len() != 1
    {
        bail!("release manifest has an unsupported contract");
    }
    let artifact = manifest
        .artifacts
        .get(target)
        .context("release manifest has no artifact for this platform")?;
    if artifact.length == 0 || artifact.length > ARTIFACT_LIMIT || !valid_hex(&artifact.sha256, 64)
    {
        bail!("release manifest artifact identity is invalid");
    }
    let encoded_tag = format!("dev-auth%2Fv{}", manifest.version);
    let expected_name = format!("dev-auth-{}-{target}", manifest.version);
    let expected_url = format!(
        "https://github.com/FutureDevGuys/dev-tools/releases/download/{encoded_tag}/{expected_name}"
    );
    if artifact.url != expected_url {
        bail!("release manifest artifact URL is outside the product authority");
    }
    Ok(())
}

fn verify_release_signature(
    manifest: &SignedEnvelope<DevAuthManifest>,
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
        let key = parse_public_key(&key.public_key)?;
        if verify_signature(&key, &canonical, &signature.signature).is_ok() {
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
        .any(|signature| verify_signature(key, &canonical, &signature.signature).is_ok())
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

fn read_public_file(path: &Path, limit: u64, description: &str) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("{description} path must be absolute");
    }
    let mut file = open_public_file(path).with_context(|| format!("open {description}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened {description}"))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit {
        bail!("{description} has unsafe filesystem authority");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description}"))?;
    if bytes.is_empty() || bytes.len() as u64 > limit || bytes.len() as u64 != metadata.len() {
        bail!("{description} changed or exceeded its size bound while being read");
    }
    Ok(bytes)
}

fn open_public_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    options.open(path).context("open public release file")
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn target_id() -> Result<String> {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        _ => bail!("release verification is unsupported on this operating system"),
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => bail!("release verification is unsupported on this architecture"),
    };
    Ok(format!("{os}-{architecture}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signature<T: Serialize>(value: &T, key_id: &str, key: &SigningKey) -> DocumentSignature {
        let canonical = serde_jcs::to_vec(value).unwrap();
        DocumentSignature {
            key_id: key_id.into(),
            signature: BASE64.encode(key.sign(&canonical).to_bytes()),
        }
    }

    #[test]
    fn signed_release_binds_source_target_url_and_artifact() {
        let root_key = SigningKey::from_bytes(&[7; 32]);
        let release_key = SigningKey::from_bytes(&[9; 32]);
        let root = RootDocument {
            schema: "dev-tools-root-v1".into(),
            generation: 3,
            release_keys: vec![ReleaseKey {
                key_id: "release-test".into(),
                public_key: hex(&release_key.verifying_key().to_bytes()),
                revoked: false,
            }],
        };
        let root = SignedEnvelope {
            signatures: vec![signature(&root, "root-test", &root_key)],
            signed: root,
        };
        let artifact_bytes = b"signed dev-auth fixture";
        let artifact = ArtifactIdentity {
            url: "https://github.com/FutureDevGuys/dev-tools/releases/download/dev-auth%2Fv0.3.0/dev-auth-0.3.0-linux-x86_64".into(),
            length: artifact_bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(artifact_bytes)),
        };
        let manifest = DevAuthManifest {
            schema: "dev-auth-product-v2".into(),
            product: "dev-auth".into(),
            generation: 11,
            version: "0.3.0".into(),
            source_commit: "a".repeat(40),
            engine_protocol: 1,
            artifacts: BTreeMap::from([("linux-x86_64".into(), artifact)]),
        };
        let envelope = SignedEnvelope {
            signatures: vec![signature(&manifest, "release-test", &release_key)],
            signed: manifest,
        };
        let root_bytes = serde_json::to_vec(&root).unwrap();
        let manifest_bytes = serde_json::to_vec(&envelope).unwrap();
        let trusted = hex(&root_key.verifying_key().to_bytes());
        let verified = verify_release_documents(
            &root_bytes,
            &manifest_bytes,
            ReleasePaths {
                root: Path::new("/tmp/dev-auth-root-fixture"),
                manifest: Path::new("/tmp/dev-auth-manifest-fixture"),
                artifact: Path::new("/tmp/dev-auth-fixture"),
            },
            artifact_bytes,
            &trusted,
            "linux-x86_64",
        )
        .unwrap();
        assert_eq!(verified.source_commit, "a".repeat(40));
        assert_eq!(verified.manifest_generation, 11);

        let mut changed = artifact_bytes.to_vec();
        changed.push(0);
        assert!(verify_release_documents(
            &root_bytes,
            &manifest_bytes,
            ReleasePaths {
                root: Path::new("/tmp/dev-auth-root-fixture"),
                manifest: Path::new("/tmp/dev-auth-manifest-fixture"),
                artifact: Path::new("/tmp/dev-auth-fixture"),
            },
            &changed,
            &trusted,
            "linux-x86_64",
        )
        .is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
