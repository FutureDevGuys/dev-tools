use anyhow::{bail, Context, Result};
#[cfg(test)]
use base64::engine::general_purpose::STANDARD as BASE64;
#[cfg(test)]
use base64::Engine as _;
use dev_tools_release::{ArtifactUrlPolicy, ReleaseAuthority, ReleaseBundle};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
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
#[cfg(test)]
struct SignedEnvelope<T> {
    signed: T,
    signatures: Vec<DocumentSignature>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct DocumentSignature {
    key_id: String,
    signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct RootDocument {
    schema: String,
    generation: u64,
    release_keys: Vec<ReleaseKey>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
struct ReleaseKey {
    key_id: String,
    public_key: String,
    #[serde(default)]
    revoked: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg(test)]
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
#[cfg(test)]
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
    let verified = dev_tools_release::verify_release_bytes(
        &ReleaseBundle {
            root: root_bytes.to_vec(),
            manifest: manifest_bytes.to_vec(),
            artifact: artifact_bytes.to_vec(),
        },
        &ReleaseAuthority {
            trusted_root_key: trusted_root.into(),
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
    )?;
    let source_commit = verified
        .source_commit
        .context("verified dev-auth release has no source commit")?;

    Ok(VerifiedDevAuthRelease {
        schema: "dev-auth-verified-release-v1".into(),
        root_path: paths.root.to_path_buf(),
        manifest_path: paths.manifest.to_path_buf(),
        root_generation: verified.root_generation,
        manifest_generation: verified.manifest_generation,
        version: verified.version.to_string(),
        source_commit,
        target: verified.target,
        artifact_path: paths.artifact.to_path_buf(),
        artifact_url: verified.artifact_url,
        artifact_length: verified.artifact_length,
        artifact_sha256: verified.artifact_sha256,
        root_sha256: verified.root_sha256,
        manifest_sha256: verified.manifest_sha256,
    })
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

pub fn target_id() -> Result<String> {
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
