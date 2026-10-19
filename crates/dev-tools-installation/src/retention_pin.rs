//! Exact versioned-artifact retention pins, independent of activation state.
//!
//! Products own authentication, admission and their outer writer lease. This
//! boundary neither locks the installation nor reads or changes its receipts,
//! active/previous pointers, release history, trust or caches. Pins protect the
//! normal superseded-version cleanup; explicit uninstall policy remains separate.

use super::*;
use std::ffi::OsString;

const PIN_SCHEMA: &str = "dev-tools-versioned-artifact-retention-v1";
const PIN_DIRECTORY: &str = "retained-artifacts-v1";
const PIN_LIMIT: u64 = 64 * 1024;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RetentionPin {
    schema: String,
    layout: VersionedLayout,
    version: String,
    identity: ArtifactIdentity,
}

/// Durably pin one already-published, caller-authenticated versioned executable.
///
/// The product must retain its outer writer lease across publication and this
/// call. No installation/release lock is acquired here. The actual artifact must
/// have the exact supplied identity, owner, ordinary mode 0755 and one link.
/// A fresh pin uses no-clobber publication; an existing strictly matching pin is
/// a synchronized no-op. Collisions and malformed/drifted pins fail closed.
/// Errors after publication may have uncertain progress and require the owning
/// product's retained journal; this API does not authenticate a release.
pub fn retain_versioned_artifact(
    layout: &VersionedLayout,
    version: &str,
    identity: &ArtifactIdentity,
) -> Result<bool> {
    validate_selection(layout, version, identity)?;
    let artifact = VerifiedArtifact::observe(layout, version, identity)?;
    let pin = expected_pin(layout, version, identity);
    let bytes = serde_json::to_vec(&pin).context("encode versioned artifact retention pin")?;
    if bytes.len() as u64 > PIN_LIMIT {
        bail!("versioned artifact retention pin exceeds its bound");
    }
    let path = pin_directory(layout);
    let name = pin_name(version);
    let preparation = observe_pin_directory(layout)?;
    let current = preparation.read(&name, &pin_authority(layout))?;
    if let Some(current) = &current {
        require_matching_pin(&current.bytes, &pin)?;
    }
    let (directory, _) = preparation.prepare()?;
    require_private_directory(&path, layout.owner_uid)?;
    artifact.revalidate()?;
    let changed = match current {
        Some(current) => directory.write(
            &name,
            &current.bytes,
            &pin_authority(layout),
            Some(&current.identity),
        )?,
        None => {
            directory.publish_new(&name, &bytes, &pin_authority(layout))?;
            true
        }
    };
    let published = directory
        .read(&name, &pin_authority(layout))?
        .context("published versioned artifact retention pin disappeared")?;
    require_matching_pin(&published.bytes, &pin)?;
    require_private_directory(&path, layout.owner_uid)?;
    artifact.revalidate()?;
    Ok(changed)
}

/// Read-only check for one exact pin and its still-owned executable.
///
/// An absent pin or parent returns false without creating directories, locks or
/// documents and without synchronizing storage. A present pin must match the
/// complete selected layout/version/identity and actual strict artifact custody;
/// malformed, mismatched or drifted ownership is an error, never a blanket keep.
/// Caller-owned writer exclusion remains required through any subsequent prune.
pub fn versioned_artifact_is_retained(
    layout: &VersionedLayout,
    version: &str,
    identity: &ArtifactIdentity,
) -> Result<bool> {
    validate_selection(layout, version, identity)?;
    let preparation = observe_pin_directory(layout)?;
    let name = pin_name(version);
    let Some(document) = preparation.read(&name, &pin_authority(layout))? else {
        preparation.verify_observed()?;
        return Ok(false);
    };
    let artifact = VerifiedArtifact::observe(layout, version, identity)?;
    require_matching_pin(&document.bytes, &expected_pin(layout, version, identity))?;
    require_private_directory(&pin_directory(layout), layout.owner_uid)?;
    let after = preparation
        .read(&name, &pin_authority(layout))?
        .context("versioned artifact retention pin disappeared during observation")?;
    if after.identity != document.identity {
        bail!("versioned artifact retention pin changed during observation");
    }
    artifact.revalidate()?;
    Ok(true)
}

fn validate_selection(
    layout: &VersionedLayout,
    version: &str,
    identity: &ArtifactIdentity,
) -> Result<()> {
    validate_layout(layout)?;
    validate_version_component(version, "retained version")?;
    validate_identity(identity)
}

fn expected_pin(
    layout: &VersionedLayout,
    version: &str,
    identity: &ArtifactIdentity,
) -> RetentionPin {
    RetentionPin {
        schema: PIN_SCHEMA.to_owned(),
        layout: layout.clone(),
        version: version.to_owned(),
        identity: identity.clone(),
    }
}

fn require_matching_pin(bytes: &[u8], expected: &RetentionPin) -> Result<()> {
    let pin: RetentionPin = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("versioned artifact retention pin has invalid fields"))?;
    if &pin != expected {
        bail!("versioned artifact retention pin does not match its exact selection");
    }
    Ok(())
}

fn pin_directory(layout: &VersionedLayout) -> PathBuf {
    layout.data_root.join(PIN_DIRECTORY)
}

fn pin_name(version: &str) -> OsString {
    OsString::from(format!("{version}.json"))
}

fn pin_authority(layout: &VersionedLayout) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid: layout.owner_uid,
        mode: 0o600,
        limit: PIN_LIMIT,
    }
}

fn observe_pin_directory(layout: &VersionedLayout) -> Result<DocumentDirectoryPreparation> {
    let path = pin_directory(layout);
    let preparation = DocumentDirectoryPreparation::observe(&path, layout.owner_uid, 0o700)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => require_private_directory(&path, layout.owner_uid)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect versioned artifact pin directory"),
    }
    preparation.verify_observed()?;
    Ok(preparation)
}

fn require_private_directory(path: &Path, owner_uid: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).context("inspect versioned artifact pin directory")?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != owner_uid
        || metadata.mode() & 0o7777 != 0o700
    {
        bail!("versioned artifact pin directory must have exact private owner/mode custody");
    }
    Ok(())
}

struct VerifiedArtifact {
    directory: ExistingDocumentDirectory,
    name: OsString,
    file: File,
    metadata: fs::Metadata,
}

impl VerifiedArtifact {
    fn observe(
        layout: &VersionedLayout,
        version: &str,
        identity: &ArtifactIdentity,
    ) -> Result<Self> {
        for path in [
            layout.data_root.clone(),
            layout.versions_dir(),
            layout.versions_dir().join(version),
        ] {
            inspect_owned_directory_read_only(&path, layout)?;
        }
        let directory = ExistingDocumentDirectory::open(
            &layout.versions_dir().join(version),
            layout.owner_uid,
        )?;
        let name = OsString::from(&layout.artifact_name);
        let mut file = open_read_nofollow(&layout.version_artifact(version))?;
        let metadata = file.metadata()?;
        let actual =
            ArtifactIdentity::from_open_unix_file(&mut file, identity.length, |current| {
                if !current.is_file()
                    || current.nlink() != 1
                    || current.uid() != layout.owner_uid
                    || current.mode() & 0o7777 != 0o755
                    || current.len() != identity.length
                    || !same_file(&metadata, current)
                {
                    bail!("retained versioned artifact has unsafe executable custody");
                }
                Ok(())
            })?;
        if actual != *identity {
            bail!("retained versioned artifact differs from its selected content identity");
        }
        let observed = Self {
            directory,
            name,
            metadata,
            file,
        };
        observed.revalidate()?;
        Ok(observed)
    }

    fn revalidate(&self) -> Result<()> {
        let current = self.file.metadata()?;
        let named = self
            .directory
            .metadata(&self.name)?
            .context("retained versioned artifact disappeared")?;
        if !same_file(&self.metadata, &current) || !same_file(&self.metadata, &named) {
            bail!("retained versioned artifact changed during observation");
        }
        Ok(())
    }
}

fn same_file(expected: &fs::Metadata, actual: &fs::Metadata) -> bool {
    expected.dev() == actual.dev()
        && expected.ino() == actual.ino()
        && expected.uid() == actual.uid()
        && expected.gid() == actual.gid()
        && expected.mode() == actual.mode()
        && expected.nlink() == actual.nlink()
        && expected.len() == actual.len()
        && expected.mtime() == actual.mtime()
        && expected.mtime_nsec() == actual.mtime_nsec()
        && expected.ctime() == actual.ctime()
        && expected.ctime_nsec() == actual.ctime_nsec()
}
