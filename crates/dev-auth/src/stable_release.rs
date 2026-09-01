use crate::release_manifest::VerifiedDevAuthRelease;
use anyhow::{bail, Context, Result};
use dev_tools_release::{
    fetch_https, select_stable_release_assets, verify_artifact_bytes, verify_release_metadata,
    ArtifactUrlPolicy, HttpsPolicy, ReleaseAuthority, ReleaseMetadata,
};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
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

pub fn stage_latest_stable_release(directory: &Path) -> Result<StagedStableRelease> {
    prepare_staging_directory(directory)?;
    match stage_latest_stable_release_inner(directory) {
        Ok(release) => Ok(release),
        Err(error) => {
            let _ = fs::remove_dir_all(directory);
            Err(error)
        }
    }
}

fn stage_latest_stable_release_inner(directory: &Path) -> Result<StagedStableRelease> {
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
    let authority = ReleaseAuthority {
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
    };
    let verified = verify_release_metadata(
        &ReleaseMetadata {
            root: root.bytes.clone(),
            manifest: manifest.bytes.clone(),
        },
        &authority,
    )?;
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

    let root_path = directory.join("dev-tools-root.json");
    let manifest_path = directory.join("dev-auth-stable.json");
    let artifact_path = directory.join("dev-auth");
    write_private_file(&root_path, &root.bytes, false)?;
    write_private_file(&manifest_path, &manifest.bytes, false)?;
    write_private_file(&artifact_path, &artifact.bytes, true)?;
    let verified = crate::release_manifest::verify_dev_auth_release(
        &root_path,
        &manifest_path,
        &artifact_path,
    )?;
    Ok(StagedStableRelease {
        verified,
        directory: directory.to_path_buf(),
    })
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

fn prepare_staging_directory(directory: &Path) -> Result<()> {
    if !directory.is_absolute() || directory == Path::new("/") {
        bail!("release staging directory must be a bounded absolute path");
    }
    let parent = directory
        .parent()
        .context("release staging directory has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect release staging parent {}", parent.display()))?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let parent_uid = parent_metadata.uid();
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || (parent_uid != 0 && parent_uid != effective_uid)
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!("release staging parent has unsafe filesystem authority");
    }
    fs::create_dir(directory).context("create private release staging directory")?;
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
        .context("protect release staging directory")?;
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    if bytes.is_empty() {
        bail!("release staging file cannot be empty");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if executable { 0o700 } else { 0o600 })
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("create release staging file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write release staging file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync release staging file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_requires_a_private_native_parent_before_network_access() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).unwrap();
        let stage = root.path().join("stage");
        assert!(prepare_staging_directory(&stage).is_err());
        assert!(!stage.exists());
    }
}
