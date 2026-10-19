//! Replayable retirement of one exact nested pinned artifact store.

use super::*;
use anyhow::anyhow;
use std::os::unix::fs::MetadataExt;

const RETIREMENT_SCHEMA: &str = "dev-auth-pinned-retirement-v1";
const RETIREMENT_NAME: &str = "retirement-v1.json";

fn abort_after(stage: &str) {
    #[cfg(test)]
    if std::env::var("DEV_AUTH_TEST_PIN_RETIRE_ABORT").as_deref() == Ok(stage) {
        // SAFETY: an ignored child fixture simulates process death without
        // destructors or a host core dump. Production builds omit this path.
        unsafe { nix::libc::_exit(77) }
    }
    #[cfg(not(test))]
    let _ = stage;
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PinnedRetirement {
    schema: String,
    layout: VersionedLayout,
    receipt: VersionedReceipt,
}

fn marker_path(data_account: &Path) -> PathBuf {
    data_account.join(RETIREMENT_NAME)
}

fn marker_authority(owner_uid: u32) -> DocumentAuthority {
    DocumentAuthority {
        owner_uid,
        mode: 0o600,
        limit: 4096,
    }
}

fn read_marker(
    data_account: &Path,
    owner_uid: u32,
) -> Result<Option<(PinnedRetirement, ArtifactIdentity)>> {
    let Some(document) =
        read_atomic_document(&marker_path(data_account), &marker_authority(owner_uid))?
    else {
        return Ok(None);
    };
    let marker: PinnedRetirement =
        serde_json::from_slice(&document.bytes).context("decode pinned retirement marker")?;
    if serde_jcs::to_vec(&marker)? != document.bytes {
        bail!("pinned retirement marker is not canonical");
    }
    Ok(Some((marker, document.identity)))
}

pub(super) fn pending_at(data_account: &Path, owner_uid: u32) -> Result<bool> {
    Ok(read_marker(data_account, owner_uid)?.is_some())
}

fn validate_marker(
    marker: &PinnedRetirement,
    data_account: &Path,
    link_account: &Path,
    owner_uid: u32,
    directory_mode: u32,
) -> Result<String> {
    let layout = &marker.layout;
    let receipt = &marker.receipt;
    let alias = receipt
        .aliases
        .first()
        .context("pinned retirement has no alias")?;
    crate::setup::validate_workload_alias_names(std::slice::from_ref(alias))?;
    if marker.schema != RETIREMENT_SCHEMA
        || receipt.schema != "dev-tools-versioned-installation-v1"
        || receipt.product != "dev-auth-binding"
        || receipt.aliases != [alias.clone()]
        || receipt.active_version != "v1"
        || receipt.previous_version.is_some()
        || receipt.previous_identity.is_some()
        || layout.product != receipt.product
        || layout.artifact_name != "payload"
        || layout.owner_uid != owner_uid
        || layout.directory_mode != directory_mode
        || layout.bin_directory_mode.is_some()
        || layout.data_root.parent().and_then(Path::parent) != Some(data_account)
        || layout.bin_dir.parent().and_then(Path::parent) != Some(link_account)
        || layout.data_root.parent().and_then(Path::file_name) != Some(alias.as_ref())
        || layout.bin_dir.parent().and_then(Path::file_name) != Some(alias.as_ref())
        || receipt.data_root != layout.data_root
        || receipt.bin_dir != layout.bin_dir
        || receipt.artifact_name != layout.artifact_name
    {
        bail!("pinned retirement marker differs from its owned store");
    }
    let generation = layout
        .data_root
        .file_name()
        .and_then(|name| name.to_str())
        .context("pinned retirement generation is invalid")?;
    let (number, digest) = generation
        .strip_prefix('g')
        .and_then(|value| value.split_once('-'))
        .context("pinned retirement generation is invalid")?;
    if number
        .parse::<u64>()
        .ok()
        .filter(|number| *number > 0)
        .map(|number| number.to_string())
        != Some(number.to_owned())
        || digest != receipt.active_identity.sha256
        || layout.bin_dir.file_name() != layout.data_root.file_name()
    {
        bail!("pinned retirement generation differs from its receipt");
    }
    layout.validate_candidate("v1", &receipt.active_identity, &receipt.aliases)?;
    Ok(alias.clone())
}

fn require_subset(path: &Path, owner_uid: u32, mode: u32, allowed: &[&str]) -> Result<bool> {
    let Some(entries) = owned_store_entries(path, owner_uid, mode)? else {
        return Ok(false);
    };
    if entries
        .iter()
        .any(|entry| !allowed.contains(&entry.as_str()))
    {
        bail!("retiring pinned store contains an unowned entry");
    }
    Ok(true)
}

fn exact_link_if_present(path: &Path, target: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() && fs::read_link(path)? == target => {
            Ok(true)
        }
        Ok(_) => bail!("retiring pinned store has a changed link"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect retiring pinned link"),
    }
}

fn remove_dir_if_present(path: &Path) -> Result<()> {
    match fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove empty retired pin directory"),
    }
}

fn sync_directory_if_present(path: &Path) -> Result<()> {
    match fs::File::open(path) {
        Ok(directory) => directory
            .sync_all()
            .context("sync retiring pinned directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("open retiring pinned directory for sync"),
    }
}

fn finish_marked_retirement(
    marker: &PinnedRetirement,
    data_account: &Path,
    link_account: &Path,
    owner_uid: u32,
    directory_mode: u32,
) -> Result<()> {
    let alias = validate_marker(
        marker,
        data_account,
        link_account,
        owner_uid,
        directory_mode,
    )?;
    let layout = &marker.layout;
    let artifact = layout.data_root.join("versions/v1/payload");
    let active = layout.data_root.join("active");
    let receipt_path = layout.data_root.join("installation-receipt-v1.json");
    let lock_path = layout.data_root.join("installation.lock");
    let alias_path = layout.bin_dir.join(&alias);
    let root_present = require_subset(
        &layout.data_root,
        owner_uid,
        directory_mode,
        &[
            "versions",
            "active",
            "installation-receipt-v1.json",
            "installation.lock",
        ],
    )?;
    require_subset(&layout.bin_dir, owner_uid, directory_mode, &[&alias])?;
    if root_present {
        require_subset(
            &layout.data_root.join("versions"),
            owner_uid,
            directory_mode,
            &["v1"],
        )?;
        require_subset(
            &layout.data_root.join("versions/v1"),
            owner_uid,
            directory_mode,
            &["payload"],
        )?;
    }
    let alias_exists = exact_link_if_present(&alias_path, &active)?;
    let active_exists = exact_link_if_present(&active, &artifact)?;
    let receipt_exists = match fs::symlink_metadata(&receipt_path) {
        Ok(_) => {
            if dev_tools_installation::read_versioned_installation_receipt(layout)?
                != Some(marker.receipt.clone())
            {
                bail!("retiring pinned receipt changed outside its marker");
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect retiring pinned receipt"),
    };
    let artifact_exists = match fs::symlink_metadata(&artifact) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.uid() != owner_uid
                || metadata.mode() & 0o777 != 0o755
                || metadata.nlink() != 1
                || ArtifactIdentity::from_file(&artifact, marker.receipt.active_identity.length)?
                    != marker.receipt.active_identity
            {
                bail!("retiring pinned artifact changed outside its marker");
            }
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error).context("inspect retiring pinned artifact"),
    };
    let lock = if root_present {
        Some(dev_tools_installation::InstallationLock::acquire(
            &lock_path,
        )?)
    } else {
        None
    };
    if alias_exists {
        fs::remove_file(&alias_path).context("remove retired pin alias")?;
    }
    abort_after("after_alias");
    if active_exists {
        fs::remove_file(&active).context("remove retired pin pointer")?;
    }
    abort_after("after_active");
    if receipt_exists {
        fs::remove_file(&receipt_path).context("remove retired pin receipt")?;
    }
    abort_after("after_receipt");
    if artifact_exists {
        dev_tools_installation::remove_owned_file(&artifact, &marker.receipt.active_identity)?;
    }
    abort_after("after_artifact");
    sync_directory_if_present(&layout.bin_dir)?;
    sync_directory_if_present(&layout.data_root)?;
    remove_dir_if_present(&layout.data_root.join("versions/v1"))?;
    sync_directory_if_present(&layout.data_root.join("versions"))?;
    remove_dir_if_present(&layout.data_root.join("versions"))?;
    abort_after("after_versions");
    sync_directory_if_present(&layout.data_root)?;
    if lock.is_some() {
        let metadata = fs::symlink_metadata(&lock_path).context("inspect retired pin lock")?;
        if !metadata.file_type().is_file()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            bail!("retiring pinned lock has unsafe custody");
        }
        fs::remove_file(&lock_path).context("remove retired pin lock")?;
    }
    drop(lock);
    abort_after("after_lock");
    sync_directory_if_present(&layout.data_root)?;
    remove_dir_if_present(&layout.data_root)?;
    abort_after("after_data_root");
    remove_dir_if_present(&layout.bin_dir)?;
    abort_after("after_bin_dir");
    sync_directory_if_present(&data_account.join(&alias))?;
    sync_directory_if_present(&link_account.join(&alias))?;
    Ok(())
}

pub(super) fn resume_at(
    data_account: &Path,
    link_account: &Path,
    owner_uid: u32,
    directory_mode: u32,
    keep: &BTreeSet<PathBuf>,
) -> Result<bool> {
    let Some((marker, identity)) = read_marker(data_account, owner_uid)? else {
        return Ok(false);
    };
    validate_marker(
        &marker,
        data_account,
        link_account,
        owner_uid,
        directory_mode,
    )?;
    if keep.contains(&marker.layout.data_root) {
        bail!("retiring pin became part of the retained binding window");
    }
    finish_marked_retirement(
        &marker,
        data_account,
        link_account,
        owner_uid,
        directory_mode,
    )?;
    remove_atomic_document_if_unchanged(
        &marker_path(data_account),
        &marker_authority(owner_uid),
        &identity,
    )?
    .then_some(())
    .ok_or_else(|| anyhow!("pinned retirement marker disappeared before completion"))?;
    Ok(true)
}

pub(super) fn retire_at(
    layout: &VersionedLayout,
    receipt: &VersionedReceipt,
    data_account: &Path,
    link_account: &Path,
    owner_uid: u32,
    directory_mode: u32,
    keep: &BTreeSet<PathBuf>,
) -> Result<()> {
    if read_marker(data_account, owner_uid)?.is_some() {
        bail!("another pinned retirement requires recovery");
    }
    let marker = PinnedRetirement {
        schema: RETIREMENT_SCHEMA.into(),
        layout: layout.clone(),
        receipt: receipt.clone(),
    };
    validate_marker(
        &marker,
        data_account,
        link_account,
        owner_uid,
        directory_mode,
    )?;
    let bytes = serde_jcs::to_vec(&marker)?;
    write_atomic_document(
        &marker_path(data_account),
        &bytes,
        &marker_authority(owner_uid),
        None,
    )?;
    abort_after("after_marker");
    if !resume_at(data_account, link_account, owner_uid, directory_mode, keep)? {
        bail!("pinned retirement was not completed");
    }
    Ok(())
}
