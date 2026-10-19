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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wait_timeout::ChildExt;

    #[test]
    #[ignore = "child fixture invoked only by every_retirement_crash_boundary_replays"]
    fn retirement_abrupt_child() {
        let input = PathBuf::from(std::env::var_os("DEV_AUTH_TEST_PIN_RETIRE_INPUT").unwrap());
        let marker: PinnedRetirement = serde_json::from_slice(&fs::read(input).unwrap()).unwrap();
        let data_account = marker.layout.data_root.parent().unwrap().parent().unwrap();
        let link_account = marker.layout.bin_dir.parent().unwrap().parent().unwrap();
        retire_at(
            &marker.layout,
            &marker.receipt,
            data_account,
            link_account,
            marker.layout.owner_uid,
            marker.layout.directory_mode,
            &BTreeSet::new(),
        )
        .unwrap();
        panic!("retirement child did not reach the abrupt boundary");
    }

    #[test]
    fn every_retirement_crash_boundary_replays() {
        for stage in [
            "after_marker",
            "after_alias",
            "after_active",
            "after_receipt",
            "after_artifact",
            "after_versions",
            "after_lock",
            "after_data_root",
            "after_bin_dir",
        ] {
            let root = tempfile::tempdir().unwrap();
            let owner_uid = nix::unistd::Uid::effective().as_raw();
            let data_account = root.path().join("data/1234");
            let link_account = root.path().join("links/1234");
            let alias = "bound-tool";
            let identity =
                ArtifactIdentity::from_file(Path::new("/usr/bin/true"), 512 * 1024 * 1024).unwrap();
            let generation = format!("g1-{}", identity.sha256);
            let layout = VersionedLayout {
                product: "dev-auth-binding".into(),
                data_root: data_account.join(alias).join(&generation),
                bin_dir: link_account.join(alias).join(&generation),
                artifact_name: "payload".into(),
                owner_uid,
                directory_mode: 0o700,
                bin_directory_mode: None,
            };
            let receipt = dev_tools_installation::apply_versioned_installation_if_unchanged(
                &VersionedInstallRequest {
                    layout: layout.clone(),
                    version: "v1".into(),
                    source: "/usr/bin/true".into(),
                    identity,
                    aliases: vec![alias.into()],
                },
                None,
                |_| Ok(()),
            )
            .unwrap()
            .receipt;
            for path in [
                &data_account,
                &data_account.join(alias),
                &link_account,
                &link_account.join(alias),
            ] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let marker = PinnedRetirement {
                schema: RETIREMENT_SCHEMA.into(),
                layout: layout.clone(),
                receipt,
            };
            let input = root.path().join("retirement-input.json");
            fs::write(&input, serde_jcs::to_vec(&marker).unwrap()).unwrap();
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "binding_activation::retirement::tests::retirement_abrupt_child",
                    "--test-threads=1",
                ])
                .env("DEV_AUTH_TEST_PIN_RETIRE_INPUT", &input)
                .env("DEV_AUTH_TEST_PIN_RETIRE_ABORT", stage)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            let status = match child
                .wait_timeout(std::time::Duration::from_secs(10))
                .unwrap()
            {
                Some(status) => status,
                None => {
                    let _ = child.kill();
                    child.wait().unwrap();
                    panic!("retirement child stalled at {stage}");
                }
            };
            assert_eq!(status.code(), Some(77), "retirement child missed {stage}");
            assert!(
                marker_path(&data_account).is_file(),
                "marker missing at {stage}"
            );
            assert!(
                resume_at(
                    &data_account,
                    &link_account,
                    owner_uid,
                    0o700,
                    &BTreeSet::new()
                )
                .unwrap(),
                "retirement could not resume after {stage}"
            );
            assert!(
                !layout.data_root.exists(),
                "data root remains after {stage}"
            );
            assert!(!layout.bin_dir.exists(), "link root remains after {stage}");
            assert!(
                !marker_path(&data_account).exists(),
                "marker remains after {stage}"
            );
        }
    }

    #[test]
    fn marked_partial_retirement_replays_without_deleting_foreign_content() {
        let root = tempfile::tempdir().unwrap();
        let owner_uid = nix::unistd::Uid::effective().as_raw();
        let data_account = root.path().join("data/1234");
        let link_account = root.path().join("links/1234");
        let alias = "bound-tool";
        let identity =
            ArtifactIdentity::from_file(Path::new("/usr/bin/true"), 512 * 1024 * 1024).unwrap();
        let generation = format!("g1-{}", identity.sha256);
        let layout = VersionedLayout {
            product: "dev-auth-binding".into(),
            data_root: data_account.join(alias).join(&generation),
            bin_dir: link_account.join(alias).join(&generation),
            artifact_name: "payload".into(),
            owner_uid,
            directory_mode: 0o700,
            bin_directory_mode: None,
        };
        let receipt = dev_tools_installation::apply_versioned_installation_if_unchanged(
            &VersionedInstallRequest {
                layout: layout.clone(),
                version: "v1".into(),
                source: "/usr/bin/true".into(),
                identity,
                aliases: vec![alias.into()],
            },
            None,
            |_| Ok(()),
        )
        .unwrap()
        .receipt;
        for path in [
            &data_account,
            &data_account.join(alias),
            &link_account,
            &link_account.join(alias),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let marker = PinnedRetirement {
            schema: RETIREMENT_SCHEMA.into(),
            layout: layout.clone(),
            receipt,
        };
        write_atomic_document(
            &marker_path(&data_account),
            &serde_jcs::to_vec(&marker).unwrap(),
            &marker_authority(owner_uid),
            None,
        )
        .unwrap();
        assert!(pending_at(&data_account, owner_uid).unwrap());
        fs::remove_file(layout.bin_dir.join(alias)).unwrap();
        fs::remove_file(layout.data_root.join("active")).unwrap();
        fs::remove_file(layout.data_root.join("installation-receipt-v1.json")).unwrap();
        let foreign = layout.data_root.join("foreign");
        fs::write(&foreign, b"not retirement owned").unwrap();
        assert!(resume_at(
            &data_account,
            &link_account,
            owner_uid,
            0o700,
            &BTreeSet::new(),
        )
        .is_err());
        assert!(layout.data_root.join("versions/v1/payload").is_file());
        fs::remove_file(foreign).unwrap();
        assert!(resume_at(
            &data_account,
            &link_account,
            owner_uid,
            0o700,
            &BTreeSet::new(),
        )
        .unwrap());
        assert!(!layout.data_root.exists());
        assert!(!layout.bin_dir.exists());
        assert!(!marker_path(&data_account).exists());
        assert!(!pending_at(&data_account, owner_uid).unwrap());
        assert!(!resume_at(
            &data_account,
            &link_account,
            owner_uid,
            0o700,
            &BTreeSet::new(),
        )
        .unwrap());
    }
}
