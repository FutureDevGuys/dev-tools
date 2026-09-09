use super::*;
use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;

/// Withdraw only the activation named by an externally retained exact receipt.
/// The caller owns durable recovery authority, release authentication, ancestor
/// trust and exclusion of nonparticipating writers. Immutable artifacts, the
/// installation lock, directories and unrelated files remain retained. This is
/// not an uninstall or a permanent legacy-writer fence. Errors may follow
/// partial removal; retry with the same retained authority. Existing roots and
/// intact artifacts are required, including on an already-absent retry.
pub fn withdraw_versioned_installation_activation(
    layout: &VersionedLayout,
    expected: &VersionedReceipt,
    artifact_limit: u64,
) -> Result<bool> {
    validate_layout(layout)?;
    validate_versioned_receipt(layout, expected)?;
    if artifact_limit == 0 {
        bail!("activation withdrawal requires an artifact bound");
    }
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    let lock = InstallationLock::acquire(&layout.lock_path())?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    inspect_owned_directory_read_only(&layout.bin_dir, layout)?;
    require_path_absent(&layout.journal_path())
        .context("activation withdrawal requires explicit binary journal recovery")?;
    let current = read_versioned_receipt_document(layout)?;
    if let Some(document) = &current {
        let receipt: VersionedReceipt = serde_json::from_slice(&document.bytes)?;
        if &receipt != expected {
            bail!("activation withdrawal receipt differs from retained authority");
        }
    }
    verify_recovery_artifacts(layout, expected, artifact_limit)?;
    let (bin, _) = open_directory_chain(&layout.bin_dir, false)?;
    let (data, _) = open_directory_chain(&layout.data_root, false)?;
    let mut links = expected
        .aliases
        .iter()
        .map(|alias| RetainedLink {
            in_bin: true,
            name: OsString::from(alias),
            target: layout.active_pointer(),
            identity: None,
        })
        .collect::<Vec<_>>();
    links.push(RetainedLink {
        in_bin: false,
        name: "active".into(),
        target: layout.version_artifact(&expected.active_version),
        identity: None,
    });
    if let Some(version) = &expected.previous_version {
        links.push(RetainedLink {
            in_bin: false,
            name: "previous".into(),
            target: layout.version_artifact(version),
            identity: None,
        });
    } else {
        match rustix::fs::statat(&data, "previous", rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(error) => return Err(error).context("inspect unowned previous pointer"),
            Ok(_) => bail!("activation withdrawal has an undeclared previous pointer"),
        }
    }
    // Complete inventory admission before removing even the first link.
    for link in &mut links {
        link.identity = inspect_link(
            if link.in_bin { &bin } else { &data },
            &link.name,
            &link.target,
            layout.owner_uid,
        )?;
    }
    verify_named_parent(&layout.bin_dir, &bin, layout)?;
    verify_named_parent(&layout.data_root, &data, layout)?;
    verify_observation_lock(layout, &lock)?;
    let mut changed = false;
    for link in &links {
        let parent = if link.in_bin { &bin } else { &data };
        let observed = inspect_link(parent, &link.name, &link.target, layout.owner_uid)?;
        if observed != link.identity {
            bail!("activation withdrawal pointer changed after admission");
        }
        if observed.is_some() {
            rustix::fs::unlinkat(parent, &link.name, rustix::fs::AtFlags::empty())
                .context("remove retained installation activation pointer")?;
            changed = true;
        }
    }
    // Synchronize absent pointers before removing their ownership receipt.
    // Repeating these syncs also settles an earlier post-unlink failure.
    rustix::fs::fsync(&bin).context("sync withdrawn public aliases")?;
    rustix::fs::fsync(&data).context("sync withdrawn installation pointers")?;
    verify_named_parent(&layout.bin_dir, &bin, layout)?;
    verify_named_parent(&layout.data_root, &data, layout)?;
    verify_observation_lock(layout, &lock)?;
    if let Some(document) = &current {
        changed |= remove_atomic_document_if_unchanged(
            &layout.receipt_path(),
            &receipt_authority(layout),
            &document.identity,
        )?;
    } else {
        require_path_absent(&layout.receipt_path())?;
    }
    Ok(changed)
}

struct RetainedLink {
    in_bin: bool,
    name: OsString,
    target: PathBuf,
    identity: Option<(u128, u128)>,
}

fn inspect_link(
    parent: &OwnedFd,
    name: &OsStr,
    target: &Path,
    owner_uid: u32,
) -> Result<Option<(u128, u128)>> {
    let metadata = match rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(metadata) => metadata,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => return Err(error).context("inspect retained activation pointer"),
    };
    if rustix::fs::FileType::from_raw_mode(metadata.st_mode) != rustix::fs::FileType::Symlink
        || metadata.st_uid != owner_uid
        || metadata.st_nlink != 1
    {
        bail!("activation pointer has unsafe ownership or type");
    }
    let observed = rustix::fs::readlinkat(parent, name, Vec::new())
        .context("read retained activation pointer")?;
    if observed.as_bytes() != target.as_os_str().as_bytes() {
        bail!("activation pointer differs from its retained target");
    }
    Ok(Some((metadata.st_dev as u128, metadata.st_ino as u128)))
}

fn verify_named_parent(path: &Path, held: &OwnedFd, layout: &VersionedLayout) -> Result<()> {
    let retained = rustix::fs::fstat(held).context("inspect retained activation directory")?;
    let named = fs::symlink_metadata(path).context("reinspect activation directory")?;
    if !named.is_dir()
        || named.file_type().is_symlink()
        || retained.st_uid != layout.owner_uid
        || named.uid() != layout.owner_uid
        || retained.st_mode & 0o777 != layout.directory_mode_for(path)
        || named.mode() & 0o777 != layout.directory_mode_for(path)
        || retained.st_dev as u128 != named.dev() as u128
        || retained.st_ino as u128 != named.ino() as u128
    {
        bail!("activation directory changed after admission");
    }
    Ok(())
}
