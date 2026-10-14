//! Explicit repair from a caller's durable, exact installation authority.
use super::*;
use std::ffi::OsStr;

/// Read-only admission for a retained repair. This does not acquire/create a
/// lock or recover a journal. The caller owns its outer writer exclusion.
pub fn observe_retained_versioned_installation_repair(
    layout: &VersionedLayout,
    expected: &VersionedReceipt,
    artifact_limit: u64,
) -> Result<()> {
    observe(layout, expected, artifact_limit)
}

/// Reconstruct only absent links/receipt from exact externally retained
/// authority. The live receipt must equal that authority or be absent. All
/// artifacts and links are admitted before mutation; journals are never
/// implicitly recovered. The caller retains its recovery record after failure.
pub fn repair_retained_versioned_installation(
    layout: &VersionedLayout,
    expected: &VersionedReceipt,
    artifact_limit: u64,
) -> Result<bool> {
    validate_layout(layout)?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    let lock = InstallationLock::acquire(&layout.lock_path())?;
    observe(layout, expected, artifact_limit)?;
    let (bin, _) = open_directory_chain(&layout.bin_dir, false)?;
    let (data, _) = open_directory_chain(&layout.data_root, false)?;
    activation_withdrawal::verify_named_parent(&layout.bin_dir, &bin, layout)?;
    activation_withdrawal::verify_named_parent(&layout.data_root, &data, layout)?;
    verify_observation_lock(layout, &lock)?;
    let changed = repair_missing_receipt_links(layout, expected)?;
    rustix::fs::fsync(&bin)?;
    rustix::fs::fsync(&data)?;
    activation_withdrawal::verify_named_parent(&layout.bin_dir, &bin, layout)?;
    activation_withdrawal::verify_named_parent(&layout.data_root, &data, layout)?;
    verify_observation_lock(layout, &lock)?;
    let authority = receipt_authority(layout);
    let current = read_versioned_receipt_document(layout)?;
    if current.as_ref().is_some_and(|document| {
        serde_json::from_slice::<VersionedReceipt>(&document.bytes)
            .ok()
            .as_ref()
            != Some(expected)
    }) {
        bail!("retained repair receipt changed before publication");
    }
    let bytes = serde_jcs::to_vec(expected)?;
    let receipt_changed = write_atomic_document(
        &layout.receipt_path(),
        &bytes,
        &authority,
        current.as_ref().map(|document| &document.identity),
    )?;
    verify_versioned_receipt(layout, expected)?;
    Ok(changed || receipt_changed)
}

fn observe(
    layout: &VersionedLayout,
    expected: &VersionedReceipt,
    artifact_limit: u64,
) -> Result<()> {
    validate_layout(layout)?;
    validate_versioned_receipt(layout, expected)?;
    if artifact_limit == 0 {
        bail!("retained repair requires an artifact bound");
    }
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    inspect_owned_directory_read_only(&layout.bin_dir, layout)?;
    require_path_absent(&layout.journal_path())?;
    if read_versioned_receipt_document(layout)?
        .as_ref()
        .is_some_and(|document| {
            serde_json::from_slice::<VersionedReceipt>(&document.bytes)
                .ok()
                .as_ref()
                != Some(expected)
        })
    {
        bail!("retained repair receipt differs from retained authority");
    }
    verify_recovery_artifacts(layout, expected, artifact_limit)?;
    let (bin, _) = open_directory_chain(&layout.bin_dir, false)?;
    let (data, _) = open_directory_chain(&layout.data_root, false)?;
    for alias in &expected.aliases {
        activation_withdrawal::inspect_link(
            &bin,
            OsStr::new(alias),
            &layout.active_pointer(),
            layout.owner_uid,
        )?;
    }
    activation_withdrawal::inspect_link(
        &data,
        OsStr::new("active"),
        &layout.version_artifact(&expected.active_version),
        layout.owner_uid,
    )?;
    match &expected.previous_version {
        Some(version) => {
            activation_withdrawal::inspect_link(
                &data,
                OsStr::new("previous"),
                &layout.version_artifact(version),
                layout.owner_uid,
            )?;
        }
        None => require_path_absent(&layout.previous_pointer())?,
    }
    activation_withdrawal::verify_named_parent(&layout.bin_dir, &bin, layout)?;
    activation_withdrawal::verify_named_parent(&layout.data_root, &data, layout)
}
