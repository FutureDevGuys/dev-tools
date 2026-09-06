use crate::ledger_store::LedgerStore;
use dev_tools_installation::{
    observe_versioned_installation, rollback_versioned_installation_if_unchanged,
    VersionedApplyReport, VersionedLayout,
};
use dev_tools_update::artifact::{ArtifactRecord, InstallationPolicy};

pub(super) fn execute_with_store(
    record: &ArtifactRecord,
    store: &LedgerStore,
    changed: &mut Option<bool>,
) -> Result<VersionedApplyReport, (&'static str, i32)> {
    let authority = record.release_authority().ok_or(("check-only", 3))?;
    if authority.target != format!("linux-{}", std::env::consts::ARCH) {
        return Err(("non-native-target", 3));
    }
    let Some(InstallationPolicy::VersionedBinary(config)) = record.installation() else {
        return Err(("installation-unconfigured", 3));
    };
    let owner = rustix::process::geteuid().as_raw();
    for (path, mode) in [(config.data_root(), 0o700), (config.bin_dir(), 0o755)] {
        crate::private_directory::inspect_directory(path, owner, mode)
            .map_err(|_| ("installation-authority-unavailable", 4))?;
    }
    let layout = VersionedLayout {
        product: record.id().into(),
        data_root: config.data_root().into(),
        bin_dir: config.bin_dir().into(),
        artifact_name: config.artifact_name().into(),
        owner_uid: owner,
        directory_mode: 0o700,
        bin_directory_mode: Some(0o755),
    };
    let prior = observe_versioned_installation(&layout, 256 * 1024 * 1024)
        .map_err(|_| ("installation-authority-unavailable", 4))?
        .ok_or(("managed-installation-required", 3))?;
    let mut aliases = config.aliases().to_vec();
    aliases.sort();
    if prior.aliases != aliases {
        return Err(("installation-authority-unavailable", 4));
    }
    let (Some(previous), Some(previous_identity)) =
        (&prior.previous_version, &prior.previous_identity)
    else {
        return Err(("retained-version-required", 3));
    };
    let (_, identity) = store
        .load(record)
        .map_err(|_| ("authority-unavailable", 4))?
        .ok_or(("trust-initialization-required", 3))?;
    let evidence =
        crate::signed_cache::Store::new(layout.data_root.join("release-evidence-v1"), owner)
            .map_err(|_| ("retained-evidence-unavailable", 4))?;
    let report = store
        .with_current(record, &identity, |ledger| {
            // Current trust must authenticate both sides of the swap. No cache
            // freshness or online acceptance transition grants rollback authority.
            for (version, identity) in [
                (&prior.active_version, &prior.active_identity),
                (previous, previous_identity),
            ] {
                if !crate::retained_evidence::verify(&evidence, record, version, identity, || {
                    Ok(ledger.clone())
                })? {
                    return Err("retained evidence is required".into());
                }
            }
            *changed = None;
            rollback_versioned_installation_if_unchanged(&layout, &prior, |_| Ok(()))
                .map_err(|_| "rollback activation failed".into())
        })
        .map_err(|_| ("rollback-authority-or-activation-failed", 4))?;
    *changed = Some(report.changed);
    Ok(report)
}
