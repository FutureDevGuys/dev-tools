use crate::ledger_store::LedgerStore;
use dev_tools_installation::{
    recover_versioned_installation_with_verification, VersionedLayout, VersionedReceipt,
};
use dev_tools_update::artifact::{ArtifactRecord, InstallationPolicy};

pub(super) fn execute_with_store(
    record: &ArtifactRecord,
    store: &LedgerStore,
    changed: &mut Option<bool>,
) -> Result<(bool, Option<VersionedReceipt>), (&'static str, i32)> {
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
    let (_, identity) = store
        .load(record)
        .map_err(|_| ("authority-unavailable", 4))?
        .ok_or(("trust-initialization-required", 3))?;
    let evidence =
        crate::signed_cache::Store::new(layout.data_root.join("release-evidence-v1"), owner)
            .map_err(|_| ("retained-evidence-unavailable", 4))?;
    let mut aliases = config.aliases().to_vec();
    aliases.sort();
    let result = store
        .with_current(record, &identity, |ledger| {
            // Lock order is ledger, installation, then read-only retained evidence.
            // No network, executable invocation or ledger acceptance occurs here.
            *changed = None;
            recover_versioned_installation_with_verification(
                &layout,
                256 * 1024 * 1024,
                |receipt| {
                    if receipt.aliases != aliases {
                        return Err(std::io::Error::other("configured aliases changed").into());
                    }
                    for (version, identity) in
                        std::iter::once((&receipt.active_version, &receipt.active_identity)).chain(
                            receipt
                                .previous_version
                                .as_ref()
                                .zip(receipt.previous_identity.as_ref()),
                        )
                    {
                        if !crate::retained_evidence::verify(
                            &evidence,
                            record,
                            version,
                            identity,
                            || Ok(ledger.clone()),
                        )
                        .map_err(|_| {
                            std::io::Error::other("retained evidence verification failed")
                        })? {
                            return Err(
                                std::io::Error::other("retained evidence is required").into()
                            );
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|_| "recovery verification or restoration failed".into())
        })
        .map_err(|_| ("recovery-authority-or-restoration-failed", 4))?;
    *changed = Some(result.0);
    Ok(result)
}
