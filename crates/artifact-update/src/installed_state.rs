//! Local receipt evidence is distinct from authenticated release evidence.
use dev_tools_installation::{observe_versioned_installation, VersionedLayout};
use dev_tools_update::artifact::{ArtifactRecord, InstallationPolicy};

const ERROR: &str = "installed receipt or filesystem authority is unavailable";
const ARTIFACT_LIMIT: u64 = 256 * 1024 * 1024;

enum Observation {
    Unconfigured,
    Unknown,
    External,
    Managed {
        version: String,
        authenticated: bool,
    },
}

fn observe(record: &ArtifactRecord, owner: u32) -> Result<Observation, String> {
    let config = match record.installation() {
        None => return Ok(Observation::Unconfigured),
        Some(InstallationPolicy::VersionedBinary(config)) => config,
        Some(_) => return Err(ERROR.into()),
    };
    crate::private_directory::inspect_directory(config.data_root(), owner, 0o700)
        .map_err(|_| ERROR)?;
    let bin_exists = crate::private_directory::inspect_directory(config.bin_dir(), owner, 0o755)
        .map_err(|_| ERROR)?;
    let layout = VersionedLayout {
        product: record.id().into(),
        data_root: config.data_root().into(),
        bin_dir: config.bin_dir().into(),
        artifact_name: config.artifact_name().into(),
        owner_uid: owner,
        directory_mode: 0o700,
        bin_directory_mode: Some(0o755),
    };
    if let Some(receipt) =
        observe_versioned_installation(&layout, ARTIFACT_LIMIT).map_err(|_| ERROR)?
    {
        let mut aliases = config.aliases().to_vec();
        aliases.sort();
        if aliases != receipt.aliases {
            return Err(ERROR.into());
        }
        let evidence =
            crate::signed_cache::Store::new(layout.data_root.join("release-evidence-v1"), owner)
                .map_err(|_| ERROR)?;
        let authenticated = crate::retained_evidence::verify(
            &evidence,
            record,
            &receipt.active_version,
            &receipt.active_identity,
            || {
                crate::ledger_store::LedgerStore::for_record(record)?
                    .load(record)?
                    .map(|(ledger, _)| ledger)
                    .ok_or_else(|| ERROR.into())
            },
        )?;
        return Ok(Observation::Managed {
            version: receipt.active_version,
            authenticated,
        });
    }
    let mut external = false;
    if bin_exists {
        for alias in config.aliases() {
            match std::fs::symlink_metadata(config.bin_dir().join(alias)) {
                Ok(_) => external = true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(ERROR.into()),
            }
        }
    }
    Ok(if external {
        Observation::External
    } else {
        Observation::Unknown
    })
}

pub(super) fn attach(row: &mut serde_json::Value, record: &ArtifactRecord) {
    match observe(record, rustix::process::geteuid().as_raw()) {
        Ok(observed) => {
            row["installation_configured"] =
                serde_json::json!(!matches!(observed, Observation::Unconfigured));
            row["installation_state"] = serde_json::json!(match &observed {
                Observation::External => "external",
                Observation::Managed { .. } => "managed",
                Observation::Unconfigured | Observation::Unknown => "unknown",
            });
            if let Observation::Managed {
                version,
                authenticated,
            } = observed
            {
                row["installed_version"] = serde_json::json!(version);
                row["installed_verification"] = serde_json::json!(if authenticated {
                    "signed-manifest-and-receipt-content"
                } else {
                    "receipt-content"
                });
            }
        }
        Err(_) => {
            row["outcome"] = serde_json::json!("authority-unavailable");
            row["installation_state"] = serde_json::json!("unknown");
            row["error_kind"] = serde_json::json!("authority-violation");
        }
    }
}
