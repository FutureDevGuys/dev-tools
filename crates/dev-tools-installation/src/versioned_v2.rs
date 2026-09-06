//! Explicit Linux installation-protocol cutover, retaining the v1 filesystem
//! layout and lock. The outer v2 documents exclude v1 writers; their inner
//! receipt describes the unchanged artifact/link ownership model.
//!
//! Products own release authentication and the retirement of other old writers.
//! Initialization is an explicit mutation, never a side effect of observation.
//! All callbacks run under the installation lock: they must be bounded and local,
//! must not reacquire it, and must not wait for an operation that needs it.

use super::*;

const RECEIPT_SCHEMA: &str = "dev-tools-versioned-protocol-v2";
const UPGRADE_SCHEMA: &str = "dev-tools-versioned-protocol-upgrade-v2";
const TRANSITION_SCHEMA: &str = "dev-tools-versioned-protocol-transition-v2";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolReceipt {
    schema: String,
    layout: VersionedLayout,
    installation: Option<VersionedReceipt>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UpgradeJournal {
    schema: String,
    layout: VersionedLayout,
    prior: Option<VersionedReceipt>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransitionJournal {
    schema: String,
    layout: VersionedLayout,
    transition: VersionedTransitionJournal,
}

/// Initialize or resume v2 without changing the active or retained version.
/// The durable upgrade journal is written before `commit_product_state` runs.
/// An error retains that journal, excluding v1 writers until explicit resumption;
/// ordinary recovery cannot cancel the upgrade or restore v1 authority.
///
/// The callback must authenticate the supplied receipt and durably complete its
/// product-owned state cutover. It must be idempotent: interruption can repeat it
/// even after the v2 receipt was published. Success without a pending upgrade
/// does not call it again. This API cannot itself exclude legacy product writers
/// that bypass the installation protocol. Products must satisfy that boundary in
/// the callback before returning success.
///
/// A legacy adoption or normal installation journal requires its own explicit
/// recovery first. An empty v2 receipt is retained to exclude old first-install
/// writers. Errors after admission may have changed durable state.
pub fn initialize<F>(
    layout: &VersionedLayout,
    artifact_limit: u64,
    commit_product_state: F,
) -> Result<(bool, Option<VersionedReceipt>)>
where
    F: FnOnce(Option<&VersionedReceipt>) -> Result<()>,
{
    validate_layout(layout)?;
    require_bound(artifact_limit)?;
    ensure_owned_directory(&layout.data_root, layout.owner_uid, layout.directory_mode)?;
    let lock = InstallationLock::acquire(&layout.lock_path())?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    let journal = read_atomic_document(&layout.journal_path(), &receipt_authority(layout))?;
    let current = read_versioned_receipt_document(layout)?;
    if journal.is_none() && current.is_none() {
        prepare_layout(layout, None)?;
    }
    inspect_owned_directory_read_only(&layout.bin_dir, layout)?;
    let initialized = current
        .as_ref()
        .and_then(|document| serde_json::from_slice::<ProtocolReceipt>(&document.bytes).ok());
    let prior = if let Some(document) = journal {
        let upgrade: UpgradeJournal = serde_json::from_slice(&document.bytes)
            .context("installation requires its explicit transition recovery")?;
        if upgrade.schema != UPGRADE_SCHEMA || upgrade.layout != *layout {
            bail!("installation protocol upgrade does not match its layout");
        }
        validate_optional(layout, upgrade.prior.as_ref())?;
        let installed = match initialized {
            Some(receipt) => validate_envelope(layout, receipt)?,
            None => read_versioned_receipt(layout)?,
        };
        if installed != upgrade.prior {
            bail!("installation changed during protocol upgrade");
        }
        upgrade.prior
    } else if let Some(receipt) = initialized {
        let installed = validate_envelope(layout, receipt)?;
        verify_optional(layout, installed.as_ref(), artifact_limit)?;
        return Ok((false, installed));
    } else {
        let prior = read_versioned_receipt(layout)?;
        verify_optional(layout, prior.as_ref(), artifact_limit)?;
        write_new_journal(
            layout,
            &UpgradeJournal {
                schema: UPGRADE_SCHEMA.into(),
                layout: layout.clone(),
                prior: prior.clone(),
            },
        )?;
        prior
    };
    verify_optional(layout, prior.as_ref(), artifact_limit)?;
    commit_product_state(prior.as_ref())?;
    verify_observation_lock(layout, &lock)?;
    write_receipt(layout, prior.as_ref())?;
    remove_transition_journal(layout)?;
    Ok((true, prior))
}

/// Observe initialized v2 state without creation, recovery, repair or network.
/// An absent namespace or receipt is an error: initialization is explicit.
pub fn observe(layout: &VersionedLayout, artifact_limit: u64) -> Result<Option<VersionedReceipt>> {
    validate_layout(layout)?;
    require_bound(artifact_limit)?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    let lock = acquire_observation_lock(layout)?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    inspect_owned_directory_read_only(&layout.bin_dir, layout)?;
    require_path_absent(&layout.journal_path())
        .context("installation requires explicit recovery or protocol upgrade resumption")?;
    let receipt = read_receipt(layout)?;
    verify_optional(layout, receipt.as_ref(), artifact_limit)?;
    verify_observation_lock(layout, &lock)?;
    Ok(receipt)
}

/// Read only bounded v2 receipt metadata, including during a pending transition.
/// This validates the outer schema, exact layout and inner receipt structure,
/// but does not inspect journals, links or artifact bytes, acquire a lock, repair,
/// authenticate a release, or authorize mutation. Use `observe` for complete
/// installation custody and the explicit mutation APIs for recovery/activation.
/// `None` is an initialized empty receipt; a missing receipt is an error.
pub fn read_receipt_metadata(layout: &VersionedLayout) -> Result<Option<VersionedReceipt>> {
    validate_layout(layout)?;
    read_receipt(layout)
}

/// A recognized v2 journal's required explicit recovery boundary. Classification
/// alone establishes neither receipt/artifact custody nor permission to mutate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingRecovery {
    ProtocolUpgrade,
    Activation,
}

/// Classify a bounded v2 journal without creating, locking or recovering.
/// Unknown, malformed, foreign-layout and legacy journals are errors, not an
/// empty journal or a reason to guess a recovery operation. The selected mutation
/// API must independently revalidate the journal and all required custody.
pub fn pending_recovery(layout: &VersionedLayout) -> Result<Option<PendingRecovery>> {
    validate_layout(layout)?;
    let Some(document) = read_atomic_document(&layout.journal_path(), &receipt_authority(layout))?
    else {
        return Ok(None);
    };
    if let Ok(upgrade) = serde_json::from_slice::<UpgradeJournal>(&document.bytes) {
        if upgrade.schema != UPGRADE_SCHEMA || upgrade.layout != *layout {
            bail!("installation protocol upgrade does not match its layout");
        }
        validate_optional(layout, upgrade.prior.as_ref())?;
        return Ok(Some(PendingRecovery::ProtocolUpgrade));
    }
    let transition: TransitionJournal = serde_json::from_slice(&document.bytes)
        .context("installation journal is not a recognized v2 transition")?;
    if transition.schema != TRANSITION_SCHEMA || transition.layout != *layout {
        bail!("installation transition does not match its layout");
    }
    validate_transition_journal(layout, &transition.transition)?;
    if transition.transition.legacy.is_some() {
        bail!("v2 transition cannot contain legacy adoption");
    }
    Ok(Some(PendingRecovery::Activation))
}

/// Apply only if the initialized receipt equals the caller's observation.
/// Pending journals, link drift and receipt changes fail before candidate
/// publication. Product authentication and candidate health remain caller-owned.
pub fn apply_if_unchanged<F>(
    request: &VersionedInstallRequest,
    expected: Option<&VersionedReceipt>,
    post_install_verify: F,
) -> Result<VersionedApplyReport>
where
    F: FnOnce(&Path) -> Result<()>,
{
    validate_versioned_request(request)?;
    let layout = &request.layout;
    let _lock = mutation_lock(layout)?;
    let prior = read_receipt(layout)?;
    if prior.as_ref() != expected {
        bail!("installation receipt changed since observation");
    }
    verify_optional(layout, prior.as_ref(), u64::MAX)?;
    if let Some(receipt) = &prior {
        if receipt.active_version == request.version {
            if receipt.active_identity != request.identity || receipt.aliases != request.aliases {
                bail!("an installed version cannot change its identity or owned aliases in place");
            }
            post_install_verify(&layout.version_artifact(&request.version))?;
            return Ok(VersionedApplyReport {
                changed: false,
                receipt: receipt.clone(),
            });
        }
    }
    preflight_alias_transition(layout, prior.as_ref(), &request.aliases)?;
    prepare_layout(layout, Some(&request.version))?;
    let candidate = layout.version_artifact(&request.version);
    publish_executable(&request.source, &candidate, &request.identity)?;
    verify_versioned_artifact_authority(&candidate, layout.owner_uid, &request.identity)?;
    post_install_verify(&candidate).context("product post-install verification failed")?;
    let next = VersionedReceipt {
        schema: VERSIONED_RECEIPT_SCHEMA.into(),
        product: layout.product.clone(),
        data_root: layout.data_root.clone(),
        bin_dir: layout.bin_dir.clone(),
        artifact_name: layout.artifact_name.clone(),
        active_version: request.version.clone(),
        active_identity: request.identity.clone(),
        previous_version: prior.as_ref().map(|receipt| receipt.active_version.clone()),
        previous_identity: prior
            .as_ref()
            .map(|receipt| receipt.active_identity.clone()),
        aliases: request.aliases.clone(),
    };
    commit(layout, prior.as_ref(), &next)?;
    remove_superseded_version(layout, prior.as_ref(), &next)?;
    Ok(VersionedApplyReport {
        changed: true,
        receipt: next,
    })
}

/// Activate the authenticated retained version only while the observed receipt
/// remains current. This neither accesses the network nor lowers release history.
pub fn rollback_if_unchanged<F>(
    layout: &VersionedLayout,
    expected: &VersionedReceipt,
    post_install_verify: F,
) -> Result<VersionedApplyReport>
where
    F: FnOnce(&Path) -> Result<()>,
{
    validate_layout(layout)?;
    let _lock = mutation_lock(layout)?;
    let prior = read_receipt(layout)?.context("installation receipt is empty")?;
    if prior != *expected {
        bail!("installation receipt changed since observation");
    }
    verify_optional(layout, Some(&prior), u64::MAX)?;
    let version = prior
        .previous_version
        .clone()
        .context("no retained previous version")?;
    let identity = prior
        .previous_identity
        .clone()
        .context("no retained previous identity")?;
    post_install_verify(&layout.version_artifact(&version))
        .context("product rollback verification failed")?;
    let next = VersionedReceipt {
        active_version: version,
        active_identity: identity,
        previous_version: Some(prior.active_version.clone()),
        previous_identity: Some(prior.active_identity.clone()),
        ..prior.clone()
    };
    commit(layout, Some(&prior), &next)?;
    Ok(VersionedApplyReport {
        changed: true,
        receipt: next,
    })
}

/// Authenticate and recover a normal v2 transition. A protocol upgrade requires
/// `initialize` instead; it can never be undone by ordinary recovery. The verifier
/// may run for both receipts, including a candidate whose links are not active.
pub fn recover<F>(
    layout: &VersionedLayout,
    artifact_limit: u64,
    mut verify: F,
) -> Result<(bool, Option<VersionedReceipt>)>
where
    F: FnMut(&VersionedReceipt) -> Result<()>,
{
    validate_layout(layout)?;
    require_bound(artifact_limit)?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    let lock = InstallationLock::acquire(&layout.lock_path())?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    inspect_owned_directory_read_only(&layout.bin_dir, layout)?;
    let installed = read_receipt(layout)?;
    let Some(document) = read_atomic_document(&layout.journal_path(), &receipt_authority(layout))?
    else {
        if let Some(receipt) = &installed {
            verify(receipt)?;
        }
        verify_optional(layout, installed.as_ref(), artifact_limit)?;
        return Ok((false, installed));
    };
    let envelope: TransitionJournal = serde_json::from_slice(&document.bytes)
        .context("installation requires explicit protocol upgrade resumption")?;
    if envelope.schema != TRANSITION_SCHEMA || envelope.layout != *layout {
        bail!("installation transition does not match its layout");
    }
    let journal = envelope.transition;
    validate_transition_journal(layout, &journal)?;
    if journal.legacy.is_some() {
        bail!("v2 transition cannot contain legacy adoption");
    }
    let committed = installed.as_ref() == Some(&journal.next);
    if !committed && installed != journal.prior {
        bail!("installation receipt changed during interrupted transition");
    }
    verify(&journal.next)?;
    if let Some(prior) = &journal.prior {
        verify(prior)?;
    }
    verify_recovery_artifacts(layout, &journal.next, artifact_limit)?;
    if let Some(prior) = &journal.prior {
        verify_recovery_artifacts(layout, prior, artifact_limit)?;
    }
    verify_observation_lock(layout, &lock)?;
    if committed {
        verify_versioned_receipt(layout, &journal.next)?;
    } else {
        restore_transition_prior(layout, &journal)?;
    }
    remove_transition_journal(layout)?;
    Ok((true, installed))
}

fn require_bound(limit: u64) -> Result<()> {
    if limit == 0 {
        bail!("installation requires an artifact bound");
    }
    Ok(())
}

fn validate_optional(layout: &VersionedLayout, receipt: Option<&VersionedReceipt>) -> Result<()> {
    if let Some(receipt) = receipt {
        validate_versioned_receipt(layout, receipt)?;
    }
    Ok(())
}

fn verify_optional(
    layout: &VersionedLayout,
    receipt: Option<&VersionedReceipt>,
    limit: u64,
) -> Result<()> {
    if let Some(receipt) = receipt {
        verify_recovery_artifacts(layout, receipt, limit)?;
        verify_versioned_receipt(layout, receipt)?;
    } else {
        require_path_absent(&layout.active_pointer())?;
        require_path_absent(&layout.previous_pointer())?;
    }
    Ok(())
}

fn validate_envelope(
    layout: &VersionedLayout,
    receipt: ProtocolReceipt,
) -> Result<Option<VersionedReceipt>> {
    if receipt.schema != RECEIPT_SCHEMA || receipt.layout != *layout {
        bail!("installation protocol receipt does not match its layout");
    }
    validate_optional(layout, receipt.installation.as_ref())?;
    Ok(receipt.installation)
}

fn read_receipt(layout: &VersionedLayout) -> Result<Option<VersionedReceipt>> {
    let document = read_versioned_receipt_document(layout)?
        .context("installation protocol requires explicit initialization")?;
    let receipt =
        serde_json::from_slice(&document.bytes).context("parse v2 installation receipt")?;
    validate_envelope(layout, receipt)
}

fn write_receipt(layout: &VersionedLayout, installed: Option<&VersionedReceipt>) -> Result<()> {
    validate_optional(layout, installed)?;
    let bytes = serde_jcs::to_vec(&ProtocolReceipt {
        schema: RECEIPT_SCHEMA.into(),
        layout: layout.clone(),
        installation: installed.cloned(),
    })?;
    let current = read_versioned_receipt_document(layout)?;
    write_atomic_document(
        &layout.receipt_path(),
        &bytes,
        &receipt_authority(layout),
        current.as_ref().map(|document| &document.identity),
    )?;
    Ok(())
}

fn write_new_journal(layout: &VersionedLayout, journal: &impl Serialize) -> Result<()> {
    require_path_absent(&layout.journal_path())?;
    write_atomic_document(
        &layout.journal_path(),
        &serde_jcs::to_vec(journal)?,
        &receipt_authority(layout),
        None,
    )?;
    Ok(())
}

fn mutation_lock(layout: &VersionedLayout) -> Result<InstallationLock> {
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    let lock = InstallationLock::acquire(&layout.lock_path())?;
    inspect_owned_directory_read_only(&layout.data_root, layout)?;
    inspect_owned_directory_read_only(&layout.bin_dir, layout)?;
    require_path_absent(&layout.journal_path())
        .context("installation requires explicit recovery or protocol upgrade resumption")?;
    Ok(lock)
}

fn commit(
    layout: &VersionedLayout,
    prior: Option<&VersionedReceipt>,
    next: &VersionedReceipt,
) -> Result<()> {
    validate_versioned_receipt(layout, next)?;
    verify_optional(layout, prior, u64::MAX)?;
    preflight_alias_transition(layout, prior, &next.aliases)?;
    write_new_journal(
        layout,
        &TransitionJournal {
            schema: TRANSITION_SCHEMA.into(),
            layout: layout.clone(),
            transition: VersionedTransitionJournal {
                schema: VERSIONED_JOURNAL_SCHEMA.into(),
                prior: prior.cloned(),
                next: next.clone(),
                legacy: None,
            },
        },
    )?;
    publish_versioned_transition_links(layout, prior, next)?;
    write_receipt(layout, Some(next))?;
    verify_versioned_receipt(layout, next)?;
    remove_transition_journal(layout)
}
