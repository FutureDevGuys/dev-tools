use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use wait_timeout::ChildExt;
use walkdir::WalkDir;

use crate::artifacts::{self, ArtifactRecord};
use crate::cargo_intercept;
use crate::config::GcConfig;
use crate::lease::{active_resource_ids, RootLease};
use crate::repository::{
    classify_identity_record, current_identity_record, records_describe_same_workspace,
    scan_identity_issues, validate_identity_record, IdentityDisposition, IdentityIssue,
    IdentityRecord,
};
use crate::resources::{self, CleanupStrategy, ResourceKind, ResourceRecord};
use crate::root::RootHandle;
use crate::util::{directory_size, now_unix, write_json_atomic};

#[derive(Clone, Debug, Default)]
pub struct GcOverrides {
    pub max_bytes: Option<u64>,
    pub min_free_bytes: Option<u64>,
    pub target_free_bytes: Option<u64>,
    pub stale_after_days: Option<u64>,
    pub max_actions: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GcAction {
    pub kind: String,
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub companion_paths: Vec<PathBuf>,
    pub bytes: u64,
    pub reason: String,
    pub strategy: String,
    pub resource_id: Option<String>,
    pub last_used_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GcAbstention {
    pub resource_id: Option<String>,
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GcFailure {
    pub resource_id: Option<String>,
    pub path: PathBuf,
    pub phase: String,
    pub error: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GcReport {
    pub applied: bool,
    pub complete: bool,
    pub bytes_before: u64,
    pub bytes_selected: u64,
    pub bytes_reclaimed: u64,
    pub free_before: u64,
    pub free_after: u64,
    pub target_free_bytes: u64,
    pub target_shortfall_bytes: u64,
    pub size_limit_shortfall_bytes: u64,
    pub actions: Vec<GcAction>,
    pub abstentions: Vec<GcAbstention>,
    pub failures: Vec<GcFailure>,
    pub trash_backlog: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct MaintenanceStatus {
    pub resources: usize,
    pub catalog_issues: Vec<resources::CatalogIssue>,
    pub repository_issues: Vec<IdentityIssue>,
    pub hazards: std::collections::BTreeMap<String, Vec<String>>,
    pub trash_backlog: usize,
    pub last_automatic: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TrashJournal {
    schema_version: u32,
    transaction_id: String,
    resource_id: Option<String>,
    original_paths: Vec<PathBuf>,
    trash_path: PathBuf,
    committed: bool,
    created_unix: u64,
}

struct NativeOutput {
    status: ExitStatus,
    stderr: Vec<u8>,
}

pub fn pressure_needed(root: &RootHandle, policy: &GcConfig) -> Result<bool> {
    let free = fs2::available_space(&root.root)?;
    let bytes = directory_size(&root.platform_root);
    Ok(free < policy.min_free_bytes || policy.max_bytes.is_some_and(|limit| bytes > limit))
}

pub fn maintenance_status(root: &RootHandle) -> Result<MaintenanceStatus> {
    let (records, issues) = resources::scan(root)?;
    let last_automatic = fs::read(root.control().join("last-automatic-gc.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    Ok(MaintenanceStatus {
        resources: records.len(),
        catalog_issues: issues,
        repository_issues: scan_identity_issues(root)?,
        hazards: resources::hazard_map(&records),
        trash_backlog: trash_backlog(root)?,
        last_automatic,
    })
}

pub fn collect(
    root: &RootHandle,
    policy: &GcConfig,
    artifact_stale_after_days: u64,
    overrides: &GcOverrides,
    apply: bool,
) -> Result<GcReport> {
    let _lease = RootLease::exclusive(root)?;
    collect_with_lease(root, policy, artifact_stale_after_days, overrides, apply)
}

pub fn collect_if_idle(
    root: &RootHandle,
    policy: &GcConfig,
    artifact_stale_after_days: u64,
    overrides: &GcOverrides,
    apply: bool,
) -> Result<Option<GcReport>> {
    let Some(_lease) = RootLease::try_exclusive(root)? else {
        return Ok(None);
    };
    collect_with_lease(root, policy, artifact_stale_after_days, overrides, apply).map(Some)
}

fn collect_with_lease(
    root: &RootHandle,
    policy: &GcConfig,
    artifact_stale_after_days: u64,
    overrides: &GcOverrides,
    apply: bool,
) -> Result<GcReport> {
    if apply {
        recover_trash(root)?;
    }
    let bytes_before = directory_size(&root.platform_root);
    let free_before = fs2::available_space(&root.root)?;
    let stale_days = overrides
        .stale_after_days
        .unwrap_or(policy.stale_after_days);
    let min_free = overrides.min_free_bytes.unwrap_or(policy.min_free_bytes);
    let target_free = overrides
        .target_free_bytes
        .unwrap_or(policy.target_free_bytes);
    let max_bytes = overrides.max_bytes.or(policy.max_bytes);
    let pressure = free_before < min_free || max_bytes.is_some_and(|limit| bytes_before > limit);
    let now = now_unix();
    let active_resource_ids = active_resource_ids(root)?;
    let active_paths = active_resource_paths(root, &active_resource_ids)?;
    let mut abstentions = Vec::new();
    let (repository_actions, repository_abstentions) =
        repository_actions(root, now, stale_days, policy, &active_paths)?;
    let mut actions = repository_actions;
    abstentions.extend(repository_abstentions);
    let (artifact_actions, artifact_abstentions) =
        artifact_actions(root, now, artifact_stale_after_days)?;
    actions.extend(artifact_actions);
    abstentions.extend(artifact_abstentions);
    let (resource_actions, resource_abstentions) =
        resource_actions(root, now, stale_days, policy, &active_resource_ids)?;
    actions.extend(resource_actions);
    abstentions.extend(resource_abstentions);
    remove_nested_actions(&mut actions);
    actions.sort_by(|left, right| {
        action_age_rank(left)
            .cmp(&action_age_rank(right))
            .then(left.last_used_unix.cmp(&right.last_used_unix))
            .then(left.resource_id.cmp(&right.resource_id))
            .then(left.path.cmp(&right.path))
    });
    if pressure {
        let needed_for_free = target_free.saturating_sub(free_before);
        let needed_for_size = max_bytes
            .map(|limit| bytes_before.saturating_sub(limit))
            .unwrap_or(0);
        let needed = needed_for_free.max(needed_for_size);
        let mut selected = 0_u64;
        actions.retain(|action| {
            if action.reason == "pressure" && selected >= needed {
                return false;
            }
            selected = selected.saturating_add(action.bytes);
            true
        });
    } else {
        actions.retain(|action| action.reason != "pressure");
    }
    let mut work_remaining = false;
    if let Some(limit) = overrides.max_actions {
        work_remaining = actions.len() > limit;
        actions.truncate(limit);
    }
    let bytes_selected = actions.iter().map(|action| action.bytes).sum();
    let mut failures = Vec::new();
    if apply {
        for action in &actions {
            if let Err(error) = apply_action(root, action) {
                failures.push(GcFailure {
                    resource_id: action.resource_id.clone(),
                    path: action.path.clone(),
                    phase: "apply".to_owned(),
                    error: format!("{error:#}"),
                });
            }
        }
    }
    let free_after = fs2::available_space(&root.root)?;
    let bytes_after = directory_size(&root.platform_root);
    let bytes_reclaimed = bytes_before.saturating_sub(bytes_after);
    let target_shortfall_bytes = if pressure {
        target_free.saturating_sub(free_after)
    } else {
        0
    };
    let size_limit_shortfall_bytes = max_bytes
        .map(|limit| bytes_after.saturating_sub(limit))
        .unwrap_or(0);
    let trash_backlog = trash_backlog(root)?;
    Ok(GcReport {
        applied: apply,
        complete: failures.is_empty() && trash_backlog == 0 && !work_remaining,
        bytes_before,
        bytes_selected,
        bytes_reclaimed,
        free_before,
        free_after,
        target_free_bytes: target_free,
        target_shortfall_bytes,
        size_limit_shortfall_bytes,
        actions,
        abstentions,
        failures,
        trash_backlog,
    })
}

fn resource_actions(
    root: &RootHandle,
    now: u64,
    stale_days: u64,
    policy: &GcConfig,
    active_resource_ids: &std::collections::BTreeSet<String>,
) -> Result<(Vec<GcAction>, Vec<GcAbstention>)> {
    let (records, issues) = resources::scan(root)?;
    let mut actions = Vec::new();
    let mut abstentions = issues
        .into_iter()
        .map(|issue| GcAbstention {
            resource_id: None,
            path: issue.path,
            reason: issue.reason,
        })
        .collect::<Vec<_>>();
    for record in records {
        let path = match resources::absolute_path(root, &record) {
            Ok(path) => path,
            Err(error) => {
                abstentions.push(GcAbstention {
                    resource_id: Some(record.resource_id.clone()),
                    path: root.platform_root.join(&record.relative_path),
                    reason: format!("invalid resource containment: {error:#}"),
                });
                continue;
            }
        };
        if active_resource_ids.contains(&record.resource_id) {
            abstentions.push(GcAbstention {
                resource_id: Some(record.resource_id.clone()),
                path,
                reason: "resource is held by an active routed command".to_owned(),
            });
            continue;
        }
        if !record.hazards.is_empty() {
            abstentions.push(GcAbstention {
                resource_id: Some(record.resource_id.clone()),
                path,
                reason: format!(
                    "resource has persistent safety hazards: {}",
                    record
                        .hazards
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
            continue;
        }
        if !path.exists() {
            continue;
        }
        let last_used = record
            .last_completed_unix
            .unwrap_or(record.last_started_unix)
            .max(record.last_maintained_unix.unwrap_or(0));
        let age = now.saturating_sub(last_used);
        let stale_after_seconds = if matches!(
            record.kind,
            ResourceKind::GoTemp | ResourceKind::CcacheTemp | ResourceKind::GenericTemp
        ) {
            policy.temp_grace_hours.saturating_mul(3_600)
        } else {
            stale_days.saturating_mul(86_400)
        };
        let reason = if age >= stale_after_seconds {
            "stale"
        } else if age >= policy.pressure_min_age_hours.saturating_mul(3_600) {
            "pressure"
        } else {
            continue;
        };
        actions.push(GcAction {
            kind: format!("{:?}", record.kind).to_lowercase(),
            path: path.clone(),
            destination: None,
            companion_paths: Vec::new(),
            bytes: directory_size(&path),
            reason: reason.to_owned(),
            strategy: format!("{:?}", record.cleanup).to_lowercase(),
            resource_id: Some(record.resource_id.clone()),
            last_used_unix: last_used,
        });
    }
    Ok((actions, abstentions))
}

fn repository_actions(
    root: &RootHandle,
    now: u64,
    stale_days: u64,
    policy: &GcConfig,
    active_paths: &[PathBuf],
) -> Result<(Vec<GcAction>, Vec<GcAbstention>)> {
    let mut actions = Vec::new();
    let mut abstentions = Vec::new();
    if !root.repos().is_dir() {
        return Ok((actions, abstentions));
    }
    for prefix in fs::read_dir(root.repos())? {
        let prefix = prefix?;
        if !prefix.file_type()?.is_dir() {
            continue;
        }
        for entry in fs::read_dir(prefix.path())? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let identity_path = entry.path().join("identity.json");
            let record = match fs::read(&identity_path)
                .map_err(anyhow::Error::from)
                .and_then(|bytes| {
                    serde_json::from_slice::<IdentityRecord>(&bytes).map_err(Into::into)
                }) {
                Ok(record) => record,
                Err(error) => {
                    abstentions.push(GcAbstention {
                        resource_id: None,
                        path: entry.path(),
                        reason: format!("invalid repository ownership record: {error:#}"),
                    });
                    continue;
                }
            };
            match classify_identity_record(root, &entry.path(), &record) {
                Ok(IdentityDisposition::RootScoped {
                    legacy_path: _,
                    destination,
                }) => {
                    if path_overlaps_any(&entry.path(), active_paths)
                        || path_overlaps_any(&destination, active_paths)
                    {
                        abstentions.push(GcAbstention {
                            resource_id: None,
                            path: entry.path(),
                            reason: "workspace identity is held by an active routed command"
                                .to_owned(),
                        });
                        continue;
                    }
                    if let Err(error) =
                        verify_identity_reconciliation(root, &entry.path(), &destination, &record)
                    {
                        abstentions.push(GcAbstention {
                            resource_id: None,
                            path: entry.path(),
                            reason: format!(
                                "workspace identity reconciliation abstained: {error:#}"
                            ),
                        });
                        continue;
                    }
                    actions.push(GcAction {
                        kind: "repository-identity".to_owned(),
                        path: entry.path(),
                        destination: Some(destination),
                        companion_paths: Vec::new(),
                        bytes: 0,
                        reason: "identity-reconciliation".to_owned(),
                        strategy: "atomic-rehome".to_owned(),
                        resource_id: None,
                        last_used_unix: record.last_used_unix,
                    });
                    continue;
                }
                Ok(IdentityDisposition::UnknownSelfBound { destination }) => {
                    if is_empty_identity_duplicate(root, &entry.path(), &destination, &record)? {
                        actions.push(GcAction {
                            kind: "repository-identity-duplicate".to_owned(),
                            path: entry.path(),
                            destination: None,
                            companion_paths: Vec::new(),
                            bytes: directory_size(&entry.path()),
                            reason: "duplicate-identity-record".to_owned(),
                            strategy: "owneddirectory".to_owned(),
                            resource_id: None,
                            last_used_unix: record.last_used_unix,
                        });
                    } else {
                        abstentions.push(GcAbstention {
                            resource_id: None,
                            path: entry.path(),
                            reason: "workspace identity generation is unknown and is not an empty duplicate"
                                .to_owned(),
                        });
                    }
                    continue;
                }
                Ok(IdentityDisposition::Current) => {}
                Err(error) => {
                    abstentions.push(GcAbstention {
                        resource_id: None,
                        path: entry.path(),
                        reason: format!("invalid repository ownership record: {error:#}"),
                    });
                    continue;
                }
            }
            let age = now.saturating_sub(record.last_used_unix);
            let orphan = !record.canonical_worktree.exists();
            let threshold = if orphan {
                policy.orphan_grace_days.saturating_mul(86_400)
            } else {
                stale_days.saturating_mul(86_400)
            };
            if age >= threshold && !path_overlaps_any(&entry.path(), active_paths) {
                actions.push(GcAction {
                    kind: "repository".to_owned(),
                    path: entry.path(),
                    destination: None,
                    companion_paths: Vec::new(),
                    bytes: directory_size(&entry.path()),
                    reason: if orphan { "orphan" } else { "stale" }.to_owned(),
                    strategy: "owneddirectory".to_owned(),
                    resource_id: None,
                    last_used_unix: record.last_used_unix,
                });
            }
        }
    }
    Ok((actions, abstentions))
}

fn active_resource_paths(
    root: &RootHandle,
    active_resource_ids: &std::collections::BTreeSet<String>,
) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for resource_id in active_resource_ids {
        let record = resources::get(root, resource_id)?
            .with_context(|| format!("active lease references missing resource {resource_id}"))?;
        paths.push(resources::absolute_path(root, &record)?);
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn path_overlaps_any(path: &Path, active_paths: &[PathBuf]) -> bool {
    active_paths
        .iter()
        .any(|active| active.starts_with(path) || path.starts_with(active))
}

fn artifact_actions(
    root: &RootHandle,
    now: u64,
    stale_days: u64,
) -> Result<(Vec<GcAction>, Vec<GcAbstention>)> {
    let mut actions = Vec::new();
    let mut abstentions = Vec::new();
    let metadata = root.platform_root.join("artifacts/metadata");
    if !metadata.is_dir() {
        return Ok((actions, abstentions));
    }
    for entry in fs::read_dir(metadata)? {
        let entry = entry?;
        let record = match fs::read(entry.path())
            .map_err(anyhow::Error::from)
            .and_then(|bytes| serde_json::from_slice::<ArtifactRecord>(&bytes).map_err(Into::into))
        {
            Ok(record) => record,
            Err(error) => {
                abstentions.push(GcAbstention {
                    resource_id: None,
                    path: entry.path(),
                    reason: format!("malformed artifact metadata: {error:#}"),
                });
                continue;
            }
        };
        if now.saturating_sub(record.last_verified_unix) < stale_days.saturating_mul(86_400) {
            continue;
        }
        let object = match artifacts::object_path(root, &record.digest) {
            Ok(path) => path,
            Err(error) => {
                abstentions.push(GcAbstention {
                    resource_id: None,
                    path: entry.path(),
                    reason: format!("invalid artifact digest: {error:#}"),
                });
                continue;
            }
        };
        let required_metadata = artifacts::metadata_path(root, &record.digest)?;
        if required_metadata != entry.path() {
            abstentions.push(GcAbstention {
                resource_id: None,
                path: entry.path(),
                reason: "artifact metadata filename does not match its digest".to_owned(),
            });
            continue;
        }
        let mut companions = Vec::new();
        if object.exists() {
            companions.push(object.clone());
        }
        companions.push(entry.path());
        actions.push(GcAction {
            kind: "artifact".to_owned(),
            path: object,
            destination: None,
            companion_paths: companions,
            bytes: record.size.saturating_add(entry.metadata()?.len()),
            reason: "stale".to_owned(),
            strategy: "owneddirectory".to_owned(),
            resource_id: Some(record.digest),
            last_used_unix: record.last_verified_unix,
        });
    }
    Ok((actions, abstentions))
}

fn remove_nested_actions(actions: &mut Vec<GcAction>) {
    let repository_roots = actions
        .iter()
        .filter(|action| action.kind == "repository")
        .map(|action| action.path.clone())
        .collect::<Vec<_>>();
    actions.retain(|action| {
        action.kind == "repository"
            || !repository_roots
                .iter()
                .any(|repository| action.path.starts_with(repository))
    });
}

fn apply_action(root: &RootHandle, action: &GcAction) -> Result<()> {
    if action.kind == "repository-identity" {
        return reconcile_repository_identity(root, action);
    }
    if action.kind == "repository-identity-duplicate" {
        return remove_empty_identity_duplicate(root, action);
    }
    if !action.path.exists() && action.companion_paths.iter().all(|path| !path.exists()) {
        return Ok(());
    }
    let record = if matches!(action.kind.as_str(), "artifact" | "repository") {
        None
    } else {
        action
            .resource_id
            .as_deref()
            .map(|resource_id| resources::get(root, resource_id))
            .transpose()?
            .flatten()
    };
    if let Some(record) = record.as_ref() {
        match record.cleanup {
            CleanupStrategy::OwnedDirectory => {
                owned_transaction(root, action)?;
                resources::remove_record(root, &record.resource_id)?;
            }
            CleanupStrategy::SccacheServerAware => {
                stop_sccache(record, &action.path)?;
                owned_transaction(root, action)?;
                resources::remove_record(root, &record.resource_id)?;
            }
            _ => {
                run_native_cleanup(record, &action.path, &action.reason)?;
                resources::mark_maintained(root, &record.resource_id)?;
            }
        }
    } else {
        let nested_resources = if action.kind == "repository" {
            resources::resource_ids_under(root, &action.path)?
        } else {
            Vec::new()
        };
        owned_transaction(root, action)?;
        for resource_id in nested_resources {
            resources::remove_record(root, &resource_id)?;
        }
    }
    Ok(())
}

fn remove_empty_identity_duplicate(root: &RootHandle, action: &GcAction) -> Result<()> {
    let record: IdentityRecord = serde_json::from_slice(
        &fs::read(action.path.join("identity.json"))
            .with_context(|| format!("read duplicate identity {}", action.path.display()))?,
    )
    .context("parse duplicate workspace identity")?;
    let destination = match classify_identity_record(root, &action.path, &record)? {
        IdentityDisposition::UnknownSelfBound { destination } => destination,
        _ => bail!("workspace identity changed after the collection plan was created"),
    };
    if !is_empty_identity_duplicate(root, &action.path, &destination, &record)? {
        bail!("workspace identity is no longer a safe empty duplicate");
    }
    owned_transaction(root, action)?;
    remove_empty_prefix(action.path.parent(), &root.repos())
}

fn verify_identity_reconciliation(
    root: &RootHandle,
    source: &Path,
    destination: &Path,
    source_record: &IdentityRecord,
) -> Result<()> {
    validate_action_path(root, source)?;
    validate_action_destination(root, destination)?;
    if source == destination {
        return Ok(());
    }
    if !destination.exists() {
        return Ok(());
    }
    let destination_record: IdentityRecord =
        serde_json::from_slice(&fs::read(destination.join("identity.json")).with_context(
            || format!("read current workspace identity {}", destination.display()),
        )?)
        .context("parse current workspace identity")?;
    validate_identity_record(root, destination, &destination_record)?;
    if !records_describe_same_workspace(source_record, &destination_record) {
        bail!("current destination describes a different workspace");
    }
    verify_mergeable_tree(root, source, destination, true)
}

fn is_empty_identity_duplicate(
    root: &RootHandle,
    source: &Path,
    destination: &Path,
    source_record: &IdentityRecord,
) -> Result<bool> {
    if source == destination || !destination.is_dir() {
        return Ok(false);
    }
    validate_action_path(root, source)?;
    validate_action_destination(root, destination)?;
    if !contains_only_identity_and_empty_directories(source)? {
        return Ok(false);
    }
    let destination_record: IdentityRecord = match fs::read(destination.join("identity.json"))
        .map_err(anyhow::Error::from)
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
    {
        Ok(record) => record,
        Err(_) => return Ok(false),
    };
    if validate_identity_record(root, destination, &destination_record).is_err() {
        return Ok(false);
    }
    Ok(records_describe_same_workspace(
        source_record,
        &destination_record,
    ))
}

fn contains_only_identity_and_empty_directories(source: &Path) -> Result<bool> {
    let identity = source.join("identity.json");
    let mut found_identity = false;
    for entry in WalkDir::new(source).follow_links(false) {
        let entry = entry?;
        if entry.path() == source {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Ok(false);
        }
        if metadata.is_dir() {
            continue;
        }
        if metadata.is_file() && entry.path() == identity {
            found_identity = true;
            continue;
        }
        return Ok(false);
    }
    Ok(found_identity)
}

fn reconcile_repository_identity(root: &RootHandle, action: &GcAction) -> Result<()> {
    let destination = action
        .destination
        .as_deref()
        .context("workspace identity action has no destination")?;
    let source_record: IdentityRecord = serde_json::from_slice(
        &fs::read(action.path.join("identity.json"))
            .with_context(|| format!("read workspace identity {}", action.path.display()))?,
    )
    .context("parse workspace identity during reconciliation")?;
    let disposition = classify_identity_record(root, &action.path, &source_record)?;
    let legacy_path = match disposition {
        IdentityDisposition::RootScoped {
            legacy_path,
            destination: expected,
        } if expected == destination => legacy_path,
        _ => bail!("workspace identity changed after the collection plan was created"),
    };
    verify_identity_reconciliation(root, &action.path, destination, &source_record)?;
    if action.path != destination {
        if destination.exists() {
            resources::rebase_under(root, &legacy_path, destination)?;
            merge_tree(root, &action.path, destination, true)?;
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::rename(&action.path, destination).with_context(|| {
                format!(
                    "atomically rehome workspace cache {} to {}",
                    action.path.display(),
                    destination.display()
                )
            })?;
            resources::rebase_under(root, &legacy_path, destination)?;
        }
    } else {
        resources::rebase_under(root, &legacy_path, destination)?;
    }
    let mut current = current_identity_record(root, &source_record);
    if let Ok(bytes) = fs::read(destination.join("identity.json")) {
        if let Ok(existing) = serde_json::from_slice::<IdentityRecord>(&bytes) {
            if validate_identity_record(root, destination, &existing).is_ok()
                && records_describe_same_workspace(&source_record, &existing)
            {
                current.created_unix = current.created_unix.min(existing.created_unix);
                current.last_used_unix = current.last_used_unix.max(existing.last_used_unix);
            }
        }
    }
    write_json_atomic(&destination.join("identity.json"), &current)?;
    remove_empty_prefix(action.path.parent(), &root.repos())?;
    Ok(())
}

fn verify_mergeable_tree(
    root: &RootHandle,
    source: &Path,
    destination: &Path,
    workspace_root: bool,
) -> Result<()> {
    validate_action_path(root, source)?;
    validate_action_destination(root, destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if workspace_root && entry.file_name() == "identity.json" {
            continue;
        }
        let source_child = entry.path();
        let destination_child = destination.join(entry.file_name());
        let source_type = entry.file_type()?;
        if source_type.is_symlink() || is_reparse_point(&entry.metadata()?) {
            bail!(
                "workspace cache contains a link at {}",
                source_child.display()
            );
        }
        if !destination_child.exists() {
            continue;
        }
        let destination_metadata = fs::symlink_metadata(&destination_child)?;
        if destination_metadata.file_type().is_symlink() || is_reparse_point(&destination_metadata)
        {
            bail!(
                "current workspace cache contains a link at {}",
                destination_child.display()
            );
        }
        if source_type.is_dir() && destination_metadata.is_dir() {
            verify_mergeable_tree(root, &source_child, &destination_child, false)?;
        } else if source_type.is_file()
            && destination_metadata.is_file()
            && files_equal(&source_child, &destination_child)?
        {
            continue;
        } else {
            bail!(
                "workspace cache collision differs at {}",
                destination_child.display()
            );
        }
    }
    Ok(())
}

fn merge_tree(
    root: &RootHandle,
    source: &Path,
    destination: &Path,
    workspace_root: bool,
) -> Result<()> {
    verify_mergeable_tree(root, source, destination, workspace_root)?;
    let mut identity = None;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_child = entry.path();
        if workspace_root && entry.file_name() == "identity.json" {
            identity = Some(source_child);
            continue;
        }
        let destination_child = destination.join(entry.file_name());
        if !destination_child.exists() {
            fs::rename(&source_child, &destination_child)?;
        } else if entry.file_type()?.is_dir() {
            merge_tree(root, &source_child, &destination_child, false)?;
        } else {
            fs::remove_file(&source_child)?;
        }
    }
    if let Some(identity) = identity {
        fs::remove_file(identity)?;
    }
    fs::remove_dir(source)?;
    Ok(())
}

fn files_equal(left: &Path, right: &Path) -> Result<bool> {
    if fs::metadata(left)?.len() != fs::metadata(right)?.len() {
        return Ok(false);
    }
    let mut left = fs::File::open(left)?;
    let mut right = fs::File::open(right)?;
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    loop {
        let left_read = left.read(&mut left_buffer)?;
        let right_read = right.read(&mut right_buffer)?;
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return Ok(false);
        }
        if left_read == 0 {
            return Ok(true);
        }
    }
}

fn validate_action_destination(root: &RootHandle, path: &Path) -> Result<()> {
    if !path.starts_with(root.repos()) || path == root.repos() {
        bail!(
            "workspace identity destination is outside workspace storage: {}",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        validate_action_path(root, parent)?;
    }
    Ok(())
}

fn remove_empty_prefix(prefix: Option<&Path>, boundary: &Path) -> Result<()> {
    if let Some(prefix) = prefix.filter(|prefix| *prefix != boundary) {
        if prefix.is_dir() && fs::read_dir(prefix)?.next().is_none() {
            fs::remove_dir(prefix)?;
        }
    }
    Ok(())
}

fn owned_transaction(root: &RootHandle, action: &GcAction) -> Result<()> {
    let transaction_id = uuid::Uuid::new_v4().simple().to_string();
    let trash_path = root.trash().join(&transaction_id);
    let journal_path = root
        .control()
        .join("gc-journal")
        .join(format!("{transaction_id}.json"));
    let mut paths = if action.companion_paths.is_empty() {
        vec![action.path.clone()]
    } else {
        action.companion_paths.clone()
    };
    paths.sort();
    paths.dedup();
    for path in &paths {
        validate_action_path(root, path)?;
    }
    let mut journal = TrashJournal {
        schema_version: 1,
        transaction_id: transaction_id.clone(),
        resource_id: action.resource_id.clone(),
        original_paths: paths.clone(),
        trash_path: trash_path.clone(),
        committed: false,
        created_unix: now_unix(),
    };
    write_json_atomic(&journal_path, &journal)?;
    fs::create_dir_all(&trash_path)?;
    for (index, path) in paths.iter().enumerate() {
        if !path.exists() {
            continue;
        }
        if let Err(error) = fs::rename(path, trash_path.join(index.to_string())) {
            if let Err(rollback) = restore_uncommitted(root, &journal) {
                bail!(
                    "move {} into owned GC trash failed: {error}; rollback also failed: {rollback:#}",
                    path.display()
                );
            }
            fs::remove_file(&journal_path)?;
            return Err(error)
                .with_context(|| format!("move {} into owned GC trash", path.display()));
        }
    }
    journal.committed = true;
    write_json_atomic(&journal_path, &journal)?;
    remove_path(&trash_path)?;
    fs::remove_file(journal_path)?;
    Ok(())
}

fn recover_trash(root: &RootHandle) -> Result<()> {
    let directory = root.control().join("gc-journal");
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let journal: TrashJournal = serde_json::from_slice(&fs::read(entry.path())?)
            .with_context(|| format!("parse GC journal {}", entry.path().display()))?;
        if journal.schema_version != 1
            || journal.transaction_id.is_empty()
            || journal.trash_path != root.trash().join(&journal.transaction_id)
            || !journal.trash_path.starts_with(root.trash())
        {
            bail!("invalid GC journal {}", entry.path().display());
        }
        if journal.trash_path.exists() {
            if journal.committed {
                remove_path(&journal.trash_path)?;
            } else {
                restore_uncommitted(root, &journal)?;
            }
        }
        if !journal.trash_path.exists() {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn restore_uncommitted(root: &RootHandle, journal: &TrashJournal) -> Result<()> {
    if journal.committed {
        bail!("refusing to roll back a committed GC transaction");
    }
    for (index, original) in journal.original_paths.iter().enumerate().rev() {
        validate_action_path(root, original)?;
        let staged = journal.trash_path.join(index.to_string());
        if !staged.exists() {
            continue;
        }
        if original.exists() {
            bail!(
                "cannot restore uncommitted GC transaction because {} already exists",
                original.display()
            );
        }
        if let Some(parent) = original.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&staged, original).with_context(|| {
            format!(
                "restore {} from uncommitted GC transaction",
                original.display()
            )
        })?;
    }
    remove_path(&journal.trash_path)
}

fn stop_sccache(record: &ResourceRecord, path: &Path) -> Result<()> {
    let program = resolve_program(record, "sccache")?;
    let mut command = Command::new(program);
    command
        .arg("--stop-server")
        .env("SCCACHE_DIR", path)
        .envs(&record.native_environment);
    let output = run_bounded(command, "stop owned sccache server")?;
    if !output.status.success() {
        bail!(
            "sccache refused to stop its owned server: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn run_native_cleanup(record: &ResourceRecord, path: &Path, reason: &str) -> Result<()> {
    let (program_name, args, environment): (&str, Vec<String>, Vec<(String, String)>) =
        match record.cleanup {
            CleanupStrategy::GoBuild => (
                "go",
                vec!["clean".into(), "-cache".into()],
                vec![("GOCACHE".into(), path.to_string_lossy().into_owned())],
            ),
            CleanupStrategy::GoModule => (
                "go",
                vec!["clean".into(), "-modcache".into()],
                vec![("GOMODCACHE".into(), path.to_string_lossy().into_owned())],
            ),
            CleanupStrategy::Npm => (
                "npm",
                if reason == "pressure" || reason == "stale" {
                    vec![
                        "cache".into(),
                        "clean".into(),
                        "--force".into(),
                        "--cache".into(),
                        path.to_string_lossy().into_owned(),
                    ]
                } else {
                    vec![
                        "cache".into(),
                        "verify".into(),
                        "--cache".into(),
                        path.to_string_lossy().into_owned(),
                    ]
                },
                Vec::new(),
            ),
            CleanupStrategy::PnpmStore => (
                "pnpm",
                vec![
                    "--store-dir".into(),
                    path.to_string_lossy().into_owned(),
                    "store".into(),
                    "prune".into(),
                ],
                Vec::new(),
            ),
            CleanupStrategy::Uv => (
                "uv",
                vec![
                    "cache".into(),
                    "prune".into(),
                    "--cache-dir".into(),
                    path.to_string_lossy().into_owned(),
                ],
                Vec::new(),
            ),
            CleanupStrategy::Pip => (
                "pip",
                vec![
                    "--cache-dir".into(),
                    path.to_string_lossy().into_owned(),
                    "cache".into(),
                    "purge".into(),
                ],
                Vec::new(),
            ),
            CleanupStrategy::Ccache => (
                "ccache",
                vec![
                    "-d".into(),
                    path.to_string_lossy().into_owned(),
                    "--cleanup".into(),
                ],
                Vec::new(),
            ),
            CleanupStrategy::BunInstall => (
                "bun",
                vec!["pm".into(), "cache".into(), "rm".into()],
                vec![(
                    "BUN_INSTALL_CACHE_DIR".into(),
                    path.to_string_lossy().into_owned(),
                )],
            ),
            CleanupStrategy::YarnClassic => (
                "yarn",
                vec![
                    "cache".into(),
                    "clean".into(),
                    "--cache-folder".into(),
                    path.to_string_lossy().into_owned(),
                ],
                Vec::new(),
            ),
            CleanupStrategy::OwnedDirectory | CleanupStrategy::SccacheServerAware => {
                bail!("owned cleanup strategy was passed to native cleanup")
            }
        };
    let program = resolve_program(record, program_name)?;
    let mut command = Command::new(program);
    command
        .args(&record.native_prefix)
        .args(args)
        .envs(&record.native_environment)
        .envs(environment);
    let output = run_bounded(command, "run native cache cleanup")?;
    if !output.status.success() {
        bail!(
            "native cleanup exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn run_bounded(mut command: Command, operation: &str) -> Result<NativeOutput> {
    command.stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = command.spawn().with_context(|| operation.to_owned())?;
    let stderr = child
        .stderr
        .take()
        .context("capture native cleanup stderr")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let mut stderr = stderr;
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = match child.wait_timeout(Duration::from_secs(120))? {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("{operation} exceeded the 120 second safety timeout");
        }
    };
    let stderr = reader
        .join()
        .map_err(|_| anyhow::anyhow!("native cleanup stderr reader panicked"))??;
    Ok(NativeOutput { status, stderr })
}

fn resolve_program(record: &ResourceRecord, fallback: &str) -> Result<PathBuf> {
    if let Some(program) = record.native_program.as_ref().filter(|path| path.is_file()) {
        return Ok(program.clone());
    }
    cargo_intercept::resolve_real_command(fallback, &std::env::current_exe()?)
}

fn validate_action_path(root: &RootHandle, path: &Path) -> Result<()> {
    if !path.starts_with(&root.platform_root) || path == root.platform_root {
        bail!(
            "GC candidate is outside the runtime domain: {}",
            path.display()
        );
    }
    let relative = path.strip_prefix(&root.platform_root)?;
    let mut current = root.platform_root.clone();
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            bail!("GC candidate contains a non-normal component");
        }
        current.push(component.as_os_str());
        if fs::symlink_metadata(&current).ok().is_some_and(|metadata| {
            metadata.file_type().is_symlink() || is_reparse_point(&metadata)
        }) {
            bail!(
                "GC candidate contains a symbolic link: {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn remove_path(path: &Path) -> Result<()> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(());
    };
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn trash_backlog(root: &RootHandle) -> Result<usize> {
    if !root.trash().is_dir() {
        return Ok(0);
    }
    Ok(fs::read_dir(root.trash())?.count())
}

fn action_age_rank(action: &GcAction) -> u8 {
    match action.reason.as_str() {
        "identity-reconciliation" | "duplicate-identity-record" => 0,
        "stale-temp" => 1,
        "orphan" => 2,
        "stale" => 3,
        _ => 4,
    }
}
