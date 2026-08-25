use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::artifacts::ArtifactRecord;
use crate::config::GcConfig;
use crate::lease::RootLease;
use crate::repository::IdentityRecord;
use crate::root::RootHandle;
use crate::util::{directory_size, now_unix};

#[derive(Clone, Debug, Default)]
pub struct GcOverrides {
    pub max_bytes: Option<u64>,
    pub min_free_bytes: Option<u64>,
    pub target_free_bytes: Option<u64>,
    pub stale_after_days: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GcAction {
    pub kind: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GcReport {
    pub applied: bool,
    pub bytes_before: u64,
    pub bytes_selected: u64,
    pub free_before: u64,
    pub actions: Vec<GcAction>,
}

pub fn collect(
    root: &RootHandle,
    policy: &GcConfig,
    artifact_stale_after_days: u64,
    overrides: &GcOverrides,
    apply: bool,
) -> Result<GcReport> {
    let _lease = RootLease::exclusive(root)?;
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
    let mut actions = repository_actions(root, now, stale_days, policy)?;
    actions.extend(artifact_actions(root, now, artifact_stale_after_days)?);
    actions.extend(shared_actions(
        root,
        now,
        stale_days,
        policy.pressure_min_age_hours,
    )?);
    actions.sort_by_key(action_age_rank);
    if pressure {
        let needed_for_free = target_free.saturating_sub(free_before);
        let needed_for_size = max_bytes
            .map(|limit| bytes_before.saturating_sub(limit))
            .unwrap_or(0);
        let needed = needed_for_free.max(needed_for_size);
        let mut selected = 0;
        actions.retain(|action| {
            if selected >= needed && action.reason == "pressure" {
                return false;
            }
            selected = selected.saturating_add(action.bytes);
            true
        });
    } else {
        actions.retain(|action| action.reason != "pressure");
    }
    let bytes_selected = actions.iter().map(|action| action.bytes).sum();
    if apply {
        for (index, action) in actions.iter().enumerate() {
            if !action.path.exists() {
                continue;
            }
            let trash = root
                .trash()
                .join(format!("{}-{}-{index}", now, std::process::id()));
            fs::rename(&action.path, &trash)
                .with_context(|| format!("move {} to GC trash", action.path.display()))?;
            if trash.is_dir() {
                fs::remove_dir_all(trash)?;
            } else {
                fs::remove_file(trash)?;
            }
        }
    }
    Ok(GcReport {
        applied: apply,
        bytes_before,
        bytes_selected,
        free_before,
        actions,
    })
}

fn shared_actions(
    root: &RootHandle,
    now: u64,
    stale_days: u64,
    pressure_min_age_hours: u64,
) -> Result<Vec<GcAction>> {
    let mut actions = Vec::new();
    if !root.shared().is_dir() {
        return Ok(actions);
    }
    for entry in fs::read_dir(root.shared())? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || entry.file_name() == "sccache" {
            continue;
        }
        let canonical_marker = entry.path().join(".dev-cache-owned.json");
        let Ok(value) = fs::read(&canonical_marker).and_then(|bytes| {
            serde_json::from_slice::<serde_json::Value>(&bytes).map_err(std::io::Error::other)
        }) else {
            continue;
        };
        let Some(last_used) = value["last_used_unix"].as_u64() else {
            continue;
        };
        let age = now.saturating_sub(last_used);
        let reason = if age >= stale_days * 86_400 {
            "stale"
        } else if age >= pressure_min_age_hours * 3_600 {
            "pressure"
        } else {
            continue;
        };
        actions.push(GcAction {
            kind: "shared-cache".to_owned(),
            path: entry.path(),
            bytes: directory_size(&entry.path()),
            reason: reason.to_owned(),
        });
    }
    Ok(actions)
}

fn repository_actions(
    root: &RootHandle,
    now: u64,
    stale_days: u64,
    policy: &GcConfig,
) -> Result<Vec<GcAction>> {
    let mut actions = Vec::new();
    if !root.repos().is_dir() {
        return Ok(actions);
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
            let Ok(record) = fs::read(&identity_path).and_then(|bytes| {
                serde_json::from_slice::<IdentityRecord>(&bytes).map_err(std::io::Error::other)
            }) else {
                continue;
            };
            let age = now.saturating_sub(record.last_used_unix);
            let orphan = !record.canonical_worktree.exists();
            let threshold = if orphan {
                policy.orphan_grace_days * 86_400
            } else {
                stale_days * 86_400
            };
            if age >= threshold {
                actions.push(GcAction {
                    kind: "repository".to_owned(),
                    path: entry.path(),
                    bytes: directory_size(&entry.path()),
                    reason: if orphan { "orphan" } else { "stale" }.to_owned(),
                });
                continue;
            }
            let temp = entry.path().join("temp");
            if temp.exists() && age >= policy.temp_grace_hours * 3_600 {
                actions.push(GcAction {
                    kind: "temp".to_owned(),
                    path: temp.clone(),
                    bytes: directory_size(&temp),
                    reason: "stale-temp".to_owned(),
                });
            }
        }
    }
    Ok(actions)
}

fn artifact_actions(root: &RootHandle, now: u64, stale_days: u64) -> Result<Vec<GcAction>> {
    let mut actions = Vec::new();
    let metadata = root.platform_root.join("artifacts/metadata");
    if !metadata.is_dir() {
        return Ok(actions);
    }
    for entry in fs::read_dir(metadata)? {
        let entry = entry?;
        let Ok(record) = fs::read(entry.path()).and_then(|bytes| {
            serde_json::from_slice::<ArtifactRecord>(&bytes).map_err(std::io::Error::other)
        }) else {
            continue;
        };
        if now.saturating_sub(record.last_verified_unix) < stale_days * 86_400 {
            continue;
        }
        let object = root
            .artifacts()
            .join(&record.digest[..2])
            .join(&record.digest);
        if object.exists() {
            actions.push(GcAction {
                kind: "artifact".to_owned(),
                path: object,
                bytes: record.size,
                reason: "stale".to_owned(),
            });
        }
        actions.push(GcAction {
            kind: "artifact-metadata".to_owned(),
            path: entry.path(),
            bytes: entry.metadata()?.len(),
            reason: "stale".to_owned(),
        });
    }
    Ok(actions)
}

fn action_age_rank(action: &GcAction) -> u8 {
    match action.reason.as_str() {
        "stale-temp" => 0,
        "orphan" => 1,
        "stale" => 2,
        _ => 3,
    }
}

pub fn mark_shared_cache(path: &Path, adapter: &str) -> Result<()> {
    fs::create_dir_all(path)?;
    let marker =
        serde_json::json!({"schema_version": 1, "adapter": adapter, "last_used_unix": now_unix()});
    crate::util::write_json_atomic(&path.join(".dev-cache-owned.json"), &marker)?;
    Ok(())
}
