use super::state::CompletionIssueStore;
use super::CompletionShell;
use crate::util::lockfile::{try_acquire_pid_lock, PidLockOptions};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SNAPSHOT_SCHEMA_VERSION: u64 = 1;
const SHA256_HEX_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedCompletionRootStatus {
    pub root: PathBuf,
    pub current_snapshot: Option<String>,
    pub available_shells: Vec<String>,
    pub active_bindings: Vec<ManagedCompletionBindingStatus>,
    pub historical_snapshots: Vec<ManagedCompletionSnapshotStatus>,
    pub issues: Vec<ManagedCompletionIssueStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedCompletionSnapshotStatus {
    pub snapshot: String,
    pub modified_unix_ms: Option<u64>,
    pub bytes: u64,
    pub healthy: bool,
    pub issue: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedCompletionBindingStatus {
    pub shell: String,
    pub command: String,
    pub provider: String,
    pub executable: PathBuf,
    pub classification: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedCompletionIssueStatus {
    pub shell: Option<String>,
    pub provider: String,
    pub command: String,
    pub outcome: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionSnapshotPublishOutcome {
    Published { snapshot: PathBuf },
    Repaired { snapshot: PathBuf },
    Unchanged { snapshot: PathBuf },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CompletionSnapshotRetentionPolicy {
    pub(crate) retain_prior_snapshots: usize,
    pub(crate) minimum_age: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct CompletionSnapshotPruneReport {
    pub(crate) removed_snapshots: Vec<String>,
    pub(crate) removed_objects: Vec<String>,
    pub(crate) reclaimed_bytes: u64,
    pub(crate) deferred_reason: Option<String>,
}

struct OwnedSnapshot {
    manifest: SnapshotManifest,
    bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotManifest {
    schema_version: u64,
    views: BTreeMap<String, SnapshotView>,
    #[serde(default)]
    bindings: Vec<ManagedCompletionBindingStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotView {
    file_name: String,
    object_digest: String,
}

struct ActiveSnapshot {
    name: String,
    manifest: SnapshotManifest,
}

pub(crate) struct ManagedCompletionRoot {
    root: PathBuf,
}

impl ManagedCompletionRoot {
    pub(crate) fn new(root: PathBuf) -> Result<Self> {
        if !root.is_absolute() {
            anyhow::bail!(
                "managed completion root must be absolute: {}",
                root.display()
            );
        }
        Ok(Self { root })
    }

    pub(crate) fn lock_sync(&self) -> Result<crate::util::lockfile::ScopedFileLock> {
        let parent = self.root.parent().with_context(|| {
            format!(
                "managed completion root has no lock parent: {}",
                self.root.display()
            )
        })?;
        let root_digest = sha256_hex(self.root.as_os_str().as_encoded_bytes());
        let file_name = format!(".update-all-completions-{}.lock", &root_digest[..16]);
        try_acquire_pid_lock(
            parent,
            PidLockOptions {
                file_name: &file_name,
                label: "managed completion sync",
                active_detail: "another completion sync is already using this managed root",
                retry_detail: "retry after the active completion sync finishes",
                stale_after: Duration::from_secs(6 * 60 * 60),
            },
        )
    }

    pub(crate) fn status(&self) -> Result<ManagedCompletionRootStatus> {
        let active = self.read_active_snapshot()?;
        let (current_snapshot, available_shells, active_bindings) = match active {
            Some(active) => (
                Some(active.name),
                active.manifest.views.keys().cloned().collect::<Vec<_>>(),
                active.manifest.bindings,
            ),
            None => (None, Vec::new(), Vec::new()),
        };
        let historical_snapshots =
            self.historical_snapshot_statuses(current_snapshot.as_deref())?;
        let issues = CompletionIssueStore::new(&self.root)?
            .load()?
            .into_iter()
            .map(|issue| ManagedCompletionIssueStatus {
                shell: issue.shell,
                provider: issue.provider,
                command: issue.command,
                outcome: issue.outcome,
                reason: issue.reason,
            })
            .collect();
        Ok(ManagedCompletionRootStatus {
            root: self.root.clone(),
            current_snapshot,
            available_shells,
            active_bindings,
            historical_snapshots,
            issues,
        })
    }

    pub(crate) fn init_script(&self, shell: CompletionShell) -> Result<String> {
        let Some(active) = self.read_active_snapshot()? else {
            return Ok(String::new());
        };
        let shell_name = shell.as_event_name();
        let Some(view) = active.manifest.views.get(shell_name) else {
            return Ok(String::new());
        };
        let path = self.view_path(&active.name, shell_name, view)?;
        Ok(match shell {
            CompletionShell::Bash | CompletionShell::Zsh => {
                format!(". '{}'\n", shell_single_quote_path(&path))
            }
            CompletionShell::Fish => {
                format!("source '{}'\n", shell_single_quote_path(&path))
            }
            CompletionShell::Elvish => {
                format!("source '{}'\n", shell_single_quote_path(&path))
            }
            CompletionShell::PowerShell => {
                format!(". '{}'\n", powershell_single_quote_path(&path))
            }
        })
    }

    pub(crate) fn publish_shell_completions(
        &self,
        payloads: &BTreeMap<CompletionShell, String>,
    ) -> Result<CompletionSnapshotPublishOutcome> {
        let _lock = self.lock_sync()?;
        self.publish_shell_completions_assuming_lock(payloads)
    }

    pub(crate) fn publish_shell_completions_assuming_lock(
        &self,
        payloads: &BTreeMap<CompletionShell, String>,
    ) -> Result<CompletionSnapshotPublishOutcome> {
        self.publish_activation_assuming_lock(payloads, Vec::new())
    }

    pub(crate) fn publish_activation_assuming_lock(
        &self,
        payloads: &BTreeMap<CompletionShell, String>,
        mut bindings: Vec<ManagedCompletionBindingStatus>,
    ) -> Result<CompletionSnapshotPublishOutcome> {
        bindings.sort_by(|left, right| {
            (&left.shell, &left.command, &left.provider).cmp(&(
                &right.shell,
                &right.command,
                &right.provider,
            ))
        });
        let manifest = SnapshotManifest {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            views: payloads
                .iter()
                .map(|(shell, payload)| {
                    let digest = sha256_hex(payload.as_bytes());
                    (
                        shell.as_event_name().to_string(),
                        SnapshotView {
                            file_name: shell.view_file_name().to_string(),
                            object_digest: digest,
                        },
                    )
                })
                .collect(),
            bindings,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .context("serialize completion snapshot manifest")?;
        let snapshot_name = sha256_hex(&manifest_bytes);
        let snapshot_dir = self.snapshot_dir(&snapshot_name);
        let current_is_target =
            self.read_current_snapshot()?.as_deref() == Some(snapshot_name.as_str());

        if current_is_target && self.validate_snapshot(&snapshot_name).is_ok() {
            return Ok(CompletionSnapshotPublishOutcome::Unchanged {
                snapshot: snapshot_dir,
            });
        }

        fs::create_dir_all(self.objects_dir())
            .with_context(|| format!("create {}", self.objects_dir().display()))?;
        fs::create_dir_all(self.snapshots_dir())
            .with_context(|| format!("create {}", self.snapshots_dir().display()))?;

        for payload in payloads.values() {
            self.write_object(payload.as_bytes())?;
        }

        if !snapshot_dir.exists() || self.validate_snapshot(&snapshot_name).is_err() {
            self.write_snapshot(&snapshot_name, &manifest, &manifest_bytes, payloads)?;
        }
        if current_is_target {
            return Ok(CompletionSnapshotPublishOutcome::Repaired {
                snapshot: snapshot_dir,
            });
        }

        self.write_current(&snapshot_name)?;
        Ok(CompletionSnapshotPublishOutcome::Published {
            snapshot: snapshot_dir,
        })
    }

    pub(crate) fn prune_historical_snapshots_assuming_lock(
        &self,
        policy: CompletionSnapshotRetentionPolicy,
    ) -> Result<CompletionSnapshotPruneReport> {
        let Some(current) = self.read_current_snapshot()? else {
            return Ok(CompletionSnapshotPruneReport::default());
        };
        if let Err(error) = self.inspect_owned_snapshot(&current) {
            return Ok(CompletionSnapshotPruneReport {
                deferred_reason: Some(format!(
                    "active snapshot ownership could not be proven: {error:#}"
                )),
                ..CompletionSnapshotPruneReport::default()
            });
        }

        let history = self.historical_snapshot_statuses(Some(&current))?;
        if let Some(snapshot) = history.iter().find(|snapshot| !snapshot.healthy) {
            return Ok(CompletionSnapshotPruneReport {
                deferred_reason: Some(format!(
                    "historical snapshot {} ownership could not be proven: {}",
                    snapshot.snapshot,
                    snapshot.issue.as_deref().unwrap_or("invalid snapshot")
                )),
                ..CompletionSnapshotPruneReport::default()
            });
        }

        let now = SystemTime::now();
        let mut removed_snapshots = Vec::new();
        let mut reclaimed_bytes = 0_u64;
        for (index, snapshot) in history.iter().enumerate() {
            let modified = snapshot.modified_unix_ms.map(|value| {
                UNIX_EPOCH
                    .checked_add(Duration::from_millis(value))
                    .unwrap_or(UNIX_EPOCH)
            });
            let age = modified
                .and_then(|modified| now.duration_since(modified).ok())
                .unwrap_or(Duration::ZERO);
            if index < policy.retain_prior_snapshots || age < policy.minimum_age {
                continue;
            }
            removed_snapshots.push(snapshot.snapshot.clone());
            reclaimed_bytes = reclaimed_bytes.saturating_add(snapshot.bytes);
        }

        let removed_set = removed_snapshots.iter().cloned().collect::<BTreeSet<_>>();
        let survivor_names = std::iter::once(current.clone())
            .chain(
                history
                    .iter()
                    .filter(|snapshot| !removed_set.contains(&snapshot.snapshot))
                    .map(|snapshot| snapshot.snapshot.clone()),
            )
            .collect::<Vec<_>>();
        let mut referenced_objects = BTreeSet::new();
        for snapshot in &survivor_names {
            let owned = self.inspect_owned_snapshot(snapshot)?;
            referenced_objects.extend(
                owned
                    .manifest
                    .views
                    .values()
                    .map(|view| view.object_digest.clone()),
            );
        }

        let mut removable_objects = Vec::new();
        if self.objects_dir().exists() {
            let metadata = fs::symlink_metadata(self.objects_dir())
                .with_context(|| format!("inspect {}", self.objects_dir().display()))?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Ok(CompletionSnapshotPruneReport {
                    deferred_reason: Some("object store is not a real directory".to_string()),
                    ..CompletionSnapshotPruneReport::default()
                });
            }
            for entry in fs::read_dir(self.objects_dir())
                .with_context(|| format!("read {}", self.objects_dir().display()))?
            {
                let entry = entry
                    .with_context(|| format!("read entry in {}", self.objects_dir().display()))?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if !is_owned_digest_name(&name) {
                    continue;
                }
                let metadata = fs::symlink_metadata(entry.path()).with_context(|| {
                    format!("inspect completion object {}", entry.path().display())
                })?;
                if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                    return Ok(CompletionSnapshotPruneReport {
                        deferred_reason: Some(format!(
                            "completion object {} is not a real regular file",
                            name
                        )),
                        ..CompletionSnapshotPruneReport::default()
                    });
                }
                let bytes = fs::read(entry.path()).with_context(|| {
                    format!("read completion object {}", entry.path().display())
                })?;
                if sha256_hex(&bytes) != name {
                    return Ok(CompletionSnapshotPruneReport {
                        deferred_reason: Some(format!(
                            "completion object {} failed content-address verification",
                            name
                        )),
                        ..CompletionSnapshotPruneReport::default()
                    });
                }
                if !referenced_objects.contains(&name) {
                    removable_objects.push((name, entry.path(), metadata.len()));
                }
            }
        }

        for snapshot in &removed_snapshots {
            let path = self.snapshot_dir(snapshot);
            fs::remove_dir_all(&path).with_context(|| {
                format!("remove retained completion snapshot {}", path.display())
            })?;
        }
        let mut removed_objects = Vec::new();
        for (name, path, bytes) in removable_objects {
            fs::remove_file(&path).with_context(|| {
                format!("remove unreferenced completion object {}", path.display())
            })?;
            reclaimed_bytes = reclaimed_bytes.saturating_add(bytes);
            removed_objects.push(name);
        }

        Ok(CompletionSnapshotPruneReport {
            removed_snapshots,
            removed_objects,
            reclaimed_bytes,
            deferred_reason: None,
        })
    }

    fn read_active_snapshot(&self) -> Result<Option<ActiveSnapshot>> {
        let Some(name) = self.read_current_snapshot()? else {
            return Ok(None);
        };
        let manifest = self.validate_snapshot(&name)?;
        Ok(Some(ActiveSnapshot { name, manifest }))
    }

    fn validate_snapshot(&self, snapshot: &str) -> Result<SnapshotManifest> {
        let manifest = self.read_manifest(snapshot)?;
        for (shell_name, view) in &manifest.views {
            let path = self.view_path(snapshot, shell_name, view)?;
            let payload = fs::read(&path)
                .with_context(|| format!("read managed completion view {}", path.display()))?;
            if sha256_hex(&payload) != view.object_digest {
                anyhow::bail!(
                    "managed completion view digest mismatch: {}",
                    path.display()
                );
            }
        }
        Ok(manifest)
    }

    fn historical_snapshot_statuses(
        &self,
        current_snapshot: Option<&str>,
    ) -> Result<Vec<ManagedCompletionSnapshotStatus>> {
        let snapshots_dir = self.snapshots_dir();
        if !snapshots_dir.exists() {
            return Ok(Vec::new());
        }
        let mut snapshots = Vec::new();
        for entry in fs::read_dir(&snapshots_dir)
            .with_context(|| format!("read {}", snapshots_dir.display()))?
        {
            let entry =
                entry.with_context(|| format!("read entry in {}", snapshots_dir.display()))?;
            let Some(snapshot) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !is_owned_digest_name(&snapshot)
                || current_snapshot.is_some_and(|current| current == snapshot)
            {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).with_context(|| {
                format!("inspect completion snapshot {}", entry.path().display())
            })?;
            let modified_unix_ms = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
                .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX));
            let inspected = self.inspect_owned_snapshot(&snapshot);
            let (bytes, healthy, issue) = match inspected {
                Ok(owned) => (owned.bytes, true, None),
                Err(error) => (0, false, Some(format!("{error:#}"))),
            };
            snapshots.push(ManagedCompletionSnapshotStatus {
                snapshot,
                modified_unix_ms,
                bytes,
                healthy,
                issue,
            });
        }
        snapshots.sort_by(|left, right| {
            right
                .modified_unix_ms
                .cmp(&left.modified_unix_ms)
                .then_with(|| left.snapshot.cmp(&right.snapshot))
        });
        Ok(snapshots)
    }

    fn inspect_owned_snapshot(&self, snapshot: &str) -> Result<OwnedSnapshot> {
        validate_snapshot_name(snapshot)?;
        let manifest = self.validate_snapshot(snapshot)?;
        let root = self.snapshot_dir(snapshot);
        require_real_directory(&root)?;
        let root_entries = real_directory_entry_names(&root)?;
        let expected_root = ["manifest.json".to_string(), "views".to_string()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        if root_entries != expected_root {
            anyhow::bail!("completion snapshot contains unexpected root entries");
        }

        let manifest_path = root.join("manifest.json");
        let mut bytes = require_real_file(&manifest_path)?;
        let views_root = root.join("views");
        require_real_directory(&views_root)?;
        let view_entries = real_directory_entry_names(&views_root)?;
        let expected_views = manifest.views.keys().cloned().collect::<BTreeSet<_>>();
        if view_entries != expected_views {
            anyhow::bail!("completion snapshot contains unexpected shell views");
        }
        for (shell, view) in &manifest.views {
            let shell_root = views_root.join(shell);
            require_real_directory(&shell_root)?;
            let shell_entries = real_directory_entry_names(&shell_root)?;
            let expected_shell = [view.file_name.clone()]
                .into_iter()
                .collect::<BTreeSet<_>>();
            if shell_entries != expected_shell {
                anyhow::bail!("completion snapshot contains unexpected files for shell {shell}");
            }
            bytes = bytes.saturating_add(require_real_file(&shell_root.join(&view.file_name))?);
        }
        Ok(OwnedSnapshot { manifest, bytes })
    }

    fn read_current_snapshot(&self) -> Result<Option<String>> {
        let path = self.current_path();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
        };
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        validate_snapshot_name(trimmed)?;
        Ok(Some(trimmed.to_string()))
    }

    fn read_manifest(&self, snapshot: &str) -> Result<SnapshotManifest> {
        validate_snapshot_name(snapshot)?;
        let path = self.snapshot_dir(snapshot).join("manifest.json");
        let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        let manifest: SnapshotManifest =
            serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        validate_manifest(&manifest).with_context(|| format!("validate {}", path.display()))?;
        Ok(manifest)
    }

    fn write_object(&self, bytes: &[u8]) -> Result<PathBuf> {
        let digest = sha256_hex(bytes);
        let path = self.objects_dir().join(&digest);
        if path.exists() {
            return Ok(path);
        }
        write_atomic_bytes(&path, bytes)?;
        Ok(path)
    }

    fn write_snapshot(
        &self,
        snapshot_name: &str,
        manifest: &SnapshotManifest,
        manifest_bytes: &[u8],
        payloads: &BTreeMap<CompletionShell, String>,
    ) -> Result<()> {
        let final_dir = self.snapshot_dir(snapshot_name);
        let staging_dir =
            self.snapshots_dir()
                .join(format!(".{}.{}.tmp", snapshot_name, std::process::id()));
        if staging_dir.exists() {
            fs::remove_dir_all(&staging_dir)
                .with_context(|| format!("remove {}", staging_dir.display()))?;
        }

        fs::create_dir_all(staging_dir.join("views"))
            .with_context(|| format!("create {}", staging_dir.display()))?;
        for (shell_name, view) in &manifest.views {
            let shell_dir = staging_dir.join("views").join(shell_name);
            fs::create_dir_all(&shell_dir)
                .with_context(|| format!("create {}", shell_dir.display()))?;
            let shell = payloads
                .keys()
                .find(|candidate| candidate.as_event_name() == shell_name.as_str())
                .copied()
                .with_context(|| format!("missing payload for shell {}", shell_name))?;
            let payload = payloads
                .get(&shell)
                .with_context(|| format!("missing payload for shell {}", shell_name))?;
            fs::write(shell_dir.join(&view.file_name), payload)
                .with_context(|| format!("write snapshot view {}", shell_dir.display()))?;
        }
        fs::write(staging_dir.join("manifest.json"), manifest_bytes)
            .with_context(|| format!("write {}", staging_dir.join("manifest.json").display()))?;
        if final_dir.exists() {
            fs::remove_dir_all(&final_dir)
                .with_context(|| format!("remove broken snapshot {}", final_dir.display()))?;
        }
        fs::rename(&staging_dir, &final_dir)
            .with_context(|| format!("activate snapshot {}", final_dir.display()))?;
        Ok(())
    }

    fn write_current(&self, snapshot: &str) -> Result<()> {
        write_atomic_bytes(&self.current_path(), format!("{snapshot}\n").as_bytes())
    }

    fn current_path(&self) -> PathBuf {
        self.root.join("current")
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn snapshots_dir(&self) -> PathBuf {
        self.root.join("snapshots")
    }

    fn snapshot_dir(&self, snapshot: &str) -> PathBuf {
        self.snapshots_dir().join(snapshot)
    }

    fn view_path(&self, snapshot: &str, shell_name: &str, view: &SnapshotView) -> Result<PathBuf> {
        validate_snapshot_name(snapshot)?;
        validate_manifest_view(shell_name, view)?;
        let path = self
            .snapshot_dir(snapshot)
            .join("views")
            .join(shell_name)
            .join(&view.file_name);
        if !path.is_file() {
            anyhow::bail!("managed completion view is missing: {}", path.display());
        }
        Ok(path)
    }
}

fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    {
        let mut file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_snapshot_name(snapshot: &str) -> Result<()> {
    if !is_owned_digest_name(snapshot) {
        anyhow::bail!("managed completion snapshot id is invalid: {snapshot}");
    }
    Ok(())
}

fn is_owned_digest_name(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_real_directory(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        anyhow::bail!(
            "completion snapshot path is not a real directory: {}",
            path.display()
        );
    }
    Ok(())
}

fn require_real_file(path: &Path) -> Result<u64> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!(
            "completion snapshot path is not a real regular file: {}",
            path.display()
        );
    }
    Ok(metadata.len())
}

fn real_directory_entry_names(path: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(path)
        .with_context(|| format!("read {}", path.display()))?
        .map(|entry| {
            let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
            entry.file_name().into_string().map_err(|_| {
                anyhow::anyhow!(
                    "completion snapshot contains a non-UTF-8 entry: {}",
                    path.display()
                )
            })
        })
        .collect()
}

fn validate_manifest(manifest: &SnapshotManifest) -> Result<()> {
    if manifest.schema_version != SNAPSHOT_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported managed completion snapshot schema: {}",
            manifest.schema_version
        );
    }
    for (shell_name, view) in &manifest.views {
        validate_manifest_view(shell_name, view)?;
    }
    Ok(())
}

fn validate_manifest_view(shell_name: &str, view: &SnapshotView) -> Result<()> {
    if view.object_digest.len() != SHA256_HEX_LENGTH
        || !view
            .object_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!(
            "managed completion view digest is invalid for shell {}",
            shell_name
        );
    }

    let path = Path::new(&view.file_name);
    if path.is_absolute() {
        anyhow::bail!(
            "managed completion view file escapes the snapshot for shell {}",
            shell_name
        );
    }
    let mut components = path.components();
    let Some(Component::Normal(_)) = components.next() else {
        anyhow::bail!(
            "managed completion view file escapes the snapshot for shell {}",
            shell_name
        );
    };
    if components.next().is_some() {
        anyhow::bail!(
            "managed completion view file escapes the snapshot for shell {}",
            shell_name
        );
    }
    Ok(())
}

fn shell_single_quote_path(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "'\\''")
}

fn powershell_single_quote_path(path: &Path) -> String {
    path.to_string_lossy().replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn publish_is_idempotent_for_unchanged_snapshot() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let mut payloads = BTreeMap::new();
        payloads.insert(
            CompletionShell::Bash,
            "complete -F _update_all update-all\n".to_string(),
        );
        payloads.insert(CompletionShell::Zsh, "#compdef update-all\n".to_string());

        let first = root.publish_shell_completions(&payloads).unwrap();
        let current = root.current_path();
        let before = fs::read_to_string(&current).unwrap();
        let before_meta = fs::metadata(&current).unwrap().modified().unwrap();
        let second = root.publish_shell_completions(&payloads).unwrap();
        let after = fs::read_to_string(&current).unwrap();
        let after_meta = fs::metadata(&current).unwrap().modified().unwrap();

        assert!(matches!(
            first,
            CompletionSnapshotPublishOutcome::Published { .. }
        ));
        assert!(matches!(
            second,
            CompletionSnapshotPublishOutcome::Unchanged { .. }
        ));
        assert_eq!(before, after);
        assert_eq!(before_meta, after_meta);
        assert_eq!(fs::read_dir(root.snapshots_dir()).unwrap().count(), 1);
    }

    #[test]
    fn publish_repairs_missing_active_snapshot_without_rewriting_current() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let mut payloads = BTreeMap::new();
        payloads.insert(
            CompletionShell::Bash,
            "complete -F _update_all update-all\n".to_string(),
        );

        root.publish_shell_completions(&payloads).unwrap();
        let snapshot = root.read_current_snapshot().unwrap().unwrap();
        let current_before = fs::read(root.current_path()).unwrap();
        fs::remove_dir_all(root.snapshot_dir(&snapshot)).unwrap();

        let outcome = root.publish_shell_completions(&payloads).unwrap();

        assert!(matches!(
            outcome,
            CompletionSnapshotPublishOutcome::Repaired { .. }
        ));
        assert_eq!(fs::read(root.current_path()).unwrap(), current_before);
        assert_eq!(
            root.status().unwrap().available_shells,
            vec!["bash".to_string()]
        );
        assert!(!root.init_script(CompletionShell::Bash).unwrap().is_empty());
    }

    #[test]
    fn init_script_is_empty_without_snapshot() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        assert_eq!(root.init_script(CompletionShell::Fish).unwrap(), "");
    }

    #[test]
    fn init_script_rejects_snapshot_path_escape() {
        let temp = TempDir::new().unwrap();
        let root_path = temp.path().join("managed-root");
        fs::create_dir_all(&root_path).unwrap();
        fs::write(root_path.join("current"), "../escape\n").unwrap();

        let root = ManagedCompletionRoot::new(root_path).unwrap();
        let error = root.init_script(CompletionShell::Bash).unwrap_err();
        assert!(format!("{error:#}").contains("snapshot id is invalid"));
    }

    #[test]
    fn init_script_rejects_manifest_view_path_escape() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let snapshot = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let snapshot_dir = root.snapshot_dir(snapshot);
        fs::create_dir_all(snapshot_dir.join("views/bash")).unwrap();
        fs::write(root.current_path(), format!("{snapshot}\n")).unwrap();
        fs::write(
            snapshot_dir.join("manifest.json"),
            r#"{
  "schema_version": 1,
  "views": {
    "bash": {
      "file_name": "../escape",
      "object_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  }
}"#,
        )
        .unwrap();

        let error = root.init_script(CompletionShell::Bash).unwrap_err();
        assert!(format!("{error:#}").contains("view file escapes"));
    }

    #[test]
    fn init_script_rejects_view_digest_mismatch() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let snapshot = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let snapshot_dir = root.snapshot_dir(snapshot);
        let payload_path = snapshot_dir.join("views/bash/update-all.bash");
        fs::create_dir_all(payload_path.parent().unwrap()).unwrap();
        fs::write(root.current_path(), format!("{snapshot}\n")).unwrap();
        fs::write(
            snapshot_dir.join("manifest.json"),
            r#"{
  "schema_version": 1,
  "views": {
    "bash": {
      "file_name": "update-all.bash",
      "object_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  }
}"#,
        )
        .unwrap();
        fs::write(&payload_path, "complete -F _update_all update-all\n").unwrap();

        let error = root.init_script(CompletionShell::Bash).unwrap_err();
        assert!(format!("{error:#}").contains("digest mismatch"));
    }

    #[test]
    fn status_reports_current_snapshot_and_shells_after_publish() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let mut payloads = BTreeMap::new();
        payloads.insert(
            CompletionShell::Bash,
            "complete -F _update_all update-all\n".to_string(),
        );
        payloads.insert(CompletionShell::Fish, "complete update-all\n".to_string());

        root.publish_shell_completions(&payloads).unwrap();
        let status = root.status().unwrap();

        assert_eq!(status.root, temp.path().join("managed-root"));
        assert!(status.current_snapshot.is_some());
        assert_eq!(
            status.available_shells,
            vec!["bash".to_string(), "fish".to_string()]
        );
    }

    #[test]
    fn status_and_init_reject_an_active_snapshot_with_a_missing_view() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let mut payloads = BTreeMap::new();
        payloads.insert(
            CompletionShell::Bash,
            "complete -F _update_all update-all\n".to_string(),
        );
        payloads.insert(CompletionShell::Fish, "complete update-all\n".to_string());

        root.publish_shell_completions(&payloads).unwrap();
        let snapshot = root.read_current_snapshot().unwrap().unwrap();
        fs::remove_file(
            root.snapshot_dir(&snapshot)
                .join("views/bash/update-all.bash"),
        )
        .unwrap();

        let status_error = root.status().unwrap_err();
        assert!(format!("{status_error:#}").contains("view is missing"));
        let init_error = root.init_script(CompletionShell::Fish).unwrap_err();
        assert!(format!("{init_error:#}").contains("view is missing"));
    }

    #[test]
    fn init_script_sources_active_snapshot_view() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let mut payloads = BTreeMap::new();
        payloads.insert(CompletionShell::Zsh, "#compdef update-all\n".to_string());

        root.publish_shell_completions(&payloads).unwrap();
        let snapshot = root.read_current_snapshot().unwrap().unwrap();
        let expected = format!(
            ". '{}'\n",
            shell_single_quote_path(
                &temp
                    .path()
                    .join("managed-root")
                    .join("snapshots")
                    .join(snapshot)
                    .join("views/zsh/_update-all")
            )
        );

        assert_eq!(root.init_script(CompletionShell::Zsh).unwrap(), expected);
    }

    #[test]
    fn status_reports_snapshot_bindings_and_current_issues_without_writing() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let mut payloads = BTreeMap::new();
        payloads.insert(CompletionShell::Fish, "complete -c demo\n".to_string());
        let _lock = root.lock_sync().unwrap();
        root.publish_activation_assuming_lock(
            &payloads,
            vec![ManagedCompletionBindingStatus {
                shell: "fish".to_string(),
                command: "demo".to_string(),
                provider: "path".to_string(),
                executable: PathBuf::from("/usr/bin/demo"),
                classification: Some("static".to_string()),
            }],
        )
        .unwrap();
        CompletionIssueStore::new(&root.root)
            .unwrap()
            .save_if_changed(&[super::super::state::CompletionIssueMemo {
                shell: Some("zsh".to_string()),
                provider: "uv".to_string(),
                command: "other".to_string(),
                outcome: "retained_previous".to_string(),
                reason: Some("inventory_failed".to_string()),
            }])
            .unwrap();
        drop(_lock);

        let before = tree_fingerprint(&root.root);
        let status = root.status().unwrap();
        let init = root.init_script(CompletionShell::Fish).unwrap();
        assert_eq!(status.active_bindings.len(), 1);
        assert_eq!(status.active_bindings[0].command, "demo");
        assert_eq!(status.issues.len(), 1);
        assert_eq!(status.issues[0].outcome, "retained_previous");
        assert!(!init.is_empty());
        assert_eq!(tree_fingerprint(&root.root), before);
    }

    #[test]
    fn managed_root_lock_covers_the_full_sync_owner() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let first = root.lock_sync().unwrap();
        let error = root.lock_sync().unwrap_err();
        assert!(format!("{error:#}").contains("another completion sync"));
        drop(first);
        assert!(root.lock_sync().is_ok());
    }

    #[test]
    fn retention_keeps_current_and_recent_history_and_reclaims_unreferenced_objects() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let _lock = root.lock_sync().unwrap();

        for generation in 0..5 {
            let mut payloads = BTreeMap::new();
            payloads.insert(
                CompletionShell::Bash,
                format!("complete -F _update_all_{generation} update-all\n"),
            );
            root.publish_shell_completions_assuming_lock(&payloads)
                .unwrap();
        }

        let before = root.status().unwrap();
        assert_eq!(before.historical_snapshots.len(), 4);
        let report = root
            .prune_historical_snapshots_assuming_lock(CompletionSnapshotRetentionPolicy {
                retain_prior_snapshots: 2,
                minimum_age: Duration::ZERO,
            })
            .unwrap();

        assert_eq!(report.removed_snapshots.len(), 2);
        assert_eq!(root.status().unwrap().historical_snapshots.len(), 2);
        assert_eq!(fs::read_dir(root.snapshots_dir()).unwrap().count(), 3);
        assert_eq!(fs::read_dir(root.objects_dir()).unwrap().count(), 3);
    }

    #[test]
    fn retention_age_floor_protects_recent_snapshots_beyond_the_count_floor() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let _lock = root.lock_sync().unwrap();

        for generation in 0..4 {
            let mut payloads = BTreeMap::new();
            payloads.insert(
                CompletionShell::Fish,
                format!("complete -c update-all -a generation-{generation}\n"),
            );
            root.publish_shell_completions_assuming_lock(&payloads)
                .unwrap();
        }
        let before = tree_fingerprint(&root.root);
        let report = root
            .prune_historical_snapshots_assuming_lock(CompletionSnapshotRetentionPolicy {
                retain_prior_snapshots: 1,
                minimum_age: Duration::from_secs(60 * 60),
            })
            .unwrap();

        assert!(report.removed_snapshots.is_empty());
        assert_eq!(before, tree_fingerprint(&root.root));
    }

    #[test]
    fn malformed_historical_snapshot_defers_all_retention_mutation() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let _lock = root.lock_sync().unwrap();

        for generation in 0..3 {
            let mut payloads = BTreeMap::new();
            payloads.insert(
                CompletionShell::Zsh,
                format!("#compdef update-all\n# generation {generation}\n"),
            );
            root.publish_shell_completions_assuming_lock(&payloads)
                .unwrap();
        }
        let broken = root
            .status()
            .unwrap()
            .historical_snapshots
            .first()
            .unwrap()
            .snapshot
            .clone();
        fs::write(root.snapshot_dir(&broken).join("unexpected"), "unowned\n").unwrap();
        let before = tree_fingerprint(&root.root);

        let report = root
            .prune_historical_snapshots_assuming_lock(CompletionSnapshotRetentionPolicy {
                retain_prior_snapshots: 0,
                minimum_age: Duration::ZERO,
            })
            .unwrap();

        assert!(report.deferred_reason.is_some());
        assert!(report.removed_snapshots.is_empty());
        assert_eq!(before, tree_fingerprint(&root.root));
        assert!(root
            .status()
            .unwrap()
            .historical_snapshots
            .iter()
            .any(|snapshot| snapshot.snapshot == broken && !snapshot.healthy));
    }

    #[test]
    fn malformed_content_addressed_object_defers_all_retention_mutation() {
        let temp = TempDir::new().unwrap();
        let root = ManagedCompletionRoot::new(temp.path().join("managed-root")).unwrap();
        let _lock = root.lock_sync().unwrap();

        for generation in 0..3 {
            let mut payloads = BTreeMap::new();
            payloads.insert(
                CompletionShell::Bash,
                format!("complete -F _update_all_{generation} update-all\n"),
            );
            root.publish_shell_completions_assuming_lock(&payloads)
                .unwrap();
        }
        let corrupt = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        fs::write(root.objects_dir().join(corrupt), "not the named digest\n").unwrap();
        let before = tree_fingerprint(&root.root);

        let report = root
            .prune_historical_snapshots_assuming_lock(CompletionSnapshotRetentionPolicy {
                retain_prior_snapshots: 0,
                minimum_age: Duration::ZERO,
            })
            .unwrap();

        assert!(report
            .deferred_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("content-address verification")));
        assert!(report.removed_snapshots.is_empty());
        assert_eq!(before, tree_fingerprint(&root.root));
    }

    fn tree_fingerprint(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(root: &Path, path: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
            if !path.exists() {
                return;
            }
            let mut entries = fs::read_dir(path)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect::<Vec<_>>();
            entries.sort();
            for entry in entries {
                let relative = entry.strip_prefix(root).unwrap().to_path_buf();
                let metadata = fs::symlink_metadata(&entry).unwrap();
                if metadata.is_dir() {
                    out.push((relative.clone(), Vec::new()));
                    walk(root, &entry, out);
                } else if metadata.is_file() {
                    out.push((relative, fs::read(entry).unwrap()));
                }
            }
        }

        let mut out = Vec::new();
        walk(root, root, &mut out);
        out
    }
}
