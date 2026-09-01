use super::CompletionShell;
use crate::util::lockfile::{try_acquire_pid_lock, PidLockOptions};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::Component;
use std::path::{Path, PathBuf};
use std::time::Duration;

const SNAPSHOT_SCHEMA_VERSION: u64 = 1;
const SHA256_HEX_LENGTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManagedCompletionRootStatus {
    pub root: PathBuf,
    pub current_snapshot: Option<String>,
    pub available_shells: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionSnapshotPublishOutcome {
    Published { snapshot: PathBuf },
    Repaired { snapshot: PathBuf },
    Unchanged { snapshot: PathBuf },
}

#[derive(Debug, Serialize, Deserialize)]
struct SnapshotManifest {
    schema_version: u64,
    views: BTreeMap<String, SnapshotView>,
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

    pub(crate) fn status(&self) -> Result<ManagedCompletionRootStatus> {
        let active = self.read_active_snapshot()?;
        let (current_snapshot, available_shells) = match active {
            Some(active) => (
                Some(active.name),
                active.manifest.views.keys().cloned().collect::<Vec<_>>(),
            ),
            None => (None, Vec::new()),
        };
        Ok(ManagedCompletionRootStatus {
            root: self.root.clone(),
            current_snapshot,
            available_shells,
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
        let _lock = try_acquire_pid_lock(
            &self.root,
            PidLockOptions {
                file_name: ".sync.lock",
                label: "managed completion sync",
                active_detail: "another completion sync is already publishing this managed root",
                retry_detail: "retry after the active completion sync finishes",
                stale_after: Duration::from_secs(6 * 60 * 60),
            },
        )?;
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
    if snapshot.len() != SHA256_HEX_LENGTH || !snapshot.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        anyhow::bail!("managed completion snapshot id is invalid: {snapshot}");
    }
    Ok(())
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
}
