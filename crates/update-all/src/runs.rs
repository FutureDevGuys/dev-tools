//! Run history indexing and lookup for persisted update-all artifacts.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static METADATA_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct RunMetadata {
    pub(crate) schema_version: u32,
    pub(crate) run_id: String,
    pub(crate) display_name: String,
    pub(crate) created_unix_ms: u64,
    pub(crate) updated_unix_ms: u64,
    pub(crate) status: String,
    pub(crate) run_dir: String,
    pub(crate) pid: u32,
    pub(crate) host_os: Option<String>,
    pub(crate) ui_mode: Option<String>,
    pub(crate) engine_mode: Option<String>,
    pub(crate) selected_tasks: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RunSummary {
    pub(crate) metadata: RunMetadata,
    pub(crate) path: PathBuf,
    pub(crate) run_json_status: RunArtifactStatus,
    pub(crate) task_count: usize,
    pub(crate) issue_count: usize,
    pub(crate) exit_code: Option<i32>,
    pub(crate) elapsed_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunArtifactStatus {
    Loaded,
    Missing,
    Malformed,
}

impl RunArtifactStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
        }
    }
}

pub(crate) fn scan_runs(root: &Path) -> Result<Vec<RunSummary>> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(root).with_context(|| format!("read run root {}", root.display()))? {
        let entry = entry.with_context(|| format!("read run root entry {}", root.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(summary) = read_run_summary(&path)? {
            out.push(summary);
        }
    }
    out.sort_by(|left, right| {
        right
            .metadata
            .updated_unix_ms
            .cmp(&left.metadata.updated_unix_ms)
            .then_with(|| {
                right
                    .metadata
                    .created_unix_ms
                    .cmp(&left.metadata.created_unix_ms)
            })
            .then_with(|| left.metadata.display_name.cmp(&right.metadata.display_name))
    });
    Ok(out)
}

pub(crate) fn resolve_run_query(root: &Path, query: &str) -> Result<Vec<RunSummary>> {
    let normalized = query.trim();
    if normalized.is_empty() {
        return Ok(Vec::new());
    }
    let runs = scan_runs(root)?;
    let exact = runs
        .iter()
        .filter(|run| run_matches_exact_query(run, normalized))
        .cloned()
        .collect::<Vec<_>>();
    if !exact.is_empty() {
        return Ok(exact);
    }
    let needle = normalized.to_ascii_lowercase();
    Ok(runs
        .into_iter()
        .filter(|run| run_matches_query(run, &needle))
        .collect())
}

pub(crate) fn run_matches_exact_query(run: &RunSummary, query: &str) -> bool {
    let normalized = query.trim();
    run.metadata.run_id == normalized
        || run.metadata.display_name == normalized
        || run
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == normalized)
}

pub(crate) fn write_metadata_atomic(run_dir: &Path, metadata: &RunMetadata) -> Result<()> {
    fs::create_dir_all(run_dir)
        .with_context(|| format!("create run directory {}", run_dir.display()))?;
    let path = run_dir.join("run-meta.json");
    let write_seq = METADATA_WRITE_SEQ.fetch_add(1, Ordering::SeqCst);
    let temp_path = run_dir.join(format!(
        ".run-meta.{}.{}.tmp",
        std::process::id(),
        write_seq
    ));
    let payload = serde_json::to_vec_pretty(metadata)
        .with_context(|| format!("serialize {}", path.display()))?;
    fs::write(&temp_path, payload).with_context(|| format!("write {}", temp_path.display()))?;
    replace_file(&temp_path, &path)?;
    Ok(())
}

fn replace_file(temp_path: &Path, path: &Path) -> Result<()> {
    let mut last_error = None;
    for _ in 0..16 {
        match fs::rename(temp_path, path) {
            Ok(()) => return Ok(()),
            Err(err) if can_retry_replace(&err, path) => {
                last_error = Some(err);
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(remove_err) if remove_err.kind() == io::ErrorKind::NotFound => {}
                    Err(remove_err) => {
                        return Err(remove_err).with_context(|| {
                            format!("remove existing metadata file {}", path.display())
                        });
                    }
                }
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("replace {} using {}", path.display(), temp_path.display())
                });
            }
        }
    }

    let err = last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "metadata destination remained occupied",
        )
    });
    Err(err).with_context(|| {
        format!(
            "replace {} using {} after retrying existing destination",
            path.display(),
            temp_path.display()
        )
    })
}

fn can_retry_replace(err: &io::Error, path: &Path) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
    ) && path.exists()
}

pub(crate) fn rename_metadata(
    run_dir: &Path,
    display_name: &str,
    updated_unix_ms: u64,
) -> Result<RunMetadata> {
    let metadata_path = run_dir.join("run-meta.json");
    let mut metadata: RunMetadata = serde_json::from_slice(
        &fs::read(&metadata_path).with_context(|| format!("read {}", metadata_path.display()))?,
    )
    .with_context(|| format!("parse {}", metadata_path.display()))?;
    metadata.display_name = display_name.trim().to_string();
    metadata.updated_unix_ms = updated_unix_ms;
    write_metadata_atomic(run_dir, &metadata)?;
    Ok(metadata)
}

pub(crate) fn status_from_exit_code(exit_code: i32) -> String {
    match exit_code {
        0 => "completed".to_string(),
        130 => "canceled".to_string(),
        _ => "failed".to_string(),
    }
}

fn read_run_summary(path: &Path) -> Result<Option<RunSummary>> {
    let meta_path = path.join("run-meta.json");
    if meta_path.exists() {
        let metadata: RunMetadata = serde_json::from_slice(
            &fs::read(&meta_path).with_context(|| format!("read {}", meta_path.display()))?,
        )
        .with_context(|| format!("parse {}", meta_path.display()))?;
        let (artifact, run_json_status) = read_run_json_status(path);
        return Ok(Some(summary_from_parts(
            path,
            metadata,
            artifact,
            run_json_status,
        )));
    }
    Ok(None)
}

fn read_run_json_status(path: &Path) -> (Option<Value>, RunArtifactStatus) {
    let run_json = path.join("run.json");
    if !run_json.exists() {
        return (None, RunArtifactStatus::Missing);
    }
    let Ok(payload) = fs::read(&run_json) else {
        return (None, RunArtifactStatus::Malformed);
    };
    match serde_json::from_slice(&payload) {
        Ok(value) => (Some(value), RunArtifactStatus::Loaded),
        Err(_) => (None, RunArtifactStatus::Malformed),
    }
}

fn summary_from_parts(
    path: &Path,
    metadata: RunMetadata,
    artifact: Option<Value>,
    run_json_status: RunArtifactStatus,
) -> RunSummary {
    let task_count = artifact
        .as_ref()
        .and_then(|value| value.get("tasks"))
        .and_then(Value::as_array)
        .map_or(0, |tasks| tasks.len());
    let issue_count = artifact
        .as_ref()
        .and_then(|value| value.get("tasks"))
        .and_then(Value::as_array)
        .map_or(0, |tasks| count_issue_tasks(tasks));
    let exit_code = artifact
        .as_ref()
        .and_then(|value| value.get("exit_code"))
        .and_then(Value::as_i64)
        .and_then(|code| i32::try_from(code).ok());
    let elapsed_ms = artifact
        .as_ref()
        .and_then(|value| value.get("tasks_elapsed_ms"))
        .and_then(Value::as_u64);
    RunSummary {
        metadata,
        path: path.to_path_buf(),
        run_json_status,
        task_count,
        issue_count,
        exit_code,
        elapsed_ms,
    }
}

fn count_issue_tasks(tasks: &[Value]) -> usize {
    tasks
        .iter()
        .filter(|task| {
            let status = task.get("status").and_then(Value::as_str).unwrap_or("");
            let completed_with_issues = task
                .get("completed_with_issues")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            matches!(status, "failed" | "canceled") || completed_with_issues
        })
        .count()
}

fn run_matches_query(run: &RunSummary, needle: &str) -> bool {
    run.metadata.run_id.to_ascii_lowercase().contains(needle)
        || run
            .metadata
            .display_name
            .to_ascii_lowercase()
            .contains(needle)
        || run.metadata.status.to_ascii_lowercase().contains(needle)
        || run
            .metadata
            .selected_tasks
            .iter()
            .any(|task| task.to_ascii_lowercase().contains(needle))
}

#[cfg(test)]
#[path = "tests/runs.rs"]
mod tests;
