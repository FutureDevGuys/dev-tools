//! Run history indexing and lookup for persisted update-all artifacts.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static METADATA_WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RunRetentionPolicy {
    pub(crate) max_age_days: u64,
    pub(crate) max_runs: usize,
    pub(crate) max_bytes: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct RunPruneReport {
    pub(crate) dry_run: bool,
    pub(crate) removed: Vec<String>,
    pub(crate) retained: Vec<String>,
    pub(crate) reclaimed_bytes: u64,
}

#[derive(Clone, Debug)]
struct RetentionCandidate {
    path: PathBuf,
    updated_unix_ms: u64,
    bytes: u64,
    protected: bool,
}

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
    pub(crate) task_count: Option<usize>,
    pub(crate) issue_count: Option<usize>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) elapsed_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunArtifactStatus {
    Loaded,
    Missing,
    Malformed,
    Unreadable,
    Unsafe,
    Oversized,
    Unsupported,
}

impl RunArtifactStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Unreadable => "unreadable",
            Self::Unsafe => "unsafe",
            Self::Oversized => "oversized",
            Self::Unsupported => "unsupported",
        }
    }
}

pub(crate) fn scan_runs(root: &Path) -> Result<Vec<RunSummary>> {
    let mut out = Vec::new();
    let mut omitted = 0;
    for path in history_directories(root)? {
        if let Some(summary) = read_run_summary(&path)? {
            out.push(summary);
        } else {
            omitted += 1;
        }
    }
    if omitted > 0 {
        crate::ua_errln!(
            "update-all: omitted {omitted} entries with unavailable run metadata; use runs inspect for evidence status"
        );
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

pub(crate) fn prune_runs(
    root: &Path,
    policy: RunRetentionPolicy,
    now_unix_ms: u64,
    protected_run: Option<&Path>,
    dry_run: bool,
) -> Result<RunPruneReport> {
    if !root.exists() {
        return Ok(RunPruneReport {
            dry_run,
            removed: Vec::new(),
            retained: Vec::new(),
            reclaimed_bytes: 0,
        });
    }
    let root_metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect run root {}", root.display()))?;
    if !root_metadata.file_type().is_dir() {
        anyhow::bail!("run root is not a real directory: {}", root.display());
    }
    let mut candidates = Vec::new();
    let mut retained = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("read run root {}", root.display()))? {
        let entry = entry.with_context(|| format!("read run root entry {}", root.display()))?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .with_context(|| format!("inspect run entry {}", path.display()))?;
        if !metadata.is_dir()
            || fs::symlink_metadata(&path)
                .map(|value| value.file_type().is_symlink())
                .unwrap_or(true)
        {
            continue;
        }
        let metadata_path = path.join("run-meta.json");
        let Ok(raw) = fs::read(&metadata_path) else {
            retained.push(path_file_name(&path));
            continue;
        };
        let Ok(run_metadata) = serde_json::from_slice::<RunMetadata>(&raw) else {
            retained.push(path_file_name(&path));
            continue;
        };
        if !matches!(
            run_metadata.status.as_str(),
            "completed" | "failed" | "canceled"
        ) {
            retained.push(path_file_name(&path));
            continue;
        }
        candidates.push(RetentionCandidate {
            bytes: directory_size_without_symlinks(&path)?,
            protected: protected_run.is_some_and(|protected| protected == path),
            path,
            updated_unix_ms: run_metadata.updated_unix_ms,
        });
    }
    candidates.sort_by(|left, right| {
        left.updated_unix_ms
            .cmp(&right.updated_unix_ms)
            .then_with(|| left.path.cmp(&right.path))
    });

    let age_limit_ms = policy
        .max_age_days
        .saturating_mul(24)
        .saturating_mul(60)
        .saturating_mul(60)
        .saturating_mul(1000);
    let mut removal = BTreeSet::new();
    for candidate in &candidates {
        if !candidate.protected
            && now_unix_ms.saturating_sub(candidate.updated_unix_ms) > age_limit_ms
        {
            removal.insert(candidate.path.clone());
        }
    }

    let mut survivor_count = candidates
        .iter()
        .filter(|candidate| !removal.contains(&candidate.path))
        .count();
    for candidate in &candidates {
        if survivor_count <= policy.max_runs {
            break;
        }
        if !candidate.protected && removal.insert(candidate.path.clone()) {
            survivor_count = survivor_count.saturating_sub(1);
        }
    }

    let mut survivor_bytes = candidates
        .iter()
        .filter(|candidate| !removal.contains(&candidate.path))
        .map(|candidate| candidate.bytes)
        .fold(0_u64, u64::saturating_add);
    for candidate in &candidates {
        if survivor_bytes <= policy.max_bytes {
            break;
        }
        if !candidate.protected && removal.insert(candidate.path.clone()) {
            survivor_bytes = survivor_bytes.saturating_sub(candidate.bytes);
        }
    }

    let mut removed = Vec::new();
    let mut reclaimed_bytes = 0_u64;
    for candidate in &candidates {
        if removal.contains(&candidate.path) {
            removed.push(path_file_name(&candidate.path));
            reclaimed_bytes = reclaimed_bytes.saturating_add(candidate.bytes);
            if !dry_run {
                fs::remove_dir_all(&candidate.path)
                    .with_context(|| format!("remove retained run {}", candidate.path.display()))?;
            }
        } else {
            retained.push(path_file_name(&candidate.path));
        }
    }
    retained.sort();
    Ok(RunPruneReport {
        dry_run,
        removed,
        retained,
        reclaimed_bytes,
    })
}

fn path_file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<non-utf8>")
        .to_string()
}

fn directory_size_without_symlinks(path: &Path) -> Result<u64> {
    let mut total = 0_u64;
    for entry in fs::read_dir(path).with_context(|| format!("read run {}", path.display()))? {
        let entry = entry.with_context(|| format!("read run entry {}", path.display()))?;
        let child = entry.path();
        let metadata = fs::symlink_metadata(&child)
            .with_context(|| format!("inspect run artifact {}", child.display()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            total = total.saturating_add(directory_size_without_symlinks(&child)?);
        } else if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
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
    #[cfg(unix)]
    fs::set_permissions(run_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set owner-only permissions on {}", run_dir.display()))?;
    let path = run_dir.join("run-meta.json");
    let write_seq = METADATA_WRITE_SEQ.fetch_add(1, Ordering::SeqCst);
    let temp_path = run_dir.join(format!(
        ".run-meta.{}.{}.tmp",
        std::process::id(),
        write_seq
    ));
    let payload = serde_json::to_vec_pretty(metadata)
        .with_context(|| format!("serialize {}", path.display()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(&temp_path)
        .with_context(|| format!("open {}", temp_path.display()))?;
    let result = (|| {
        // Own the handle here so every returned error closes it before cleanup.
        let mut file = file;
        use std::io::Write as _;
        file.write_all(&payload)
            .with_context(|| format!("write {}", temp_path.display()))?;
        file.flush()
            .with_context(|| format!("flush {}", temp_path.display()))?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set owner-only permissions on {}", temp_path.display()))?;
        drop(file);
        replace_file(&temp_path, &path)
    })();
    if result.is_err() {
        // Only successful create_new grants cleanup ownership. Keep the causal
        // error if removing this invocation's exact stage also fails.
        let _ = fs::remove_file(&temp_path);
    }
    result
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
        3 => "canceled".to_string(),
        _ => "failed".to_string(),
    }
}

fn read_run_summary(path: &Path) -> Result<Option<RunSummary>> {
    let (metadata, _) = read_run_metadata(path);
    let Some(metadata) = metadata else {
        return Ok(None);
    };
    let (artifact, run_json_status) = read_run_json_status(path);
    Ok(Some(summary_from_parts(
        path,
        metadata,
        artifact,
        run_json_status,
    )))
}

fn read_run_json_status(path: &Path) -> (Option<Value>, RunArtifactStatus) {
    let payload = match bounded_regular_read(&path.join("run.json"), MAX_ARTIFACT_BYTES) {
        Ok(payload) => payload,
        Err(status) => return (None, status),
    };
    let Ok(value) = serde_json::from_slice::<Value>(&payload) else {
        return (None, RunArtifactStatus::Malformed);
    };
    if value
        .get("schema_version")
        .is_some_and(|v| v.as_u64() != Some(1))
    {
        return (None, RunArtifactStatus::Unsupported);
    }
    let valid = value
        .get("tasks")
        .and_then(Value::as_array)
        .is_some_and(|tasks| {
            tasks.iter().all(|task| {
                task.is_object()
                    && matches!(
                        task.get("status").and_then(Value::as_str),
                        Some("completed" | "failed" | "canceled" | "skipped")
                    )
                    && valid_issue_evidence(task)
                    && task
                        .get("completed_with_issues")
                        .is_none_or(Value::is_boolean)
            })
        });
    if !valid {
        return (None, RunArtifactStatus::Malformed);
    }
    (Some(value), RunArtifactStatus::Loaded)
}

fn valid_issue_evidence(task: &Value) -> bool {
    let advisories_valid = task.get("advisories").is_none_or(|value| {
        value.as_array().is_some_and(|items| {
            items.iter().all(|item| {
                item.is_object()
                    && matches!(
                        item.get("severity").and_then(Value::as_str),
                        Some("info" | "warning" | "error")
                    )
            })
        })
    });
    let reports_valid = task.get("report_sections").is_none_or(|value| {
        value.as_array().is_some_and(|sections| {
            sections.iter().all(|section| {
                section
                    .get("rows")
                    .and_then(Value::as_array)
                    .is_some_and(|rows| {
                        rows.iter().all(|row| {
                            row.is_object()
                                && matches!(
                                    row.get("status").and_then(Value::as_str),
                                    Some(
                                        "updated"
                                            | "refreshed"
                                            | "passed"
                                            | "unchanged"
                                            | "failed"
                                            | "blocked"
                                            | "skipped"
                                            | "info"
                                    )
                                )
                        })
                    })
            })
        })
    });
    advisories_valid && reports_valid
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
        .map(|tasks| tasks.len());
    let issue_count = artifact
        .as_ref()
        .and_then(|value| value.get("tasks"))
        .and_then(Value::as_array)
        .map(|tasks| count_issue_tasks(tasks));
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
            matches!(status, "failed" | "canceled")
                || completed_with_issues
                || task
                    .get("advisories")
                    .and_then(Value::as_array)
                    .is_some_and(|items| {
                        items.iter().any(|item| {
                            item.get("code").and_then(Value::as_str) == Some("deferred")
                                || matches!(
                                    item.get("severity").and_then(Value::as_str),
                                    Some("warning" | "warn" | "error")
                                )
                        })
                    })
                || task
                    .get("report_sections")
                    .and_then(Value::as_array)
                    .is_some_and(|sections| {
                        sections.iter().any(|section| {
                            section
                                .get("rows")
                                .and_then(Value::as_array)
                                .is_some_and(|rows| {
                                    rows.iter().any(|row| {
                                        matches!(
                                            row.get("status").and_then(Value::as_str),
                                            Some("failed" | "blocked")
                                        )
                                    })
                                })
                        })
                    })
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

// Inspection is observation, never a repair authority. These limits also apply to legacy browsing.
const MAX_HISTORY_ENTRIES: usize = 4096;
const MAX_METADATA_BYTES: u64 = 256 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;

fn history_directories(root: &Path) -> Result<Vec<std::path::PathBuf>> {
    let metadata = match fs::symlink_metadata(root) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).context("inspect run history root"),
    };
    if !metadata.file_type().is_dir() {
        anyhow::bail!("run history root is not a real directory");
    }
    let mut paths = Vec::new();
    for (index, entry) in fs::read_dir(root)?.enumerate() {
        if index >= MAX_HISTORY_ENTRIES {
            anyhow::bail!("run history exceeds the 4096-entry inspection bound");
        }
        let entry = entry.context("read run history entry")?;
        if entry.file_type()?.is_dir() {
            paths.push(entry.path());
        }
    }
    paths.sort();
    let mut bytes = 0_u64;
    for path in &paths {
        for (name, limit) in [
            ("run-meta.json", MAX_METADATA_BYTES),
            ("run.json", MAX_ARTIFACT_BYTES),
        ] {
            if let Ok(meta) = fs::symlink_metadata(path.join(name)) {
                if meta.file_type().is_file() && meta.len() <= limit {
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
    }
    if bytes > 64 * 1024 * 1024 {
        anyhow::bail!("run history exceeds the 64 MiB observation bound");
    }
    Ok(paths)
}

fn bounded_regular_read(
    path: &Path,
    limit: u64,
) -> std::result::Result<Vec<u8>, RunArtifactStatus> {
    let classify = |error: io::Error| {
        if error.kind() == io::ErrorKind::NotFound {
            RunArtifactStatus::Missing
        } else {
            RunArtifactStatus::Unreadable
        }
    };
    let metadata = fs::symlink_metadata(path).map_err(classify)?;
    if !metadata.file_type().is_file() {
        return Err(RunArtifactStatus::Unsafe);
    }
    if metadata.len() > limit {
        return Err(RunArtifactStatus::Oversized);
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path).map_err(classify)?;
    let opened = file.metadata().map_err(classify)?;
    if !opened.file_type().is_file() {
        return Err(RunArtifactStatus::Unsafe);
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(classify)?;
    if bytes.len() as u64 > limit {
        return Err(RunArtifactStatus::Oversized);
    }
    Ok(bytes)
}

fn read_run_metadata(path: &Path) -> (Option<RunMetadata>, RunArtifactStatus) {
    let bytes = match bounded_regular_read(&path.join("run-meta.json"), MAX_METADATA_BYTES) {
        Ok(bytes) => bytes,
        Err(status) => return (None, status),
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return (None, RunArtifactStatus::Malformed);
    };
    if value
        .get("schema_version")
        .is_some_and(|v| v.as_u64() != Some(1))
    {
        return (None, RunArtifactStatus::Unsupported);
    }
    let Ok(metadata) = serde_json::from_value::<RunMetadata>(value) else {
        return (None, RunArtifactStatus::Malformed);
    };
    if metadata.run_id.is_empty()
        || !matches!(
            metadata.status.as_str(),
            "running" | "finalizing" | "completed" | "failed" | "canceled"
        )
    {
        return (None, RunArtifactStatus::Malformed);
    }
    (Some(metadata), RunArtifactStatus::Loaded)
}

#[derive(Serialize)]
pub(crate) struct RunInspectionReport {
    schema: &'static str,
    pub(crate) runs: Vec<RunInspection>,
}

#[derive(Serialize)]
pub(crate) struct RunInspection {
    pub(crate) directory_name: String,
    path: PathBuf,
    pub(crate) metadata_status: &'static str,
    pub(crate) run_artifact_status: &'static str,
    pub(crate) evidence_status: &'static str,
    run_id: Option<String>,
    display_name: Option<String>,
    pub(crate) recorded_status: Option<String>,
    created_unix_ms: Option<u64>,
    updated_unix_ms: Option<u64>,
    selected_tasks: Option<Vec<String>>,
    pub(crate) task_count: Option<usize>,
    pub(crate) issue_count: Option<usize>,
    exit_code: Option<i32>,
}

fn inspection_directories(root: &Path, query: Option<&str>) -> Result<Vec<PathBuf>> {
    if let Some(query) = query {
        let mut components = Path::new(query).components();
        if matches!(components.next(), Some(std::path::Component::Normal(_)))
            && components.next().is_none()
        {
            let path = root.join(query);
            if fs::symlink_metadata(root).is_ok_and(|meta| meta.file_type().is_dir())
                && fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_dir())
            {
                return Ok(vec![path]);
            }
        }
    }
    history_directories(root)
}

pub(crate) fn inspect_runs(root: &Path, query: Option<&str>) -> Result<RunInspectionReport> {
    let mut runs = Vec::new();
    for path in inspection_directories(root, query)? {
        let (metadata, metadata_status) = read_run_metadata(&path);
        let directory_name = path_file_name(&path);
        if let Some(query) = query {
            // Damaged entries have only an observed directory locator, never an invented identity.
            if directory_name != query
                && !metadata
                    .as_ref()
                    .is_some_and(|meta| meta.run_id == query || meta.display_name == query)
            {
                continue;
            }
        }
        let (artifact, run_status) = read_run_json_status(&path);
        let task_count = artifact
            .as_ref()
            .and_then(|a| a.get("tasks"))
            .and_then(Value::as_array)
            .map(Vec::len);
        let issue_count = artifact
            .as_ref()
            .and_then(|a| a.get("tasks"))
            .and_then(Value::as_array)
            .map(|tasks| count_issue_tasks(tasks));
        let evidence_status = if metadata.is_some() && artifact.is_some() {
            "available"
        } else {
            "incomplete"
        };
        runs.push(RunInspection {
            directory_name,
            path,
            metadata_status: metadata_status.as_str(),
            run_artifact_status: run_status.as_str(),
            evidence_status,
            run_id: metadata.as_ref().map(|m| m.run_id.clone()),
            display_name: metadata.as_ref().map(|m| m.display_name.clone()),
            recorded_status: metadata.as_ref().map(|m| m.status.clone()),
            created_unix_ms: metadata.as_ref().map(|m| m.created_unix_ms),
            updated_unix_ms: metadata.as_ref().map(|m| m.updated_unix_ms),
            selected_tasks: metadata.as_ref().map(|m| m.selected_tasks.clone()),
            task_count,
            issue_count,
            exit_code: artifact
                .as_ref()
                .and_then(|a| a.get("exit_code"))
                .and_then(Value::as_i64)
                .and_then(|v| i32::try_from(v).ok()),
        });
    }
    if query.is_some() && runs.is_empty() {
        anyhow::bail!("no run matched the exact inspection query");
    }
    Ok(RunInspectionReport {
        schema: "update-all-run-inspection-v1",
        runs,
    })
}
