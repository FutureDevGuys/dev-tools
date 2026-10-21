use crate::ui::{is_report_meta_line, LogLevel, LogRecord, LogStream, RUN_LOG_SCOPE};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub struct RunLogSink {
    build_info: dev_tools_product::BuildInfo,
    run_dir: PathBuf,
    run_id: String,
    display_name: Mutex<String>,
    started_unix_ms: u64,
    timestamps: bool,
    run_file: Mutex<File>,
    run_file_path: PathBuf,
    event_file: Mutex<File>,
    event_file_path: PathBuf,
    event_sequence: Mutex<u64>,
    journal_failure: Mutex<Option<String>>,
    run_snapshot: Mutex<Option<Value>>,
    selected_tasks: Mutex<Vec<String>>,
    started_tasks: Mutex<BTreeSet<String>>,
    #[cfg(test)]
    journal_fault_injected: AtomicBool,
    task_files: Mutex<BTreeMap<String, LogFileHandle>>,
    raw_task_files: Mutex<BTreeMap<String, LogFileHandle>>,
}

struct LogFileHandle {
    file: File,
    path: PathBuf,
}

impl RunLogSink {
    pub fn new(root_dir: &Path, timestamps: bool) -> Result<Self> {
        let build_info = crate::build_info::current_product_build_info()?;
        let started_unix_ms = unix_ms_now()?;
        create_owner_only_dir(root_dir)?;
        let run_id = Uuid::new_v4().to_string();
        let run_dir = make_run_dir(root_dir, started_unix_ms, &run_id);
        create_owner_only_dir(&run_dir)
            .with_context(|| format!("create run log directory {}", run_dir.display()))?;
        let run_file_path = run_dir.join("run.log");
        let run_file = open_append(&run_file_path)?;
        let event_file_path = run_dir.join("events.jsonl");
        let event_file = open_append(&event_file_path)?;
        let sink = Self {
            build_info,
            run_dir,
            run_id: run_id.clone(),
            display_name: Mutex::new(run_id),
            started_unix_ms,
            timestamps,
            run_file: Mutex::new(run_file),
            run_file_path,
            event_file: Mutex::new(event_file),
            event_file_path,
            event_sequence: Mutex::new(0),
            journal_failure: Mutex::new(None),
            run_snapshot: Mutex::new(None),
            selected_tasks: Mutex::new(Vec::new()),
            started_tasks: Mutex::new(BTreeSet::new()),
            #[cfg(test)]
            journal_fault_injected: AtomicBool::new(false),
            task_files: Mutex::new(BTreeMap::new()),
            raw_task_files: Mutex::new(BTreeMap::new()),
        };
        sink.write_event(
            "run_started",
            None,
            serde_json::json!({
                "run_id": sink.run_id.clone(),
                "display_name": sink.display_name(),
                "build_info": sink.build_info(),
            }),
        )?;
        sink.write_metadata("running", None, None, None, Vec::new(), started_unix_ms)?;
        Ok(sink)
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    pub fn build_info(&self) -> &dev_tools_product::BuildInfo {
        &self.build_info
    }

    pub fn started_unix_ms(&self) -> u64 {
        self.started_unix_ms
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn display_name(&self) -> String {
        match self.display_name.lock() {
            Ok(name) => name.clone(),
            Err(_) => self.run_id.clone(),
        }
    }

    pub fn set_display_name(&self, display_name: &str) -> Result<()> {
        let trimmed = display_name.trim();
        if trimmed.is_empty() {
            anyhow::bail!("display name cannot be empty");
        }
        let mut guard = self
            .display_name
            .lock()
            .map_err(|_| anyhow::anyhow!("run display-name lock poisoned"))?;
        *guard = trimmed.to_string();
        Ok(())
    }

    pub fn write_metadata(
        &self,
        status: &str,
        host_os: Option<&str>,
        ui_mode: Option<&str>,
        engine_mode: Option<&str>,
        selected_tasks: Vec<String>,
        updated_unix_ms: u64,
    ) -> Result<()> {
        let metadata = crate::runs::RunMetadata {
            schema_version: 1,
            run_id: self.run_id.clone(),
            display_name: self.display_name(),
            created_unix_ms: self.started_unix_ms,
            updated_unix_ms,
            status: status.to_string(),
            run_dir: self.run_dir.display().to_string(),
            pid: std::process::id(),
            host_os: host_os.map(str::to_string),
            ui_mode: ui_mode.map(str::to_string),
            engine_mode: engine_mode.map(str::to_string),
            selected_tasks,
        };
        self.record_persistence_result(crate::runs::write_metadata_atomic(&self.run_dir, &metadata))
    }

    pub fn write_record(&self, rec: &LogRecord) -> Result<()> {
        self.record_persistence_result(self.write_record_inner(rec))
    }

    fn write_record_inner(&self, rec: &LogRecord) -> Result<()> {
        let run_line = render_human_record(rec, self.timestamps, true);
        let task_line = render_human_record(rec, self.timestamps, false);

        let mut run_file = self
            .run_file
            .lock()
            .map_err(|_| anyhow::anyhow!("run log file lock poisoned"))?;
        run_file
            .write_all(run_line.as_bytes())
            .with_context(|| format!("write {}", self.run_file_path.display()))?;
        run_file
            .flush()
            .with_context(|| format!("flush {}", self.run_file_path.display()))?;
        drop(run_file);

        if rec.task_id == RUN_LOG_SCOPE {
            return Ok(());
        }

        let mut files = self
            .task_files
            .lock()
            .map_err(|_| anyhow::anyhow!("task log file map lock poisoned"))?;
        let key = rec.task_id.clone();
        if !files.contains_key(&key) {
            let path = self
                .run_dir
                .join(format!("task-{}.log", task_file_stem(&key)));
            let file = open_append(&path)?;
            files.insert(key.clone(), LogFileHandle { file, path });
        }
        let Some(handle) = files.get_mut(&key) else {
            anyhow::bail!("task log file missing for {}", rec.task_id);
        };
        handle
            .file
            .write_all(task_line.as_bytes())
            .with_context(|| format!("write {}", handle.path.display()))?;
        handle
            .file
            .flush()
            .with_context(|| format!("flush {}", handle.path.display()))?;
        Ok(())
    }

    pub fn write_event(&self, kind: &str, task_id: Option<&str>, payload: Value) -> Result<()> {
        let starts_task = kind == "task_state_changed" && payload["state"] == "running";
        let result = self.write_event_inner(kind, task_id, payload);
        if result.is_ok() && starts_task {
            if let (Some(task_id), Ok(mut started)) = (task_id, self.started_tasks.lock()) {
                started.insert(task_id.to_string());
            }
        }
        if let Err(error) = &result {
            if let Ok(mut failure) = self.journal_failure.lock() {
                if failure.is_none() {
                    *failure = Some(format!("{error:#}"));
                }
            }
        }
        result
    }

    fn write_event_inner(&self, kind: &str, task_id: Option<&str>, payload: Value) -> Result<()> {
        #[cfg(test)]
        if self.journal_fault_injected.load(Ordering::SeqCst) {
            anyhow::bail!("injected authoritative journal failure");
        }
        let mut sequence = self
            .event_sequence
            .lock()
            .map_err(|_| anyhow::anyhow!("event journal sequence lock poisoned"))?;
        *sequence = sequence.saturating_add(1);
        let record = JournalRecord {
            schema_version: 1,
            sequence: *sequence,
            ts_unix_ms: unix_ms_now()?,
            kind,
            task_id,
            payload,
        };
        let mut encoded = serde_json::to_vec(&record)
            .with_context(|| format!("serialize {}", self.event_file_path.display()))?;
        encoded.push(b'\n');
        let mut file = self
            .event_file
            .lock()
            .map_err(|_| anyhow::anyhow!("event journal file lock poisoned"))?;
        file.write_all(&encoded)
            .with_context(|| format!("write {}", self.event_file_path.display()))?;
        file.flush()
            .with_context(|| format!("flush {}", self.event_file_path.display()))?;
        Ok(())
    }

    pub fn journal_failure(&self) -> Option<String> {
        self.journal_failure
            .lock()
            .ok()
            .and_then(|failure| failure.clone())
    }

    #[cfg(test)]
    pub fn inject_journal_fault_for_test(&self) {
        self.journal_fault_injected.store(true, Ordering::SeqCst);
    }

    pub fn write_raw(&self, rec: &LogRecord) -> Result<()> {
        self.record_persistence_result(self.write_raw_inner(rec))
    }

    fn write_raw_inner(&self, rec: &LogRecord) -> Result<()> {
        if rec.task_id == RUN_LOG_SCOPE {
            return Ok(());
        }
        let line = if self.timestamps {
            format!(
                "{} [{}] [{}] [{}] {}\n",
                render_ts(rec.ts_unix_ms),
                rec.task_id,
                rec.level.as_str(),
                rec.stream.as_str(),
                rec.line
            )
        } else {
            format!(
                "[{}] [{}] [{}] {}\n",
                rec.task_id,
                rec.level.as_str(),
                rec.stream.as_str(),
                rec.line
            )
        };

        let mut files = self
            .raw_task_files
            .lock()
            .map_err(|_| anyhow::anyhow!("raw task log file map lock poisoned"))?;
        let key = rec.task_id.clone();
        if !files.contains_key(&key) {
            let path = self
                .run_dir
                .join(format!("task-{}.raw.log", task_file_stem(&key)));
            let file = open_append(&path)?;
            files.insert(key.clone(), LogFileHandle { file, path });
        }
        let Some(handle) = files.get_mut(&key) else {
            anyhow::bail!("raw task log file missing for {}", rec.task_id);
        };
        handle
            .file
            .write_all(line.as_bytes())
            .with_context(|| format!("write {}", handle.path.display()))?;
        handle
            .file
            .flush()
            .with_context(|| format!("flush {}", handle.path.display()))?;
        Ok(())
    }

    pub fn write_json_file<T: Serialize>(&self, relative_name: &str, value: &T) -> Result<()> {
        let path = self.run_dir.join(relative_name);
        if relative_name == "run.json" {
            *self
                .run_snapshot
                .lock()
                .map_err(|_| anyhow::anyhow!("run snapshot lock poisoned"))? =
                Some(serde_json::to_value(value)?);
        }
        let json = serde_json::to_vec_pretty(value)
            .with_context(|| format!("serialize {}", path.display()))?;
        self.record_persistence_result(write_owner_only(&path, &json))
    }

    pub(crate) fn record_selected_tasks(&self, selected: &[String]) -> Result<()> {
        *self
            .selected_tasks
            .lock()
            .map_err(|_| anyhow::anyhow!("run selection lock poisoned"))? = selected.to_vec();
        Ok(())
    }

    /// A zero exit can include cancel-one or all-skipped plans; neither permits restart.
    pub(crate) fn restart_eligible(&self) -> Result<bool> {
        let snapshot = self
            .run_snapshot
            .lock()
            .map_err(|_| anyhow::anyhow!("run snapshot lock poisoned"))?;
        Ok(snapshot.as_ref().is_some_and(|run| {
            run["failed_task_count"].as_u64() == Some(0)
                && run["canceled_task_count"].as_u64() == Some(0)
                && run["issue_count"].as_u64() == Some(0)
                && run["tasks"]
                    .as_array()
                    .is_some_and(|tasks| tasks.iter().any(|task| task["status"] == "completed"))
        }))
    }

    /// Flush OS buffers as well as Rust buffers before a host restart request.
    pub(crate) fn sync_before_restart(&self) -> Result<()> {
        for file in [&self.run_file, &self.event_file] {
            file.lock()
                .map_err(|_| anyhow::anyhow!("run log lock poisoned"))?
                .sync_all()?;
        }
        for files in [&self.task_files, &self.raw_task_files] {
            for handle in files
                .lock()
                .map_err(|_| anyhow::anyhow!("task log lock poisoned"))?
                .values()
            {
                handle.file.sync_all()?;
            }
        }
        let snapshot = self
            .run_snapshot
            .lock()
            .map_err(|_| anyhow::anyhow!("run snapshot lock poisoned"))?;
        let tasks = snapshot
            .as_ref()
            .and_then(|run| run["tasks"].as_array())
            .context("cannot sync missing terminal task evidence")?;
        let mut names = vec![
            "run.json".to_string(),
            "run-meta.json".to_string(),
            "restart.json".to_string(),
        ];
        for task in tasks {
            let id = task["task_id"]
                .as_str()
                .context("task artifact has no task id")?;
            names.push(format!("task-{}.json", task_file_stem(id)));
        }
        for name in names {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(self.run_dir.join(name))?
                .sync_all()?;
        }
        #[cfg(unix)]
        {
            File::open(&self.run_dir)?.sync_all()?;
            if let Some(parent) = self.run_dir.parent() {
                File::open(parent)?.sync_all()?;
            }
        }
        Ok(())
    }

    /// One controlled-return owner calls this after task execution (or rejected admission).
    /// The last in-memory artifact preserves observed effects even if its disk write failed.
    pub(crate) fn finalize_task_run(
        &self,
        host_os: &str,
        ui_mode: &str,
        engine_mode: &str,
        status: &str,
        exit_code: i32,
        reason: Option<&str>,
    ) -> Result<()> {
        let now = unix_ms_now()?;
        let selected = self
            .selected_tasks
            .lock()
            .map_err(|_| anyhow::anyhow!("run selection lock poisoned"))?
            .clone();
        let snapshot = self
            .run_snapshot
            .lock()
            .map_err(|_| anyhow::anyhow!("run snapshot lock poisoned"))?
            .clone();
        let mut payload = snapshot.unwrap_or_else(|| {
            serde_json::json!({
                "schema_version": 1,
                "build_info": self.build_info(),
                "run_id": self.run_id(),
                "started_unix_ms": self.started_unix_ms,
                "tasks_ended_unix_ms": now,
                "tasks_completed_unix_ms": now,
                "ended_unix_ms": now,
                "tasks_elapsed_ms": now.saturating_sub(self.started_unix_ms),
                "completed_with_issues": false,
                "issue_count": 0,
                "failed_task_count": 0,
                "canceled_task_count": 0,
                "runtime_advisories": [],
                "tasks": [],
            })
        });
        let started = self
            .started_tasks
            .lock()
            .map_err(|_| anyhow::anyhow!("run started-task lock poisoned"))?;
        let unstarted: Vec<String> = selected
            .iter()
            .filter(|id| !started.contains(*id))
            .cloned()
            .collect();
        drop(started);
        payload["status"] = status.into();
        payload["exit_code"] = exit_code.into();
        payload["reason"] = reason
            .map(|text| text.chars().take(1024).collect::<String>())
            .into();
        payload["display_name"] = self.display_name().into();
        payload["host_os"] = host_os.into();
        payload["ui_mode"] = ui_mode.into();
        payload["engine_mode"] = engine_mode.into();
        payload["run_dir"] = self.run_dir.display().to_string().into();
        payload["selected_tasks"] = serde_json::to_value(&selected)?;
        payload["unstarted_tasks"] = serde_json::to_value(unstarted)?;
        payload["artifact_updated_unix_ms"] = now.into();
        payload["ui_wait_ms"] = now
            .saturating_sub(payload["tasks_ended_unix_ms"].as_u64().unwrap_or(now))
            .into();

        let mut failure = self.write_json_file("run.json", &payload).err();
        let final_status = if failure.is_some() { "failed" } else { status };
        let final_exit = if failure.is_some() { 1 } else { exit_code };
        if let Err(error) = self.write_metadata(
            final_status,
            Some(host_os),
            Some(ui_mode),
            Some(engine_mode),
            selected.clone(),
            now,
        ) {
            if failure.is_none() {
                failure = Some(error);
            }
        }
        let final_status = if failure.is_some() { "failed" } else { status };
        let final_exit = if failure.is_some() { 1 } else { final_exit };
        if let Err(error) = self.write_event(
            "run_completed",
            None,
            serde_json::json!({
                "status": final_status,
                "exit_code": final_exit,
                "success": final_exit == 0,
                "canceled": final_status == "canceled",
                "had_failures": payload["failed_task_count"].as_u64().unwrap_or(0) > 0
                    || self.journal_failure().is_some()
                    || (final_status == "failed" && final_exit != 2),
                "reason": payload["reason"],
            }),
        ) {
            if failure.is_none() {
                failure = Some(error);
            }
        }
        if let Some(error) = failure {
            // Preserve actual task results. Best-effort correction is diagnostic only;
            // the explicit error remains non-clean even if this correction succeeds.
            payload["status"] = "failed".into();
            payload["exit_code"] = 1.into();
            payload["finalization_error"] = format!("{error:#}")
                .chars()
                .take(1024)
                .collect::<String>()
                .into();
            let _ = self.write_json_file("run.json", &payload);
            let _ = self.write_metadata(
                "failed",
                Some(host_os),
                Some(ui_mode),
                Some(engine_mode),
                selected,
                now,
            );
            return Err(error);
        }
        Ok(())
    }

    // Producers never write diagnostics to the terminal: the lifecycle owner
    // reports the sticky failure after the dashboard restores terminal ownership.
    pub fn emit_write_warning_once(&self, err: &anyhow::Error) {
        if let Ok(mut failure) = self.journal_failure.lock() {
            if failure.is_none() {
                *failure = Some(format!("{err:#}"));
            }
        }
    }

    fn record_persistence_result<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(error) = &result {
            self.emit_write_warning_once(error);
        }
        result
    }
}

#[derive(Serialize)]
struct JournalRecord<'a> {
    schema_version: u32,
    sequence: u64,
    ts_unix_ms: u64,
    kind: &'a str,
    task_id: Option<&'a str>,
    payload: Value,
}

pub(crate) fn task_file_stem(task_id: &str) -> String {
    let mut encoded = String::with_capacity(task_id.len());
    for byte in task_id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    if encoded.is_empty() {
        "_".to_string()
    } else {
        encoded
    }
}

fn unix_ms_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_millis()
        .try_into()
        .context("unix timestamp overflow")?)
}

fn render_human_record(rec: &LogRecord, timestamps: bool, include_task: bool) -> String {
    let mut parts = Vec::new();
    if timestamps {
        parts.push(render_ts(rec.ts_unix_ms));
    }
    if include_task {
        parts.push(rec.task_id.clone());
    }
    if let Some(badge) = human_badge(rec) {
        parts.push(format!("[{badge}]"));
    }
    parts.push(rec.line.clone());
    format!("{}\n", parts.join(" "))
}

fn human_badge(rec: &LogRecord) -> Option<&'static str> {
    if looks_like_interactive_prompt(&rec.line) {
        return Some("PROMPT");
    }
    if rec.stream == LogStream::Meta && !is_report_meta_line(&rec.line) {
        return Some("SYSTEM");
    }
    None
}

fn looks_like_interactive_prompt(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("[sudo] password for")
        || lower.contains("password for ")
        || lower.contains("excluding packages may cause partial upgrades")
        || lower.contains("proceed with installation")
        || lower.contains("[y/n]")
    {
        return true;
    }
    if trimmed == "==>" {
        return true;
    }
    if lower.starts_with("==> ") {
        return lower.contains("packages to exclude")
            || lower.contains("packages to cleanbuild")
            || lower.contains("diffs to show")
            || lower.contains("pkgbuilds to edit")
            || lower.contains("[n]one [a]ll [ab]ort")
            || lower.contains('?');
    }
    let mentions_service = lower.contains("service(s)")
        || lower.contains("services")
        || lower.contains("service to restart");
    mentions_service
        && lower.contains("restart")
        && (lower.contains("select")
            || lower.contains("choose")
            || lower.contains("press \"enter\" to continue")
            || lower.contains("press enter to continue")
            || lower.contains("continue without restarting"))
}

fn render_ts(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}Z")
}

fn make_run_dir(root: &Path, started_unix_ms: u64, run_id: &str) -> PathBuf {
    let pid = std::process::id();
    root.join(format!("run-{started_unix_ms}-{pid}-{run_id}"))
}

fn open_append(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set owner-only permissions on {}", path.display()))?;
    Ok(file)
}

fn create_owner_only_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create directory {}", path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set owner-only permissions on {}", path.display()))?;
    Ok(())
}

fn write_owner_only(path: &Path, payload: &[u8]) -> Result<()> {
    let previous = artifact_leaf_metadata(path)?;
    let mut staged = artifact_staging_file(path)?;
    // Keep the old file untouched, including its mode and write authorization.
    // Directory rename permission alone must not bypass a denied file write.
    let _previous_write_access = if let Some(metadata) = &previous {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            anyhow::ensure!(
                metadata.uid() == staged.as_file().metadata()?.uid(),
                "refuse unsafe artifact leaf {}: different owner",
                path.display()
            );
        }
        let mut options = OpenOptions::new();
        options.write(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_FLAG_OPEN_REPARSE_POINT: inspect the leaf, never its target.
            options.custom_flags(0x0020_0000);
        }
        let file = options
            .open(path)
            .with_context(|| format!("check write access to {}", path.display()))?;
        anyhow::ensure!(
            same_artifact_file(metadata, &file.metadata()?)?,
            "artifact leaf changed while checking write access: {}",
            path.display()
        );
        Some(file)
    } else {
        None
    };
    staged
        .as_file_mut()
        .write_all(payload)
        .with_context(|| format!("write {} (staged)", path.display()))?;
    staged
        .as_file_mut()
        .flush()
        .with_context(|| format!("flush {} (staged)", path.display()))?;
    publish_artifact(staged, path, previous.as_ref())
}

fn artifact_leaf_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect artifact {}", path.display()))
        }
    };
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "refuse unsafe artifact leaf {}: expected a regular file",
        path.display()
    );
    anyhow::ensure!(
        !metadata.permissions().readonly(),
        "refuse read-only artifact leaf {}",
        path.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.nlink() == 1 && metadata.mode() & 0o7000 == 0 && metadata.mode() & 0o200 != 0,
            "refuse unsafe artifact leaf {}: requires one link and ordinary owner-write permissions",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        anyhow::ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "refuse unsafe artifact reparse leaf {}",
            path.display()
        );
    }
    Ok(Some(metadata))
}

fn same_artifact_file(left: &fs::Metadata, right: &fs::Metadata) -> Result<bool> {
    let same = right.file_type().is_file()
        && left.len() == right.len()
        && left.permissions() == right.permissions()
        && left.modified()? == right.modified()?;
    #[cfg(unix)]
    let same = {
        use std::os::unix::fs::MetadataExt;
        same && left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.uid() == right.uid()
            && left.gid() == right.gid()
            && left.nlink() == right.nlink()
            && left.mode() == right.mode()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    };
    #[cfg(windows)]
    let same = {
        use std::os::windows::fs::MetadataExt;
        same && left.file_attributes() == right.file_attributes()
            && left.creation_time() == right.creation_time()
    };
    Ok(same)
}

fn artifact_staging_file(path: &Path) -> Result<tempfile::NamedTempFile> {
    let parent = path.parent().context("artifact has no parent directory")?;
    let name = path.file_name().context("artifact has no filename")?;
    // Retain short diagnostic suffixes without growing near-NAME_MAX task names.
    let mut suffix = std::ffi::OsString::from("-");
    if name.as_encoded_bytes().len() <= 96 {
        suffix.push(name);
    } else {
        suffix.push("artifact.json");
    }
    let staged = tempfile::Builder::new()
        .prefix(".update-all-artifact-")
        .suffix(&suffix)
        .tempfile_in(parent)
        .with_context(|| format!("stage artifact for {}", path.display()))?;
    #[cfg(unix)]
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("set private staging permissions for {}", path.display()))?;
    Ok(staged)
}

fn publish_artifact(
    staged: tempfile::NamedTempFile,
    path: &Path,
    previous: Option<&fs::Metadata>,
) -> Result<()> {
    let current = artifact_leaf_metadata(path)?;
    let unchanged = match (previous, current.as_ref()) {
        (None, None) => true,
        (Some(previous), Some(current)) => same_artifact_file(previous, current)?,
        _ => false,
    };
    anyhow::ensure!(
        unchanged,
        "artifact leaf changed before publication: {}",
        path.display()
    );
    persist_staged_artifact(staged, path)
}

fn persist_staged_artifact(staged: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    // One namespace-atomic replacement, not a power-loss durability guarantee.
    // Never unlink the destination as a fallback. On error, drop only our stage.
    staged
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publish artifact {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{render_human_record, RunLogSink};
    use crate::ui::{LogLevel, LogRecord, LogStream};
    use tempfile::TempDir;

    #[test]
    fn artifact_replacement_publishes_complete_private_bytes_and_bounded_names() {
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), false).unwrap();
        let unknown = sink.run_dir().join(".update-all-artifact-unknown-run.json");
        std::fs::write(&unknown, b"not this invocation's stage").unwrap();
        for name in [
            "run.json".to_string(),
            format!("task-{}.json", "x".repeat(240)),
        ] {
            let payload = serde_json::json!({"schema_version":1,"tasks":[{"status":"completed"}],"exit_code":0});
            let stage = super::artifact_staging_file(&sink.run_dir().join(&name)).unwrap();
            let stage_name = stage.path().file_name().unwrap().to_string_lossy();
            assert!(stage_name.len() < 128);
            if name == "run.json" {
                assert!(stage_name.ends_with("-run.json"));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    stage.as_file().metadata().unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            drop(stage);
            sink.write_json_file(&name, &payload).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    sink.run_dir().join(&name),
                    std::fs::Permissions::from_mode(0o644),
                )
                .unwrap();
            }
            sink.write_json_file(&name, &true).unwrap();
            assert_eq!(std::fs::read(sink.run_dir().join(&name)).unwrap(), b"true");
            sink.write_json_file(&name, &payload).unwrap();
            assert_eq!(
                std::fs::read(sink.run_dir().join(&name)).unwrap(),
                serde_json::to_vec_pretty(&payload).unwrap()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(sink.run_dir().join(&name))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(
            std::fs::read(unknown).unwrap(),
            b"not this invocation's stage"
        );
        assert_eq!(std::fs::read_dir(sink.run_dir()).unwrap().count(), 6);
    }

    #[cfg(unix)]
    #[test]
    #[allow(unsafe_code)]
    fn artifact_replacement_refuses_unsafe_leaves_without_changing_them() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
        let root = TempDir::new().unwrap();
        let target = root.path().join("outside.json");
        std::fs::write(&target, b"outside preserved").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let target_before = std::fs::metadata(&target).unwrap();
        let directory = root.path().join("directory.json");
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("child"), b"preserve child").unwrap();
        let link = root.path().join("link.json");
        symlink(&target, &link).unwrap();
        let broken = root.path().join("broken.json");
        symlink(root.path().join("absent"), &broken).unwrap();
        let hardlink = root.path().join("hardlink.json");
        std::fs::hard_link(&target, &hardlink).unwrap();
        let fifo = root.path().join("fifo.json");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: create an unconnected FIFO only at this test's owned temporary path.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let readonly = root.path().join("readonly.json");
        std::fs::write(&readonly, b"read-only preserved").unwrap();
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o400)).unwrap();
        let special = root.path().join("special.json");
        std::fs::write(&special, b"special mode preserved").unwrap();
        std::fs::set_permissions(&special, std::fs::Permissions::from_mode(0o1600)).unwrap();
        let before_entries = std::fs::read_dir(root.path()).unwrap().count();
        for path in [
            &directory, &link, &broken, &hardlink, &fifo, &readonly, &special,
        ] {
            let before = std::fs::symlink_metadata(path).unwrap();
            assert!(
                super::write_owner_only(path, b"replacement").is_err(),
                "{}",
                path.display()
            );
            let after = std::fs::symlink_metadata(path).unwrap();
            assert_eq!(
                (
                    before.dev(),
                    before.ino(),
                    before.mode(),
                    before.nlink(),
                    before.len(),
                    before.mtime(),
                    before.mtime_nsec()
                ),
                (
                    after.dev(),
                    after.ino(),
                    after.mode(),
                    after.nlink(),
                    after.len(),
                    after.mtime(),
                    after.mtime_nsec()
                )
            );
        }
        assert_eq!(std::fs::read(&target).unwrap(), b"outside preserved");
        assert_eq!(
            std::fs::metadata(&target).unwrap().mode(),
            target_before.mode()
        );
        assert_eq!(std::fs::read_link(link).unwrap(), target);
        assert_eq!(
            std::fs::read(directory.join("child")).unwrap(),
            b"preserve child"
        );
        assert_eq!(std::fs::read(readonly).unwrap(), b"read-only preserved");
        assert_eq!(std::fs::read(special).unwrap(), b"special mode preserved");
        assert_eq!(
            std::fs::read_dir(root.path()).unwrap().count(),
            before_entries
        );
    }

    #[test]
    fn artifact_replacement_cleans_owned_stage_on_publication_and_revalidation_failures() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("run.json");
        std::fs::write(&path, b"prior bytes").unwrap();
        let previous = super::artifact_leaf_metadata(&path).unwrap();
        let unknown = root.path().join(".update-all-artifact-unknown-run.json");
        std::fs::write(&unknown, b"unknown stage").unwrap();
        let staged = super::artifact_staging_file(&path).unwrap();
        let stage_path = staged.path().to_path_buf();
        std::fs::write(&path, b"newly observed bytes").unwrap();
        assert!(super::publish_artifact(staged, &path, previous.as_ref()).is_err());
        assert!(!stage_path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"newly observed bytes");

        // Exercise the actual rename error boundary, independently of leaf admission.
        // This directory is an obstruction, not a preexisting regular artifact.
        let obstruction = root.path().join("obstruction.json");
        std::fs::create_dir(&obstruction).unwrap();
        std::fs::write(obstruction.join("child"), b"preserved obstruction").unwrap();
        let staged = super::artifact_staging_file(&obstruction).unwrap();
        let stage_path = staged.path().to_path_buf();
        let error = super::persist_staged_artifact(staged, &obstruction).unwrap_err();
        assert!(format!("{error:#}").contains("publish artifact"));
        assert!(
            !stage_path.exists(),
            "cleanup happens before the returned error is dropped"
        );
        assert_eq!(
            std::fs::read(obstruction.join("child")).unwrap(),
            b"preserved obstruction"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"newly observed bytes");
        assert_eq!(std::fs::read(&unknown).unwrap(), b"unknown stage");
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 3);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn artifact_replacement_preserves_previous_bytes_after_partial_write() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        use std::time::Duration;
        use wait_timeout::ChildExt;

        // Process-local limits must never affect the parallel test runner.
        const CHILD: &str = "UPDATE_ALL_ARTIFACT_PARTIAL_WRITE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let root = TempDir::new().unwrap();
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "logging::tests::artifact_replacement_preserves_previous_bytes_after_partial_write",
                    "--nocapture",
                ])
                .env_clear()
                .env(CHILD, "1")
                .env("HOME", root.path())
                .env("TMPDIR", root.path())
                .env("PATH", "")
                .current_dir(root.path())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            if child
                .wait_timeout(Duration::from_secs(15))
                .unwrap()
                .is_none()
            {
                let _ = child.kill();
                let _ = child.wait();
                panic!("owned artifact-write test exceeded its bound");
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        struct LimitGuard(libc::rlimit, libc::sighandler_t);
        impl Drop for LimitGuard {
            fn drop(&mut self) {
                // SAFETY: restore only this isolated test process's saved limit and handler.
                unsafe {
                    assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &self.0), 0);
                    libc::signal(libc::SIGXFSZ, self.1);
                }
            }
        }
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), false).unwrap();
        let path = sink.run_dir().join("run.json");
        let old = serde_json::json!({"tasks":[{"status":"completed"}],"exit_code":0});
        sink.write_json_file("run.json", &old).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = std::fs::read(&path).unwrap();
        let before_metadata = std::fs::metadata(&path).unwrap();
        let before_entries = std::fs::read_dir(sink.run_dir()).unwrap().count();
        let next =
            serde_json::json!({"tasks":[{"status":"completed"}],"exit_code":1,"status":"failed"});

        // SAFETY: get/set a valid rlimit only in this self-spawned, single-test process.
        let guard = unsafe {
            let mut old_limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut old_limit), 0);
            let old_handler = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            assert_ne!(old_handler, libc::SIG_ERR);
            let guard = LimitGuard(old_limit, old_handler);
            let limit = libc::rlimit {
                rlim_cur: 1,
                rlim_max: guard.0.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
            guard
        };
        let error = sink.write_json_file("run.json", &next).unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EFBIG)
        );
        assert!(format!("{error:#}").contains("run.json"));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode(),
            before_metadata.permissions().mode()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before_metadata.modified().unwrap()
        );
        assert_eq!(sink.run_snapshot.lock().unwrap().as_ref(), Some(&next));
        let first_failure = sink.journal_failure().unwrap();
        assert!(sink.write_json_file("missing.json", &next).is_err());
        assert!(!sink.run_dir().join("missing.json").exists());
        assert_eq!(
            std::fs::read_dir(sink.run_dir()).unwrap().count(),
            before_entries
        );
        drop(guard);
        sink.write_json_file("run.json", &next).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            serde_json::to_vec_pretty(&next).unwrap()
        );
        assert_eq!(
            sink.journal_failure().as_deref(),
            Some(first_failure.as_str())
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_artifacts_are_owner_only_even_with_a_permissive_parent() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = TempDir::new().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let sink = RunLogSink::new(root.path(), false).unwrap();
        sink.write_json_file("fixture.json", &serde_json::json!({"ok": true}))
            .unwrap();

        assert_eq!(
            std::fs::metadata(root.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(sink.run_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for name in ["run.log", "events.jsonl", "run-meta.json", "fixture.json"] {
            assert_eq!(
                std::fs::metadata(sink.run_dir().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "{name}"
            );
        }
    }

    #[test]
    fn run_log_sink_writes_run_and_task_logs() {
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), true).unwrap();
        let rec = LogRecord {
            ts_unix_ms: 1_234,
            task_id: "demo".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Meta,
            line: "hello".to_string(),
        };

        sink.write_record(&rec).unwrap();
        sink.write_raw(&rec).unwrap();
        sink.write_event(
            "task_registered",
            Some("demo"),
            serde_json::json!({"label": "Demo"}),
        )
        .unwrap();

        let run_dir = sink.run_dir().to_path_buf();
        drop(sink);

        let run_log = std::fs::metadata(run_dir.join("run.log")).unwrap();
        let task_log = std::fs::metadata(run_dir.join("task-demo.log")).unwrap();
        let raw_log = std::fs::metadata(run_dir.join("task-demo.raw.log")).unwrap();
        let events = std::fs::read_to_string(run_dir.join("events.jsonl")).unwrap();

        assert!(run_log.len() > 0);
        assert!(task_log.len() > 0);
        assert!(raw_log.len() > 0);
        let records = events
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(records[0]["kind"], "run_started");
        assert_eq!(records[1]["kind"], "task_registered");
        assert_eq!(records[1]["task_id"], "demo");
        assert_eq!(records[0]["sequence"], 1);
        assert_eq!(records[1]["sequence"], 2);
    }

    #[test]
    fn run_started_records_build_identity_before_any_task() {
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), false).unwrap();
        let journal = std::fs::read_to_string(sink.run_dir().join("events.jsonl")).unwrap();
        let records: Vec<serde_json::Value> = journal
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["kind"], "run_started");
        assert_eq!(
            records[0]["payload"]["build_info"],
            serde_json::to_value(sink.build_info()).unwrap()
        );
        assert_eq!(sink.build_info().product.as_str(), "update-all");
        assert_eq!(sink.build_info().version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn authoritative_journal_failure_is_sticky() {
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), true).unwrap();
        sink.inject_journal_fault_for_test();

        assert!(sink
            .write_event("task_registered", Some("demo"), serde_json::json!({}))
            .is_err());
        assert!(sink.journal_failure().is_some());
    }

    #[test]
    fn human_logs_use_minimal_prompt_and_system_badges() {
        let prompt = LogRecord {
            ts_unix_ms: 1_234,
            task_id: "yay".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "==> Packages to exclude:".to_string(),
        };
        let system = LogRecord {
            ts_unix_ms: 1_235,
            task_id: "runtime".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Meta,
            line: "sudo session keepalive started".to_string(),
        };
        let plain = LogRecord {
            ts_unix_ms: 1_236,
            task_id: "yay".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stderr,
            line: "==> ERROR: One or more files did not pass the validity check!".to_string(),
        };

        let run_prompt = render_human_record(&prompt, true, true);
        let task_prompt = render_human_record(&prompt, true, false);
        let run_system = render_human_record(&system, true, true);
        let run_plain = render_human_record(&plain, true, true);

        assert!(run_prompt.starts_with("00:00:01Z "));
        assert!(run_prompt.contains("yay [PROMPT] ==> Packages to exclude:"));
        assert!(task_prompt.contains("[PROMPT] ==> Packages to exclude:"));
        assert!(!run_prompt.contains("[INFO]"));
        assert!(!run_prompt.contains("[OUT]"));

        assert!(run_system.contains("runtime [SYSTEM] sudo session keepalive started"));
        assert!(!run_system.contains("[META]"));

        assert!(
            run_plain.contains("yay ==> ERROR: One or more files did not pass the validity check!")
        );
        assert!(!run_plain.contains("[STDERR]"));
        assert!(!run_plain.contains("[INFO]"));
    }

    #[test]
    fn persistence_failure_latches_without_producer_terminal_output() {
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), false).unwrap();
        std::fs::create_dir(sink.run_dir().join("fixture.json")).unwrap();
        assert!(sink.write_json_file("fixture.json", &true).is_err());
        let first = sink.journal_failure().unwrap();
        sink.emit_write_warning_once(&anyhow::anyhow!("second failure"));
        assert_eq!(sink.journal_failure().unwrap(), first);
    }

    #[test]
    fn restart_eligibility_requires_clean_completed_task_evidence() {
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), false).unwrap();
        assert!(!sink.restart_eligible().unwrap(), "missing snapshot");

        let clean = serde_json::json!({
            "status": "completed",
            "exit_code": 0,
            "failed_task_count": 0,
            "canceled_task_count": 0,
            "issue_count": 0,
            "tasks": [{"status": "completed"}],
        });
        sink.write_json_file("run.json", &clean).unwrap();
        assert!(sink.restart_eligible().unwrap());

        for tasks in [
            serde_json::json!([]),
            serde_json::json!([{"status": "skipped"}]),
        ] {
            let mut snapshot = clean.clone();
            snapshot["tasks"] = tasks;
            sink.write_json_file("run.json", &snapshot).unwrap();
            assert!(!sink.restart_eligible().unwrap(), "{snapshot}");
        }
        // Cancel-one can retain a zero invocation exit alongside a completed
        // sibling. Explicit task evidence must still suppress the restart.
        for (counter, task_status) in [
            ("canceled_task_count", "canceled"),
            ("failed_task_count", "failed"),
            ("issue_count", "completed"),
        ] {
            let mut snapshot = clean.clone();
            snapshot[counter] = 1.into();
            snapshot["tasks"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({"status": task_status}));
            sink.write_json_file("run.json", &snapshot).unwrap();
            assert!(!sink.restart_eligible().unwrap(), "{counter}: {snapshot}");
        }
    }
}
