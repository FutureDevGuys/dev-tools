use crate::ui::{is_report_meta_line, LogLevel, LogRecord, LogStream, RUN_LOG_SCOPE};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub struct RunLogSink {
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
    #[cfg(test)]
    journal_fault_injected: AtomicBool,
    task_files: Mutex<BTreeMap<String, LogFileHandle>>,
    raw_task_files: Mutex<BTreeMap<String, LogFileHandle>>,
    write_warning_targets: Mutex<BTreeSet<String>>,
}

struct LogFileHandle {
    file: File,
    path: PathBuf,
}

impl RunLogSink {
    pub fn new(root_dir: &Path, timestamps: bool) -> Result<Self> {
        let started_unix_ms = unix_ms_now()?;
        let run_dir = make_run_dir(root_dir)?;
        fs::create_dir_all(&run_dir)
            .with_context(|| format!("create run log directory {}", run_dir.display()))?;
        let run_file_path = run_dir.join("run.log");
        let run_file = open_append(&run_file_path)?;
        let event_file_path = run_dir.join("events.jsonl");
        let event_file = open_append(&event_file_path)?;
        let run_id = Uuid::new_v4().to_string();
        let sink = Self {
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
            #[cfg(test)]
            journal_fault_injected: AtomicBool::new(false),
            task_files: Mutex::new(BTreeMap::new()),
            raw_task_files: Mutex::new(BTreeMap::new()),
            write_warning_targets: Mutex::new(BTreeSet::new()),
        };
        sink.write_metadata("running", None, None, None, Vec::new(), started_unix_ms)?;
        sink.write_event(
            "run_started",
            None,
            serde_json::json!({"run_id": sink.run_id.clone(), "display_name": sink.display_name()}),
        )?;
        Ok(sink)
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
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
        crate::runs::write_metadata_atomic(&self.run_dir, &metadata)
    }

    pub fn write_record(&self, rec: &LogRecord) -> Result<()> {
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
        let result = self.write_event_inner(kind, task_id, payload);
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
        let json = serde_json::to_vec_pretty(value)
            .with_context(|| format!("serialize {}", path.display()))?;
        fs::write(&path, json).with_context(|| format!("write {}", path.display()))
    }

    pub fn emit_write_warning_once(&self, err: &anyhow::Error) {
        let target = write_warning_target(err);
        if self.mark_write_warning_target(&target) {
            crate::ua_errln!(
                "update-all: log/artifact write failed for {target}; continuing without full diagnostics: {err:#}"
            );
        }
    }

    fn mark_write_warning_target(&self, target: &str) -> bool {
        match self.write_warning_targets.lock() {
            Ok(mut targets) => targets.insert(target.to_string()),
            Err(_) => true,
        }
    }

    #[cfg(test)]
    fn mark_write_warning_target_for_test(&self, target: &str) -> bool {
        self.mark_write_warning_target(target)
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

fn make_run_dir(root: &Path) -> Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs();
    let pid = std::process::id();
    Ok(root.join(format!("run-{now}-{pid}")))
}

fn open_append(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

fn write_warning_target(err: &anyhow::Error) -> String {
    for cause in err.chain() {
        let message = cause.to_string();
        for prefix in ["write ", "flush ", "open ", "serialize "] {
            if let Some(target) = message.strip_prefix(prefix) {
                let target = target.trim();
                if !target.is_empty() {
                    return target.to_string();
                }
            }
        }
    }
    "unknown sink".to_string()
}

#[cfg(test)]
mod tests {
    use super::{render_human_record, RunLogSink};
    use crate::ui::{LogLevel, LogRecord, LogStream};
    use tempfile::TempDir;

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
    fn write_warning_dedupes_by_failure_target() {
        let root = TempDir::new().unwrap();
        let sink = RunLogSink::new(root.path(), false).unwrap();

        assert!(sink.mark_write_warning_target_for_test("/tmp/run.log"));
        assert!(!sink.mark_write_warning_target_for_test("/tmp/run.log"));
        assert!(sink.mark_write_warning_target_for_test("/tmp/task-a.log"));

        let err = anyhow::anyhow!("permission denied").context("write /tmp/run.log");
        assert_eq!(super::write_warning_target(&err), "/tmp/run.log");
    }
}
