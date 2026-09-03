//! Bounded, owner-only diagnostic run artifacts.
//!
//! Structured events deliberately expose only fixed, value-free fields. Console
//! transcripts are a separate, explicit channel because they can contain any
//! text that the command showed to its operator.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::Builder;
use uuid::Uuid;

pub const EVENT_LIMIT_BYTES: u64 = 8 * 1024 * 1024;
pub const TRANSCRIPT_LIMIT_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_AGE_DAYS: u64 = 30;
pub const DEFAULT_MAX_RUNS: usize = 100;
pub const DEFAULT_MAX_BYTES: u64 = 128 * 1024 * 1024;

const METADATA_SCHEMA_VERSION: u64 = 1;
const PRODUCT: &str = "sync-configs";
const TRANSCRIPT_TRUNCATION_MARKER: &[u8] = b"\n[transcript truncated at configured byte limit]\n";

#[derive(Debug)]
pub struct LogError {
    message: String,
    source: Option<io::Error>,
}

impl LogError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    fn io(message: impl Into<String>, source: io::Error) -> Self {
        Self {
            message: message.into(),
            source: Some(source),
        }
    }

    pub fn from_io(message: impl Into<String>, source: io::Error) -> Self {
        Self::io(message, source)
    }
}

impl fmt::Display for LogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for LogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum LogStyle {
    Off,
    #[default]
    Events,
    Transcript,
    Both,
}

impl LogStyle {
    fn records_events(self) -> bool {
        matches!(self, Self::Events | Self::Both)
    }

    fn records_transcript(self) -> bool {
        matches!(self, Self::Transcript | Self::Both)
    }
}

impl fmt::Display for LogStyle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Off => "off",
            Self::Events => "events",
            Self::Transcript => "transcript",
            Self::Both => "both",
        })
    }
}

impl FromStr for LogStyle {
    type Err = LogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "off" => Ok(Self::Off),
            "events" => Ok(Self::Events),
            "transcript" => Ok(Self::Transcript),
            "both" => Ok(Self::Both),
            _ => Err(LogError::invalid("unsupported log style")),
        }
    }
}

#[derive(
    Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for LogLevel {
    type Err = LogError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "critical" => Ok(Self::Critical),
            _ => Err(LogError::invalid("unsupported log level")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Platform {
    Unix,
    Windows,
}

impl Platform {
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else {
            Self::Unix
        }
    }
}

/// Resolve the diagnostic root from the CLI, process environment, then the
/// platform state-directory convention.
pub fn resolve_log_root(explicit: Option<&Path>) -> Result<PathBuf, LogError> {
    resolve_log_root_with(explicit, Platform::current(), |name| env::var_os(name))
}

/// Injectable form of [`resolve_log_root`] used to prove both platform paths
/// without mutating the test process environment.
pub fn resolve_log_root_with<F>(
    explicit: Option<&Path>,
    platform: Platform,
    mut variable: F,
) -> Result<PathBuf, LogError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    if let Some(path) = explicit {
        return absolute_override(path, platform, &mut variable);
    }
    if let Some(path) = variable("SYNC_CONFIGS_LOG_ROOT") {
        return absolute_override(Path::new(&path), platform, &mut variable);
    }

    let base = match platform {
        Platform::Unix => match variable("XDG_STATE_HOME") {
            Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
            _ => home_dir(platform, &mut variable)?.join(".local/state"),
        },
        Platform::Windows => match variable("LOCALAPPDATA") {
            Some(value) if Path::new(&value).is_absolute() => PathBuf::from(value),
            _ => home_dir(platform, &mut variable)?.join("AppData/Local"),
        },
    };
    Ok(base.join("sync-configs/runs"))
}

fn absolute_override<F>(
    raw: &Path,
    platform: Platform,
    variable: &mut F,
) -> Result<PathBuf, LogError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let expanded = expand_tilde(raw, platform, variable)?;
    if !expanded.is_absolute() {
        return Err(LogError::invalid("log root must be an absolute path"));
    }
    Ok(normalize_absolute(&expanded))
}

fn home_dir<F>(platform: Platform, variable: &mut F) -> Result<PathBuf, LogError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let candidate = match platform {
        Platform::Unix => variable("HOME").map(PathBuf::from),
        Platform::Windows => variable("USERPROFILE").map(PathBuf::from).or_else(|| {
            let drive = variable("HOMEDRIVE")?;
            let path = variable("HOMEPATH")?;
            let mut combined = drive;
            combined.push(path);
            Some(PathBuf::from(combined))
        }),
    }
    .ok_or_else(|| LogError::invalid("cannot resolve the current user's state directory"))?;
    if !candidate.is_absolute() {
        return Err(LogError::invalid(
            "current user's home directory must be absolute",
        ));
    }
    Ok(normalize_absolute(&candidate))
}

fn expand_tilde<F>(path: &Path, platform: Platform, variable: &mut F) -> Result<PathBuf, LogError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let mut components = path.components();
    if components.next() != Some(Component::Normal(OsStr::new("~"))) {
        return Ok(path.to_owned());
    }
    let mut expanded = home_dir(platform, variable)?;
    expanded.extend(components);
    Ok(expanded)
}

fn normalize_absolute(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogLimits {
    pub event_bytes: u64,
    pub transcript_bytes: u64,
}

impl Default for LogLimits {
    fn default() -> Self {
        Self {
            event_bytes: EVENT_LIMIT_BYTES,
            transcript_bytes: TRANSCRIPT_LIMIT_BYTES,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RecorderOptions {
    pub root: PathBuf,
    pub style: LogStyle,
    pub level: LogLevel,
    pub dry_run: bool,
    pub parent_run_id: Option<String>,
    pub limits: LogLimits,
}

impl RecorderOptions {
    pub fn process(
        root: impl Into<PathBuf>,
        style: LogStyle,
        level: LogLevel,
        dry_run: bool,
    ) -> Self {
        Self {
            root: root.into(),
            style,
            level,
            dry_run,
            parent_run_id: env::var("SYNC_CONFIGS_PARENT_RUN_ID").ok(),
            limits: LogLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Completed,
    Failed,
    Interrupted,
}

impl RunStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Interrupted)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RunMetadata {
    pub schema_version: u64,
    pub run_id: String,
    pub product: String,
    pub status: RunStatus,
    pub started_at: String,
    pub dry_run: bool,
    pub log_style: LogStyle,
    pub log_level: LogLevel,
    pub events_truncated: bool,
    pub transcript_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub summary: BTreeMap<String, u64>,
}

struct ActiveRecorder {
    root: PathBuf,
    run_dir: PathBuf,
    metadata: RunMetadata,
    events: Option<File>,
    transcript: Option<File>,
    event_bytes: u64,
    transcript_bytes: u64,
    limits: LogLimits,
    warned: bool,
    disabled: bool,
}

pub struct RunRecorder {
    active: Option<ActiveRecorder>,
}

impl RunRecorder {
    pub fn start(options: RecorderOptions) -> Result<Self, LogError> {
        if !options.root.is_absolute() {
            return Err(LogError::invalid("log root must be an absolute path"));
        }
        if options.style == LogStyle::Off {
            return Ok(Self { active: None });
        }
        create_owner_only_directory(&options.root)?;
        let started = SystemTime::now();
        let (run_id, run_dir) = create_run_directory(&options.root, started)?;
        let cleanup_path = run_dir.clone();
        let result = Self::start_in_created_directory(options, run_id, run_dir, started);
        if result.is_err() {
            // This directory was just created under an owner-only root and has
            // not been exposed as a successful run, so cleanup is bounded.
            let _ = fs::remove_dir_all(cleanup_path);
        }
        result
    }

    fn start_in_created_directory(
        options: RecorderOptions,
        run_id: String,
        run_dir: PathBuf,
        started: SystemTime,
    ) -> Result<Self, LogError> {
        let parent_run_id = options
            .parent_run_id
            .filter(|candidate| is_valid_run_id(candidate));
        let events = if options.style.records_events() {
            Some(create_owner_only_file(&run_dir.join("events.jsonl"))?)
        } else {
            None
        };
        let transcript = if options.style.records_transcript() {
            Some(create_owner_only_file(&run_dir.join("console.log"))?)
        } else {
            None
        };
        let metadata = RunMetadata {
            schema_version: METADATA_SCHEMA_VERSION,
            run_id,
            product: PRODUCT.to_owned(),
            status: RunStatus::Running,
            started_at: format_timestamp(started),
            dry_run: options.dry_run,
            log_style: options.style,
            log_level: options.level,
            events_truncated: false,
            transcript_truncated: false,
            ended_at: None,
            exit_code: None,
            parent_run_id,
            summary: BTreeMap::new(),
        };
        atomic_write_json(&run_dir.join("run.json"), &metadata)?;
        let mut recorder = Self {
            active: Some(ActiveRecorder {
                root: options.root,
                run_dir,
                metadata,
                events,
                transcript,
                event_bytes: 0,
                transcript_bytes: 0,
                limits: options.limits,
                warned: false,
                disabled: false,
            }),
        };
        recorder.fixed_event(LogLevel::Info, "run_started", |payload| {
            payload.insert("dry_run".to_owned(), json!(options.dry_run));
        });
        Ok(recorder)
    }

    /// Start logging without allowing a diagnostic failure to change the
    /// convergence outcome.
    pub fn start_safely(options: RecorderOptions) -> Self {
        match Self::start(options) {
            Ok(recorder) => recorder,
            Err(_) => {
                eprintln!("warning: sync-configs logging unavailable: io error");
                Self { active: None }
            }
        }
    }

    pub fn enabled(&self) -> bool {
        self.active.as_ref().is_some_and(|active| !active.disabled)
    }

    pub fn run_id(&self) -> Option<&str> {
        self.active
            .as_ref()
            .map(|active| active.metadata.run_id.as_str())
    }

    pub fn run_dir(&self) -> Option<&Path> {
        self.active.as_ref().map(|active| active.run_dir.as_path())
    }

    /// Record an entry outcome without persisting the entry labels. Unknown
    /// statuses and phases collapse to fixed sentinel values.
    pub fn record_entry_status(
        &mut self,
        scope_label: &str,
        entry_name: &str,
        status: &str,
        phase: Option<&str>,
    ) {
        let status = sanitized_status(status);
        let level = level_for_status(status);
        let entry_id = entry_id(scope_label, entry_name);
        let phase = sanitized_phase(phase);
        self.fixed_event(level, "entry_status", move |payload| {
            payload.insert("status".to_owned(), json!(status));
            payload.insert("entry_id".to_owned(), json!(entry_id));
            if let Some(phase) = phase {
                payload.insert("phase".to_owned(), json!(phase));
            }
        });
    }

    /// Record only recognized counter names so caller-controlled labels cannot
    /// turn structured diagnostics into a secret-bearing channel.
    pub fn record_summary(&mut self, counts: BTreeMap<String, u64>, total: u64) {
        let mut sanitized = BTreeMap::new();
        for (key, value) in counts {
            if is_known_status(&key) && value != 0 {
                sanitized.insert(key, value);
            }
        }
        sanitized.insert("total".to_owned(), total);
        if let Some(active) = self.active.as_mut() {
            active.metadata.summary = sanitized.clone();
        }
        self.fixed_event(LogLevel::Info, "run_summary", move |payload| {
            payload.insert("counts".to_owned(), json!(sanitized));
        });
    }

    /// Append console bytes to the explicit transcript. Invalid UTF-8 is
    /// replaced, and truncation always stops at a valid UTF-8 boundary.
    pub fn record_transcript(&mut self, value: &[u8]) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.disabled || !active.metadata.log_style.records_transcript() {
            return;
        }
        if active.metadata.transcript_truncated {
            return;
        }
        let normalized = String::from_utf8_lossy(value);
        let remaining = active
            .limits
            .transcript_bytes
            .saturating_sub(active.transcript_bytes);
        let normalized_bytes = normalized.as_bytes();
        let result = if normalized_bytes.len() as u64 <= remaining {
            write_transcript_bytes(active, normalized_bytes)
        } else {
            let marker_len = (TRANSCRIPT_TRUNCATION_MARKER.len() as u64).min(remaining);
            let content_limit = remaining.saturating_sub(marker_len) as usize;
            let content_end = utf8_prefix_len(&normalized, content_limit);
            write_transcript_bytes(active, &normalized_bytes[..content_end]).and_then(|()| {
                let marker_remaining = active
                    .limits
                    .transcript_bytes
                    .saturating_sub(active.transcript_bytes)
                    as usize;
                write_transcript_bytes(
                    active,
                    &TRANSCRIPT_TRUNCATION_MARKER
                        [..marker_remaining.min(TRANSCRIPT_TRUNCATION_MARKER.len())],
                )
            })
        };
        if let Err(error) = result {
            warn_and_disable(active, &error);
            return;
        }
        if normalized_bytes.len() as u64 > remaining {
            active.metadata.transcript_truncated = true;
        }
    }

    /// Write to the caller's console and, independently, to the optional
    /// transcript. A logging failure never changes the console result.
    pub fn write_console<W: Write>(&mut self, console: &mut W, value: &[u8]) -> io::Result<()> {
        console.write_all(value)?;
        self.record_transcript(value);
        Ok(())
    }

    pub fn finish(&mut self, exit_code: i32, interrupted: bool) {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.disabled || active.metadata.status.is_terminal() {
            return;
        }
        let status = if interrupted {
            RunStatus::Interrupted
        } else if exit_code == 0 {
            RunStatus::Completed
        } else {
            RunStatus::Failed
        };
        let level = if exit_code == 0 {
            LogLevel::Info
        } else {
            LogLevel::Error
        };
        self.fixed_event(level, "run_finished", |payload| {
            payload.insert("status".to_owned(), json!(status));
            payload.insert("exit_code".to_owned(), json!(exit_code));
        });

        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.disabled {
            return;
        }
        active.metadata.status = status;
        active.metadata.exit_code = Some(exit_code);
        active.metadata.ended_at = Some(format_timestamp(SystemTime::now()));
        if let Err(error) = atomic_write_json(&active.run_dir.join("run.json"), &active.metadata) {
            warn_and_disable(active, &error);
            return;
        }
        let flush_error = active
            .events
            .as_mut()
            .and_then(|events| events.flush().err())
            .or_else(|| {
                active
                    .transcript
                    .as_mut()
                    .and_then(|transcript| transcript.flush().err())
            });
        if let Some(error) = flush_error {
            warn_and_disable(
                active,
                &LogError::io("cannot flush diagnostic output", error),
            );
            return;
        }
        if let Err(error) = prune_runs(&active.root, RetentionPolicy::default(), false) {
            warn_and_disable(active, &error);
        }
    }

    fn fixed_event<F>(&mut self, level: LogLevel, kind: &'static str, fields: F)
    where
        F: FnOnce(&mut serde_json::Map<String, Value>),
    {
        let Some(active) = self.active.as_mut() else {
            return;
        };
        if active.disabled
            || !active.metadata.log_style.records_events()
            || level < active.metadata.log_level
            || active.metadata.events_truncated
        {
            return;
        }
        let mut payload = serde_json::Map::new();
        payload.insert("schema_version".to_owned(), json!(METADATA_SCHEMA_VERSION));
        payload.insert(
            "timestamp".to_owned(),
            json!(format_timestamp(SystemTime::now())),
        );
        payload.insert("level".to_owned(), json!(level));
        payload.insert("kind".to_owned(), json!(kind));
        fields(&mut payload);
        let mut encoded = match serde_json::to_vec(&payload) {
            Ok(encoded) => encoded,
            Err(_) => {
                warn_and_disable(active, &LogError::invalid("cannot serialize run event"));
                return;
            }
        };
        encoded.push(b'\n');
        if active.event_bytes.saturating_add(encoded.len() as u64) > active.limits.event_bytes {
            active.metadata.events_truncated = true;
            return;
        }
        let result = active
            .events
            .as_mut()
            .ok_or_else(|| LogError::invalid("event file is unavailable"))
            .and_then(|events| {
                events
                    .write_all(&encoded)
                    .map_err(|error| LogError::io("cannot write diagnostic event", error))
            });
        match result {
            Ok(()) => active.event_bytes += encoded.len() as u64,
            Err(error) => warn_and_disable(active, &error),
        }
    }
}

fn write_transcript_bytes(active: &mut ActiveRecorder, value: &[u8]) -> Result<(), LogError> {
    let transcript = active
        .transcript
        .as_mut()
        .ok_or_else(|| LogError::invalid("transcript file is unavailable"))?;
    transcript
        .write_all(value)
        .map_err(|error| LogError::io("cannot write diagnostic transcript", error))?;
    active.transcript_bytes = active.transcript_bytes.saturating_add(value.len() as u64);
    Ok(())
}

fn utf8_prefix_len(value: &str, maximum: usize) -> usize {
    let mut end = maximum.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn warn_and_disable(active: &mut ActiveRecorder, _error: &LogError) {
    active.disabled = true;
    if !active.warned {
        eprintln!("warning: sync-configs logging unavailable: io error");
        active.warned = true;
    }
}

fn sanitized_status(status: &str) -> &'static str {
    match status {
        "performed" => "performed",
        "up_to_date" => "up_to_date",
        "skipped_existing" => "skipped_existing",
        "missing_source" => "missing_source",
        "script_skipped" => "script_skipped",
        "deferred" => "deferred",
        "input_required" => "input_required",
        "errors" => "errors",
        "script_error" => "script_error",
        "suppressed_comment" => "suppressed_comment",
        "info" => "info",
        _ => "unknown",
    }
}

fn is_known_status(status: &str) -> bool {
    sanitized_status(status) != "unknown"
}

fn level_for_status(status: &str) -> LogLevel {
    match status {
        "errors" | "script_error" => LogLevel::Error,
        "skipped_existing" | "missing_source" | "script_skipped" | "deferred"
        | "input_required" | "unknown" => LogLevel::Warning,
        _ => LogLevel::Info,
    }
}

fn sanitized_phase(phase: Option<&str>) -> Option<&'static str> {
    match phase {
        Some("pre_script") => Some("pre_script"),
        Some("post_script") => Some("post_script"),
        _ => None,
    }
}

fn entry_id(scope_label: &str, entry_name: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(scope_label.as_bytes());
    hasher.update([0]);
    hasher.update(entry_name.as_bytes());
    let digest = hasher.finalize();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn create_owner_only_directory(path: &Path) -> Result<(), LogError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(LogError::invalid("log root is not a real directory"));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|error| LogError::io("cannot create diagnostic root", error))?;
        }
        Err(error) => return Err(LogError::io("cannot inspect diagnostic root", error)),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| LogError::io("cannot inspect diagnostic root", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LogError::invalid("log root is not a real directory"));
    }
    set_owner_only_directory(path)
}

fn create_run_directory(root: &Path, started: SystemTime) -> Result<(String, PathBuf), LogError> {
    for _ in 0..8 {
        let uuid = Uuid::new_v4().simple().to_string();
        let run_id = format!(
            "run-{}-{}-{}",
            compact_timestamp(started),
            std::process::id(),
            &uuid[..8]
        );
        let run_dir = root.join(&run_id);
        match fs::create_dir(&run_dir) {
            Ok(()) => {
                set_owner_only_directory(&run_dir)?;
                return Ok((run_id, run_dir));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(LogError::io(
                    "cannot create diagnostic run directory",
                    error,
                ));
            }
        }
    }
    Err(LogError::invalid(
        "cannot allocate a unique diagnostic run identifier",
    ))
}

fn create_owner_only_file(path: &Path) -> Result<File, LogError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|error| LogError::io("cannot create diagnostic file", error))?;
    set_owner_only_file(path)?;
    Ok(file)
}

#[cfg(unix)]
fn set_owner_only_directory(path: &Path) -> Result<(), LogError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|error| LogError::io("cannot restrict diagnostic directory", error))
}

#[cfg(not(unix))]
fn set_owner_only_directory(_path: &Path) -> Result<(), LogError> {
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<(), LogError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| LogError::io("cannot restrict diagnostic file", error))
}

#[cfg(not(unix))]
fn set_owner_only_file(_path: &Path) -> Result<(), LogError> {
    Ok(())
}

fn atomic_write_json(path: &Path, payload: &RunMetadata) -> Result<(), LogError> {
    let parent = path
        .parent()
        .ok_or_else(|| LogError::invalid("diagnostic metadata has no parent"))?;
    let mut temporary = Builder::new()
        .prefix(".run.json.")
        .tempfile_in(parent)
        .map_err(|error| LogError::io("cannot stage diagnostic metadata", error))?;
    set_owner_only_file(temporary.path())?;
    serde_json::to_writer(&mut temporary, payload).map_err(|error| {
        LogError::invalid(format!("cannot serialize diagnostic metadata: {error}"))
    })?;
    temporary
        .write_all(b"\n")
        .map_err(|error| LogError::io("cannot write diagnostic metadata", error))?;
    temporary
        .as_file_mut()
        .sync_all()
        .map_err(|error| LogError::io("cannot sync diagnostic metadata", error))?;
    temporary
        .persist(path)
        .map_err(|error| LogError::io("cannot publish diagnostic metadata", error.error))?;
    Ok(())
}

fn root_is_real_directory(root: &Path) -> Result<bool, LogError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(LogError::invalid("log root is not a real directory"))
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(LogError::io("cannot inspect diagnostic root", error)),
    }
}

fn safe_run_dir(root: &Path, run_id: &str) -> Result<PathBuf, LogError> {
    if !is_valid_run_id(run_id) {
        return Err(LogError::invalid("invalid run identifier"));
    }
    let path = root.join(run_id);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => Ok(path),
        Ok(_) | Err(_) => Err(LogError::invalid(format!("run not found: {run_id}"))),
    }
}

fn is_valid_run_id(run_id: &str) -> bool {
    let Some(value) = run_id.strip_prefix("run-") else {
        return false;
    };
    let mut parts = value.split('-');
    let Some(timestamp) = parts.next() else {
        return false;
    };
    let Some(pid) = parts.next() else {
        return false;
    };
    let Some(suffix) = parts.next() else {
        return false;
    };
    if parts.next().is_some() || timestamp.len() != 23 {
        return false;
    }
    let bytes = timestamp.as_bytes();
    let timestamp_shape = bytes.get(8) == Some(&b'T')
        && bytes.get(15) == Some(&b'.')
        && bytes.get(22) == Some(&b'Z')
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 8 | 15 | 22) || byte.is_ascii_digit());
    timestamp_shape
        && !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && suffix.len() == 8
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_metadata(path: &Path, expected_run_id: &str) -> Result<(RunMetadata, Vec<u8>), LogError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| LogError::invalid(format!("missing run metadata: {expected_run_id}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LogError::invalid(format!(
            "missing run metadata: {expected_run_id}"
        )));
    }
    if metadata.len() > EVENT_LIMIT_BYTES {
        return Err(LogError::invalid(format!(
            "run metadata is too large: {expected_run_id}"
        )));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|_| LogError::invalid(format!("invalid run metadata: {expected_run_id}")))?;
    let opened = file
        .metadata()
        .map_err(|_| LogError::invalid(format!("invalid run metadata: {expected_run_id}")))?;
    if !opened.is_file() || opened.len() > EVENT_LIMIT_BYTES {
        return Err(LogError::invalid(format!(
            "invalid run metadata: {expected_run_id}"
        )));
    }
    let mut encoded = Vec::with_capacity(opened.len() as usize);
    file.take(EVENT_LIMIT_BYTES + 1)
        .read_to_end(&mut encoded)
        .map_err(|_| LogError::invalid(format!("invalid run metadata: {expected_run_id}")))?;
    if encoded.len() as u64 > EVENT_LIMIT_BYTES {
        return Err(LogError::invalid(format!(
            "run metadata is too large: {expected_run_id}"
        )));
    }
    let parsed: RunMetadata = serde_json::from_slice(&encoded)
        .map_err(|_| LogError::invalid(format!("invalid run metadata: {expected_run_id}")))?;
    if parsed.schema_version != METADATA_SCHEMA_VERSION
        || parsed.product != PRODUCT
        || parsed.run_id != expected_run_id
        || !is_valid_run_id(&parsed.run_id)
        || parse_timestamp(&parsed.started_at).is_none()
        || parsed
            .parent_run_id
            .as_deref()
            .is_some_and(|parent| !is_valid_run_id(parent))
        || match parsed.status {
            RunStatus::Running => parsed.ended_at.is_some() || parsed.exit_code.is_some(),
            RunStatus::Completed | RunStatus::Failed | RunStatus::Interrupted => {
                parsed.exit_code.is_none()
                    || parsed
                        .ended_at
                        .as_deref()
                        .and_then(parse_timestamp)
                        .is_none()
            }
        }
    {
        return Err(LogError::invalid(format!(
            "invalid run metadata: {expected_run_id}"
        )));
    }
    Ok((parsed, encoded))
}

pub fn list_runs(root: &Path) -> Result<Vec<RunMetadata>, LogError> {
    if !root_is_real_directory(root)? {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    let entries =
        fs::read_dir(root).map_err(|error| LogError::io("cannot read diagnostic root", error))?;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let run_id = entry.file_name().to_string_lossy().into_owned();
        if !is_valid_run_id(&run_id) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        if let Ok((metadata, _)) = read_metadata(&entry.path().join("run.json"), &run_id) {
            results.push(metadata);
        }
    }
    results.sort_by(|left, right| {
        right
            .started_at
            .cmp(&left.started_at)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    Ok(results)
}

pub fn show_run(root: &Path, run_id: &str) -> Result<RunMetadata, LogError> {
    if !root_is_real_directory(root)? {
        return Err(LogError::invalid(format!("run not found: {run_id}")));
    }
    let run_dir = safe_run_dir(root, run_id)?;
    read_metadata(&run_dir.join("run.json"), run_id).map(|(metadata, _)| metadata)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetentionPolicy {
    pub max_age_days: u64,
    pub max_runs: usize,
    pub max_bytes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age_days: DEFAULT_MAX_AGE_DAYS,
            max_runs: DEFAULT_MAX_RUNS,
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PruneReport {
    pub dry_run: bool,
    pub reclaimed_bytes: u64,
    pub removed: Vec<String>,
    pub retained: Vec<String>,
}

struct CompletedRun {
    started_at: SystemTime,
    path: PathBuf,
    run_id: String,
    size: u64,
    metadata_digest: [u8; 32],
}

pub fn prune_runs(
    root: &Path,
    policy: RetentionPolicy,
    dry_run: bool,
) -> Result<PruneReport, LogError> {
    prune_runs_at(root, policy, SystemTime::now(), dry_run)
}

pub fn prune_runs_at(
    root: &Path,
    policy: RetentionPolicy,
    now: SystemTime,
    dry_run: bool,
) -> Result<PruneReport, LogError> {
    if !root_is_real_directory(root)? {
        return Ok(PruneReport {
            dry_run,
            reclaimed_bytes: 0,
            removed: Vec::new(),
            retained: Vec::new(),
        });
    }
    let mut completed = Vec::new();
    let mut retained_other = Vec::new();
    let entries =
        fs::read_dir(root).map_err(|error| LogError::io("cannot read diagnostic root", error))?;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let run_id = entry.file_name().to_string_lossy().into_owned();
        if !is_valid_run_id(&run_id) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            retained_other.push(run_id);
            continue;
        };
        if file_type.is_symlink() || !file_type.is_dir() {
            retained_other.push(run_id);
            continue;
        }
        let path = entry.path();
        let Ok((metadata, encoded)) = read_metadata(&path.join("run.json"), &run_id) else {
            retained_other.push(run_id);
            continue;
        };
        if !metadata.status.is_terminal() {
            retained_other.push(run_id);
            continue;
        }
        let Some(started_at) = parse_timestamp(&metadata.started_at) else {
            retained_other.push(run_id);
            continue;
        };
        completed.push(CompletedRun {
            started_at,
            size: directory_size(&path),
            path,
            run_id,
            metadata_digest: Sha256::digest(&encoded).into(),
        });
    }
    completed.sort_by(|left, right| {
        left.started_at
            .cmp(&right.started_at)
            .then_with(|| left.run_id.cmp(&right.run_id))
    });

    let age_limit = Duration::from_secs(policy.max_age_days.saturating_mul(86_400));
    let mut remove = vec![false; completed.len()];
    for (index, run) in completed.iter().enumerate() {
        if now
            .duration_since(run.started_at)
            .is_ok_and(|age| age > age_limit)
        {
            remove[index] = true;
        }
    }
    let survivors: Vec<_> = remove
        .iter()
        .enumerate()
        .filter_map(|(index, removed)| (!*removed).then_some(index))
        .collect();
    let excess = survivors.len().saturating_sub(policy.max_runs);
    for index in survivors.into_iter().take(excess) {
        remove[index] = true;
    }
    let mut total_bytes: u64 = completed
        .iter()
        .enumerate()
        .filter(|(index, _)| !remove[*index])
        .map(|(_, run)| run.size)
        .sum();
    for (index, run) in completed.iter().enumerate() {
        if total_bytes <= policy.max_bytes {
            break;
        }
        if !remove[index] {
            remove[index] = true;
            total_bytes = total_bytes.saturating_sub(run.size);
        }
    }

    let mut removed = Vec::new();
    let mut reclaimed_bytes = 0_u64;
    for (index, run) in completed.iter().enumerate() {
        if !remove[index] {
            continue;
        }
        removed.push(run.run_id.clone());
        reclaimed_bytes = reclaimed_bytes.saturating_add(run.size);
        if !dry_run {
            remove_run_if_unchanged(run)?;
        }
    }
    let mut retained: Vec<String> = completed
        .iter()
        .enumerate()
        .filter(|(index, _)| !remove[*index])
        .map(|(_, run)| run.run_id.clone())
        .chain(retained_other)
        .collect();
    retained.sort();
    Ok(PruneReport {
        dry_run,
        reclaimed_bytes,
        removed,
        retained,
    })
}

fn remove_run_if_unchanged(run: &CompletedRun) -> Result<(), LogError> {
    let metadata = match fs::symlink_metadata(&run.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(LogError::io("cannot revalidate diagnostic run", error)),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LogError::invalid(
            "diagnostic run changed while retention was in progress",
        ));
    }
    let (current, encoded) = read_metadata(&run.path.join("run.json"), &run.run_id)?;
    let current_digest: [u8; 32] = Sha256::digest(&encoded).into();
    if !current.status.is_terminal() || current_digest != run.metadata_digest {
        return Err(LogError::invalid(
            "diagnostic run changed while retention was in progress",
        ));
    }
    fs::remove_dir_all(&run.path)
        .map_err(|error| LogError::io("cannot remove retained diagnostic run", error))
}

fn directory_size(path: &Path) -> u64 {
    let mut total = 0_u64;
    let mut pending = vec![path.to_owned()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    total
}

fn compact_timestamp(value: SystemTime) -> String {
    let (year, month, day, hour, minute, second, micros) = timestamp_parts(value);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}.{micros:06}Z")
}

fn format_timestamp(value: SystemTime) -> String {
    let (year, month, day, hour, minute, second, micros) = timestamp_parts(value);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{micros:06}Z")
}

fn timestamp_parts(value: SystemTime) -> (i64, u32, u32, u32, u32, u32, u32) {
    let duration = value.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let seconds = duration.as_secs();
    let days = (seconds / 86_400) as i64;
    let within_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    (
        year,
        month,
        day,
        (within_day / 3_600) as u32,
        ((within_day % 3_600) / 60) as u32,
        (within_day % 60) as u32,
        duration.subsec_micros(),
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let days = days_since_epoch + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}

fn parse_timestamp(value: &str) -> Option<SystemTime> {
    let value = value.strip_suffix('Z')?;
    let (date, time) = value.split_once('T')?;
    let mut date = date.split('-');
    let year: i64 = date.next()?.parse().ok()?;
    let month: u32 = date.next()?.parse().ok()?;
    let day: u32 = date.next()?.parse().ok()?;
    if date.next().is_some() || !(1..=12).contains(&month) {
        return None;
    }
    let (clock, fraction) = time.split_once('.').unwrap_or((time, "0"));
    let mut clock = clock.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let minute: u32 = clock.next()?.parse().ok()?;
    let second: u32 = clock.next()?.parse().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let maximum_day = days_in_month(year, month);
    if day == 0
        || day > maximum_day
        || fraction.is_empty()
        || fraction.len() > 9
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let mut nanos_text = fraction.to_owned();
    while nanos_text.len() < 9 {
        nanos_text.push('0');
    }
    let nanos: u32 = nanos_text[..9].parse().ok()?;
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return None;
    }
    let seconds = (days as u64)
        .checked_mul(86_400)?
        .checked_add(u64::from(hour) * 3_600)?
        .checked_add(u64::from(minute) * 60)?
        .checked_add(u64::from(second))?;
    UNIX_EPOCH.checked_add(Duration::new(seconds, nanos))
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_timestamp_round_trips() {
        let value = UNIX_EPOCH + Duration::new(1_788_220_800, 123_456_000);
        let rendered = format_timestamp(value);
        assert_eq!(rendered, "2026-09-01T00:00:00.123456Z");
        assert_eq!(parse_timestamp(&rendered), Some(value));
        assert_eq!(compact_timestamp(value), "20260901T000000.123456Z");
    }

    #[test]
    fn run_identifier_validation_is_exact() {
        assert!(is_valid_run_id("run-20260901T120000.000000Z-7-deadbeef"));
        assert!(!is_valid_run_id("../run.json"));
        assert!(!is_valid_run_id("run-20260901T120000.000000Z-7-DEADBEEF"));
        assert!(!is_valid_run_id(
            "run-20260901T120000.000000Z-nope-deadbeef"
        ));
    }
}
