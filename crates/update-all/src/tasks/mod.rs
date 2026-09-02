mod npm;
mod package_authority;
pub(crate) mod recovery;

use crate::completions::{completion_sync, resolve_completion_shells, CompletionSyncArgs};
use crate::completions::{CompletionSyncRecordStatus, CompletionSyncResult};
use crate::config::{
    InteractiveExecutionMode, InteractiveRuntimeConfig, NoteVerbosity, TaskPolicy,
    UpdaterCommandCandidateConfig, UpdaterConfig, UpdaterDetectionMode, UpdaterPreCommandConfig,
    UpdaterReportCommandConfig, UpdaterReportCommandWhen, UpdaterReportPatternConfig,
    UpdaterScopedDeltaConfig, UpdaterStateReportPatternConfig, UpdaterTaskConfig,
};
use crate::logging::{task_file_stem, RunLogSink};
use crate::sections::Sections;
use crate::ui::{
    looks_like_interactive_prompt, report_values_are_version_change, DashboardEvent,
    DashboardQuitBehavior, LogLevel, LogRecord, LogStream, LogViewTarget, MouseRowStride,
    TaskState, UiControlEvent, UiModeResolved, RUN_LOG_SCOPE,
};
use crate::updaters::{
    builtin_windows_foundations, command_candidate_is_available, command_program_path,
    detected_builtin_tasks, detected_builtin_tasks_with_skip_overrides, BuiltinCommandCandidate,
    BuiltinFoundationCommand, BuiltinManagedExecutor, BuiltinPreCommand, BuiltinReportCommand,
    BuiltinReportCommandWhen, BuiltinReportParser, BuiltinReportPattern, BuiltinScopedDelta,
    BuiltinStateReportPattern, BuiltinTask, BuiltinTaskKind, BuiltinWindowsFoundation, HostOs,
};
use crate::util::cancel;
use crate::util::lockfile::{try_acquire_pid_lock, PidLockOptions, ScopedFileLock};
use crate::util::privilege::{resolve_privilege_decision, PrivilegeDecision};
use crate::util::process::{
    capture_guard_reason, process_exit_output, run_capture_allow_exit_codes, run_capture_streaming,
    run_capture_streaming_allow_exit_codes, run_capture_streaming_controlled,
    run_capture_streaming_controlled_allow_exit_codes, run_capture_streaming_controlled_foreground,
    run_capture_streaming_controlled_stdin_pty_capture_guarded,
    run_capture_streaming_controlled_stdin_tty_capture,
    run_capture_streaming_controlled_stdin_tty_capture_guarded, run_capture_streaming_foreground,
    run_capture_streaming_stdin_tty_capture, run_capture_streaming_stdin_tty_capture_guarded,
    terminate_process, terminate_process_group, which, CaptureGuard, CaptureGuardReason,
    ProcessExitError, StreamKind,
};
use anyhow::{bail, Context, Result};
use is_terminal::IsTerminal;
use recovery::{
    classify_package_recovery, package_manager_kind_for_task, PackageManagerKind, RecoveryAction,
    RecoveryCause, RecoveryPlan,
};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use unicode_width::UnicodeWidthStr;

pub const TASK_NPM: &str = "builtin/npm";
pub const TASK_COMPLETIONS: &str = "builtin/completions";
const ORDER_ONLY_DEPENDENCY_PREFIX: &str = "\u{1f}after:";
const TASK_RUN_LOCK_STALE_AFTER: Duration = Duration::from_secs(12 * 60 * 60);
const FORCED_CANCEL_TIMEOUT_DETAIL: &str = "forced shutdown after cancel-all grace timeout";
const EXTERNAL_MANAGER_VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const NO_TASK_DETAIL: &str = "no detail";
const DIRECT_COMMAND_MODE: &str = "direct";
const UNCATEGORIZED_TASK_CATEGORY: &str = "uncategorized";
const UNCATEGORIZED_TASK_CATEGORY_DISPLAY: &str = "Uncategorized";
const TASK_CATEGORY_COLUMN_MAX_WIDTH: usize = 30;
const COMMAND_DIAGNOSTIC_SAMPLE_LIMIT: usize = 5;
const STRUCTURED_TEXT_LIMIT_BYTES: usize = 512;
const STRUCTURED_DETAIL_LIMIT: usize = 32;
const STRUCTURED_SECTION_LIMIT: usize = 64;
const STRUCTURED_ROW_LIMIT: usize = 1_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Completed,
    Failed,
    Canceled,
    Skipped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorySeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TaskAdvisory {
    pub severity: AdvisorySeverity,
    pub code: String,
    pub summary: String,
    pub remediation: String,
    pub blocks_dependents: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TaskResult {
    pub label: String,
    pub status: TaskStatus,
    pub details: Vec<String>,
    pub advisories: Vec<TaskAdvisory>,
    pub report_sections: Vec<TaskReportSection>,
}

impl TaskResult {
    pub fn completed(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: TaskStatus::Completed,
            details: Vec::new(),
            advisories: Vec::new(),
            report_sections: Vec::new(),
        }
    }

    pub fn failed(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: TaskStatus::Failed,
            details: vec![detail.into()],
            advisories: Vec::new(),
            report_sections: Vec::new(),
        }
    }

    pub fn canceled(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: TaskStatus::Canceled,
            details: vec![detail.into()],
            advisories: Vec::new(),
            report_sections: Vec::new(),
        }
    }

    pub fn skipped(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            status: TaskStatus::Skipped,
            details: vec![detail.into()],
            advisories: Vec::new(),
            report_sections: Vec::new(),
        }
    }

    pub fn completed_with_advisory(
        label: impl Into<String>,
        detail: impl Into<String>,
        advisory: TaskAdvisory,
    ) -> Self {
        Self {
            label: label.into(),
            status: TaskStatus::Completed,
            details: vec![detail.into()],
            advisories: vec![advisory],
            report_sections: Vec::new(),
        }
    }

    fn primary_detail(&self) -> String {
        self.details
            .iter()
            .find(|detail| !detail.trim().is_empty())
            .cloned()
            .or_else(|| match self.advisories.first() {
                Some(advisory) => Some(advisory.summary.clone()),
                None => None,
            })
            .or_else(|| {
                let report_summary = summarize_task_items(self);
                (report_summary != "-").then_some(report_summary)
            })
            .unwrap_or_else(|| NO_TASK_DETAIL.to_string())
    }

    fn has_issues(&self) -> bool {
        self.advisories
            .iter()
            .any(|advisory| advisory.severity != AdvisorySeverity::Info)
            || self.has_blocking_report_rows()
    }

    fn is_deferred(&self) -> bool {
        self.advisories
            .iter()
            .any(|advisory| advisory.code == "deferred")
    }

    fn has_blocking_report_rows(&self) -> bool {
        self.report_sections.iter().any(|section| {
            section.rows.iter().any(|row| {
                matches!(
                    row.status,
                    TaskReportStatus::Failed | TaskReportStatus::Blocked
                )
            })
        })
    }

    fn has_blocking_advisory(&self) -> bool {
        self.advisories.iter().any(|advisory| {
            advisory.severity != AdvisorySeverity::Info && advisory.blocks_dependents
        })
    }

    fn blocks_dependents(&self) -> bool {
        match self.status {
            TaskStatus::Completed => {
                self.has_blocking_report_rows() || self.has_blocking_advisory()
            }
            TaskStatus::Failed => true,
            TaskStatus::Canceled => true,
            TaskStatus::Skipped => false,
        }
    }
}

fn failed_task_error_result(
    label: impl Into<String>,
    task_id: impl Into<String>,
    detail: impl Into<String>,
) -> TaskResult {
    let detail = detail.into();
    let mut result = TaskResult::failed(label, detail.clone());
    result.report_sections.push(TaskReportSection {
        key: "task_failures".to_string(),
        title: "Task Failure Results".to_string(),
        rows: vec![TaskReportRow {
            name: task_id.into(),
            status: TaskReportStatus::Failed,
            before: Some("-".to_string()),
            after: Some("-".to_string()),
            note: Some(detail),
        }],
    });
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskReportStatus {
    Updated,
    Refreshed,
    Passed,
    Unchanged,
    Failed,
    Blocked,
    Skipped,
    Info,
}

impl TaskReportStatus {
    fn plain_tag(self) -> &'static str {
        match self {
            Self::Updated => "OK",
            Self::Refreshed => "REFRESH",
            Self::Passed => "PASS",
            Self::Unchanged => "SAME",
            Self::Failed => "FAIL",
            Self::Blocked => "BLOCK",
            Self::Skipped => "SKIP",
            Self::Info => "INFO",
        }
    }

    fn ansi_tag(self) -> &'static str {
        match self {
            Self::Updated => "\x1b[32mOK\x1b[0m",
            Self::Refreshed => "\x1b[36mREFRESH\x1b[0m",
            Self::Passed => "\x1b[32mPASS\x1b[0m",
            Self::Unchanged => "SAME",
            Self::Failed => "\x1b[31mFAIL\x1b[0m",
            Self::Blocked => "\x1b[38;2;255;165;0mBLOCK\x1b[0m",
            Self::Skipped => "\x1b[33mSKIP\x1b[0m",
            Self::Info => "\x1b[36mINFO\x1b[0m",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct TaskReportRow {
    pub name: String,
    pub status: TaskReportStatus,
    pub before: Option<String>,
    pub after: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TaskReportSection {
    pub key: String,
    pub title: String,
    pub rows: Vec<TaskReportRow>,
}

#[derive(Clone, Debug)]
pub struct TaskPolicies {
    pub npm_install: TaskPolicy,
    pub pipx_upgrade: TaskPolicy,
    pub system_update: TaskPolicy,
    pub aur_update: TaskPolicy,
    pub tool_update: TaskPolicy,
    pub extra: BTreeMap<String, TaskPolicy>,
}

impl TaskPolicies {
    pub fn by_key(&self, key: &str, fallback: TaskPolicy) -> TaskPolicy {
        match key {
            "npm_install" => self.npm_install.clone(),
            "pipx_upgrade" => self.pipx_upgrade.clone(),
            "system_update" => self.system_update.clone(),
            "aur_update" => self.aur_update.clone(),
            "tool_update" => self.tool_update.clone(),
            _ => self.extra.get(key).cloned().unwrap_or(fallback),
        }
    }
}

pub struct SyncContext {
    pub flags: Sections,
    pub host_os: HostOs,
    pub updater_config: UpdaterConfig,
    pub completions_mode: String,
    pub completion_providers: String,
    pub completion_discover: String,
    pub completion_strict: String,
    pub completion_report: String,
    pub filter_progress_noise: bool,
    pub emit_plain: bool,
    pub(crate) event_tx: Option<DashboardSender>,
    pub run_log: Option<Arc<RunLogSink>>,
    pub rc_root: PathBuf,
    pub completion_managed_root: PathBuf,
    pub completion_config_path: Option<PathBuf>,
    pub completion_catalog_path: PathBuf,
    pub completion_registry_path: PathBuf,
    pub task_policies: TaskPolicies,
    pub interactive_runtime: InteractiveRuntimeConfig,
    pub note_verbosity: NoteVerbosity,
    pub debug_report: bool,
    pub(crate) privilege_session: Arc<PrivilegeSession>,
    pub(crate) runtime_control: Option<Arc<RuntimeControl>>,
    pub(crate) prompt_runtime: Arc<PromptRuntime>,
}

#[derive(Clone)]
pub(crate) struct DashboardSender {
    tx: mpsc::Sender<DashboardEvent>,
    detached: Arc<AtomicBool>,
    run_log: Option<Arc<RunLogSink>>,
}

impl DashboardSender {
    pub(crate) fn new(tx: mpsc::Sender<DashboardEvent>, run_log: Option<Arc<RunLogSink>>) -> Self {
        Self {
            tx,
            detached: Arc::new(AtomicBool::new(false)),
            run_log,
        }
    }

    fn send(
        &self,
        event: DashboardEvent,
    ) -> std::result::Result<(), mpsc::SendError<DashboardEvent>> {
        if let Some(log) = &self.run_log {
            if journal_dashboard_event(log, &event).is_err() {
                return Err(mpsc::SendError(event));
            }
        }
        if self.detached.load(Ordering::SeqCst) {
            emit_dashboard_event_plain(&event);
            return Err(mpsc::SendError(event));
        }

        match self.tx.send(event) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.record_detachment_once();
                emit_dashboard_event_plain(&err.0);
                Err(err)
            }
        }
    }

    fn is_detached(&self) -> bool {
        self.detached.load(Ordering::SeqCst)
    }

    fn journal_error(&self) -> Option<String> {
        self.run_log.as_ref().and_then(|log| log.journal_failure())
    }

    fn journal_control(&self, kind: &str, task_id: Option<&str>, payload: serde_json::Value) {
        if let Some(log) = &self.run_log {
            let _ = log.write_event(kind, task_id, payload);
        }
    }

    fn record_detachment_once(&self) {
        if self
            .detached
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let line = "frontend_detached: dashboard receiver disconnected; switched to plain output";
        crate::ua_errln!("update-all: dashboard detached; switching to plain output");
        if let Some(log) = &self.run_log {
            if let Err(err) = log.write_event(
                "frontend_detached",
                None,
                serde_json::json!({"reason": "dashboard receiver disconnected"}),
            ) {
                log.emit_write_warning_once(&err);
            }
            let rec = LogRecord {
                ts_unix_ms: now_unix_ms(),
                task_id: RUN_LOG_SCOPE.to_string(),
                level: LogLevel::Warn,
                stream: LogStream::Meta,
                line: line.to_string(),
            };
            if let Err(err) = log.write_raw(&rec) {
                log.emit_write_warning_once(&err);
            }
            if let Err(err) = log.write_record(&rec) {
                log.emit_write_warning_once(&err);
            }
        }
    }
}

fn journal_dashboard_event(log: &RunLogSink, event: &DashboardEvent) -> Result<()> {
    match event {
        DashboardEvent::RunIdentity {
            run_id,
            display_name,
        } => log.write_event(
            "run_identity",
            None,
            serde_json::json!({"run_id": run_id, "display_name": display_name}),
        ),
        DashboardEvent::RunRenamed { display_name } => log.write_event(
            "run_renamed",
            None,
            serde_json::json!({"display_name": display_name}),
        ),
        DashboardEvent::TaskRegistered {
            id,
            label,
            category,
            depends_on,
            accepts_input,
        } => log.write_event(
            "task_registered",
            Some(id),
            serde_json::json!({
                "label": label,
                "category": category,
                "depends_on": depends_on,
                "accepts_input": accepts_input,
            }),
        ),
        DashboardEvent::TaskInputStateChanged { id, enabled } => log.write_event(
            "task_input_state_changed",
            Some(id),
            serde_json::json!({"enabled": enabled}),
        ),
        DashboardEvent::PromptRequested {
            id,
            generation,
            prompt,
        } => log.write_event(
            "prompt_requested",
            Some(id),
            serde_json::json!({"generation": generation, "prompt": prompt}),
        ),
        DashboardEvent::PromptCancelled {
            id,
            generation,
            reason,
        } => log.write_event(
            "prompt_cancelled",
            Some(id),
            serde_json::json!({"generation": generation, "reason": reason}),
        ),
        DashboardEvent::TaskStateChanged { id, state, detail } => log.write_event(
            "task_state_changed",
            Some(id),
            serde_json::json!({"state": task_state_name(*state), "detail": detail}),
        ),
        DashboardEvent::LogLine(record) => log.write_event(
            "log_line",
            (record.task_id != RUN_LOG_SCOPE).then_some(record.task_id.as_str()),
            serde_json::json!({
                "level": record.level.as_str(),
                "stream": record.stream.as_str(),
                "line": record.line,
            }),
        ),
        DashboardEvent::RunComplete { success, .. } => log.write_event(
            "run_completed",
            None,
            serde_json::json!({"success": success}),
        ),
        DashboardEvent::UiSuspendRequested { reason, .. } => log.write_event(
            "frontend_suspended",
            None,
            serde_json::json!({"reason": reason}),
        ),
        DashboardEvent::UiResumeRequested { .. } => {
            log.write_event("frontend_resumed", None, serde_json::json!({}))
        }
        DashboardEvent::UiDone => log.write_event("frontend_done", None, serde_json::json!({})),
    }
}

fn task_state_name(state: TaskState) -> &'static str {
    match state {
        TaskState::Pending => "pending",
        TaskState::Running => "running",
        TaskState::Completed => "completed",
        TaskState::Failed => "failed",
        TaskState::Canceled => "cancelled",
        TaskState::Skipped => "skipped",
    }
}

fn emit_dashboard_event_plain(event: &DashboardEvent) {
    match event {
        DashboardEvent::LogLine(rec) => crate::ua_outln!("[{}] {}", rec.task_id, rec.line),
        DashboardEvent::TaskStateChanged { id, state, detail } => {
            let state = match state {
                TaskState::Pending => "pending",
                TaskState::Running => "running",
                TaskState::Completed => "completed",
                TaskState::Failed => "failed",
                TaskState::Canceled => "canceled",
                TaskState::Skipped => "skipped",
            };
            if let Some(detail) = detail {
                crate::ua_outln!("[{id}] {state}: {detail}");
            } else {
                crate::ua_outln!("[{id}] {state}");
            }
        }
        DashboardEvent::RunComplete { success, .. } => crate::ua_outln!(
            "[runtime] run complete: {}",
            if *success { "success" } else { "unsuccessful" }
        ),
        _ => {}
    }
}

fn journal_ui_control(event_tx: &DashboardSender, control: &UiControlEvent) -> bool {
    let (kind, task_id, payload) = match control {
        UiControlEvent::CancelTask { id } => (
            "task_cancel_requested",
            Some(id.as_str()),
            serde_json::json!({}),
        ),
        UiControlEvent::CancelAll => ("run_cancel_requested", None, serde_json::json!({})),
        UiControlEvent::SendStdin { .. } => return event_tx.journal_error().is_none(),
        UiControlEvent::RenameRun { name } => (
            "rename_requested",
            None,
            serde_json::json!({"character_count": name.chars().count()}),
        ),
        UiControlEvent::OpenLog { target } => (
            "log_view_requested",
            match target {
                LogViewTarget::Task { id } => Some(id.as_str()),
                LogViewTarget::Run => None,
            },
            serde_json::json!({"scope": if matches!(target, LogViewTarget::Run) { "run" } else { "task" }}),
        ),
    };
    event_tx.journal_control(kind, task_id, payload);
    event_tx.journal_error().is_none()
}

fn submit_prompt_answer(
    event_tx: &DashboardSender,
    runtime_control: &RuntimeControl,
    prompt_runtime: &PromptRuntime,
    task_id: &str,
    generation: u64,
    line: String,
) -> bool {
    let character_count = line.chars().count();
    let sent = prompt_runtime.submit(task_id, generation, || {
        runtime_control.send_stdin_line(task_id, line)
    });
    if sent {
        event_tx.journal_control(
            "prompt_answered",
            Some(task_id),
            serde_json::json!({
                "generation": generation,
                "character_count": character_count,
            }),
        );
    }
    sent
}

pub struct AsyncContext {
    pub flags: Sections,
    pub host_os: HostOs,
    pub updater_config: UpdaterConfig,
    pub jobs: String,
    pub ui: UiModeResolved,
    pub fail_fast: bool,
    pub ui_persist_until_exit: bool,
    pub completions_mode: String,
    pub completion_providers: String,
    pub completion_discover: String,
    pub completion_strict: String,
    pub completion_report: String,
    pub filter_progress_noise: bool,
    pub rc_root: PathBuf,
    pub completion_managed_root: PathBuf,
    pub completion_config_path: Option<PathBuf>,
    pub completion_catalog_path: PathBuf,
    pub completion_registry_path: PathBuf,
    pub run_log: Option<Arc<RunLogSink>>,
    pub task_policies: TaskPolicies,
    pub interactive_runtime: InteractiveRuntimeConfig,
    pub(crate) privilege_session: Arc<PrivilegeSession>,
    pub dashboard_quit_behavior: DashboardQuitBehavior,
    pub mouse_row_stride: MouseRowStride,
    pub quit_cancel_grace: Duration,
    pub show_global_log: bool,
    pub max_in_memory_lines: usize,
    pub max_events_per_frame: usize,
    pub task_colors: bool,
    pub note_verbosity: NoteVerbosity,
    pub debug_report: bool,
}

#[derive(Clone)]
struct CommandTask {
    program: String,
    args: Vec<String>,
    mode: Option<String>,
    command_candidates: Vec<BuiltinCommandCandidate>,
    pre_commands: Vec<CommandPreCommand>,
    report_commands: Vec<CommandReportCommand>,
    report_patterns: Vec<CommandReportPattern>,
    report_scoped_deltas: Vec<CommandScopedDelta>,
    policy_key: String,
    requires_elevation: bool,
    needs_sudo_session: bool,
    interactive: bool,
    external_window: bool,
    shell: bool,
    windows_bridge: bool,
    report_parser: Option<BuiltinReportParser>,
    plain_header: Option<String>,
    plain_start: Option<String>,
    success_details: Vec<String>,
    external_manager_skip: bool,
    result_protocol: Option<u32>,
}

#[derive(Clone)]
struct CommandPreCommand {
    program: String,
    args: Vec<String>,
}

#[derive(Clone)]
struct CommandReportCommand {
    program: String,
    args: Vec<String>,
    when: CommandReportWhen,
    allow_exit_codes: Vec<i32>,
    state_pattern: Option<CommandStateReportPattern>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommandReportWhen {
    Before,
    After,
    BeforeAfter,
}

impl CommandReportWhen {
    fn runs_before(self) -> bool {
        matches!(self, Self::Before | Self::BeforeAfter)
    }

    fn runs_after(self) -> bool {
        matches!(self, Self::After | Self::BeforeAfter)
    }
}

#[derive(Clone)]
struct CommandStateReportPattern {
    regex: Regex,
    section_key: String,
    section_title: String,
    name: Option<String>,
    version: Option<String>,
    include_unchanged: bool,
}

#[derive(Clone)]
struct CommandReportPattern {
    regex: Regex,
    section_key: String,
    section_title: String,
    status: TaskReportStatus,
    name: Option<String>,
    before: Option<String>,
    after: Option<String>,
    note: Option<String>,
}

#[derive(Clone)]
struct CommandScopedDelta {
    scope_regex: Regex,
    before_regex: Regex,
    after_regex: Regex,
    section_key: String,
    section_title: String,
    row_name: String,
    scope_section_key: Option<String>,
    scope_section_title: Option<String>,
    scope_row_name: Option<String>,
}

#[derive(Clone)]
enum TaskKind {
    Managed(ManagedTaskExecutor),
    Command(CommandTask),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ManagedTaskExecutor {
    Npm,
    Completions,
    WindowsFoundations { foundations: Vec<String> },
}

#[derive(Clone)]
struct TaskSpec {
    id: String,
    label: String,
    depends_on: Vec<String>,
    kind: TaskKind,
    category: String,
    resource_locks: BTreeSet<String>,
}

#[derive(Default)]
pub(crate) struct RuntimeControl {
    cancel_all: AtomicBool,
    per_task_cancel: Mutex<BTreeSet<String>>,
    running_pids: Mutex<BTreeMap<String, RunningProcess>>,
    task_stdin: Mutex<BTreeMap<String, mpsc::Sender<String>>>,
}

#[derive(Default)]
pub(crate) struct PromptRuntime {
    tasks: Mutex<BTreeMap<String, PromptRuntimeTask>>,
}

#[derive(Default)]
struct PromptRuntimeTask {
    generation: u64,
    active: Option<ActivePromptGeneration>,
}

#[derive(Clone, Copy)]
struct ActivePromptGeneration {
    generation: u64,
    answered: bool,
}

impl PromptRuntime {
    fn request(&self, task_id: &str) -> (u64, Option<u64>) {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = tasks.entry(task_id.to_string()).or_default();
        let cancelled = state
            .active
            .filter(|active| !active.answered)
            .map(|active| active.generation);
        state.generation = state.generation.saturating_add(1).max(1);
        let generation = state.generation;
        state.active = Some(ActivePromptGeneration {
            generation,
            answered: false,
        });
        (generation, cancelled)
    }

    fn submit(&self, task_id: &str, generation: u64, send: impl FnOnce() -> bool) -> bool {
        let mut tasks = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(active) = tasks
            .get_mut(task_id)
            .and_then(|state| state.active.as_mut())
        else {
            return false;
        };
        if active.generation != generation || active.answered || !send() {
            return false;
        }
        active.answered = true;
        true
    }

    fn cancel(&self, task_id: &str) -> Option<u64> {
        self.tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(task_id)
            .and_then(|state| state.active.take())
            .map(|active| active.generation)
    }
}

#[derive(Clone, Copy, Debug)]
struct RunningProcess {
    pid: u32,
    managed_process_group: bool,
}

#[derive(Default)]
pub(crate) struct PrivilegeSession {
    sudo_preflight: Mutex<Option<Result<(), String>>>,
    sudo_runtime_error: Mutex<Option<String>>,
    sudo_refresh_gate: Mutex<()>,
}

#[cfg(unix)]
struct SudoKeepalive {
    stop: Arc<AtomicBool>,
    active_pid: Arc<Mutex<Option<u32>>>,
    handle: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl SudoKeepalive {
    fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(pid_guard) = self.active_pid.lock() {
            if let Some(pid) = *pid_guard {
                terminate_process_group(pid);
            }
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(unix)]
impl Drop for SudoKeepalive {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

impl RuntimeControl {
    fn should_cancel(&self, task_id: &str) -> bool {
        if self.cancel_all.load(Ordering::SeqCst) {
            return true;
        }
        self.per_task_cancel
            .lock()
            .map(|set| set.contains(task_id))
            .unwrap_or(false)
    }

    fn register_spawn(&self, task_id: &str, pid: u32, managed_process_group: bool) {
        if let Ok(mut map) = self.running_pids.lock() {
            map.insert(
                task_id.to_string(),
                RunningProcess {
                    pid,
                    managed_process_group,
                },
            );
        }
    }

    fn clear_spawn(&self, task_id: &str) {
        if let Ok(mut map) = self.running_pids.lock() {
            map.remove(task_id);
        }
        if let Ok(mut map) = self.task_stdin.lock() {
            map.remove(task_id);
        }
    }

    fn request_task_cancel(&self, task_id: &str) -> bool {
        if let Ok(mut set) = self.per_task_cancel.lock() {
            set.insert(task_id.to_string());
        }
        let process = self
            .running_pids
            .lock()
            .ok()
            .and_then(|map| map.get(task_id).copied());
        if let Some(process) = process {
            if process.managed_process_group {
                terminate_process_group(process.pid);
            } else {
                terminate_process(process.pid);
            }
            return true;
        }
        false
    }

    fn request_cancel_all(&self) -> Vec<String> {
        self.cancel_all.store(true, Ordering::SeqCst);
        let mut running = Vec::new();
        if let Ok(map) = self.running_pids.lock() {
            for (task_id, process) in map.iter() {
                running.push(task_id.clone());
                if process.managed_process_group {
                    terminate_process_group(process.pid);
                } else {
                    terminate_process(process.pid);
                }
            }
        }
        if let Ok(mut set) = self.per_task_cancel.lock() {
            for id in &running {
                set.insert(id.clone());
            }
        }
        running
    }

    fn register_stdin_sender(&self, task_id: &str, tx: mpsc::Sender<String>) {
        if let Ok(mut map) = self.task_stdin.lock() {
            map.insert(task_id.to_string(), tx);
        }
    }

    fn clear_stdin_sender(&self, task_id: &str) {
        if let Ok(mut map) = self.task_stdin.lock() {
            map.remove(task_id);
        }
    }

    fn send_stdin_line(&self, task_id: &str, line: String) -> bool {
        if let Ok(map) = self.task_stdin.lock() {
            if let Some(tx) = map.get(task_id) {
                return tx.send(line).is_ok();
            }
        }
        false
    }
}

impl SyncContext {
    fn set_task_input_state(&self, task_id: &str, enabled: bool) {
        if !enabled {
            if let Some(generation) = self.prompt_runtime.cancel(task_id) {
                let event = DashboardEvent::PromptCancelled {
                    id: task_id.to_string(),
                    generation,
                    reason: "input channel closed".to_string(),
                };
                if let Some(tx) = &self.event_tx {
                    let _ = tx.send(event);
                } else if let Some(log) = &self.run_log {
                    let _ = journal_dashboard_event(log, &event);
                }
            }
        }
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(DashboardEvent::TaskInputStateChanged {
                id: task_id.to_string(),
                enabled,
            });
        } else if let Some(log) = &self.run_log {
            let _ = log.write_event(
                "task_input_state_changed",
                Some(task_id),
                serde_json::json!({"enabled": enabled}),
            );
        }
    }

    fn build_stream_callback(
        &self,
        task_id: &str,
        detect_prompts: bool,
    ) -> Arc<dyn Fn(StreamKind, String) + Send + Sync> {
        let task_for_logs = task_id.to_string();
        let tx = self.event_tx.clone();
        let run_log = self.run_log.clone();
        let prompt_runtime = self.prompt_runtime.clone();
        let filter_progress_noise = self.filter_progress_noise;
        Arc::new(move |kind, line| {
            let stream = match kind {
                StreamKind::Stdout => LogStream::Stdout,
                StreamKind::Stderr => LogStream::Stderr,
            };
            let level = classify_stream_level(kind, &line);
            let raw = LogRecord {
                ts_unix_ms: now_unix_ms(),
                task_id: task_for_logs.clone(),
                level,
                stream,
                line: strip_ansi(&line),
            };
            if let Some(log) = &run_log {
                if let Err(err) = log.write_raw(&raw) {
                    log.emit_write_warning_once(&err);
                }
            }
            let Some(line) = sanitize_stream_line(&line, filter_progress_noise) else {
                return;
            };
            let rec = LogRecord {
                ts_unix_ms: now_unix_ms(),
                task_id: task_for_logs.clone(),
                level,
                stream,
                line,
            };
            if let Some(log) = &run_log {
                if let Err(err) = log.write_record(&rec) {
                    log.emit_write_warning_once(&err);
                }
            }
            if let Some(tx) = &tx {
                let _ = tx.send(DashboardEvent::LogLine(rec.clone()));
            }
            if detect_prompts && looks_like_interactive_prompt(&rec.line) {
                let (generation, cancelled_generation) = prompt_runtime.request(&task_for_logs);
                if let Some(cancelled_generation) = cancelled_generation {
                    let cancelled = DashboardEvent::PromptCancelled {
                        id: task_for_logs.clone(),
                        generation: cancelled_generation,
                        reason: "superseded by a new prompt".to_string(),
                    };
                    if let Some(tx) = &tx {
                        let _ = tx.send(cancelled);
                    } else if let Some(log) = &run_log {
                        let _ = journal_dashboard_event(log, &cancelled);
                    }
                }
                let requested = DashboardEvent::PromptRequested {
                    id: task_for_logs.clone(),
                    generation,
                    prompt: rec.line,
                };
                if let Some(tx) = &tx {
                    let _ = tx.send(requested);
                } else if let Some(log) = &run_log {
                    let _ = journal_dashboard_event(log, &requested);
                }
            }
        })
    }

    pub fn log_line(
        &self,
        task_id: &str,
        level: LogLevel,
        stream: LogStream,
        line: impl Into<String>,
    ) {
        let line = line.into();
        let task_id = if task_id == "runtime" {
            RUN_LOG_SCOPE
        } else {
            task_id
        };
        let rec = LogRecord {
            ts_unix_ms: now_unix_ms(),
            task_id: task_id.to_string(),
            level,
            stream,
            line,
        };
        if self.event_tx.is_none() {
            if let Some(log) = &self.run_log {
                let _ = journal_dashboard_event(log, &DashboardEvent::LogLine(rec.clone()));
            }
        }
        if let Some(log) = &self.run_log {
            if let Err(err) = log.write_raw(&rec) {
                log.emit_write_warning_once(&err);
            }
            if let Err(err) = log.write_record(&rec) {
                log.emit_write_warning_once(&err);
            }
        }
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(DashboardEvent::LogLine(rec));
        }
    }

    pub fn set_task_state(&self, task_id: &str, state: TaskState, detail: Option<String>) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(DashboardEvent::TaskStateChanged {
                id: task_id.to_string(),
                state,
                detail,
            });
        } else if let Some(log) = &self.run_log {
            let _ = log.write_event(
                "task_state_changed",
                Some(task_id),
                serde_json::json!({"state": task_state_name(state), "detail": detail}),
            );
        }
    }

    fn request_ui_suspend_and_wait(&self, reason: impl Into<String>, timeout: Duration) -> bool {
        let Some(tx) = &self.event_tx else {
            return false;
        };
        let (ack_tx, ack_rx) = mpsc::channel::<()>();
        if tx
            .send(DashboardEvent::UiSuspendRequested {
                reason: reason.into(),
                ack: Some(ack_tx),
            })
            .is_err()
        {
            return false;
        }

        match ack_rx.recv_timeout(timeout) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => false,
            Err(mpsc::RecvTimeoutError::Disconnected) => false,
        }
    }

    fn request_ui_resume_and_wait(&self, timeout: Duration) -> bool {
        let Some(tx) = &self.event_tx else {
            return false;
        };
        let (ack_tx, ack_rx) = mpsc::channel::<()>();
        if tx
            .send(DashboardEvent::UiResumeRequested { ack: Some(ack_tx) })
            .is_err()
        {
            return false;
        }

        match ack_rx.recv_timeout(timeout) {
            Ok(()) => true,
            Err(mpsc::RecvTimeoutError::Timeout) => false,
            Err(mpsc::RecvTimeoutError::Disconnected) => false,
        }
    }

    pub fn completion_progress_cb(
        &self,
        task_id: impl Into<String>,
    ) -> Option<Arc<dyn Fn(String) + Send + Sync>> {
        let task_id = task_id.into();
        let tx = self.event_tx.clone();
        let run_log = self.run_log.clone();
        Some(Arc::new(move |msg: String| {
            let rec = LogRecord {
                ts_unix_ms: now_unix_ms(),
                task_id: task_id.to_string(),
                level: LogLevel::Info,
                stream: LogStream::Meta,
                line: msg,
            };
            if let Some(log) = &run_log {
                log.write_raw(&rec);
                log.write_record(&rec);
            }
            if let Some(tx) = &tx {
                let _ = tx.send(DashboardEvent::LogLine(rec));
            }
        }))
    }

    pub fn run_command_with_policy(
        &self,
        task_id: &str,
        program: &str,
        args: Vec<String>,
        policy: &TaskPolicy,
        interactive: bool,
    ) -> Result<String> {
        // Interactive tasks should use foreground TTY to avoid dashboard/raw-mode
        // contention with tools that may prompt or manipulate terminal state.
        let (foreground_tty, capture_foreground_output) = if interactive {
            match self.interactive_runtime.mode {
                InteractiveExecutionMode::DirectTty => (true, false),
                InteractiveExecutionMode::Capture | InteractiveExecutionMode::AutoFallback => {
                    (true, true)
                }
            }
        } else {
            (false, false)
        };
        self.run_command_with_policy_mode(
            task_id,
            program,
            args,
            policy,
            interactive,
            foreground_tty,
            capture_foreground_output,
        )
    }

    fn run_command_with_policy_foreground(
        &self,
        task_id: &str,
        program: &str,
        args: Vec<String>,
        policy: &TaskPolicy,
        interactive: bool,
    ) -> Result<String> {
        self.run_command_with_policy_mode(task_id, program, args, policy, interactive, true, false)
    }

    fn run_command_with_policy_direct_tty(
        &self,
        task_id: &str,
        program: &str,
        args: Vec<String>,
        policy: &TaskPolicy,
    ) -> Result<String> {
        self.run_command_with_policy_mode(task_id, program, args, policy, true, true, false)
    }

    fn run_report_command_with_policy(
        &self,
        task_id: &str,
        command: &CommandReportCommand,
        policy: &TaskPolicy,
    ) -> Result<String> {
        let cb = self.build_stream_callback(task_id, false);
        let args_for_run = command.args.iter().map(String::as_str);
        if let Some(runtime) = &self.runtime_control {
            let runtime_for_cancel = runtime.clone();
            let task_for_cancel = task_id.to_string();
            let cancel_check: Arc<dyn Fn() -> bool + Send + Sync> =
                Arc::new(move || runtime_for_cancel.should_cancel(&task_for_cancel));

            let runtime_for_spawn = runtime.clone();
            let task_for_spawn = task_id.to_string();
            let on_spawn: Arc<dyn Fn(u32) + Send + Sync> =
                Arc::new(move |pid| runtime_for_spawn.register_spawn(&task_for_spawn, pid, true));

            let runtime_for_exit = runtime.clone();
            let task_for_exit = task_id.to_string();
            let on_exit: Arc<dyn Fn() + Send + Sync> =
                Arc::new(move || runtime_for_exit.clear_spawn(&task_for_exit));

            run_capture_streaming_controlled_allow_exit_codes(
                &command.program,
                args_for_run,
                Some(policy.timeout),
                &command.allow_exit_codes,
                cb,
                cancel_check,
                on_spawn,
                on_exit,
            )
        } else {
            run_capture_streaming_allow_exit_codes(
                &command.program,
                args_for_run,
                Some(policy.timeout),
                &command.allow_exit_codes,
                cb,
            )
        }
    }

    #[allow(clippy::too_many_arguments)] // Reason: interactive execution mode is fully explicit by design.
    fn run_command_with_policy_mode(
        &self,
        task_id: &str,
        program: &str,
        args: Vec<String>,
        policy: &TaskPolicy,
        interactive: bool,
        foreground_tty: bool,
        capture_foreground_output: bool,
    ) -> Result<String> {
        let mut attempt = 0u32;
        let mut fallback_consumed = false;
        let mut capture_this_run = capture_foreground_output;

        loop {
            let args_for_run = args.clone();
            let task = task_id.to_string();
            let cb = self.build_stream_callback(task_id, interactive && capture_this_run);
            let capture_enabled_for_run = capture_this_run;
            let suspend_ui_for_command =
                interactive && self.runtime_control.is_some() && !capture_enabled_for_run;
            if suspend_ui_for_command {
                let suspended = self.request_ui_suspend_and_wait(
                    format!("suspending dashboard for interactive command: {}", program),
                    Duration::from_secs(2),
                );
                if !suspended {
                    self.log_line(
                        task_id,
                        LogLevel::Warn,
                        LogStream::Meta,
                        format!(
                            "dashboard suspend ack timed out before interactive command: {}",
                            program
                        ),
                    );
                }
            }
            let entering_interactive_foreground =
                interactive && foreground_tty && !capture_enabled_for_run;
            if entering_interactive_foreground {
                self.log_line(
                    task_id,
                    LogLevel::Info,
                    LogStream::Meta,
                    format!("interactive foreground handoff started for {}", program),
                );
            }
            if interactive && capture_enabled_for_run {
                self.log_line(
                    task_id,
                    LogLevel::Info,
                    LogStream::Meta,
                    format!("interactive capture started for {}", program),
                );
            }

            let dashboard_managed_input = interactive
                && capture_enabled_for_run
                && foreground_tty
                && self.runtime_control.is_some();
            let auto_fallback_enabled = interactive
                && !dashboard_managed_input
                && self.interactive_runtime.mode == InteractiveExecutionMode::AutoFallback
                && self.interactive_runtime.retry_once;
            let capture_guard = if interactive && capture_enabled_for_run {
                let stall_timeout = if dashboard_managed_input {
                    Duration::ZERO
                } else {
                    Duration::from_secs(self.interactive_runtime.stall_seconds.max(1))
                };
                Some(CaptureGuard {
                    // Dashboard-managed PTY capture must allow the child to wait for user input
                    // without tripping the stall watchdog after the prompt is visible.
                    stall_timeout,
                    max_line_bytes: self.interactive_runtime.max_line_bytes,
                    max_capture_bytes: self.interactive_runtime.max_capture_bytes,
                })
            } else {
                None
            };

            let result = if foreground_tty {
                if let Some(runtime) = &self.runtime_control {
                    let runtime_for_cancel = runtime.clone();
                    let task_for_cancel = task.clone();
                    let cancel_check: Arc<dyn Fn() -> bool + Send + Sync> =
                        Arc::new(move || runtime_for_cancel.should_cancel(&task_for_cancel));

                    let runtime_for_spawn = runtime.clone();
                    let task_for_spawn = task.clone();
                    let managed_process_group = capture_enabled_for_run;
                    let on_spawn: Arc<dyn Fn(u32) + Send + Sync> = Arc::new(move |pid| {
                        runtime_for_spawn.register_spawn(
                            &task_for_spawn,
                            pid,
                            managed_process_group,
                        )
                    });

                    let runtime_for_exit = runtime.clone();
                    let task_for_exit = task.clone();
                    let on_exit: Arc<dyn Fn() + Send + Sync> =
                        Arc::new(move || runtime_for_exit.clear_spawn(&task_for_exit));

                    let mut stdin_rx = None;
                    if interactive && capture_enabled_for_run {
                        let (stdin_tx, rx) = mpsc::channel::<String>();
                        runtime.register_stdin_sender(&task, stdin_tx);
                        self.set_task_input_state(task_id, true);
                        stdin_rx = Some(rx);
                    }

                    if capture_enabled_for_run {
                        if let Some(guard) = capture_guard {
                            if let Some(rx) = stdin_rx {
                                run_capture_streaming_controlled_stdin_pty_capture_guarded(
                                    program,
                                    args_for_run.iter().map(String::as_str),
                                    Some(policy.timeout),
                                    cb,
                                    cancel_check,
                                    on_spawn,
                                    on_exit,
                                    guard,
                                    rx,
                                )
                            } else {
                                run_capture_streaming_controlled_stdin_tty_capture_guarded(
                                    program,
                                    args_for_run.iter().map(String::as_str),
                                    Some(policy.timeout),
                                    cb,
                                    cancel_check,
                                    on_spawn,
                                    on_exit,
                                    guard,
                                )
                            }
                        } else {
                            run_capture_streaming_controlled_stdin_tty_capture(
                                program,
                                args_for_run.iter().map(String::as_str),
                                Some(policy.timeout),
                                cb,
                                cancel_check,
                                on_spawn,
                                on_exit,
                            )
                        }
                    } else {
                        run_capture_streaming_controlled_foreground(
                            program,
                            args_for_run.iter().map(String::as_str),
                            Some(policy.timeout),
                            cb,
                            cancel_check,
                            on_spawn,
                            on_exit,
                        )
                    }
                } else if capture_enabled_for_run {
                    if let Some(guard) = capture_guard {
                        run_capture_streaming_stdin_tty_capture_guarded(
                            program,
                            args_for_run.iter().map(String::as_str),
                            Some(policy.timeout),
                            cb,
                            guard,
                        )
                    } else {
                        run_capture_streaming_stdin_tty_capture(
                            program,
                            args_for_run.iter().map(String::as_str),
                            Some(policy.timeout),
                            cb,
                        )
                    }
                } else {
                    run_capture_streaming_foreground(
                        program,
                        args_for_run.iter().map(String::as_str),
                        Some(policy.timeout),
                        cb,
                    )
                }
            } else if let Some(runtime) = &self.runtime_control {
                let runtime_for_cancel = runtime.clone();
                let task_for_cancel = task.clone();
                let cancel_check: Arc<dyn Fn() -> bool + Send + Sync> =
                    Arc::new(move || runtime_for_cancel.should_cancel(&task_for_cancel));

                let runtime_for_spawn = runtime.clone();
                let task_for_spawn = task.clone();
                let managed_process_group = true;
                let on_spawn: Arc<dyn Fn(u32) + Send + Sync> = Arc::new(move |pid| {
                    runtime_for_spawn.register_spawn(&task_for_spawn, pid, managed_process_group)
                });

                let runtime_for_exit = runtime.clone();
                let task_for_exit = task.clone();
                let on_exit: Arc<dyn Fn() + Send + Sync> =
                    Arc::new(move || runtime_for_exit.clear_spawn(&task_for_exit));

                run_capture_streaming_controlled(
                    program,
                    args_for_run.iter().map(String::as_str),
                    Some(policy.timeout),
                    interactive,
                    cb,
                    cancel_check,
                    on_spawn,
                    on_exit,
                )
            } else {
                run_capture_streaming(
                    program,
                    args_for_run.iter().map(String::as_str),
                    Some(policy.timeout),
                    interactive,
                    cb,
                )
            };
            if let Some(runtime) = &self.runtime_control {
                runtime.clear_stdin_sender(&task);
            }
            self.set_task_input_state(task_id, false);

            if entering_interactive_foreground {
                self.log_line(
                    task_id,
                    LogLevel::Info,
                    LogStream::Meta,
                    format!("interactive foreground handoff finished for {}", program),
                );
            }
            if suspend_ui_for_command {
                let resumed = self.request_ui_resume_and_wait(Duration::from_secs(2));
                if !resumed {
                    self.log_line(
                        task_id,
                        LogLevel::Warn,
                        LogStream::Meta,
                        format!(
                            "dashboard resume ack timed out after interactive command: {}",
                            program
                        ),
                    );
                }
            }

            match result {
                Ok(out) => return Ok(out),
                Err(e) => {
                    if e.downcast_ref::<crate::Cancelled>().is_some() {
                        return Err(e);
                    }
                    if auto_fallback_enabled && capture_enabled_for_run && !fallback_consumed {
                        if let Some(reason) = capture_guard_reason(&e) {
                            fallback_consumed = true;
                            capture_this_run = false;
                            self.log_line(
                                task_id,
                                LogLevel::Warn,
                                LogStream::Meta,
                                format!(
                                    "interactive fallback to foreground tty for {}: {}; retrying with direct TTY",
                                    program,
                                    capture_guard_reason_label(reason)
                                ),
                            );
                            continue;
                        }
                    }
                    let err_text = if let Some(output) = process_exit_output(&e) {
                        output.to_string()
                    } else {
                        e.to_string()
                    };
                    let retry_budget = effective_retry_budget(policy, &err_text);
                    if attempt >= retry_budget {
                        return Err(e);
                    }
                    attempt += 1;
                    capture_this_run = capture_foreground_output;
                    fallback_consumed = false;
                    let class = classify_runtime_failure(&err_text, false);
                    let backoff = if class == RuntimeFailureClass::TransientNetwork {
                        transient_retry_backoff(policy.retry_backoff, attempt - 1)
                    } else {
                        compute_retry_backoff(policy.retry_backoff, attempt - 1)
                    };
                    let reason = if class == RuntimeFailureClass::TransientNetwork {
                        " after transient network failure"
                    } else {
                        ""
                    };
                    self.log_line(
                        task_id,
                        LogLevel::Warn,
                        LogStream::Meta,
                        format!(
                            "retrying {}{} (attempt {}/{}, backoff={})",
                            program,
                            reason,
                            attempt,
                            retry_budget,
                            format_retry_delay(backoff)
                        ),
                    );
                    if !backoff.is_zero() {
                        thread::sleep(backoff);
                    }
                }
            }
        }
    }

    pub fn completion_sync_for_task(&self, task_id: &str) -> Result<CompletionSyncResult> {
        let runtime = crate::config::load_runtime_config(self.completion_config_path.clone())?;
        let shells = resolve_completion_shells(&[], &runtime.completions.shells)?;
        completion_sync(CompletionSyncArgs {
            providers_csv: self.completion_providers.to_string(),
            discover: self.completion_discover == "1",
            report: self.completion_report.to_string(),
            catalog_path: self.completion_catalog_path.clone(),
            config_path: self.completion_config_path.clone(),
            rc_root: None,
            managed_root: self.completion_managed_root.clone(),
            shells,
            progress_cb: self.completion_progress_cb(task_id),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AsyncRunOutcome {
    Success,
    Failed,
    Deferred,
    Canceled,
}

fn resolve_async_outcome(failed: bool, deferred: bool, canceled: bool) -> AsyncRunOutcome {
    if canceled {
        AsyncRunOutcome::Canceled
    } else if failed {
        AsyncRunOutcome::Failed
    } else if deferred {
        AsyncRunOutcome::Deferred
    } else {
        AsyncRunOutcome::Success
    }
}

pub(crate) fn compute_retry_backoff(base: Duration, retry_index: u32) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let multiplier = 1u128.checked_shl(retry_index).unwrap_or(u128::MAX);
    let delay_ms = base
        .as_millis()
        .saturating_mul(multiplier)
        .min(Duration::from_secs(60).as_millis());
    Duration::from_millis(delay_ms as u64)
}

pub(crate) fn transient_retry_backoff(base: Duration, retry_index: u32) -> Duration {
    let effective_base = if base.is_zero() {
        Duration::from_secs(8)
    } else {
        base
    };
    compute_retry_backoff(effective_base, retry_index)
}

pub(crate) fn effective_retry_budget(policy: &TaskPolicy, err_text: &str) -> u32 {
    if classify_runtime_failure(err_text, false) == RuntimeFailureClass::TransientNetwork {
        policy.retries.max(1)
    } else {
        policy.retries
    }
}

pub(crate) fn format_retry_delay(delay: Duration) -> String {
    if delay.subsec_nanos() == 0 {
        format!("{}s", delay.as_secs())
    } else {
        format!("{:.3}s", delay.as_secs_f64())
    }
}

pub fn run_sync(ctx: SyncContext) -> Result<()> {
    let specs = build_task_specs(&ctx.flags, &ctx.host_os, &ctx.updater_config)
        .map_err(|error| crate::InvalidPlan(format!("{error:#}")))?;
    if specs.is_empty() && ctx.host_os == HostOs::Unknown {
        crate::ua_errln!(
            "update-all: no built-in updater set is defined for this host OS; configure custom tasks or run on Linux, macOS, or Windows"
        );
    }
    let selected_tasks = selected_task_ids(&specs);
    let task_categories = task_categories_by_id(&specs);
    let mut summary: Vec<(String, TaskResult)> = Vec::new();
    let task_run_lock = acquire_task_run_lock(ctx.run_log.as_ref())?;

    if let Some(log) = ctx.run_log.as_ref() {
        for spec in &specs {
            log.write_event(
                "task_registered",
                Some(&spec.id),
                serde_json::json!({
                    "label": &spec.label,
                    "category": &spec.category,
                    "depends_on": &spec.depends_on,
                    "accepts_input": matches!(&spec.kind, TaskKind::Command(command) if command.interactive),
                }),
            )?;
        }
    }

    for spec in specs {
        ctx.set_task_state(&spec.id, TaskState::Running, None);
        ensure_sync_journal_healthy(&ctx)?;
        let result = match execute_task(&ctx, &spec) {
            Ok(result) => result,
            Err(e) => {
                if e.downcast_ref::<crate::Cancelled>().is_some() {
                    return Err(e);
                }
                failed_task_error_result(spec.label.clone(), spec.id.clone(), e.to_string())
            }
        };
        emit_task_report_logs_sync(&ctx, &spec.id, &result.report_sections);
        emit_task_outcome_log_sync(&ctx, &spec.id, &result);
        ctx.set_task_state(
            &spec.id,
            to_task_state(result.status),
            result.details.first().cloned(),
        );
        ensure_sync_journal_healthy(&ctx)?;
        summary.push((spec.id, result));
    }

    let tasks_completed_unix_ms = now_unix_ms();
    drop(task_run_lock);
    print_sync_summary(&summary);
    emit_end_of_run_reports_sync(&ctx, &summary, &task_categories);
    let failed = summary
        .iter()
        .any(|(_, result)| result.status == TaskStatus::Failed);
    let deferred = summary.iter().any(|(_, result)| result.is_deferred());
    let exit_code = if failed {
        1
    } else if deferred {
        2
    } else {
        0
    };
    let tasks_ended_unix_ms = now_unix_ms();
    if let Some(log) = ctx.run_log.as_ref() {
        log.write_event(
            "run_completed",
            None,
            serde_json::json!({"success": !failed && !deferred}),
        )?;
    }
    write_run_artifact(
        ctx.run_log.as_ref(),
        ctx.host_os.as_str(),
        "plain",
        "sync",
        selected_tasks,
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        tasks_ended_unix_ms,
        exit_code,
        tasks_completed_unix_ms,
    );

    if failed {
        bail!("one or more tasks failed");
    }
    if deferred {
        return Err(anyhow::anyhow!(crate::Deferred));
    }
    Ok(())
}

fn ensure_sync_journal_healthy(ctx: &SyncContext) -> Result<()> {
    if let Some(error) = ctx.run_log.as_ref().and_then(|log| log.journal_failure()) {
        bail!("authoritative event journal failed: {error}");
    }
    Ok(())
}

fn print_sync_summary(summary: &[(String, TaskResult)]) {
    crate::ua_outln!("\nSummary");
    for (_, t) in summary {
        let status = match t.status {
            TaskStatus::Completed if t.is_deferred() => "Deferred.",
            TaskStatus::Completed if t.has_issues() => "Completed with issues.",
            TaskStatus::Completed => "Completed.",
            TaskStatus::Failed => "Failed.",
            TaskStatus::Canceled => "Canceled.",
            TaskStatus::Skipped => "Skipped.",
        };
        crate::ua_outln!("[{}] {}", t.label, status);
        for d in &t.details {
            crate::ua_outln!("  {d}");
        }
    }
}

fn acquire_task_run_lock(run_log: Option<&Arc<RunLogSink>>) -> Result<Option<ScopedFileLock>> {
    let Some(run_log) = run_log else {
        return Ok(None);
    };
    let lock_root = run_log_root(run_log);
    try_acquire_pid_lock(
        lock_root,
        PidLockOptions {
            file_name: ".update-all-task-run.lock",
            label: "update-all task lock",
            active_detail: "another update-all run is still executing tasks",
            retry_detail: "retry after the active tasks finish",
            stale_after: TASK_RUN_LOCK_STALE_AFTER,
        },
    )
    .map(Some)
}

fn run_log_root(run_log: &RunLogSink) -> &Path {
    run_log
        .run_dir()
        .parent()
        .unwrap_or_else(|| run_log.run_dir())
}

pub fn run_async(ctx: AsyncContext) -> Result<()> {
    let specs = build_task_specs(&ctx.flags, &ctx.host_os, &ctx.updater_config)
        .map_err(|error| crate::InvalidPlan(format!("{error:#}")))?;
    if specs.is_empty() && ctx.host_os == HostOs::Unknown {
        crate::ua_errln!(
            "update-all: no built-in updater set is defined for this host OS; configure custom tasks or run on Linux, macOS, or Windows"
        );
    }
    let selected_tasks = selected_task_ids(&specs);
    let task_categories = task_categories_by_id(&specs);
    let task_run_lock = acquire_task_run_lock(ctx.run_log.as_ref())?;

    let max_parallel_jobs = resolve_parallel_jobs(&ctx.jobs, specs.len())?;
    crate::ua_outln!(
        "Async Update Engine (jobs={}=>{}, ui={}, fail_fast={})",
        ctx.jobs,
        max_parallel_jobs,
        ctx.ui.as_str(),
        if ctx.fail_fast { 1 } else { 0 }
    );

    let maintain_sudo_session = maybe_prepare_sudo_session_before_run(&ctx, &specs)?;
    #[cfg(not(unix))]
    let _ = maintain_sudo_session;

    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    let event_tx = DashboardSender::new(raw_event_tx, ctx.run_log.clone());
    let (ui_control_tx, ui_control_rx) = mpsc::channel::<UiControlEvent>();
    let runtime_control = Arc::new(RuntimeControl::default());
    let prompt_runtime = Arc::new(PromptRuntime::default());
    let mut ui_handle = ctx.ui.spawn_ui_thread(
        event_rx,
        ui_control_tx,
        ctx.dashboard_quit_behavior,
        ctx.mouse_row_stride,
        ctx.show_global_log,
        ctx.max_in_memory_lines,
        ctx.max_events_per_frame,
        ctx.task_colors,
    )?;
    if let Some(run_log) = ctx.run_log.as_ref() {
        let _ = event_tx.send(DashboardEvent::RunIdentity {
            run_id: run_log.run_id().to_string(),
            display_name: run_log.display_name(),
        });
    }

    for spec in &specs {
        let accepts_input = matches!(
            &spec.kind,
            TaskKind::Command(cmd) if command_supports_dashboard_input(cmd, &ctx.interactive_runtime)
        );
        let _ = event_tx.send(DashboardEvent::TaskRegistered {
            id: spec.id.clone(),
            label: spec.label.clone(),
            category: spec.category.clone(),
            depends_on: spec
                .depends_on
                .iter()
                .map(|dependency| dependency_task_id(dependency).to_string())
                .collect(),
            accepts_input,
        });
        let _ = event_tx.send(DashboardEvent::TaskStateChanged {
            id: spec.id.clone(),
            state: TaskState::Pending,
            detail: if spec.depends_on.is_empty() {
                None
            } else {
                Some(format!(
                    "waiting on {}",
                    spec.depends_on
                        .iter()
                        .map(|dependency| dependency_task_id(dependency))
                        .collect::<Vec<_>>()
                        .join(",")
                ))
            },
        });
    }

    #[cfg(unix)]
    let (mut sudo_keepalive, mut sudo_keepalive_failure_rx) = if maintain_sudo_session {
        clear_sudo_runtime_error(&ctx.privilege_session);
        let (keepalive, rx) = start_sudo_keepalive()?;
        emit_runtime_log(
            &event_tx,
            ctx.run_log.as_ref(),
            "runtime",
            "sudo session keepalive started",
        );
        (Some(keepalive), Some(rx))
    } else {
        (None, None)
    };

    type AsyncHandle = (String, BTreeSet<String>, thread::JoinHandle<TaskResult>);
    let mut pending: BTreeMap<String, TaskSpec> =
        specs.into_iter().map(|s| (s.id.clone(), s)).collect();
    let mut running: VecDeque<AsyncHandle> = VecDeque::new();
    let mut done: BTreeMap<String, TaskResult> = BTreeMap::new();
    let cancel_new = Arc::new(AtomicBool::new(false));
    let mut cancel_all_requested = false;
    let mut cancel_all_since: Option<std::time::Instant> = None;
    let mut forced_cancel_timeout = false;
    let mut active_log_viewer: Option<thread::JoinHandle<()>> = None;
    let mut journal_abort_reported = false;

    while !pending.is_empty() || !running.is_empty() {
        let mut made_progress = false;

        if !journal_abort_reported {
            if let Some(error) = event_tx.journal_error() {
                journal_abort_reported = true;
                cancel_all_requested = true;
                if cancel_all_since.is_none() {
                    cancel_all_since = Some(std::time::Instant::now());
                }
                cancel_new.store(true, Ordering::SeqCst);
                let _ = runtime_control.request_cancel_all();
                for pending_id in pending.keys() {
                    let _ = runtime_control.request_task_cancel(pending_id);
                }
                crate::ua_errln!(
                    "update-all: authoritative event journal failed; canceling the run: {error}"
                );
                made_progress = true;
            }
        }

        #[cfg(unix)]
        if let Some(rx) = sudo_keepalive_failure_rx.as_ref() {
            if let Ok(err) = rx.try_recv() {
                sudo_keepalive_failure_rx = None;
                cancel_all_requested = true;
                if cancel_all_since.is_none() {
                    cancel_all_since = Some(std::time::Instant::now());
                }
                cancel_new.store(true, Ordering::SeqCst);
                let running_ids = runtime_control.request_cancel_all();
                for task_id in running_ids {
                    emit_runtime_log(
                        &event_tx,
                        ctx.run_log.as_ref(),
                        &task_id,
                        "cancel-all requested (running process terminated)",
                    );
                }
                let pending_ids: Vec<String> = pending.keys().cloned().collect();
                for pending_id in pending_ids {
                    let _ = runtime_control.request_task_cancel(&pending_id);
                }
                emit_runtime_log(
                    &event_tx,
                    ctx.run_log.as_ref(),
                    "runtime",
                    "sudo session keepalive failed; canceling all tasks",
                );
                let detail = format!("sudo keepalive error: {err}");
                record_sudo_runtime_error(&ctx.privilege_session, detail.clone());
                emit_runtime_log(&event_tx, ctx.run_log.as_ref(), "runtime", &detail);
                made_progress = true;
            }
        }

        while let Ok(ctrl) = ui_control_rx.try_recv() {
            if !journal_ui_control(&event_tx, &ctrl) {
                made_progress = true;
                continue;
            }
            match ctrl {
                UiControlEvent::CancelTask { id } => {
                    let mut handled = false;

                    if let Some(spec) = pending.remove(&id) {
                        handled = true;
                        let result = TaskResult::canceled(spec.label, "canceled by user");
                        emit_task_outcome_log_async(&event_tx, ctx.run_log.as_ref(), &id, &result);
                        let _ = event_tx.send(DashboardEvent::TaskStateChanged {
                            id: id.clone(),
                            state: TaskState::Canceled,
                            detail: result.details.first().cloned(),
                        });
                        done.insert(id.clone(), result);
                        made_progress = true;
                    }

                    let running_task = running.iter().any(|(task_id, _, _)| task_id == &id);
                    let killed_running = runtime_control.request_task_cancel(&id);
                    if running_task {
                        handled = true;
                    }

                    emit_runtime_log(
                        &event_tx,
                        ctx.run_log.as_ref(),
                        &id,
                        if handled {
                            if killed_running {
                                "cancel requested (running process terminated)"
                            } else {
                                "cancel requested"
                            }
                        } else {
                            "cancel ignored: task is not pending/running"
                        },
                    );
                }
                UiControlEvent::CancelAll => {
                    cancel_all_requested = true;
                    if cancel_all_since.is_none() {
                        cancel_all_since = Some(std::time::Instant::now());
                    }
                    cancel_new.store(true, Ordering::SeqCst);
                    let running_ids = runtime_control.request_cancel_all();
                    for task_id in running_ids {
                        emit_runtime_log(
                            &event_tx,
                            ctx.run_log.as_ref(),
                            &task_id,
                            "cancel-all requested (running process terminated)",
                        );
                    }
                    let pending_ids: Vec<String> = pending.keys().cloned().collect();
                    for pending_id in pending_ids {
                        let _ = runtime_control.request_task_cancel(&pending_id);
                    }
                    emit_runtime_log(
                        &event_tx,
                        ctx.run_log.as_ref(),
                        "runtime",
                        "cancel-all requested",
                    );
                    made_progress = true;
                }
                UiControlEvent::SendStdin {
                    id,
                    generation,
                    line,
                } => {
                    let sent = submit_prompt_answer(
                        &event_tx,
                        &runtime_control,
                        &prompt_runtime,
                        &id,
                        generation,
                        line.clone(),
                    );
                    let detail = if sent {
                        format!("stdin line sent ({} chars)", line.chars().count())
                    } else {
                        "stdin send ignored: task is not accepting input".to_string()
                    };
                    let stream = if sent {
                        LogStream::Stdin
                    } else {
                        LogStream::Meta
                    };
                    emit_task_log(
                        &event_tx,
                        ctx.run_log.as_ref(),
                        &id,
                        LogLevel::Info,
                        stream,
                        detail,
                    );
                    made_progress = true;
                }
                UiControlEvent::RenameRun { name } => {
                    let trimmed = name.trim();
                    if trimmed.is_empty() {
                        emit_runtime_log(
                            &event_tx,
                            ctx.run_log.as_ref(),
                            "runtime",
                            "rename ignored: display name cannot be empty",
                        );
                    } else if let Some(run_log) = ctx.run_log.as_ref() {
                        match run_log.set_display_name(trimmed).and_then(|()| {
                            run_log.write_metadata(
                                "running",
                                Some(ctx.host_os.as_str()),
                                Some(ctx.ui.as_str()),
                                Some("async"),
                                selected_tasks.clone(),
                                now_unix_ms(),
                            )
                        }) {
                            Ok(()) => {
                                let display_name = run_log.display_name();
                                let _ = event_tx.send(DashboardEvent::RunRenamed {
                                    display_name: display_name.clone(),
                                });
                                emit_runtime_log(
                                    &event_tx,
                                    ctx.run_log.as_ref(),
                                    "runtime",
                                    &format!("run renamed to {display_name}"),
                                );
                            }
                            Err(err) => emit_runtime_log(
                                &event_tx,
                                ctx.run_log.as_ref(),
                                "runtime",
                                &format!("rename failed: {err}"),
                            ),
                        }
                    }
                    made_progress = true;
                }
                UiControlEvent::OpenLog { target } => {
                    handle_active_open_log_control(
                        &event_tx,
                        ctx.run_log.as_ref(),
                        target,
                        &mut active_log_viewer,
                    );
                    made_progress = true;
                }
            }
        }

        while running.len() < max_parallel_jobs {
            let busy_resources = running
                .iter()
                .flat_map(|(_, locks, _)| locks.iter().cloned())
                .collect::<BTreeSet<_>>();
            let ready = next_ready_task(&pending, &done, &busy_resources);
            let Some((task_id, spec)) = ready else {
                break;
            };
            let _ = pending.remove(&task_id);

            if cancel_new.load(Ordering::SeqCst) || cancel::is_cancel_requested() {
                let result = TaskResult::canceled(spec.label, "canceled before start");
                emit_task_outcome_log_async(&event_tx, ctx.run_log.as_ref(), &task_id, &result);
                let _ = event_tx.send(DashboardEvent::TaskStateChanged {
                    id: task_id.clone(),
                    state: TaskState::Canceled,
                    detail: result.details.first().cloned(),
                });
                done.insert(task_id, result);
                made_progress = true;
                continue;
            }

            let _ = event_tx.send(DashboardEvent::TaskStateChanged {
                id: task_id.clone(),
                state: TaskState::Running,
                detail: None,
            });
            if ctx.ui == UiModeResolved::Plain {
                crate::ua_outln!("[async] started {}", spec.label);
            }

            let task_ctx = ctx_clone_for_task(
                &ctx,
                Some(event_tx.clone()),
                Some(runtime_control.clone()),
                prompt_runtime.clone(),
            );
            let spawned_spec = spec.clone();
            let handle = thread::spawn(move || match execute_task(&task_ctx, &spawned_spec) {
                Ok(task_result) => task_result,
                Err(e) => {
                    if e.downcast_ref::<crate::Cancelled>().is_some() {
                        TaskResult::canceled(spawned_spec.label, "canceled by user")
                    } else {
                        failed_task_error_result(spawned_spec.label, spawned_spec.id, e.to_string())
                    }
                }
            });

            running.push_back((task_id, spec.resource_locks, handle));
            made_progress = true;
        }

        let blocked = blocked_by_failed_dependency(&pending, &done);
        for blocked_id in blocked {
            let Some(spec) = pending.remove(&blocked_id) else {
                continue;
            };
            let blocking_detail = dependency_blocking_detail(&spec, &done);
            emit_runtime_log(
                &event_tx,
                ctx.run_log.as_ref(),
                &blocked_id,
                &blocking_detail,
            );
            let result = TaskResult::canceled(spec.label, blocking_detail);
            emit_task_outcome_log_async(&event_tx, ctx.run_log.as_ref(), &blocked_id, &result);
            let _ = event_tx.send(DashboardEvent::TaskStateChanged {
                id: blocked_id.clone(),
                state: TaskState::Canceled,
                detail: result.details.first().cloned(),
            });
            done.insert(blocked_id, result);
            made_progress = true;
        }

        while let Some((finished_id, result)) = take_next_finished(&mut running) {
            emit_task_report_logs_async(
                &event_tx,
                ctx.run_log.as_ref(),
                &finished_id,
                &result.report_sections,
                ctx.note_verbosity,
            );
            emit_task_outcome_log_async(&event_tx, ctx.run_log.as_ref(), &finished_id, &result);
            let state = to_task_state(result.status);
            let detail = result.details.first().cloned();
            let _ = event_tx.send(DashboardEvent::TaskStateChanged {
                id: finished_id.clone(),
                state,
                detail,
            });
            if ctx.fail_fast && result.status == TaskStatus::Failed {
                cancel_new.store(true, Ordering::SeqCst);
            }
            done.insert(finished_id, result);
            made_progress = true;
        }

        if cancel_all_requested {
            if let Some(since) = cancel_all_since {
                if since.elapsed() >= ctx.quit_cancel_grace && !running.is_empty() {
                    forced_cancel_timeout = true;
                    let running_ids: Vec<String> = running
                        .iter()
                        .map(|(task_id, _, _)| task_id.as_str())
                        .map(str::to_string)
                        .collect();
                    for task_id in running_ids {
                        let _ = runtime_control.request_task_cancel(&task_id);
                        emit_runtime_log(
                            &event_tx,
                            ctx.run_log.as_ref(),
                            &task_id,
                            "cancel-all grace timeout reached; forcing shutdown",
                        );
                    }
                    break;
                }
            }
        }

        if !made_progress {
            thread::sleep(Duration::from_millis(20));
        }
    }

    if forced_cancel_timeout {
        for (task_id, _, handle) in running.drain(..) {
            let result = join_forced_canceled_task(task_id.clone(), handle);
            let state = to_task_state(result.status);
            let detail = result.details.first().cloned();
            emit_task_outcome_log_async(&event_tx, ctx.run_log.as_ref(), &task_id, &result);
            done.insert(task_id.clone(), result);
            let _ = event_tx.send(DashboardEvent::TaskStateChanged {
                id: task_id,
                state,
                detail,
            });
        }
        let pending_ids: Vec<String> = pending.keys().cloned().collect();
        for task_id in pending_ids {
            if let Some(spec) = pending.remove(&task_id) {
                let result =
                    TaskResult::canceled(spec.label, "canceled by forced shutdown after quit");
                emit_task_outcome_log_async(&event_tx, ctx.run_log.as_ref(), &task_id, &result);
                done.insert(task_id.clone(), result);
                let _ = event_tx.send(DashboardEvent::TaskStateChanged {
                    id: task_id,
                    state: TaskState::Canceled,
                    detail: Some("canceled by forced shutdown after quit".to_string()),
                });
            }
        }
    }

    #[cfg(unix)]
    if let Some(mut keepalive) = sudo_keepalive.take() {
        keepalive.stop_and_join();
        emit_runtime_log(
            &event_tx,
            ctx.run_log.as_ref(),
            "runtime",
            "sudo session keepalive stopped",
        );
    }

    let tasks_completed_at = Instant::now();
    let tasks_completed_unix_ms = now_unix_ms();
    drop(task_run_lock);

    if cancel_all_requested {
        emit_runtime_log(
            &event_tx,
            ctx.run_log.as_ref(),
            "runtime",
            "cancel-all teardown complete",
        );
    }

    let canceled = cancel_all_requested || cancel::is_cancel_requested();
    let journal_error = event_tx.journal_error();
    let failed = done.values().any(|r| r.status == TaskStatus::Failed) || journal_error.is_some();
    let deferred = done.values().any(TaskResult::is_deferred);
    let outcome = resolve_async_outcome(failed, deferred, canceled);
    let exit_code = match outcome {
        AsyncRunOutcome::Success => 0,
        AsyncRunOutcome::Failed => 1,
        AsyncRunOutcome::Deferred => 2,
        AsyncRunOutcome::Canceled => 3,
    };
    emit_async_completion_boundary_and_reports(
        &event_tx,
        ctx.run_log.as_ref(),
        done.iter().map(|(id, result)| (id.as_str(), result)),
        &task_categories,
        ctx.note_verbosity,
        ctx.debug_report,
        outcome,
        tasks_completed_at,
    );
    let tasks_ended_unix_ms = now_unix_ms();
    write_run_artifact(
        ctx.run_log.as_ref(),
        ctx.host_os.as_str(),
        ctx.ui.as_str(),
        "async",
        selected_tasks.clone(),
        done.iter().map(|(id, result)| (id.as_str(), result)),
        tasks_ended_unix_ms,
        exit_code,
        tasks_completed_unix_ms,
    );
    join_active_log_viewer(&mut active_log_viewer);

    let mut dashboard_unavailable = event_tx.is_detached();
    if ctx.ui == UiModeResolved::Dashboard {
        if ui_handle.is_none() {
            dashboard_unavailable = true;
            crate::ua_errln!("update-all: dashboard UI unavailable; using plain summary fallback");
        }
        if ctx.ui_persist_until_exit {
            if let Some(h) = ui_handle.take() {
                while !h.is_finished() {
                    let handled = drain_completed_run_ui_controls(
                        &ui_control_rx,
                        &event_tx,
                        ctx.run_log.as_ref(),
                    );
                    thread::sleep(if handled {
                        Duration::from_millis(2)
                    } else {
                        Duration::from_millis(20)
                    });
                }
                match h.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        dashboard_unavailable = true;
                        crate::ua_errln!("update-all: dashboard exited with error: {e}");
                    }
                    Err(_) => {
                        dashboard_unavailable = true;
                        crate::ua_errln!("update-all: dashboard thread panicked");
                    }
                }
            }
        } else if let Some(h) = ui_handle.take() {
            let _ = event_tx.send(DashboardEvent::UiDone);
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    dashboard_unavailable = true;
                    crate::ua_errln!("update-all: dashboard exited with error: {e}");
                }
                Err(_) => {
                    dashboard_unavailable = true;
                    crate::ua_errln!("update-all: dashboard thread panicked");
                }
            }
        }
    } else if let Some(h) = ui_handle.take() {
        let _ = event_tx.send(DashboardEvent::UiDone);
        match h.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                crate::ua_errln!("update-all: plain UI event drain exited with error: {e}");
            }
            Err(_) => {
                crate::ua_errln!("update-all: plain UI event drain thread panicked");
            }
        }
    }

    if ctx.ui == UiModeResolved::Plain || dashboard_unavailable {
        crate::ua_outln!("\nAsync Task Summary");
        for result in done.values() {
            print_async_task_line(&result.label, result);
        }
        print_end_of_run_reports(
            done.iter().map(|(id, result)| (id.as_str(), result)),
            &task_categories,
            ctx.note_verbosity,
            ctx.debug_report,
        );
    }

    write_run_artifact(
        ctx.run_log.as_ref(),
        ctx.host_os.as_str(),
        ctx.ui.as_str(),
        "async",
        selected_tasks,
        done.iter().map(|(id, result)| (id.as_str(), result)),
        tasks_ended_unix_ms,
        exit_code,
        tasks_completed_unix_ms,
    );

    if let Some(error) = event_tx.journal_error().or(journal_error) {
        bail!("authoritative event journal failed: {error}");
    }
    match outcome {
        AsyncRunOutcome::Success => Ok(()),
        AsyncRunOutcome::Failed => bail!("one or more tasks failed"),
        AsyncRunOutcome::Deferred => Err(anyhow::anyhow!(crate::Deferred)),
        AsyncRunOutcome::Canceled => Err(anyhow::anyhow!(crate::Cancelled)),
    }
}

fn drain_completed_run_ui_controls(
    ui_control_rx: &mpsc::Receiver<UiControlEvent>,
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
) -> bool {
    let mut handled = false;
    while let Ok(ctrl) = ui_control_rx.try_recv() {
        handle_completed_run_ui_control(ctrl, event_tx, run_log);
        handled = true;
    }
    handled
}

fn handle_completed_run_ui_control(
    ctrl: UiControlEvent,
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
) {
    match ctrl {
        UiControlEvent::OpenLog { target } => {
            if let Err(err) = open_requested_log_view(event_tx, run_log, &target) {
                emit_runtime_log(
                    event_tx,
                    run_log,
                    "runtime",
                    &format!("log viewer failed: {err}"),
                );
            }
        }
        UiControlEvent::CancelTask { id } => {
            emit_runtime_log(
                event_tx,
                run_log,
                &id,
                "cancel ignored: run already complete",
            );
        }
        UiControlEvent::CancelAll => {
            emit_runtime_log(
                event_tx,
                run_log,
                "runtime",
                "cancel-all ignored: run already complete",
            );
        }
        UiControlEvent::SendStdin { id, .. } => {
            emit_task_log(
                event_tx,
                run_log,
                &id,
                LogLevel::Info,
                LogStream::Meta,
                "stdin send ignored: run already complete".to_string(),
            );
        }
        UiControlEvent::RenameRun { name } => {
            let Some(run_log) = run_log else {
                return;
            };
            match run_log.set_display_name(&name).and_then(|()| {
                crate::runs::rename_metadata(run_log.run_dir(), &name, now_unix_ms()).map(|_| ())
            }) {
                Ok(()) => {
                    let display_name = run_log.display_name();
                    let _ = event_tx.send(DashboardEvent::RunRenamed {
                        display_name: display_name.clone(),
                    });
                    emit_runtime_log(
                        event_tx,
                        Some(run_log),
                        "runtime",
                        &format!("run renamed to {display_name}"),
                    );
                }
                Err(err) => emit_runtime_log(
                    event_tx,
                    Some(run_log),
                    "runtime",
                    &format!("rename failed: {err}"),
                ),
            }
        }
    }
}

fn handle_active_open_log_control(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    target: LogViewTarget,
    active_log_viewer: &mut Option<thread::JoinHandle<()>>,
) {
    if active_log_viewer
        .as_ref()
        .is_some_and(|handle| handle.is_finished())
    {
        if let Some(handle) = active_log_viewer.take() {
            let _ = handle.join();
        }
    }

    if active_log_viewer.is_some() {
        emit_runtime_log(
            event_tx,
            run_log,
            "runtime",
            "log viewer already open; close it before opening another",
        );
        return;
    }

    let Some(run_log_for_thread) = run_log.cloned() else {
        emit_runtime_log(
            event_tx,
            run_log,
            "runtime",
            "log viewer failed: run log directory is unavailable",
        );
        return;
    };

    let event_tx_for_thread = event_tx.clone();
    *active_log_viewer = Some(thread::spawn(move || {
        if let Err(err) =
            open_requested_log_view(&event_tx_for_thread, Some(&run_log_for_thread), &target)
        {
            emit_runtime_log(
                &event_tx_for_thread,
                Some(&run_log_for_thread),
                "runtime",
                &format!("log viewer failed: {err}"),
            );
        }
    }));
}

fn join_active_log_viewer(active_log_viewer: &mut Option<thread::JoinHandle<()>>) {
    if let Some(handle) = active_log_viewer.take() {
        let _ = handle.join();
    }
}

fn command_needs_sudo_session(cmd: &CommandTask) -> bool {
    cmd.requires_elevation || cmd.needs_sudo_session
}

fn command_supports_dashboard_input(cmd: &CommandTask, runtime: &InteractiveRuntimeConfig) -> bool {
    cmd.interactive
        && !cmd.external_window
        && !matches!(runtime.mode, InteractiveExecutionMode::DirectTty)
}

fn find_first_sudo_session_task(specs: &[TaskSpec]) -> Option<&TaskSpec> {
    specs.iter().find(|spec| {
        matches!(
            &spec.kind,
            TaskKind::Command(cmd) if command_needs_sudo_session(cmd)
        )
    })
}

fn maybe_prepare_sudo_session_before_run(ctx: &AsyncContext, specs: &[TaskSpec]) -> Result<bool> {
    #[cfg(unix)]
    {
        if !matches!(ctx.host_os, HostOs::Linux | HostOs::Macos) {
            return Ok(false);
        }
        let Some(spec) = find_first_sudo_session_task(specs) else {
            return Ok(false);
        };

        let decision = resolve_privilege_decision(
            ctx.updater_config.privilege_mode,
            ctx.host_os,
            &spec.label,
        )?;
        if !matches!(decision, PrivilegeDecision::Proceed) {
            return Ok(false);
        }

        // Authenticate before dashboard startup to avoid prompt/render contention.
        crate::ua_outln!("Preparing elevated session (sudo authentication required)...");
        let preflight_ctx = ctx_clone_for_task(ctx, None, None, Arc::new(PromptRuntime::default()));
        ensure_sudo_preflight_once(&preflight_ctx, spec)?;
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = (ctx, specs);
        Ok(false)
    }
}

#[cfg(unix)]
fn start_sudo_keepalive() -> Result<(SudoKeepalive, mpsc::Receiver<String>)> {
    let stop = Arc::new(AtomicBool::new(false));
    let active_pid = Arc::new(Mutex::new(None));
    let (failure_tx, failure_rx) = mpsc::channel::<String>();

    let stop_for_thread = stop.clone();
    let active_pid_for_thread = active_pid.clone();
    let handle = thread::Builder::new()
        .name("update-all-sudo-keepalive".to_string())
        .spawn(move || {
            while !stop_for_thread.load(Ordering::SeqCst) {
                let stop_for_cancel = stop_for_thread.clone();
                let active_pid_for_spawn = active_pid_for_thread.clone();
                let active_pid_for_exit = active_pid_for_thread.clone();
                let result = run_capture_streaming_controlled(
                    "sudo",
                    ["-n", "-v"],
                    Some(Duration::from_secs(15)),
                    false,
                    Arc::new(|_, _| {}),
                    Arc::new(move || stop_for_cancel.load(Ordering::SeqCst)),
                    Arc::new(move |pid| {
                        if let Ok(mut slot) = active_pid_for_spawn.lock() {
                            *slot = Some(pid);
                        }
                    }),
                    Arc::new(move || {
                        if let Ok(mut slot) = active_pid_for_exit.lock() {
                            *slot = None;
                        }
                    }),
                );

                if stop_for_thread.load(Ordering::SeqCst) {
                    break;
                }

                match result {
                    Ok(_) => {}
                    Err(e) => {
                        if e.downcast_ref::<crate::Cancelled>().is_some() {
                            break;
                        }
                        let _ = failure_tx.send(e.to_string());
                        break;
                    }
                }

                for _ in 0..225 {
                    if stop_for_thread.load(Ordering::SeqCst) {
                        return;
                    }
                    thread::sleep(Duration::from_millis(200));
                }
            }
        })
        .context("spawn sudo keepalive thread")?;

    Ok((
        SudoKeepalive {
            stop,
            active_pid,
            handle: Some(handle),
        },
        failure_rx,
    ))
}

fn open_requested_log_view(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    target: &LogViewTarget,
) -> Result<()> {
    let Some(run_log) = run_log else {
        bail!("run log directory is unavailable");
    };
    let target_path = match target {
        LogViewTarget::Task { id } => run_log
            .run_dir()
            .join(format!("task-{}.log", task_file_stem(id))),
        LogViewTarget::Run => run_log.run_dir().join("run.log"),
    };
    if !target_path.is_file() {
        bail!("log file not found: {}", target_path.display());
    }

    suspend_dashboard(
        event_tx,
        format!("opening log viewer for {}", target_path.display()),
    );
    let pager_result = run_log_pager(&target_path);
    resume_dashboard(event_tx);
    pager_result
}

fn suspend_dashboard(event_tx: &DashboardSender, reason: String) {
    let (ack_tx, ack_rx) = mpsc::channel::<()>();
    let _ = event_tx.send(DashboardEvent::UiSuspendRequested {
        reason,
        ack: Some(ack_tx),
    });
    let _ = ack_rx.recv_timeout(Duration::from_secs(2));
}

fn resume_dashboard(event_tx: &DashboardSender) {
    let (ack_tx, ack_rx) = mpsc::channel::<()>();
    let _ = event_tx.send(DashboardEvent::UiResumeRequested { ack: Some(ack_tx) });
    let _ = ack_rx.recv_timeout(Duration::from_secs(2));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogPagerKind {
    Less,
    Tail,
    Bat,
    More,
}

impl LogPagerKind {
    fn command_name(self) -> &'static str {
        match self {
            Self::Less => "less",
            Self::Tail => "tail",
            Self::Bat => "bat",
            Self::More => "more",
        }
    }
}

fn run_log_pager(path: &Path) -> Result<()> {
    let _signal_guard = cancel::suppress_signal_cancel();
    for kind in [
        LogPagerKind::Less,
        LogPagerKind::Tail,
        LogPagerKind::Bat,
        LogPagerKind::More,
    ] {
        if let Some(program) = which(kind.command_name()) {
            return run_log_pager_command(kind, &program, path);
        }
    }
    bail!("no supported pager found (need one of `less`, `bat`, `more`, or `tail`)")
}

fn run_log_pager_command(kind: LogPagerKind, program: &Path, path: &Path) -> Result<()> {
    let status = Command::new(program)
        .args(log_pager_args(kind, path))
        .status()
        .with_context(|| format!("launch {}", kind.command_name()))?;
    if status.success() {
        return Ok(());
    }
    bail!("{} exited with status {status}", kind.command_name())
}

fn log_pager_args(kind: LogPagerKind, path: &Path) -> Vec<OsString> {
    let path = path.as_os_str();
    match kind {
        LogPagerKind::Less => os_args(["+F", "-K", "-R", "-S"], path),
        LogPagerKind::Tail => os_args(["-n", "+1", "-f"], path),
        LogPagerKind::Bat => os_args(["--paging=always", "--style=plain"], path),
        LogPagerKind::More => vec![path.to_os_string()],
    }
}

fn os_args<const N: usize>(args: [&str; N], path: &OsStr) -> Vec<OsString> {
    args.into_iter()
        .map(OsString::from)
        .chain(std::iter::once(path.to_os_string()))
        .collect()
}

fn execute_task(ctx: &SyncContext, spec: &TaskSpec) -> Result<TaskResult> {
    match &spec.kind {
        TaskKind::Managed(ManagedTaskExecutor::Npm) => npm::task_npm_sync(ctx),
        TaskKind::Command(cmd) => run_command_task(ctx, spec, cmd),
        TaskKind::Managed(ManagedTaskExecutor::Completions) => task_completions(ctx, spec),
        TaskKind::Managed(ManagedTaskExecutor::WindowsFoundations { foundations }) => {
            task_bootstrap_windows_foundations(ctx, spec, foundations)
        }
    }
}

fn task_completions(ctx: &SyncContext, spec: &TaskSpec) -> Result<TaskResult> {
    if ctx.completions_mode == "off" {
        return Ok(TaskResult::skipped(
            spec.label.clone(),
            "completion sync disabled".to_string(),
        ));
    }

    ctx.log_line(
        &spec.id,
        LogLevel::Info,
        LogStream::Meta,
        format!(
            "completion-sync: providers={}, discover={}",
            ctx.completion_providers, ctx.completion_discover
        ),
    );
    if ctx.emit_plain {
        crate::ua_outln!("Completion Sync");
        crate::ua_outln!(
            "Refreshing managed completions (providers={}, discover={})...",
            ctx.completion_providers,
            ctx.completion_discover
        );
    }

    let sync = match ctx.completion_sync_for_task(&spec.id) {
        Ok(sync) => sync,
        Err(e) => {
            if e.downcast_ref::<crate::Cancelled>().is_some() {
                return Err(e);
            }
            let detail = format!(
                "[Completions] Sync failed using catalog {}: {e}",
                ctx.completion_catalog_path.display()
            );
            if ctx.completion_strict.eq_ignore_ascii_case("error") {
                return Ok(completion_sync_error_result(
                    spec.label.clone(),
                    TaskStatus::Failed,
                    detail,
                    &ctx.completion_providers,
                    &ctx.completion_catalog_path,
                ));
            }
            if ctx.emit_plain {
                crate::ua_errln!("{detail}");
            }
            ctx.log_line(&spec.id, LogLevel::Warn, LogStream::Meta, detail.clone());
            return Ok(completion_sync_error_result(
                spec.label.clone(),
                TaskStatus::Completed,
                detail,
                &ctx.completion_providers,
                &ctx.completion_catalog_path,
            ));
        }
    };

    let mut details = Vec::new();
    let sync_failed = sync
        .records
        .iter()
        .filter(|record| record.status == CompletionSyncRecordStatus::Failed)
        .count();
    if sync_failed > 0 {
        let sync_skipped = sync
            .records
            .iter()
            .filter(|record| record.status == CompletionSyncRecordStatus::Skipped)
            .count();
        details.push(format!(
            "[Completions] Sync {} generated, {} unchanged, {} skipped, {} failed",
            sync.generated, sync.unchanged, sync_skipped, sync_failed
        ));
    } else {
        details.push(format!(
            "[Completions] Sync {} generated, {} unchanged, {} skipped",
            sync.generated, sync.unchanged, sync.skipped
        ));
    }
    details.push(format!("[Completions] Outcome {}", sync.outcome.as_str()));
    let report_sections = completion_report_sections(&sync);

    details.push(format!(
        "strict={}, discover={}",
        ctx.completion_strict, ctx.completion_discover
    ));
    Ok(TaskResult {
        label: spec.label.clone(),
        status: TaskStatus::Completed,
        details,
        advisories: Vec::new(),
        report_sections,
    })
}

fn completion_sync_error_result(
    label: impl Into<String>,
    status: TaskStatus,
    detail: String,
    providers: &str,
    catalog_path: &Path,
) -> TaskResult {
    TaskResult {
        label: label.into(),
        status,
        details: vec![detail.clone()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "completion_generation".to_string(),
            title: "Completion Generation Results".to_string(),
            rows: vec![TaskReportRow {
                name: "completion-sync".to_string(),
                status: TaskReportStatus::Failed,
                before: Some(providers.to_string()),
                after: Some(catalog_path.display().to_string()),
                note: Some(detail),
            }],
        }],
    }
}

fn completion_report_sections(sync: &CompletionSyncResult) -> Vec<TaskReportSection> {
    let mut rows = sync
        .records
        .iter()
        .map(|record| {
            let status = match record.status {
                CompletionSyncRecordStatus::Generated | CompletionSyncRecordStatus::Retired => {
                    TaskReportStatus::Updated
                }
                CompletionSyncRecordStatus::Unchanged
                | CompletionSyncRecordStatus::ProbedUnchanged
                | CompletionSyncRecordStatus::Reused => TaskReportStatus::Unchanged,
                CompletionSyncRecordStatus::Retained => TaskReportStatus::Blocked,
                CompletionSyncRecordStatus::Shadowed => TaskReportStatus::Info,
                CompletionSyncRecordStatus::Skipped => TaskReportStatus::Skipped,
                CompletionSyncRecordStatus::Failed => TaskReportStatus::Failed,
            };
            let mut details = Vec::new();
            if let Some(reason) = &record.reason {
                let duplicates_outcome = matches!(
                    (record.status, reason.as_str()),
                    (CompletionSyncRecordStatus::Unchanged, "unchanged")
                        | (
                            CompletionSyncRecordStatus::ProbedUnchanged,
                            "probed_unchanged"
                        )
                        | (CompletionSyncRecordStatus::Reused, "reused")
                );
                if !duplicates_outcome {
                    details.push(reason.clone());
                }
            }
            if let Some(classification) = record.classification {
                details.push(format!("classification={}", classification.as_str()));
            }
            if let Some(recipe) = &record.recipe {
                details.push(format!("recipe={recipe}"));
            }
            TaskReportRow {
                name: record.tool.clone(),
                status,
                before: Some(record.provider.clone()),
                after: Some(record.artifact.clone().unwrap_or_else(|| "-".to_string())),
                note: (!details.is_empty()).then(|| details.join("; ")),
            }
        })
        .collect::<Vec<_>>();

    let records_already_report_behavior_change = sync.records.iter().any(|record| {
        matches!(
            record.status,
            CompletionSyncRecordStatus::Generated | CompletionSyncRecordStatus::Retired
        )
    });
    if !records_already_report_behavior_change
        && matches!(
            sync.outcome,
            crate::completions::CompletionSyncOutcome::Published
                | crate::completions::CompletionSyncOutcome::Removed
        )
    {
        rows.push(TaskReportRow {
            name: "managed-snapshot".to_string(),
            status: TaskReportStatus::Updated,
            before: Some("completion-state".to_string()),
            after: Some(sync.outcome.as_str().to_string()),
            note: Some(format!("shells={}", sync.shells.join(","))),
        });
    }
    if rows.is_empty() {
        return Vec::new();
    }

    vec![TaskReportSection {
        key: "completion_generation".to_string(),
        title: "Completion Generation Results".to_string(),
        rows,
    }]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InteractiveExecutionPath {
    Standard,
    DashboardManaged,
    ImmediateForeground,
    ForegroundReplay,
    ExternalWindow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalTerminalLauncher {
    Kitty,
    Konsole,
    WezTerm,
    Alacritty,
    GnomeTerminal,
    Xterm,
}

struct InteractiveTranscript {
    transcript_path: PathBuf,
    status_path: PathBuf,
    wrapper_path: PathBuf,
}

impl InteractiveTranscript {
    fn new(run_dir: &Path, task_id: &str) -> Result<Self> {
        let stem = format!("interactive-{}", task_file_stem(task_id));
        Ok(Self {
            transcript_path: run_dir.join(format!("{stem}.transcript.log")),
            status_path: run_dir.join(format!("{stem}.status")),
            wrapper_path: run_dir.join(format!("{stem}.sh")),
        })
    }
}

fn interactive_execution_path(host_os: HostOs, cmd: &CommandTask) -> InteractiveExecutionPath {
    if matches!(host_os, HostOs::Windows) && cmd.requires_elevation {
        return InteractiveExecutionPath::Standard;
    }
    if !cmd.interactive {
        return InteractiveExecutionPath::Standard;
    }
    if cmd.external_window {
        return InteractiveExecutionPath::ExternalWindow;
    }
    if command_needs_sudo_session(cmd) {
        return InteractiveExecutionPath::DashboardManaged;
    }
    InteractiveExecutionPath::DashboardManaged
}

fn detect_external_terminal_launcher() -> Option<ExternalTerminalLauncher> {
    if which("kitty").is_some() {
        return Some(ExternalTerminalLauncher::Kitty);
    }
    if which("konsole").is_some() {
        return Some(ExternalTerminalLauncher::Konsole);
    }
    if which("wezterm").is_some() {
        return Some(ExternalTerminalLauncher::WezTerm);
    }
    if which("alacritty").is_some() {
        return Some(ExternalTerminalLauncher::Alacritty);
    }
    if which("gnome-terminal").is_some() {
        return Some(ExternalTerminalLauncher::GnomeTerminal);
    }
    if which("xterm").is_some() {
        return Some(ExternalTerminalLauncher::Xterm);
    }
    None
}

fn shell_single_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn transcript_wrapper_script(
    transcript: &InteractiveTranscript,
    program: &str,
    args: &[String],
) -> String {
    let quoted_program = shell_single_quote(program);
    let quoted_args = args
        .iter()
        .map(|arg| shell_single_quote(arg))
        .collect::<Vec<_>>()
        .join(" ");
    let command = if quoted_args.is_empty() {
        quoted_program
    } else {
        format!("{quoted_program} {quoted_args}")
    };
    format!(
        concat!(
            "#!/usr/bin/env bash\n",
            "set +e\n",
            "set -o pipefail\n",
            "mkdir -p {run_dir}\n",
            ": > {transcript}\n",
            "rm -f {status}\n",
            "{command} 2>&1 | tee -a {transcript}\n",
            "code=${{PIPESTATUS[0]}}\n",
            "printf '%s\\n' \"$code\" > {status}\n",
            "exit \"$code\"\n"
        ),
        run_dir = shell_single_quote(
            transcript
                .transcript_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_string_lossy()
                .as_ref()
        ),
        transcript = shell_single_quote(transcript.transcript_path.to_string_lossy().as_ref()),
        status = shell_single_quote(transcript.status_path.to_string_lossy().as_ref()),
        command = command,
    )
}

fn write_interactive_transcript_wrapper(
    ctx: &SyncContext,
    task_id: &str,
    program: &str,
    args: &[String],
) -> Result<InteractiveTranscript> {
    let run_dir = ctx
        .run_log
        .as_ref()
        .map(|log| log.run_dir().to_path_buf())
        .unwrap_or_else(std::env::temp_dir);
    let transcript = InteractiveTranscript::new(&run_dir, task_id)?;
    let _ = fs::remove_file(&transcript.status_path);
    let script = transcript_wrapper_script(&transcript, program, args);
    fs::write(&transcript.wrapper_path, script)
        .with_context(|| format!("write {}", transcript.wrapper_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&transcript.wrapper_path)
            .with_context(|| format!("stat {}", transcript.wrapper_path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&transcript.wrapper_path, perms)
            .with_context(|| format!("chmod {}", transcript.wrapper_path.display()))?;
    }
    Ok(transcript)
}

fn launch_external_terminal(
    launcher: ExternalTerminalLauncher,
    title: &str,
    cwd: &Path,
    wrapper_path: &Path,
) -> Result<Child> {
    match launcher {
        ExternalTerminalLauncher::Kitty => Command::new("kitty")
            .arg("--title")
            .arg(title)
            .arg("--directory")
            .arg(cwd)
            .arg("bash")
            .arg(wrapper_path)
            .spawn()
            .context("spawn kitty"),
        ExternalTerminalLauncher::Konsole => Command::new("konsole")
            .arg("--separate")
            .arg("--workdir")
            .arg(cwd)
            .arg("-p")
            .arg(format!("TabTitle={title}"))
            .arg("-e")
            .arg("bash")
            .arg(wrapper_path)
            .spawn()
            .context("spawn konsole"),
        ExternalTerminalLauncher::WezTerm => Command::new("wezterm")
            .arg("start")
            .arg("--cwd")
            .arg(cwd)
            .arg("bash")
            .arg(wrapper_path)
            .spawn()
            .context("spawn wezterm"),
        ExternalTerminalLauncher::Alacritty => Command::new("alacritty")
            .arg("--title")
            .arg(title)
            .arg("--working-directory")
            .arg(cwd)
            .arg("-e")
            .arg("bash")
            .arg(wrapper_path)
            .spawn()
            .context("spawn alacritty"),
        ExternalTerminalLauncher::GnomeTerminal => Command::new("gnome-terminal")
            .arg("--title")
            .arg(title)
            .arg("--working-directory")
            .arg(cwd)
            .arg("--")
            .arg("bash")
            .arg(wrapper_path)
            .spawn()
            .context("spawn gnome-terminal"),
        ExternalTerminalLauncher::Xterm => Command::new("xterm")
            .arg("-T")
            .arg(title)
            .arg("-e")
            .arg("bash")
            .arg(wrapper_path)
            .spawn()
            .context("spawn xterm"),
    }
}

fn wait_for_interactive_status(
    ctx: &SyncContext,
    task_id: &str,
    status_path: &Path,
    mut launcher_child: Option<&mut Child>,
) -> Result<i32> {
    loop {
        if let Ok(text) = fs::read_to_string(status_path) {
            if let Ok(code) = text.trim().parse::<i32>() {
                return Ok(code);
            }
        }
        if cancel::is_cancel_requested()
            || ctx
                .runtime_control
                .as_ref()
                .is_some_and(|rt| rt.should_cancel(task_id))
        {
            if let Some(child) = launcher_child.as_mut() {
                let _ = child.kill();
            }
            bail!(crate::Cancelled);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn replay_interactive_transcript(
    ctx: &SyncContext,
    task_id: &str,
    transcript_path: &Path,
) -> Result<String> {
    let transcript = fs::read_to_string(transcript_path)
        .with_context(|| format!("read {}", transcript_path.display()))?;
    for line in transcript.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let level = classify_stream_level(StreamKind::Stdout, line);
        ctx.log_line(task_id, level, LogStream::Stdout, line.to_string());
    }
    Ok(transcript)
}

fn run_command_with_transcript(
    ctx: &SyncContext,
    task_id: &str,
    policy: &TaskPolicy,
    program: &str,
    args: &[String],
    execution_path: InteractiveExecutionPath,
) -> Result<String> {
    let transcript = write_interactive_transcript_wrapper(ctx, task_id, program, args)?;
    match execution_path {
        InteractiveExecutionPath::DashboardManaged => {
            ctx.log_line(
                task_id,
                LogLevel::Info,
                LogStream::Meta,
                "interactive execution via dashboard input".to_string(),
            );
            ctx.run_command_with_policy(task_id, program, args.to_vec(), policy, true)
        }
        InteractiveExecutionPath::ImmediateForeground => {
            ctx.log_line(
                task_id,
                LogLevel::Info,
                LogStream::Meta,
                "interactive execution via immediate-foreground-tty".to_string(),
            );
            let wrapper_program = transcript.wrapper_path.to_string_lossy().to_string();
            let run_result = ctx.run_command_with_policy_direct_tty(
                task_id,
                &wrapper_program,
                Vec::new(),
                policy,
            );
            let transcript_out =
                replay_interactive_transcript(ctx, task_id, &transcript.transcript_path)?;
            run_result.map(|_| transcript_out)
        }
        InteractiveExecutionPath::ExternalWindow => {
            if let Some(launcher) = detect_external_terminal_launcher() {
                ctx.log_line(
                    task_id,
                    LogLevel::Info,
                    LogStream::Meta,
                    format!("interactive execution via popup-window ({launcher:?})"),
                );
                let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let launch = launch_external_terminal(
                    launcher,
                    &format!("update-all input: {task_id}"),
                    &cwd,
                    &transcript.wrapper_path,
                );
                let mut child = match launch {
                    Ok(child) => child,
                    Err(err) => {
                        ctx.log_line(
                            task_id,
                            LogLevel::Warn,
                            LogStream::Meta,
                            format!("popup-window launch failed: {err}; falling back to foreground replay"),
                        );
                        return run_command_with_transcript(
                            ctx,
                            task_id,
                            policy,
                            program,
                            args,
                            InteractiveExecutionPath::ForegroundReplay,
                        );
                    }
                };
                let code = wait_for_interactive_status(
                    ctx,
                    task_id,
                    &transcript.status_path,
                    Some(&mut child),
                )?;
                let transcript_out =
                    replay_interactive_transcript(ctx, task_id, &transcript.transcript_path)?;
                if code == 0 {
                    return Ok(transcript_out);
                }
                bail!("{program} exited non-zero (code={code})");
            }
            ctx.log_line(
                task_id,
                LogLevel::Warn,
                LogStream::Meta,
                "popup-window unavailable; falling back to foreground replay".to_string(),
            );
            run_command_with_transcript(
                ctx,
                task_id,
                policy,
                program,
                args,
                InteractiveExecutionPath::ForegroundReplay,
            )
        }
        InteractiveExecutionPath::ForegroundReplay => {
            ctx.log_line(
                task_id,
                LogLevel::Info,
                LogStream::Meta,
                "interactive execution via foreground-fallback".to_string(),
            );
            let wrapper_program = transcript.wrapper_path.to_string_lossy().to_string();
            let run_result =
                ctx.run_command_with_policy(task_id, &wrapper_program, Vec::new(), policy, true);
            let transcript_out =
                replay_interactive_transcript(ctx, task_id, &transcript.transcript_path)?;
            run_result.map(|_| transcript_out)
        }
        InteractiveExecutionPath::Standard => {
            ctx.run_command_with_policy(task_id, program, args.to_vec(), policy, false)
        }
    }
}

fn resolve_command_task(ctx: &SyncContext, cmd: &CommandTask) -> Option<CommandTask> {
    if cmd.command_candidates.is_empty()
        || cmd.shell
        || command_program_path(&cmd.program, ctx.host_os).is_some()
    {
        let mut direct = cmd.clone();
        direct.command_candidates.clear();
        return Some(direct);
    }

    cmd.command_candidates
        .iter()
        .find(|candidate| command_candidate_is_available(candidate, ctx.host_os))
        .map(|candidate| {
            let mut selected = cmd.clone();
            selected.program = candidate.program.clone();
            selected.args = candidate.args.clone();
            selected.mode = candidate.mode.clone();
            selected.command_candidates.clear();
            selected
        })
}

fn render_command_template(input: &str, mode: Option<&str>) -> String {
    input.replace("{mode}", mode.unwrap_or(DIRECT_COMMAND_MODE))
}

fn run_command_execution(
    ctx: &SyncContext,
    task_id: &str,
    policy: &TaskPolicy,
    program: &str,
    args: &[String],
    execution_path: InteractiveExecutionPath,
    effective_interactive: bool,
) -> Result<String> {
    if matches!(execution_path, InteractiveExecutionPath::Standard) {
        ctx.run_command_with_policy(
            task_id,
            program,
            args.to_vec(),
            policy,
            effective_interactive,
        )
    } else {
        run_command_with_transcript(ctx, task_id, policy, program, args, execution_path)
    }
}

fn run_command_task(ctx: &SyncContext, spec: &TaskSpec, cmd: &CommandTask) -> Result<TaskResult> {
    let mut command = cmd.clone();
    let mut authority_outcome: Option<package_authority::PackageAuthorityOutcome> = None;
    let mut authority_errors = Vec::new();
    let uses_linux_pacman = ctx.host_os == HostOs::Linux
        && package_manager_kind_for_task(&spec.id, &cmd.program) == PackageManagerKind::PacmanLike;
    if uses_linux_pacman {
        for backend in ["pacman", "aur"] {
            match package_authority::reconcile_for_task(ctx, backend, Vec::new(), false) {
                Ok(outcome) => {
                    if let Some(existing) = authority_outcome.as_mut() {
                        existing.merge(outcome);
                    } else {
                        authority_outcome = Some(outcome);
                    }
                }
                Err(error) => {
                    let detail = format!("package-provider reconciliation skipped: {error}");
                    ctx.log_line(&spec.id, LogLevel::Warn, LogStream::Meta, detail.clone());
                    authority_errors.push(detail);
                }
            }
        }
        if let Some(outcome) = authority_outcome.as_ref() {
            if !outcome.excluded_packages.is_empty() {
                command.args = append_ignore_args(&command.args, &outcome.excluded_packages);
            }
        }
    }

    let mut result = run_command_task_inner(ctx, spec, &command)?;
    if uses_linux_pacman && result.status == TaskStatus::Failed {
        let mut repaired_after_failure = false;
        for backend in ["pacman", "aur"] {
            match package_authority::reconcile_for_task(ctx, backend, Vec::new(), false) {
                Ok(outcome) => {
                    repaired_after_failure = repaired_after_failure || outcome.changed;
                    if let Some(existing) = authority_outcome.as_mut() {
                        existing.merge(outcome);
                    } else {
                        authority_outcome = Some(outcome);
                    }
                }
                Err(error) => {
                    let detail =
                        format!("post-failure package-provider reconciliation skipped: {error}");
                    ctx.log_line(&spec.id, LogLevel::Warn, LogStream::Meta, detail.clone());
                    authority_errors.push(detail);
                }
            }
        }
        if repaired_after_failure {
            if let Some(outcome) = authority_outcome.as_ref() {
                command.args = append_ignore_args(&command.args, &outcome.excluded_packages);
            }
            result = run_command_task_inner(ctx, spec, &command)?;
            result.details.push(
                "Retried the package-manager task after catalog-driven provider reconciliation."
                    .to_string(),
            );
        }
    }
    if let Some(outcome) = authority_outcome.as_ref() {
        if let Some(section) = package_authority::report_section(outcome) {
            result.report_sections.push(section);
        }
    }
    for detail in authority_errors {
        result.advisories.push(TaskAdvisory {
            severity: AdvisorySeverity::Warning,
            code: "package-authority-unavailable".to_string(),
            summary: "Package-provider reconciliation was unavailable".to_string(),
            remediation: detail,
            blocks_dependents: false,
        });
    }
    Ok(result)
}

fn run_command_task_inner(
    ctx: &SyncContext,
    spec: &TaskSpec,
    cmd: &CommandTask,
) -> Result<TaskResult> {
    let Some(cmd) = resolve_command_task(ctx, cmd) else {
        return Ok(TaskResult::skipped(
            spec.label.clone(),
            "no command candidate available".to_string(),
        ));
    };

    if cmd.external_manager_skip {
        if let Some(result) = preflight_external_manager_skip(ctx.host_os, spec, &cmd.program) {
            return Ok(result);
        }
    }

    if command_needs_sudo_session(&cmd) {
        if let Some(err) = sudo_runtime_error(&ctx.privilege_session) {
            return Ok(TaskResult::failed(
                spec.label.clone(),
                format!(
                    "sudo session is unavailable before launch: {err}; rerun update-all and complete sudo authentication again"
                ),
            ));
        }
        let decision = resolve_privilege_decision(
            ctx.updater_config.privilege_mode,
            ctx.host_os,
            &spec.label,
        )?;
        match decision {
            PrivilegeDecision::Proceed => {
                if let Err(e) = ensure_sudo_session_fresh(ctx, spec, &cmd) {
                    return Ok(TaskResult::failed(spec.label.clone(), e.to_string()));
                }
            }
            PrivilegeDecision::Skip(msg) => {
                return Ok(TaskResult::skipped(spec.label.clone(), msg));
            }
            PrivilegeDecision::Fail(msg) => {
                return Ok(TaskResult::failed(spec.label.clone(), msg));
            }
        }
    }

    let policy = ctx
        .task_policies
        .by_key(&cmd.policy_key, TaskPolicy::new(1800, 0, 0));
    let execution_path = interactive_execution_path(ctx.host_os, &cmd);
    let effective_interactive = !matches!(execution_path, InteractiveExecutionPath::Standard);

    if ctx.emit_plain {
        if let Some(header) = &cmd.plain_header {
            crate::ua_outln!("{}", render_command_template(header, cmd.mode.as_deref()));
        }
        if let Some(start) = &cmd.plain_start {
            crate::ua_outln!("{}", render_command_template(start, cmd.mode.as_deref()));
        }
    }

    let pre_output = match run_command_pre_commands(ctx, spec, &cmd, &policy)? {
        PreCommandOutcome::Continue(output) => output,
        PreCommandOutcome::Stop(result) => return Ok(result),
    };
    let before_report_output = append_command_report_outputs(
        ctx,
        &spec.id,
        &cmd.report_commands,
        "",
        &policy,
        CommandReportPhase::Before,
    );

    let (program, args) = build_command_invocation(ctx.host_os, &cmd);
    ctx.log_line(
        &spec.id,
        LogLevel::Info,
        LogStream::Meta,
        command_log_line(ctx.host_os, &cmd, &program, &args),
    );
    if matches!(ctx.host_os, HostOs::Windows) && cmd.requires_elevation && cmd.interactive {
        ctx.log_line(
            &spec.id,
            LogLevel::Info,
            LogStream::Meta,
            "windows elevated command: interactive capture disabled; waiting for UAC/elevated child"
                .to_string(),
        );
    }

    let out = match run_command_execution(
        ctx,
        &spec.id,
        &policy,
        &program,
        &args,
        execution_path,
        effective_interactive,
    ) {
        Ok(out) => out,
        Err(e) => {
            let err_text = if let Some(output) = process_exit_output(&e) {
                output.to_string()
            } else {
                e.to_string()
            };
            if let Some(partial) = classify_partial_winget_result(spec, &err_text) {
                return Ok(partial);
            }
            if cmd.external_manager_skip && is_external_manager_self_update_unsupported(&err_text) {
                let command_name = command_display_name(&cmd.program);
                let mut result = TaskResult::skipped(
                    spec.label.clone(),
                    format!(
                        "{} self update unsupported for this install method; update it via package manager",
                        command_name
                    ),
                );
                result.advisories.push(TaskAdvisory {
                    severity: AdvisorySeverity::Info,
                    code: "external-manager-skip".to_string(),
                    summary: format!("{command_name} is managed by an external package manager"),
                    remediation: format!(
                        "Update {command_name} through the system package manager instead of running self update."
                    ),
                    blocks_dependents: false,
                });
                attach_external_manager_skip_report(&mut result, &program, &command_name);
                return Ok(result);
            }
            let class = classify_runtime_failure(&err_text, cmd.requires_elevation);
            if class == RuntimeFailureClass::SudoSessionUnavailable
                && command_needs_sudo_session(&cmd)
            {
                ctx.log_line(
                    &spec.id,
                    LogLevel::Warn,
                    LogStream::Meta,
                    "sudo session unavailable at command launch; refreshing sudo session and retrying once".to_string(),
                );
                if let Err(refresh_err) = refresh_sudo_session_after_launch_failure(ctx, spec) {
                    return Ok(TaskResult::failed(
                        spec.label.clone(),
                        refresh_err.to_string(),
                    ));
                }
                match run_command_execution(
                    ctx,
                    &spec.id,
                    &policy,
                    &program,
                    &args,
                    execution_path,
                    effective_interactive,
                ) {
                    Ok(out) => {
                        ctx.log_line(
                            &spec.id,
                            LogLevel::Info,
                            LogStream::Meta,
                            "sudo session refresh retry succeeded".to_string(),
                        );
                        out
                    }
                    Err(retry_err) => {
                        let retry_text = if let Some(output) = process_exit_output(&retry_err) {
                            output.to_string()
                        } else {
                            retry_err.to_string()
                        };
                        return Ok(failed_command_result_with_report_sections(
                            spec.label.clone(),
                            build_command_failure_detail(spec, &cmd, &program, &retry_text),
                            &cmd,
                            &retry_text,
                        ));
                    }
                }
            } else {
                if class == RuntimeFailureClass::UserCanceledElevation {
                    return Ok(user_canceled_elevation_result(spec.label.clone()));
                }
                if class == RuntimeFailureClass::ElevationDenied {
                    return Ok(TaskResult::skipped(
                        spec.label.clone(),
                        build_elevation_required_detail(spec),
                    ));
                }
                let recovery_plan = classify_package_recovery(
                    package_manager_kind_for_command(spec, &cmd, &program),
                    &err_text,
                );
                if let Some(recovery_result) = try_recover_verified_repository_retirement(
                    ctx,
                    spec,
                    &cmd,
                    &args,
                    &policy,
                    effective_interactive,
                    &err_text,
                    recovery_plan.as_ref(),
                )? {
                    return Ok(recovery_result);
                }
                if let Some(recovery_result) = try_recover_yay_conflicts(
                    ctx,
                    spec,
                    &cmd,
                    &program,
                    &args,
                    &policy,
                    effective_interactive,
                    &err_text,
                    recovery_plan.as_ref(),
                )? {
                    return Ok(recovery_result);
                }
                if recovery_plan
                    .as_ref()
                    .is_some_and(|plan| plan.actions.contains(&RecoveryAction::RetryWhole))
                    && class == RuntimeFailureClass::TransientLockOrBusy
                {
                    ctx.log_line(
                        &spec.id,
                        LogLevel::Warn,
                        LogStream::Meta,
                        "package recovery classified lock/busy output for whole-command retry"
                            .to_string(),
                    );
                }
                if let Some(detail) = format_package_manager_timeout_failure(
                    spec,
                    &cmd,
                    &policy,
                    ctx.run_log.as_ref().map(Arc::as_ref),
                    &err_text,
                ) {
                    return Ok(failed_command_result_with_report_sections(
                        spec.label.clone(),
                        detail,
                        &cmd,
                        &err_text,
                    ));
                }
                if let Some(plan) = recovery_plan {
                    if plan.actions.contains(&RecoveryAction::DiagnoseOnly) {
                        let mut result = TaskResult::failed(
                            spec.label.clone(),
                            build_package_recovery_diagnostic_detail(
                                plan.kind.label(),
                                &plan.causes,
                                &err_text,
                            ),
                        );
                        result.report_sections =
                            build_failed_command_report_sections_for_command(&cmd, &err_text);
                        result.report_sections.push(TaskReportSection {
                            key: package_recovery_section_key().to_string(),
                            title: package_recovery_section_title().to_string(),
                            rows: recovery_diagnostic_rows(plan.kind.label(), &plan.causes),
                        });
                        attach_command_output_diagnostics(&mut result, &err_text);
                        return Ok(result);
                    }
                }
                if let Some(detail) = format_package_manager_failure(&err_text) {
                    return Ok(failed_command_result_with_report_sections(
                        spec.label.clone(),
                        detail,
                        &cmd,
                        &err_text,
                    ));
                }
                if class == RuntimeFailureClass::TransientLockOrBusy {
                    let retry_delay = transient_retry_backoff(policy.retry_backoff, 0);
                    ctx.log_line(
                        &spec.id,
                        LogLevel::Warn,
                        LogStream::Meta,
                        format!(
                            "transient lock/busy failure detected; retrying in {}",
                            format_retry_delay(retry_delay)
                        ),
                    );
                    thread::sleep(retry_delay);
                    match ctx.run_command_with_policy(
                        &spec.id,
                        &program,
                        args,
                        &policy,
                        effective_interactive,
                    ) {
                        Ok(out) => {
                            ctx.log_line(
                                &spec.id,
                                LogLevel::Info,
                                LogStream::Meta,
                                "transient retry succeeded".to_string(),
                            );
                            out
                        }
                        Err(retry_err) => {
                            let retry_text = if let Some(output) = process_exit_output(&retry_err) {
                                output.to_string()
                            } else {
                                retry_err.to_string()
                            };
                            return Ok(failed_command_result_with_report_sections(
                                spec.label.clone(),
                                build_command_failure_detail(spec, &cmd, &program, &retry_text),
                                &cmd,
                                &retry_text,
                            ));
                        }
                    }
                } else {
                    return Ok(failed_command_result_with_report_sections(
                        spec.label.clone(),
                        build_command_failure_detail(spec, &cmd, &program, &err_text),
                        &cmd,
                        &err_text,
                    ));
                }
            }
        }
    };

    if ctx.emit_plain {
        crate::ua_out!("{out}");
    }

    let primary_report_input = join_command_outputs(&pre_output, &out);
    let after_report_output = append_command_report_outputs(
        ctx,
        &spec.id,
        &cmd.report_commands,
        &primary_report_input,
        &policy,
        CommandReportPhase::After,
    );
    let mut probe_rows = before_report_output.probe_rows;
    probe_rows.extend(after_report_output.probe_rows);
    let mut state_samples = before_report_output.state_samples;
    state_samples.extend(after_report_output.state_samples);
    let mut report_sections =
        build_command_report_sections_for_command(&cmd, &after_report_output.input);
    merge_report_sections(
        &mut report_sections,
        build_command_state_report_sections(state_samples),
    );
    if let Some(section) = command_report_probe_section(probe_rows) {
        report_sections.push(section);
    }
    if let Some(output_failure) = detect_command_output_failure(&cmd, &out) {
        let detail = build_command_failure_detail(
            spec,
            &cmd,
            &program,
            &format!("detected failure output: {output_failure}"),
        );
        ctx.log_line(
            &spec.id,
            LogLevel::Error,
            LogStream::Meta,
            format!("output indicated failure: {output_failure}"),
        );
        mark_unconfirmed_command_report_sections(&cmd, &mut report_sections, &primary_report_input);
        let mut result = TaskResult::failed(spec.label.clone(), detail);
        result.report_sections = report_sections;
        attach_command_output_diagnostics(&mut result, &primary_report_input);
        return Ok(result);
    }

    let mut result = TaskResult::completed(spec.label.clone());
    result.details.extend(
        cmd.success_details
            .iter()
            .map(|detail| render_command_template(detail, cmd.mode.as_deref())),
    );
    result.report_sections = report_sections;
    attach_command_output_diagnostics(&mut result, &after_report_output.input);
    attach_command_advisories(&mut result);
    let structured_result_applied = apply_structured_command_result(&mut result, &out);
    if cmd.result_protocol.is_some() && !structured_result_applied {
        result.status = TaskStatus::Failed;
        result.details.insert(
            0,
            "required structured result protocol was absent or invalid".to_string(),
        );
    }
    Ok(result)
}

const STRUCTURED_RESULT_PREFIX: &str = "UPDATE_ALL_RESULT ";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StructuredCommandResult {
    outcome: String,
    detail: Option<String>,
    current: Option<String>,
    latest: Option<String>,
}

fn parse_structured_command_result(output: &str) -> Option<StructuredCommandResult> {
    output.lines().rev().find_map(|line| {
        let payload = line.trim().strip_prefix(STRUCTURED_RESULT_PREFIX)?;
        if payload.len() > STRUCTURED_TEXT_LIMIT_BYTES {
            return None;
        }
        serde_json::from_str(payload).ok()
    })
}

fn apply_structured_command_result(result: &mut TaskResult, output: &str) -> bool {
    let Some(protocol) = parse_structured_command_result(output) else {
        return false;
    };
    let detail = protocol
        .detail
        .filter(|detail| !detail.trim().is_empty())
        .unwrap_or_else(|| protocol.outcome.replace('_', " "));
    if !result.details.iter().any(|existing| existing == &detail) {
        result.details.insert(0, detail.clone());
    }
    match protocol.outcome.as_str() {
        "deferred" => result.advisories.push(TaskAdvisory {
            severity: AdvisorySeverity::Info,
            code: "deferred".to_string(),
            summary: detail,
            remediation: "retry when the blocking runtime condition is clear".to_string(),
            blocks_dependents: false,
        }),
        "failed" | "blocked" => {
            result.status = TaskStatus::Failed;
        }
        "updated" | "no_op" | "not_applicable" | "cancelled" => {}
        _ => {
            result.status = TaskStatus::Failed;
            result.details.insert(
                0,
                format!("invalid structured command outcome '{}'", protocol.outcome),
            );
        }
    }
    if let (Some(current), Some(latest)) = (protocol.current, protocol.latest) {
        result
            .details
            .push(format!("version: {current} -> {latest}"));
    }
    true
}

fn failed_command_result_with_report_sections(
    label: impl Into<String>,
    detail: impl Into<String>,
    cmd: &CommandTask,
    output: &str,
) -> TaskResult {
    let detail = detail.into();
    let mut result = TaskResult::failed(label, detail.clone());
    result.report_sections = build_failed_command_report_sections_for_command(cmd, output);
    attach_command_output_diagnostics(&mut result, output);
    if result.report_sections.is_empty() {
        result.report_sections.push(TaskReportSection {
            key: "task_failures".to_string(),
            title: "Task Failure Results".to_string(),
            rows: vec![TaskReportRow {
                name: command_display_name(&cmd.program),
                status: TaskReportStatus::Failed,
                before: Some("-".to_string()),
                after: Some("-".to_string()),
                note: Some(detail),
            }],
        });
    }
    result
}

fn attach_command_output_diagnostics(result: &mut TaskResult, output: &str) {
    let Some(section) = command_diagnostic_report_section(output) else {
        return;
    };
    let diagnostic_count = section.rows.len();
    result.report_sections.push(section);
    if result.status == TaskStatus::Completed
        && !result
            .advisories
            .iter()
            .any(|advisory| advisory.code == "command-output-diagnostics")
    {
        result.advisories.push(TaskAdvisory {
            severity: AdvisorySeverity::Warning,
            code: "command-output-diagnostics".to_string(),
            summary: format!(
                "command output included {diagnostic_count} warning/error diagnostics"
            ),
            remediation:
                "Review the command diagnostics section and raw task log for full context."
                    .to_string(),
            blocks_dependents: false,
        });
    }
}

fn command_diagnostic_report_section(output: &str) -> Option<TaskReportSection> {
    let rows = command_diagnostic_rows(output);
    (!rows.is_empty()).then(|| TaskReportSection {
        key: "command_diagnostics".to_string(),
        title: "Command Diagnostics".to_string(),
        rows,
    })
}

fn command_diagnostic_rows(output: &str) -> Vec<TaskReportRow> {
    let mut samples = Vec::<CommandDiagnosticSample>::new();
    for raw_line in strip_ansi(output).replace('\r', "\n").lines() {
        let Some((kind, normalized)) = command_diagnostic_sample(raw_line) else {
            continue;
        };
        if let Some(sample) = samples
            .iter_mut()
            .find(|sample| sample.kind == kind && sample.key == normalized.key)
        {
            sample.count += 1;
            continue;
        }
        samples.push(CommandDiagnosticSample {
            kind,
            key: normalized.key,
            text: normalized.text,
            count: 1,
        });
    }
    samples
        .into_iter()
        .take(COMMAND_DIAGNOSTIC_SAMPLE_LIMIT)
        .map(|sample| {
            let note = if sample.count > 1 {
                format!("{} ({} occurrences)", sample.text, sample.count)
            } else {
                sample.text
            };
            TaskReportRow {
                name: sample.kind.to_string(),
                status: TaskReportStatus::Info,
                before: Some("emitted".to_string()),
                after: Some("captured".to_string()),
                note: Some(note),
            }
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandDiagnosticSample {
    kind: &'static str,
    key: String,
    text: String,
    count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NormalizedCommandDiagnostic {
    key: String,
    text: String,
}

fn command_diagnostic_sample(line: &str) -> Option<(&'static str, NormalizedCommandDiagnostic)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("no debugging symbols") {
        return Some((
            "warning",
            NormalizedCommandDiagnostic {
                key: "no-debugging-symbols".to_string(),
                text: trimmed.to_string(),
            },
        ));
    }
    if is_warning_diagnostic_line(&lower) {
        return Some((
            "warning",
            NormalizedCommandDiagnostic {
                key: lower,
                text: trimmed.to_string(),
            },
        ));
    }
    if is_error_diagnostic_line(&lower) {
        return Some((
            "error",
            NormalizedCommandDiagnostic {
                key: lower,
                text: trimmed.to_string(),
            },
        ));
    }
    None
}

fn is_warning_diagnostic_line(lower: &str) -> bool {
    lower.starts_with("warning:")
        || lower.starts_with("warn:")
        || lower.starts_with("warn ")
        || lower.starts_with("npm warn")
        || lower.starts_with("==> warning:")
}

fn is_error_diagnostic_line(lower: &str) -> bool {
    lower.starts_with("error:")
        || lower.starts_with("error ")
        || lower.starts_with("==> error:")
        || lower.starts_with("==> error ")
        || lower.starts_with("fatal:")
        || lower.starts_with("fatal ")
        || lower.starts_with("panic:")
        || lower.starts_with("panic ")
}

fn destructive_recovery_rollback_decision(
    owners: &[YayRecoveryOwnerPlan],
) -> DestructiveRecoveryRollbackDecision {
    let mut proofs = Vec::new();
    let mut blocked = Vec::new();
    for owner in owners {
        if let Some(archive) = owner
            .cached_archive
            .as_deref()
            .filter(|archive| local_package_archive_matches(archive, &owner.owner))
        {
            proofs.push(PackageRollbackProof::LocalArchive {
                package: owner.owner.clone(),
                archive: archive.to_string(),
            });
        } else {
            blocked.push(owner.owner.clone());
        }
    }
    if blocked.is_empty() {
        DestructiveRecoveryRollbackDecision::Allowed { proofs }
    } else {
        DestructiveRecoveryRollbackDecision::Blocked { packages: blocked }
    }
}

fn local_package_archive_matches(archive_path: &str, package: &str) -> bool {
    let path = Path::new(archive_path);
    if !path.is_file() {
        return false;
    }
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.contains(".pkg.tar"))
    {
        return false;
    }
    archive_target_from_path(archive_path, &BTreeSet::from([package.to_string()])).as_deref()
        == Some(package)
}

fn build_failed_command_report_sections_for_command(
    cmd: &CommandTask,
    output: &str,
) -> Vec<TaskReportSection> {
    let mut sections = build_command_report_sections_for_command(cmd, output);
    mark_unconfirmed_command_report_sections(cmd, &mut sections, output);
    sections
}

fn build_recovered_command_report_sections_for_command(
    cmd: &CommandTask,
    original_output: &str,
    resumed_output: &str,
) -> Vec<TaskReportSection> {
    if !matches!(cmd.report_parser, Some(BuiltinReportParser::Yay)) {
        return build_command_report_sections_for_command(cmd, resumed_output);
    }
    let combined_output = join_command_outputs(original_output, resumed_output);
    let mut sections = build_command_report_sections_for_command(cmd, original_output);
    mark_unconfirmed_command_report_sections(cmd, &mut sections, &combined_output);
    let resumed_sections = build_command_report_sections_for_command(cmd, resumed_output);
    merge_resumed_yay_report_sections(&mut sections, resumed_sections);
    sections
}

fn merge_resumed_yay_report_sections(
    sections: &mut Vec<TaskReportSection>,
    incoming: Vec<TaskReportSection>,
) {
    for incoming_section in incoming {
        if let Some(section) = sections.iter_mut().find(|section| {
            section.key == incoming_section.key && section.title == incoming_section.title
        }) {
            for mut row in incoming_section.rows {
                if let Some(existing) = section
                    .rows
                    .iter_mut()
                    .find(|existing| existing.name == row.name)
                {
                    merge_report_row_values(&mut row, existing);
                    reconcile_merged_report_row_status(&mut row);
                    *existing = row;
                } else {
                    section.rows.push(row);
                }
            }
        } else {
            sections.push(incoming_section);
        }
    }
}

fn merge_report_sections(sections: &mut Vec<TaskReportSection>, incoming: Vec<TaskReportSection>) {
    for incoming_section in incoming {
        if let Some(section) = sections.iter_mut().find(|section| {
            section.key == incoming_section.key && section.title == incoming_section.title
        }) {
            for row in incoming_section.rows {
                append_report_pattern_row(section, row);
            }
        } else {
            sections.push(incoming_section);
        }
    }
}

fn mark_unconfirmed_command_report_sections(
    cmd: &CommandTask,
    sections: &mut [TaskReportSection],
    output: &str,
) {
    if !matches!(cmd.report_parser, Some(BuiltinReportParser::Yay)) {
        return;
    }

    let confirmed_packages = confirmed_pacman_transaction_packages(output);
    let ignored_packages = ignored_yay_upgrade_packages(output);
    for section in sections {
        if section.key != "yay_packages" {
            continue;
        }
        for row in &mut section.rows {
            if row.status == TaskReportStatus::Updated {
                let package = report_package_name(&row.name);
                if confirmed_packages.contains(package.as_str()) {
                    continue;
                }
                if ignored_packages.contains(package.as_str()) {
                    row.status = TaskReportStatus::Skipped;
                    row.note
                        .get_or_insert_with(|| "excluded from resumed bulk update".to_string());
                    continue;
                }
                row.status = TaskReportStatus::Blocked;
                row.note.get_or_insert_with(|| {
                    "listed before failed transaction; update not confirmed".to_string()
                });
            }
        }
    }
}

fn confirmed_pacman_transaction_packages(output: &str) -> BTreeSet<String> {
    strip_ansi(output)
        .replace('\r', "\n")
        .lines()
        .filter_map(parse_pacman_transaction_package_line)
        .collect()
}

fn parse_pacman_transaction_package_line(line: &str) -> Option<String> {
    let trimmed = strip_log_timestamp_prefix(line.trim());
    let actions = ["upgrading", "installing", "reinstalling", "downgrading"];
    let rest = actions
        .iter()
        .find_map(|action| trimmed.strip_prefix(&format!("{action} ")))?;
    let package = rest
        .trim()
        .trim_end_matches("...")
        .split_whitespace()
        .next()?
        .trim();
    looks_like_plain_package_name(package).then_some(package.to_string())
}

fn ignored_yay_upgrade_packages(output: &str) -> BTreeSet<String> {
    strip_ansi(output)
        .replace('\r', "\n")
        .lines()
        .filter_map(parse_ignored_yay_upgrade_package_line)
        .collect()
}

fn parse_ignored_yay_upgrade_package_line(line: &str) -> Option<String> {
    let trimmed = strip_log_timestamp_prefix(line.trim())
        .trim_start_matches("->")
        .trim();
    let (package, rest) = trimmed.split_once(':')?;
    if rest.contains("ignoring package upgrade") && looks_like_plain_package_name(package.trim()) {
        Some(package.trim().to_string())
    } else {
        None
    }
}

fn strip_log_timestamp_prefix(line: &str) -> &str {
    let Some(split_at) = line.find(char::is_whitespace) else {
        return line;
    };
    let first = &line[..split_at];
    let rest = &line[split_at..];
    if first.ends_with('Z') && first.contains(':') {
        rest.trim_start()
    } else {
        line
    }
}

fn report_package_name(name: &str) -> String {
    name.split_once('/')
        .map(|(_, package)| package)
        .unwrap_or(name)
        .trim()
        .to_string()
}

fn looks_like_plain_package_name(package: &str) -> bool {
    !package.is_empty()
        && package
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '+' | '_' | '-' | '~'))
}

enum PreCommandOutcome {
    Continue(String),
    Stop(TaskResult),
}

fn run_command_pre_commands(
    ctx: &SyncContext,
    spec: &TaskSpec,
    cmd: &CommandTask,
    policy: &TaskPolicy,
) -> Result<PreCommandOutcome> {
    let mut combined_output = String::new();
    for pre_command in &cmd.pre_commands {
        let pre_cmd = command_task_for_pre_command(cmd, pre_command);
        let pre_execution_path = interactive_execution_path(ctx.host_os, &pre_cmd);
        let pre_effective_interactive =
            !matches!(pre_execution_path, InteractiveExecutionPath::Standard);
        let (program, args) = build_command_invocation(ctx.host_os, &pre_cmd);
        ctx.log_line(
            &spec.id,
            LogLevel::Info,
            LogStream::Meta,
            format!(
                "pre-command: {}",
                command_log_line(ctx.host_os, &pre_cmd, &program, &args)
            ),
        );
        let output = match if matches!(pre_execution_path, InteractiveExecutionPath::Standard) {
            ctx.run_command_with_policy(
                &spec.id,
                &program,
                args.clone(),
                policy,
                pre_effective_interactive,
            )
        } else {
            run_command_with_transcript(ctx, &spec.id, policy, &program, &args, pre_execution_path)
        } {
            Ok(output) => output,
            Err(err) => {
                let err_text = process_exit_output(&err)
                    .map(str::to_string)
                    .unwrap_or_else(|| err.to_string());
                let class = classify_runtime_failure(&err_text, cmd.requires_elevation);
                if class == RuntimeFailureClass::UserCanceledElevation {
                    return Ok(PreCommandOutcome::Stop(user_canceled_elevation_result(
                        spec.label.clone(),
                    )));
                }
                if class == RuntimeFailureClass::ElevationDenied {
                    return Ok(PreCommandOutcome::Stop(TaskResult::skipped(
                        spec.label.clone(),
                        build_elevation_required_detail(spec),
                    )));
                }
                let report_input = join_command_outputs(&combined_output, &err_text);
                return Ok(PreCommandOutcome::Stop(
                    failed_command_result_with_report_sections(
                        spec.label.clone(),
                        build_pre_command_failure_detail(spec, &pre_cmd, &program, &err_text),
                        cmd,
                        &report_input,
                    ),
                ));
            }
        };
        if ctx.emit_plain {
            crate::ua_out!("{output}");
        }
        combined_output = join_command_outputs(&combined_output, &output);
    }
    Ok(PreCommandOutcome::Continue(combined_output))
}

fn command_task_for_pre_command(cmd: &CommandTask, pre_command: &CommandPreCommand) -> CommandTask {
    CommandTask {
        program: pre_command.program.clone(),
        args: pre_command.args.clone(),
        mode: cmd.mode.clone(),
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: cmd.policy_key.clone(),
        requires_elevation: cmd.requires_elevation,
        needs_sudo_session: cmd.needs_sudo_session,
        interactive: cmd.interactive,
        external_window: false,
        shell: false,
        windows_bridge: cmd.windows_bridge,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    }
}

fn build_pre_command_failure_detail(
    spec: &TaskSpec,
    cmd: &CommandTask,
    program: &str,
    err_text: &str,
) -> String {
    format!(
        "pre-command failed before primary updater: {}; {}",
        format_command_for_log(&cmd.program, &cmd.args),
        build_command_failure_detail(spec, cmd, program, err_text)
    )
}

fn join_command_outputs(existing: &str, next: &str) -> String {
    if existing.is_empty() {
        return next.to_string();
    }
    if next.is_empty() {
        return existing.to_string();
    }
    let mut combined = existing.to_string();
    if !combined.ends_with('\n') {
        combined.push('\n');
    }
    combined.push_str(next);
    combined
}

struct CommandReportOutput {
    input: String,
    probe_rows: Vec<TaskReportRow>,
    state_samples: Vec<CommandStateReportSample>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommandReportPhase {
    Before,
    After,
}

struct CommandStateReportSample {
    command_index: usize,
    command_label: String,
    phase: CommandReportPhase,
    section_key: String,
    section_title: String,
    include_unchanged: bool,
    versions: BTreeMap<String, String>,
}

fn append_command_report_outputs(
    ctx: &SyncContext,
    task_id: &str,
    report_commands: &[CommandReportCommand],
    primary_output: &str,
    task_policy: &TaskPolicy,
    phase: CommandReportPhase,
) -> CommandReportOutput {
    if report_commands.is_empty()
        || !report_commands
            .iter()
            .any(|command| command_report_runs_in_phase(command, phase))
    {
        return CommandReportOutput {
            input: primary_output.to_string(),
            probe_rows: Vec::new(),
            state_samples: Vec::new(),
        };
    }

    let mut report_input = primary_output.to_string();
    let mut probe_rows = Vec::new();
    let mut state_samples = Vec::new();
    let report_timeout_secs = task_policy.timeout.as_secs().clamp(1, 120);
    let report_policy = TaskPolicy::new(report_timeout_secs, 0, 0);
    for (idx, command) in report_commands.iter().enumerate() {
        if !command_report_runs_in_phase(command, phase) {
            continue;
        }
        ctx.log_line(
            task_id,
            LogLevel::Info,
            LogStream::Meta,
            format!(
                "report probe: {}",
                format_command_for_log(&command.program, &command.args)
            ),
        );
        match ctx.run_report_command_with_policy(task_id, command, &report_policy) {
            Ok(output) => {
                if let Some(pattern) = &command.state_pattern {
                    state_samples.push(CommandStateReportSample {
                        command_index: idx,
                        command_label: format_command_for_log(&command.program, &command.args),
                        phase,
                        section_key: pattern.section_key.clone(),
                        section_title: pattern.section_title.clone(),
                        include_unchanged: pattern.include_unchanged,
                        versions: parse_command_state_report_versions(pattern, &output),
                    });
                } else if !output.trim().is_empty() {
                    if !report_input.ends_with('\n') {
                        report_input.push('\n');
                    }
                    report_input.push_str(&output);
                    if !report_input.ends_with('\n') {
                        report_input.push('\n');
                    }
                }
            }
            Err(err) => {
                let summary = report_command_failure_summary(&err);
                let command_label = format_command_for_log(&command.program, &command.args);
                ctx.log_line(
                    task_id,
                    LogLevel::Warn,
                    LogStream::Meta,
                    format!("report probe failed: {command_label}: {summary}"),
                );
                probe_rows.push(TaskReportRow {
                    name: command_label,
                    status: TaskReportStatus::Failed,
                    before: Some("probe".to_string()),
                    after: Some("failed".to_string()),
                    note: Some(summary.to_string()),
                });
            }
        }
    }
    CommandReportOutput {
        input: report_input,
        probe_rows,
        state_samples,
    }
}

fn report_command_failure_summary(err: &anyhow::Error) -> String {
    if let Some(output) = process_exit_output(err) {
        if let Some(line) = output.lines().map(str::trim).find(|line| !line.is_empty()) {
            return line.to_string();
        }
    }

    if let Some(exit) = err.downcast_ref::<ProcessExitError>() {
        return format!("report probe failed without output (code={})", exit.code);
    }

    err.to_string()
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "report probe failed without output".to_string())
}

fn command_report_runs_in_phase(command: &CommandReportCommand, phase: CommandReportPhase) -> bool {
    match phase {
        CommandReportPhase::Before => command.when.runs_before(),
        CommandReportPhase::After => command.when.runs_after(),
    }
}

fn parse_command_state_report_versions(
    pattern: &CommandStateReportPattern,
    output: &str,
) -> BTreeMap<String, String> {
    let mut versions = BTreeMap::new();
    for line in output.lines() {
        for captures in pattern.regex.captures_iter(line) {
            let Some(name) =
                render_report_pattern_field(pattern.name.as_deref(), "name", &captures)
                    .or_else(|| first_report_pattern_capture(&captures))
            else {
                continue;
            };
            let name = sanitize_report_cell_text(&name);
            if name.is_empty() {
                continue;
            }
            let Some(version) =
                render_report_pattern_field(pattern.version.as_deref(), "version", &captures)
            else {
                continue;
            };
            let version = normalize_command_state_report_version(&version);
            if version.is_empty() {
                continue;
            }
            versions.insert(name, version);
        }
    }
    versions
}

fn normalize_command_state_report_version(version: &str) -> String {
    let version = sanitize_report_cell_text(version);
    let Some((current, note)) = split_trailing_parenthetical_note(&version) else {
        return version;
    };
    if note
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|word| word.eq_ignore_ascii_case("available"))
    {
        return current.to_string();
    }
    version
}

fn split_trailing_parenthetical_note(value: &str) -> Option<(&str, &str)> {
    let value = value.trim();
    if !value.ends_with(')') {
        return None;
    }
    let start = value.rfind(" (")?;
    let current = value[..start].trim();
    let note = value[start + 2..value.len() - 1].trim();
    if current.is_empty() || note.is_empty() {
        return None;
    }
    Some((current, note))
}

struct CommandStateReportGroup {
    command_label: String,
    section_key: String,
    section_title: String,
    include_unchanged: bool,
    before: Option<BTreeMap<String, String>>,
    after: Option<BTreeMap<String, String>>,
}

fn build_command_state_report_sections(
    samples: Vec<CommandStateReportSample>,
) -> Vec<TaskReportSection> {
    let mut groups: BTreeMap<(usize, String, String), CommandStateReportGroup> = BTreeMap::new();
    for sample in samples {
        let key = (
            sample.command_index,
            sample.section_key.clone(),
            sample.section_title.clone(),
        );
        let group = groups
            .entry(key)
            .or_insert_with(|| CommandStateReportGroup {
                command_label: sample.command_label.clone(),
                section_key: sample.section_key.clone(),
                section_title: sample.section_title.clone(),
                include_unchanged: sample.include_unchanged,
                before: None,
                after: None,
            });
        match sample.phase {
            CommandReportPhase::Before => group.before = Some(sample.versions),
            CommandReportPhase::After => group.after = Some(sample.versions),
        }
    }

    let mut sections: BTreeMap<(String, String), Vec<TaskReportRow>> = BTreeMap::new();
    for group in groups.into_values() {
        let rows = command_state_report_rows(&group);
        if rows.is_empty() {
            continue;
        }
        sections
            .entry((group.section_key, group.section_title))
            .or_default()
            .extend(rows);
    }

    sections
        .into_iter()
        .map(|((key, title), rows)| TaskReportSection { key, title, rows })
        .collect()
}

fn command_state_report_rows(group: &CommandStateReportGroup) -> Vec<TaskReportRow> {
    let (Some(before), Some(after)) = (&group.before, &group.after) else {
        return Vec::new();
    };
    let mut rows = Vec::new();
    let names = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for name in names {
        match (before.get(&name), after.get(&name)) {
            (Some(before_version), Some(after_version)) if before_version != after_version => {
                rows.push(TaskReportRow {
                    name,
                    status: TaskReportStatus::Updated,
                    before: Some(before_version.clone()),
                    after: Some(after_version.clone()),
                    note: Some("detected by state report probe".to_string()),
                });
            }
            (Some(version), Some(_)) if group.include_unchanged => {
                rows.push(TaskReportRow {
                    name,
                    status: TaskReportStatus::Unchanged,
                    before: Some(version.clone()),
                    after: Some(version.clone()),
                    note: Some("state unchanged after update".to_string()),
                });
            }
            (Some(before_version), None) => {
                rows.push(TaskReportRow {
                    name,
                    status: TaskReportStatus::Failed,
                    before: Some(before_version.clone()),
                    after: Some("-".to_string()),
                    note: Some("missing from after-state probe".to_string()),
                });
            }
            (None, Some(after_version)) => {
                rows.push(TaskReportRow {
                    name,
                    status: TaskReportStatus::Updated,
                    before: Some("-".to_string()),
                    after: Some(after_version.clone()),
                    note: Some("new in after-state probe".to_string()),
                });
            }
            _ => {}
        }
    }
    if rows.is_empty() {
        rows.push(TaskReportRow {
            name: group.command_label.clone(),
            status: TaskReportStatus::Unchanged,
            before: Some("-".to_string()),
            after: Some("-".to_string()),
            note: Some("no state changes detected".to_string()),
        });
    }
    rows
}

fn command_report_probe_section(rows: Vec<TaskReportRow>) -> Option<TaskReportSection> {
    if rows.is_empty() {
        return None;
    }
    Some(TaskReportSection {
        key: "report_probes".to_string(),
        title: "Report Probe Results".to_string(),
        rows,
    })
}

fn task_bootstrap_windows_foundations(
    ctx: &SyncContext,
    spec: &TaskSpec,
    foundations: &[String],
) -> Result<TaskResult> {
    if !matches!(ctx.host_os, HostOs::Windows) {
        return Ok(TaskResult::skipped(
            spec.label.clone(),
            "Windows foundations bootstrap only runs on Windows".to_string(),
        ));
    }

    let policy = ctx
        .task_policies
        .by_key("system_update", TaskPolicy::new(1800, 0, 0));
    let mut rows = Vec::new();
    let mut installed_or_updated = 0usize;
    let mut failed = 0usize;
    let available = builtin_windows_foundations()?;
    let selected = normalize_bootstrap_foundations(foundations, &available);

    for foundation in &available {
        if !selected.contains(&foundation.id) {
            continue;
        }
        let present = which(&foundation.probe).is_some();
        let before = if present { "present" } else { "missing" };
        if let Some(missing_probe) = missing_required_foundation_probe(foundation) {
            failed += 1;
            rows.push(TaskReportRow {
                name: foundation.id.clone(),
                status: TaskReportStatus::Failed,
                before: Some(before.to_string()),
                after: Some("-".to_string()),
                note: Some(format!(
                    "{missing_probe} is required for this foundation but is not available"
                )),
            });
            continue;
        }

        let command = if present {
            foundation.present_command.as_ref()
        } else {
            foundation.missing_command.as_ref()
        };
        let Some(command) = command else {
            let note = foundation
                .present_note
                .as_deref()
                .unwrap_or("already installed")
                .to_string();
            rows.push(TaskReportRow {
                name: foundation.id.clone(),
                status: TaskReportStatus::Unchanged,
                before: Some(before.to_string()),
                after: Some(before.to_string()),
                note: Some(note),
            });
            continue;
        };

        match run_bootstrap_command(ctx, &spec.id, command, &policy) {
            Ok(_) => {
                installed_or_updated += 1;
                rows.push(TaskReportRow {
                    name: foundation.id.clone(),
                    status: TaskReportStatus::Updated,
                    before: Some(before.to_string()),
                    after: Some(command.after.clone()),
                    note: None,
                });
            }
            Err(err) => {
                failed += 1;
                rows.push(TaskReportRow {
                    name: foundation.id.clone(),
                    status: TaskReportStatus::Failed,
                    before: Some(before.to_string()),
                    after: Some("-".to_string()),
                    note: Some(concise_command_text(&err.to_string())),
                });
            }
        }
    }

    let mut result = if failed > 0 && installed_or_updated == 0 {
        TaskResult::failed(
            spec.label.clone(),
            "Windows foundations bootstrap failed before completing any foundation".to_string(),
        )
    } else if failed > 0 {
        TaskResult::completed_with_advisory(
            spec.label.clone(),
            "Windows foundations bootstrap completed with warnings".to_string(),
            TaskAdvisory {
                severity: AdvisorySeverity::Warning,
                code: "windows-bootstrap-partial".to_string(),
                summary: "one or more Windows foundations failed during bootstrap".to_string(),
                remediation: "Review the bootstrap task log, fix the failed foundation, then rerun `update-all --bootstrap`.".to_string(),
                blocks_dependents: false,
            },
        )
    } else {
        TaskResult::completed(spec.label.clone())
    };
    if !rows.is_empty() {
        result.report_sections.push(TaskReportSection {
            key: "windows_bootstrap_foundations".to_string(),
            title: "Windows Bootstrap Foundations".to_string(),
            rows,
        });
    }
    Ok(result)
}

fn normalize_bootstrap_foundations(
    foundations: &[String],
    available: &[BuiltinWindowsFoundation],
) -> BTreeSet<String> {
    let supported = available
        .iter()
        .map(|foundation| foundation.id.clone())
        .collect::<BTreeSet<_>>();
    let mut selected = BTreeSet::new();
    for foundation in foundations {
        let normalized = foundation.trim().to_ascii_lowercase();
        if let Some(id) = supported.get(&normalized) {
            selected.insert(id.clone());
        }
    }
    if selected.is_empty() {
        selected.extend(supported);
    }
    selected
}

fn missing_required_foundation_probe(foundation: &BuiltinWindowsFoundation) -> Option<String> {
    foundation
        .requires_probe
        .iter()
        .find(|probe| which(probe).is_none())
        .cloned()
}

fn run_bootstrap_command(
    ctx: &SyncContext,
    task_id: &str,
    command: &BuiltinFoundationCommand,
    policy: &TaskPolicy,
) -> Result<String> {
    ctx.log_line(
        task_id,
        LogLevel::Info,
        LogStream::Meta,
        format_command_for_log(&command.program, &command.args),
    );
    ctx.run_command_with_policy(
        task_id,
        &command.program,
        command.args.clone(),
        policy,
        false,
    )
}

fn command_log_line(
    host_os: HostOs,
    cmd: &CommandTask,
    invocation_program: &str,
    invocation_args: &[String],
) -> String {
    if matches!(host_os, HostOs::Windows)
        && invocation_program.eq_ignore_ascii_case("powershell")
        && invocation_args.iter().any(|arg| arg == "-Command")
    {
        return format_command_for_log(&cmd.program, &cmd.args);
    }
    format_command_for_log(invocation_program, invocation_args)
}

fn format_command_for_log(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{} {}", program, args.join(" "))
    }
}

fn normalize_winget_scope(scope: &str) -> Option<&'static str> {
    match scope
        .trim()
        .trim_matches(|c| c == '"' || c == '\'')
        .to_ascii_lowercase()
        .as_str()
    {
        "machine" => Some("machine"),
        "user" => Some("user"),
        _ => None,
    }
}

fn winget_scope_from_args(args: &[String]) -> Option<&'static str> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let trimmed = arg.trim();
        if trimmed.eq_ignore_ascii_case("--scope") {
            if let Some(scope) = iter.next().and_then(|scope| normalize_winget_scope(scope)) {
                return Some(scope);
            }
            continue;
        }
        if let Some(scope) = trimmed
            .strip_prefix("--scope=")
            .and_then(normalize_winget_scope)
        {
            return Some(scope);
        }
    }
    None
}

fn command_is_winget(cmd: &CommandTask) -> bool {
    matches!(cmd.report_parser, Some(BuiltinReportParser::Winget))
        || command_display_name(&cmd.program).eq_ignore_ascii_case("winget")
}

fn winget_scope_for_command(cmd: &CommandTask) -> Option<&'static str> {
    if command_is_winget(cmd) {
        Some(winget_scope_from_args(&cmd.args).unwrap_or("user"))
    } else {
        None
    }
}

fn winget_scope_for_spec(spec: &TaskSpec) -> Option<&'static str> {
    match &spec.kind {
        TaskKind::Command(cmd) => winget_scope_for_command(cmd),
        _ => None,
    }
}

fn classify_partial_winget_result(spec: &TaskSpec, output: &str) -> Option<TaskResult> {
    let scope = winget_scope_for_spec(spec)?;
    let cleaned = strip_progress_output(output);
    let report_sections = parse_winget_report(&cleaned);
    let counts = count_report_rows(&report_sections);
    if counts.updated == 0 || counts.failed == 0 {
        return None;
    }
    let mut result = TaskResult::completed_with_advisory(
        spec.label.clone(),
        format!(
            "winget {scope}-scope update completed with warnings: {} updated, {} failed",
            counts.updated, counts.failed
        ),
        TaskAdvisory {
            severity: AdvisorySeverity::Warning,
            code: "winget-partial-success".to_string(),
            summary: format!(
                "winget {scope}-scope update installed at least one package but reported package-level failures"
            ),
            remediation: format!(
                "Review failed package rows, then retry `winget upgrade --all --scope {scope}` after fixing installer or source issues."
            ),
            blocks_dependents: false,
        },
    );
    result.report_sections = report_sections;
    Some(result)
}

fn count_report_rows(sections: &[TaskReportSection]) -> ReportCounts {
    let mut counts = ReportCounts::default();
    for section in sections {
        for row in &section.rows {
            match row.status {
                TaskReportStatus::Updated => counts.updated += 1,
                TaskReportStatus::Refreshed => counts.refreshed += 1,
                TaskReportStatus::Passed => counts.passed += 1,
                TaskReportStatus::Unchanged => counts.unchanged += 1,
                TaskReportStatus::Failed => counts.failed += 1,
                TaskReportStatus::Blocked => counts.blocked += 1,
                TaskReportStatus::Skipped => counts.skipped += 1,
                TaskReportStatus::Info => counts.info += 1,
            }
        }
    }
    counts
}

fn package_recovery_section_key() -> &'static str {
    "package_recovery"
}

fn package_recovery_section_title() -> &'static str {
    "Package Recovery Actions"
}

fn build_package_recovery_diagnostic_detail(
    manager_label: &str,
    causes: &[RecoveryCause],
    err_text: &str,
) -> String {
    let cause = causes
        .first()
        .map(describe_recovery_cause)
        .unwrap_or_else(|| "package-manager recovery is diagnostic-only".to_string());
    format!(
        "command failed: {manager_label} classified the failure as {cause}; automatic mutation is not safe for this case. Original error: {err_text}"
    )
}

fn recovery_diagnostic_rows(manager_label: &str, causes: &[RecoveryCause]) -> Vec<TaskReportRow> {
    let rows = causes
        .iter()
        .map(|cause| TaskReportRow {
            name: recovery_cause_row_name(manager_label, cause),
            status: recovery_diagnostic_status(cause),
            before: Some("failed".to_string()),
            after: Some("diagnostic only".to_string()),
            note: Some(describe_recovery_cause(cause)),
        })
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return vec![TaskReportRow {
            name: manager_label.to_string(),
            status: TaskReportStatus::Info,
            before: Some("failed".to_string()),
            after: Some("diagnostic only".to_string()),
            note: Some("no safe recovery action available".to_string()),
        }];
    }
    rows
}

fn recovery_cause_row_name(manager_label: &str, cause: &RecoveryCause) -> String {
    match cause {
        RecoveryCause::FileConflict { owners } if !owners.is_empty() => owners.join(", "),
        RecoveryCause::PackageConflict { packages, .. } if !packages.is_empty() => {
            packages.join(", ")
        }
        RecoveryCause::SourceChecksumDrift {
            package: Some(package),
        }
        | RecoveryCause::InvalidManifest {
            package: Some(package),
        }
        | RecoveryCause::BuildFailure {
            package: Some(package),
            ..
        } => package.clone(),
        RecoveryCause::RunningProcess { packages } if !packages.is_empty() => packages.join(", "),
        _ => manager_label.to_string(),
    }
}

fn recovery_diagnostic_status(cause: &RecoveryCause) -> TaskReportStatus {
    match cause {
        RecoveryCause::PackageConflict { .. }
        | RecoveryCause::LockOrBusy { .. }
        | RecoveryCause::BuildFailure { .. }
        | RecoveryCause::RunningProcess { .. } => TaskReportStatus::Blocked,
        _ => TaskReportStatus::Info,
    }
}

fn describe_recovery_cause(cause: &RecoveryCause) -> String {
    match cause {
        RecoveryCause::FileConflict { owners } if owners.is_empty() => {
            "file/package conflict".to_string()
        }
        RecoveryCause::FileConflict { owners } => {
            format!("file/package conflict involving {}", owners.join(", "))
        }
        RecoveryCause::PackageConflict { packages, .. } if packages.is_empty() => {
            "package dependency conflict".to_string()
        }
        RecoveryCause::PackageConflict { packages, .. } => {
            format!(
                "package dependency conflict involving {}",
                packages.join(", ")
            )
        }
        RecoveryCause::LockOrBusy { summary } => summary.clone(),
        RecoveryCause::SourceChecksumDrift {
            package: Some(package),
        } => {
            format!("source/checksum drift for {package}")
        }
        RecoveryCause::SourceChecksumDrift { package: None } => "source/checksum drift".to_string(),
        RecoveryCause::BuildFailure {
            package: Some(package),
            summary,
        } => {
            format!("build failure for {package}: {summary}")
        }
        RecoveryCause::BuildFailure {
            package: None,
            summary,
        } => {
            format!("build failure: {summary}")
        }
        RecoveryCause::InvalidManifest {
            package: Some(package),
        } => {
            format!("invalid package manifest for {package}")
        }
        RecoveryCause::InvalidManifest { package: None } => "invalid package manifest".to_string(),
        RecoveryCause::InstallerHashMismatch => "installer hash mismatch".to_string(),
        RecoveryCause::PartialBatchFailure => "partial batch failure".to_string(),
        RecoveryCause::RunningProcess { packages } if packages.is_empty() => {
            "running process blocked update".to_string()
        }
        RecoveryCause::RunningProcess { packages } => {
            format!("running process blocked {}", packages.join(", "))
        }
    }
}

fn append_original_recovery_diagnostics(
    recovery_rows: &mut Vec<TaskReportRow>,
    original_recovery_plan: Option<&RecoveryPlan>,
    handled_packages: &[String],
) -> Vec<String> {
    let Some(plan) = original_recovery_plan else {
        return Vec::new();
    };
    let causes = plan
        .causes
        .iter()
        .filter(|cause| !is_handled_package_recovery_cause(cause, handled_packages))
        .cloned()
        .collect::<Vec<_>>();
    if causes.is_empty() {
        return Vec::new();
    }
    let summaries = causes
        .iter()
        .map(describe_recovery_cause)
        .collect::<Vec<_>>();
    recovery_rows.extend(recovery_diagnostic_rows(plan.kind.label(), &causes));
    summaries
}

fn annotate_unresolved_recovery_diagnostics(result: &mut TaskResult, summaries: &[String]) {
    if summaries.is_empty() {
        return;
    }
    result.status = TaskStatus::Failed;
    let joined = summaries.join("; ");
    let detail =
        format!("other package-manager blockers also require manual intervention: {joined}");
    result.details.push(detail);
    if let Some(advisory) = result.advisories.first_mut() {
        advisory.summary = format!("{}; also {}", advisory.summary, joined);
    }
}

fn is_handled_package_recovery_cause(cause: &RecoveryCause, handled_packages: &[String]) -> bool {
    match cause {
        RecoveryCause::SourceChecksumDrift {
            package: Some(package),
        }
        | RecoveryCause::BuildFailure {
            package: Some(package),
            ..
        } => handled_packages
            .iter()
            .any(|handled_package| handled_package == package),
        RecoveryCause::SourceChecksumDrift { package: None } => true,
        _ => false,
    }
}

#[derive(Default)]
struct ReportCounts {
    updated: usize,
    refreshed: usize,
    passed: usize,
    unchanged: usize,
    failed: usize,
    blocked: usize,
    skipped: usize,
    info: usize,
}

fn strip_progress_output(output: &str) -> String {
    output
        .lines()
        .filter_map(|line| {
            let cleaned = strip_ansi(line).replace('\r', "");
            let trimmed = cleaned.trim();
            if trimmed.is_empty() || looks_like_progress_noise(trimmed) {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn concise_command_text(output: &str) -> String {
    strip_progress_output(output)
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "command failed".to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeFailureClass {
    UserCanceledElevation,
    ElevationDenied,
    SudoSessionUnavailable,
    CommandLaunchFailed,
    TransientLockOrBusy,
    TransientNetwork,
    Other,
}

pub(crate) fn classify_runtime_failure(
    err_text: &str,
    requires_elevation: bool,
) -> RuntimeFailureClass {
    let lower = err_text.to_ascii_lowercase();
    if requires_elevation
        && (lower.contains("code=1223")
            || lower.contains("exit code 1223")
            || lower.contains("exit status 1223")
            || lower.contains("operation was canceled by the user")
            || lower.contains("operation was cancelled by the user"))
    {
        return RuntimeFailureClass::UserCanceledElevation;
    }
    if requires_elevation
        && (lower.contains("access is denied")
            || lower.contains("requested operation requires elevation")
            || lower.contains("the requested operation requires elevation")
            || lower.contains("a required privilege is not held by the client"))
    {
        return RuntimeFailureClass::ElevationDenied;
    }
    if lower.contains("password is required")
        || lower.contains("a terminal is required")
        || lower.contains("no tty present")
        || lower.contains("must have a tty")
    {
        return RuntimeFailureClass::SudoSessionUnavailable;
    }
    if lower.contains("is not recognized as the name of")
        || lower.contains("the system cannot find the file specified")
        || lower.contains("no such file or directory")
    {
        return RuntimeFailureClass::CommandLaunchFailed;
    }
    if is_transient_network_failure(&lower) {
        return RuntimeFailureClass::TransientNetwork;
    }
    if lower.contains("access is denied")
        || lower.contains("resource busy")
        || lower.contains("ebusy")
        || lower.contains("file in use")
        || lower.contains("used by another process")
        || lower.contains("db.lck")
        || lower.contains("database lock")
    {
        return RuntimeFailureClass::TransientLockOrBusy;
    }
    RuntimeFailureClass::Other
}

fn is_transient_network_failure(lower: &str) -> bool {
    lower.contains("etimedout")
        || lower.contains("timed out")
        || lower.contains("timeout running ")
        || lower.contains("operation too slow")
        || lower.contains("less than 1 bytes/sec")
        || lower.contains("connection reset by peer")
        || lower.contains("recv failure")
        || lower.contains("early eof")
        || lower.contains("unexpected disconnect")
        || lower.contains("temporary failure in name resolution")
        || lower.contains("could not resolve host")
        || lower.contains("network is unreachable")
        || lower.contains("econnreset")
        || lower.contains("econnrefused")
        || lower.contains("tls connection was non-properly terminated")
        || lower.contains("http 429")
        || lower.contains("http 500")
        || lower.contains("http 502")
        || lower.contains("http 503")
        || lower.contains("http 504")
}

fn build_elevation_required_detail(spec: &TaskSpec) -> String {
    if winget_scope_for_spec(spec) == Some("machine") {
        return "machine-scope winget update requires Administrator privileges; update-all did not receive elevation".to_string();
    }
    format!(
        "{} requires elevated privileges; update-all did not receive elevation",
        spec.label
    )
}

fn user_canceled_elevation_result(label: impl Into<String>) -> TaskResult {
    let mut result = TaskResult::canceled(label, "elevation prompt canceled by user".to_string());
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "elevation-canceled".to_string(),
        summary: "elevated task was canceled before machine-scope updates could run".to_string(),
        remediation:
            "Rerun update-all and approve the Administrator prompt, or skip machine-scope updates."
                .to_string(),
        blocks_dependents: false,
    });
    result
}

fn build_command_failure_detail(
    _spec: &TaskSpec,
    cmd: &CommandTask,
    program: &str,
    err_text: &str,
) -> String {
    let class = classify_runtime_failure(err_text, cmd.requires_elevation);
    if cmd.requires_elevation && class == RuntimeFailureClass::SudoSessionUnavailable {
        return format!(
            "command failed because the cached sudo session was unavailable or expired: {err_text}; rerun update-all, complete sudo authentication again, and retry"
        );
    }
    if cmd.requires_elevation && program == "sudo" {
        return format!(
            "command failed after elevation preflight: {err_text}; run 'sudo -v' and retry"
        );
    }
    if let Some(scope) = winget_scope_for_command(cmd) {
        if winget_hash_mismatch_detected(err_text) {
            return format!(
                "winget reported an installer hash mismatch; the upstream installer or manifest may have changed. Retry later, run `winget source reset --force` if metadata looks stale, then retry `winget upgrade --all --scope {scope}`"
            );
        }
        if let Some(summary) = summarize_winget_failure(err_text) {
            return format!(
                "{summary}; winget {scope}-scope update failed. common fixes: close locking processes, run `winget source reset --force`, then retry `winget upgrade --all --scope {scope}`"
            );
        }
        match class {
            RuntimeFailureClass::CommandLaunchFailed => {
                return format!(
                    "command failed before winget started: {err_text}; update-all could not launch winget for the {scope}-scope run. Verify `winget --info` works directly, then retry."
                );
            }
            RuntimeFailureClass::ElevationDenied => {
                return format!(
                    "winget {scope}-scope update was not started because elevation was not granted; rerun update-all with Administrator privileges or skip machine-scope updates"
                );
            }
            _ => {}
        }
        return format!(
            "command failed: {err_text}; winget {scope}-scope update failed. \
common fixes: close locking processes (for example uv.exe), run `winget source reset --force`, \
then retry `winget upgrade --all --scope {scope}`"
        );
    }
    format!("command failed: {err_text}")
}

fn summarize_winget_failure(err_text: &str) -> Option<String> {
    for line in err_text.lines() {
        let trimmed = line.trim();
        if let Some(marker) = winget_output_failure_marker(trimmed) {
            return Some(marker.to_string());
        }
    }
    None
}

fn winget_hash_mismatch_detected(err_text: &str) -> bool {
    err_text
        .lines()
        .any(|line| line.trim().contains("Installer hash does not match."))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PacmanConflictRecord {
    target: String,
    path: String,
    owner: String,
    transaction_internal: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RecoverableConflictTarget {
    target: String,
    owners: Vec<String>,
    paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct YayRecoveryTargetPlan {
    target: String,
    owners: Vec<String>,
    paths: Vec<String>,
    cached_archive: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct YayRecoveryOwnerPlan {
    owner: String,
    targets: Vec<String>,
    cached_archive: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum PackageRollbackProof {
    LocalArchive { package: String, archive: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DestructiveRecoveryRollbackDecision {
    Allowed { proofs: Vec<PackageRollbackProof> },
    Blocked { packages: Vec<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct YayRecoveryPlan {
    targets: Vec<YayRecoveryTargetPlan>,
    owners_to_remove: Vec<YayRecoveryOwnerPlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct YayPackageRetryFailure {
    package: String,
    kind: YayPackageRecoveryKind,
    cause_summary: Option<String>,
    error_text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct YayIgnoredRecoveryPackage {
    package: String,
    reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum YayPackageRecoveryKind {
    SourceDrift,
    BuildFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct YayPackageRecoveryTargetPlan {
    package: String,
    kind: YayPackageRecoveryKind,
    cause_summary: Option<String>,
    cleanup_paths: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct YayPackageRecoveryPlan {
    packages: Vec<YayPackageRecoveryTargetPlan>,
}

fn build_yay_package_recovery_plan(
    err_text: &str,
    original_recovery_plan: Option<&RecoveryPlan>,
) -> Option<YayPackageRecoveryPlan> {
    if let Some(recovery_plan) = original_recovery_plan {
        let has_uncontained_cause = recovery_plan.causes.iter().any(|cause| {
            !matches!(
                cause,
                RecoveryCause::SourceChecksumDrift { .. }
                    | RecoveryCause::BuildFailure {
                        package: Some(_),
                        ..
                    }
            )
        });
        if has_uncontained_cause {
            return None;
        }
    }

    let mut package_kinds = BTreeMap::new();
    let mut build_summaries = BTreeMap::new();
    if is_yay_source_validity_failure(err_text) {
        package_kinds.extend(
            parse_yay_failed_package_names(err_text)
                .into_iter()
                .map(|package| (package, YayPackageRecoveryKind::SourceDrift)),
        );
    }
    if let Some(recovery_plan) = original_recovery_plan {
        for cause in &recovery_plan.causes {
            match cause {
                RecoveryCause::SourceChecksumDrift {
                    package: Some(package),
                } => {
                    package_kinds.insert(package.clone(), YayPackageRecoveryKind::SourceDrift);
                }
                RecoveryCause::BuildFailure {
                    package: Some(package),
                    summary,
                } => {
                    package_kinds
                        .entry(package.clone())
                        .or_insert(YayPackageRecoveryKind::BuildFailure);
                    build_summaries.insert(package.clone(), summary.clone());
                }
                _ => {}
            }
        }
    }

    let source_paths = parse_yay_failed_source_paths(err_text);
    let packages = package_kinds
        .into_iter()
        .map(|(package, kind)| {
            let mut cleanup_paths = BTreeSet::new();
            if kind == YayPackageRecoveryKind::SourceDrift {
                cleanup_paths.extend(
                    source_paths
                        .iter()
                        .filter(|source_path| {
                            yay_source_path_matches_package(source_path, &package)
                        })
                        .cloned(),
                );
                if let Some(home) = std::env::var_os("HOME") {
                    cleanup_paths.insert(
                        Path::new(&home)
                            .join(".cache")
                            .join("yay")
                            .join(&package)
                            .to_string_lossy()
                            .to_string(),
                    );
                }
            }
            YayPackageRecoveryTargetPlan {
                cause_summary: (kind == YayPackageRecoveryKind::BuildFailure)
                    .then(|| build_summaries.get(&package).cloned())
                    .flatten(),
                package,
                kind,
                cleanup_paths: cleanup_paths.into_iter().collect(),
            }
        })
        .collect::<Vec<_>>();
    (!packages.is_empty()).then_some(YayPackageRecoveryPlan { packages })
}

fn try_recover_yay_conflicts(
    ctx: &SyncContext,
    spec: &TaskSpec,
    cmd: &CommandTask,
    _program: &str,
    args: &[String],
    policy: &TaskPolicy,
    effective_interactive: bool,
    err_text: &str,
    original_recovery_plan: Option<&RecoveryPlan>,
) -> Result<Option<TaskResult>> {
    if !command_uses_yay_helper(cmd) {
        return Ok(None);
    }

    if is_pacman_conflicting_files_error(err_text) {
        if let Some(recovery_plan) = build_yay_recovery_plan(err_text) {
            return try_recover_yay_conflict_plan(
                ctx,
                spec,
                cmd,
                args,
                policy,
                effective_interactive,
                err_text,
                recovery_plan,
            );
        }
        let detail = format_package_manager_failure(err_text)
            .unwrap_or_else(|| build_command_failure_detail(spec, cmd, &cmd.program, err_text));
        return Ok(Some(TaskResult::failed(spec.label.clone(), detail)));
    }

    if let Some(recovery_plan) = build_yay_recovery_plan(err_text) {
        return try_recover_yay_conflict_plan(
            ctx,
            spec,
            cmd,
            args,
            policy,
            effective_interactive,
            err_text,
            recovery_plan,
        );
    }

    if let Some(recovery_plan) = build_yay_package_recovery_plan(err_text, original_recovery_plan) {
        return try_recover_yay_package_plan(
            ctx,
            spec,
            cmd,
            args,
            policy,
            effective_interactive,
            err_text,
            recovery_plan,
            original_recovery_plan,
        );
    }

    Ok(None)
}

fn verified_repository_retirement_pairs(
    plan: Option<&RecoveryPlan>,
) -> Option<Vec<recovery::PackageConflictPair>> {
    let plan = plan?;
    if !plan
        .actions
        .contains(&RecoveryAction::VerifiedRepositoryRetirement)
        || plan.causes.len() != 1
    {
        return None;
    }
    match &plan.causes[0] {
        RecoveryCause::PackageConflict { pairs, .. } if !pairs.is_empty() => Some(pairs.clone()),
        _ => None,
    }
}

fn normalize_repository_retirement_retry_args(args: &[String]) -> Option<Vec<String>> {
    let has_sync = args.iter().any(|arg| {
        arg == "--sync" || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('S'))
    });
    let has_upgrade = args.iter().any(|arg| {
        arg == "--sysupgrade"
            || (arg.starts_with('-') && !arg.starts_with("--") && arg.contains('u'))
    });
    if !has_sync
        || !has_upgrade
        || args
            .iter()
            .any(|arg| arg == "--ask" || arg.starts_with("--ask="))
    {
        return None;
    }

    let mut normalized = Vec::with_capacity(args.len() + 1);
    for arg in args {
        if arg == "--refresh" {
            continue;
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg.contains('y') {
            let stripped = arg
                .chars()
                .filter(|character| *character != 'y')
                .collect::<String>();
            if stripped != "-" {
                normalized.push(stripped);
            }
        } else {
            normalized.push(arg.clone());
        }
    }
    normalized.push("--ask=4".to_string());
    Some(normalized)
}

fn package_conflict_artifact_dir(ctx: &SyncContext) -> PathBuf {
    ctx.run_log
        .as_ref()
        .map(|run_log| run_log.run_dir().to_path_buf())
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "update-all-package-conflict-{}",
                std::process::id()
            ))
        })
}

fn repository_retirement_failure(
    spec: &TaskSpec,
    cmd: &CommandTask,
    original_output: &str,
    reason: impl Into<String>,
) -> TaskResult {
    let reason = reason.into();
    let mut result = TaskResult::failed(
        spec.label.clone(),
        format!(
            "repository-retirement recovery was refused: {reason}; the original package failure remains blocking"
        ),
    );
    result.report_sections = build_failed_command_report_sections_for_command(cmd, original_output);
    result.report_sections.push(TaskReportSection {
        key: package_recovery_section_key().to_string(),
        title: package_recovery_section_title().to_string(),
        rows: vec![TaskReportRow {
            name: "repository-retirement-proof".to_string(),
            status: TaskReportStatus::Blocked,
            before: Some("unverified".to_string()),
            after: Some("refused".to_string()),
            note: Some(concise_command_text(&reason)),
        }],
    });
    attach_command_output_diagnostics(&mut result, original_output);
    result
}

fn run_package_state_probe(
    ctx: &SyncContext,
    task_id: &str,
    helper_bin_dir: Option<&Path>,
    args: &[&str],
) -> std::result::Result<(bool, String), String> {
    let program = resolve_recovery_program("pacman", helper_bin_dir);
    ctx.log_line(
        task_id,
        LogLevel::Info,
        LogStream::Meta,
        format!("recovery proof: {program} {}", args.join(" ")),
    );
    let output = Command::new(&program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| format!("could not execute pacman state proof: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for line in stdout.lines() {
        ctx.log_line(task_id, LogLevel::Info, LogStream::Stdout, line.to_string());
    }
    for line in stderr.lines() {
        ctx.log_line(task_id, LogLevel::Info, LogStream::Stderr, line.to_string());
    }
    Ok((
        output.status.success(),
        join_command_outputs(&stdout, &stderr),
    ))
}

fn try_recover_verified_repository_retirement(
    ctx: &SyncContext,
    spec: &TaskSpec,
    cmd: &CommandTask,
    args: &[String],
    policy: &TaskPolicy,
    effective_interactive: bool,
    original_output: &str,
    original_recovery_plan: Option<&RecoveryPlan>,
) -> Result<Option<TaskResult>> {
    if !command_uses_yay_helper(cmd) {
        return Ok(None);
    }
    let Some(pairs) = verified_repository_retirement_pairs(original_recovery_plan) else {
        return Ok(None);
    };
    let Some(retry_args) = normalize_repository_retirement_retry_args(args) else {
        return Ok(Some(repository_retirement_failure(
            spec,
            cmd,
            original_output,
            "the original invocation was not an unambiguous full system upgrade without a pre-existing --ask option",
        )));
    };

    if std::env::var("UPDATE_ALL_PACKAGE_AUTHORITY").as_deref() != Ok("on") {
        return Ok(None);
    }
    let source_root = crate::build_info::package_support_root();
    let artifact_dir = package_conflict_artifact_dir(ctx);
    let fingerprint = match package_authority::package_database_fingerprint(
        &source_root,
        &artifact_dir,
        "initial",
    ) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            return Ok(Some(repository_retirement_failure(
                spec,
                cmd,
                original_output,
                error.to_string(),
            )))
        }
    };
    let request = package_authority::UpgradeConflictProbeRequest {
        conflicts: pairs
            .iter()
            .map(|pair| package_authority::UpgradeConflictPair {
                incoming: pair.incoming.clone(),
                remove: pair.remove.clone(),
            })
            .collect(),
        package_database_fingerprint: fingerprint.clone(),
    };
    let proof =
        match package_authority::verify_upgrade_conflicts(&source_root, &artifact_dir, &request) {
            Ok(proof) => proof,
            Err(error) => {
                return Ok(Some(repository_retirement_failure(
                    spec,
                    cmd,
                    original_output,
                    error.to_string(),
                )))
            }
        };
    if !proof.eligible {
        return Ok(Some(repository_retirement_failure(
            spec,
            cmd,
            original_output,
            if proof.rejection_reason.is_empty() {
                "libalpm did not approve the projected transaction".to_string()
            } else {
                proof.rejection_reason.clone()
            },
        )));
    }
    let expected_removals = pairs
        .iter()
        .map(|pair| pair.remove.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if proof.approved_removals != expected_removals || proof.projected_removals != expected_removals
    {
        return Ok(Some(repository_retirement_failure(
            spec,
            cmd,
            original_output,
            "the eligible proof did not return the exact requested removal set",
        )));
    }
    let projected_additions = proof.projected_additions.iter().collect::<BTreeSet<_>>();
    if pairs
        .iter()
        .any(|pair| !projected_additions.contains(&pair.incoming))
    {
        return Ok(Some(repository_retirement_failure(
            spec,
            cmd,
            original_output,
            "the eligible proof omitted an incoming conflict package from projected additions",
        )));
    }
    if proof.package_database_fingerprint != fingerprint {
        return Ok(Some(repository_retirement_failure(
            spec,
            cmd,
            original_output,
            "the proof result did not preserve the requested package database fingerprint",
        )));
    }
    let before_retry_fingerprint = match package_authority::package_database_fingerprint(
        &source_root,
        &artifact_dir,
        "before-retry",
    ) {
        Ok(value) => value,
        Err(error) => {
            return Ok(Some(repository_retirement_failure(
                spec,
                cmd,
                original_output,
                error.to_string(),
            )))
        }
    };
    if before_retry_fingerprint != fingerprint {
        return Ok(Some(repository_retirement_failure(
            spec,
            cmd,
            original_output,
            "the package database changed between transaction proof and retry",
        )));
    }

    ctx.log_line(
        &spec.id,
        LogLevel::Warn,
        LogStream::Meta,
        format!(
            "libalpm approved one atomic repository-retirement retry removing exactly: {}",
            format_package_list(&proof.approved_removals)
        ),
    );
    let helper_bin_dir = Path::new(&cmd.program).parent();
    let retry_output = match run_recovery_command(
        ctx,
        &spec.id,
        policy,
        &cmd.program,
        retry_args,
        effective_interactive,
        false,
        helper_bin_dir,
    ) {
        Ok(output) => output,
        Err(error) => {
            let retry_output = process_exit_output(&error)
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string());
            let combined = join_command_outputs(original_output, &retry_output);
            let mut result = repository_retirement_failure(
                spec,
                cmd,
                &combined,
                format!("the single approved atomic retry failed: {error}"),
            );
            attach_command_output_diagnostics(&mut result, &combined);
            return Ok(Some(result));
        }
    };

    for package in &proof.approved_removals {
        let (installed, probe_output) =
            match run_package_state_probe(ctx, &spec.id, helper_bin_dir, &["-Q", package]) {
                Ok(result) => result,
                Err(error) => {
                    return Ok(Some(repository_retirement_failure(
                        spec,
                        cmd,
                        original_output,
                        error,
                    )))
                }
            };
        if installed {
            return Ok(Some(repository_retirement_failure(
                spec,
                cmd,
                original_output,
                format!("validated removal candidate {package} is still installed after retry"),
            )));
        }
        let expected_absence = format!("package '{package}' was not found");
        if !probe_output.contains(&expected_absence) {
            return Ok(Some(repository_retirement_failure(
                spec,
                cmd,
                original_output,
                format!(
                    "could not prove validated removal candidate {package} absent: {}",
                    concise_command_text(&probe_output)
                ),
            )));
        }
    }
    for pair in &pairs {
        let incoming_installed =
            match run_package_state_probe(ctx, &spec.id, helper_bin_dir, &["-Q", &pair.incoming]) {
                Ok((installed, _)) => installed,
                Err(error) => {
                    return Ok(Some(repository_retirement_failure(
                        spec,
                        cmd,
                        original_output,
                        error,
                    )))
                }
            };
        if !incoming_installed {
            return Ok(Some(repository_retirement_failure(
                spec,
                cmd,
                original_output,
                format!(
                    "incoming conflict package {} is not installed after retry",
                    pair.incoming
                ),
            )));
        }
    }
    let dependency_check = match run_package_state_probe(ctx, &spec.id, helper_bin_dir, &["-Dk"]) {
        Ok((succeeded, _)) => succeeded,
        Err(error) => {
            return Ok(Some(repository_retirement_failure(
                spec,
                cmd,
                original_output,
                error,
            )))
        }
    };
    if !dependency_check {
        return Ok(Some(repository_retirement_failure(
            spec,
            cmd,
            original_output,
            "pacman's local package database dependency check failed after retry",
        )));
    }

    let mut rows = vec![TaskReportRow {
        name: "repository-retirement-proof".to_string(),
        status: TaskReportStatus::Updated,
        before: Some(fingerprint),
        after: Some("atomic transaction completed".to_string()),
        note: Some(format!(
            "libalpm projected additions [{}] and exact removals [{}]",
            format_package_list(&proof.projected_additions),
            format_package_list(&proof.projected_removals)
        )),
    }];
    rows.extend(proof.approved_removals.iter().map(|package| TaskReportRow {
        name: package.clone(),
        status: TaskReportStatus::Updated,
        before: Some("installed dependency".to_string()),
        after: Some("removed atomically".to_string()),
        note: Some("actual removal matched the libalpm projection".to_string()),
    }));
    rows.extend(pairs.iter().map(|pair| TaskReportRow {
        name: pair.incoming.clone(),
        status: TaskReportStatus::Updated,
        before: Some("projected addition".to_string()),
        after: Some("installed".to_string()),
        note: Some(format!(
            "validated repository conflict replaced {}",
            pair.remove
        )),
    }));
    let mut result = TaskResult::completed(spec.label.clone());
    result.details.push(format!(
        "completed a libalpm-verified atomic repository retirement removing {}",
        format_package_list(&proof.approved_removals)
    ));
    result.report_sections =
        build_recovered_command_report_sections_for_command(cmd, original_output, &retry_output);
    result.report_sections.push(TaskReportSection {
        key: package_recovery_section_key().to_string(),
        title: package_recovery_section_title().to_string(),
        rows,
    });
    attach_command_output_diagnostics(
        &mut result,
        &join_command_outputs(original_output, &retry_output),
    );
    Ok(Some(result))
}

fn package_manager_kind_for_command(
    spec: &TaskSpec,
    cmd: &CommandTask,
    program: &str,
) -> PackageManagerKind {
    package_manager_kind_from_report_parser(cmd.report_parser)
        .unwrap_or_else(|| package_manager_kind_for_task(&spec.id, program))
}

fn command_uses_yay_helper(cmd: &CommandTask) -> bool {
    command_display_name(&cmd.program).eq_ignore_ascii_case("yay")
}

fn command_reports_aur_helper(cmd: &CommandTask) -> bool {
    matches!(cmd.report_parser, Some(BuiltinReportParser::Yay)) || command_uses_yay_helper(cmd)
}

fn package_manager_kind_from_report_parser(
    parser: Option<BuiltinReportParser>,
) -> Option<PackageManagerKind> {
    match parser? {
        BuiltinReportParser::Scoop => Some(PackageManagerKind::Scoop),
        BuiltinReportParser::Winget => Some(PackageManagerKind::Winget),
        BuiltinReportParser::Yay => Some(PackageManagerKind::PacmanLike),
        _ => None,
    }
}

fn try_recover_yay_conflict_plan(
    ctx: &SyncContext,
    spec: &TaskSpec,
    cmd: &CommandTask,
    args: &[String],
    policy: &TaskPolicy,
    effective_interactive: bool,
    original_output: &str,
    recovery_plan: YayRecoveryPlan,
) -> Result<Option<TaskResult>> {
    ctx.log_line(
        &spec.id,
        LogLevel::Warn,
        LogStream::Meta,
        format!(
            "yay recovery mode: found {} conflicting target package(s); retrying with target exclusion first",
            recovery_plan.targets.len()
        ),
    );

    let helper_bin_dir = Path::new(&cmd.program).parent();
    let ignored_targets = recovery_plan
        .targets
        .iter()
        .map(|target| target.target.clone())
        .collect::<Vec<_>>();
    let ignored_target_list = format_package_list(&ignored_targets);
    let mut recovery_rows = recovery_plan
        .targets
        .iter()
        .map(|target| TaskReportRow {
            name: target.target.clone(),
            status: TaskReportStatus::Info,
            before: Some("bulk conflict".to_string()),
            after: Some("ignored".to_string()),
            note: Some(yay_conflict_exclusion_note(target)),
        })
        .collect::<Vec<_>>();
    let resumed_args = append_ignore_args(args, &ignored_targets);
    ctx.log_line(
        &spec.id,
        LogLevel::Info,
        LogStream::Meta,
        format!(
            "resuming bulk yay update with conflicting target(s) ignored: {}",
            ignored_target_list
        ),
    );

    let resumed_output = run_recovery_command(
        ctx,
        &spec.id,
        policy,
        &cmd.program,
        resumed_args,
        effective_interactive,
        false,
        helper_bin_dir,
    );
    match resumed_output {
        Ok(out) => {
            let mut result = TaskResult::completed(spec.label.clone());
            result.details.push(format!(
                "continued bulk update with conflicting {} excluded: {}",
                pluralized_package_label(ignored_targets.len()),
                ignored_target_list
            ));
            result.advisories.push(TaskAdvisory {
                severity: AdvisorySeverity::Warning,
                code: "package-conflict-excluded".to_string(),
                summary: format!(
                    "{} excluded from the resumed bulk update after a package file conflict",
                    ignored_target_list
                ),
                remediation: "Review the installed owner package(s) and conflicting target package(s), choose the package set to keep, then rerun update-all when the conflict is resolved.".to_string(),
                blocks_dependents: false,
            });
            result.report_sections =
                build_recovered_command_report_sections_for_command(cmd, original_output, &out);
            result.report_sections.push(TaskReportSection {
                key: package_recovery_section_key().to_string(),
                title: package_recovery_section_title().to_string(),
                rows: recovery_rows,
            });
            attach_command_output_diagnostics(
                &mut result,
                &join_command_outputs(original_output, &out),
            );
            Ok(Some(result))
        }
        Err(resume_err) => {
            let resume_err_output = process_exit_output(&resume_err)
                .map(str::to_string)
                .unwrap_or_else(|| resume_err.to_string());
            for row in &mut recovery_rows {
                row.status = TaskReportStatus::Failed;
                row.after = Some("ignore retry failed".to_string());
                row.note = Some(format!(
                    "{}; retry output: {}",
                    row.note.clone().unwrap_or_default(),
                    concise_command_text(&resume_err_output)
                ));
            }
            append_destructive_recovery_gate_rows(
                &mut recovery_rows,
                &destructive_recovery_rollback_decision(&recovery_plan.owners_to_remove),
            );
            let mut failed = TaskResult::failed(
                spec.label.clone(),
                build_command_failure_detail(
                    spec,
                    cmd,
                    &cmd.program,
                    &format!("recovery resumed bulk update failed: {resume_err}"),
                ),
            );
            let combined_output = join_command_outputs(original_output, &resume_err_output);
            failed.report_sections =
                build_failed_command_report_sections_for_command(cmd, &combined_output);
            failed.report_sections.push(TaskReportSection {
                key: package_recovery_section_key().to_string(),
                title: package_recovery_section_title().to_string(),
                rows: recovery_rows,
            });
            attach_command_output_diagnostics(&mut failed, &combined_output);
            Ok(Some(failed))
        }
    }
}

fn yay_conflict_exclusion_note(target: &YayRecoveryTargetPlan) -> String {
    let mut note = format!(
        "excluded because it conflicted with installed owner(s): {}",
        target.owners.join(", ")
    );
    if let Some(archive) = target
        .cached_archive
        .as_deref()
        .filter(|archive| Path::new(archive).is_file())
    {
        note.push_str(&format!(
            "; cached target archive was left unused: {}",
            archive
        ));
    }
    if !target.paths.is_empty() {
        note.push_str(&format!(
            "; conflicting file(s): {}",
            target.paths.join(", ")
        ));
    }
    note
}

fn append_destructive_recovery_gate_rows(
    rows: &mut Vec<TaskReportRow>,
    decision: &DestructiveRecoveryRollbackDecision,
) {
    match decision {
        DestructiveRecoveryRollbackDecision::Allowed { proofs } if !proofs.is_empty() => {
            rows.extend(proofs.iter().map(|proof| match proof {
                PackageRollbackProof::LocalArchive { package, archive } => TaskReportRow {
                    name: package.clone(),
                    status: TaskReportStatus::Info,
                    before: Some("destructive recovery".to_string()),
                    after: Some("rollback proof available".to_string()),
                    note: Some(format!("validated local package archive: {archive}")),
                },
            }));
        }
        DestructiveRecoveryRollbackDecision::Blocked { packages } => {
            rows.extend(packages.iter().map(|package| TaskReportRow {
                name: package.clone(),
                status: TaskReportStatus::Blocked,
                before: Some("destructive recovery".to_string()),
                after: Some("refused".to_string()),
                note: Some(
                    "owner removal was refused because rollback to the same package identity/version could not be proven".to_string(),
                ),
            }));
        }
        _ => {}
    }
}

fn try_recover_yay_package_plan(
    ctx: &SyncContext,
    spec: &TaskSpec,
    cmd: &CommandTask,
    args: &[String],
    policy: &TaskPolicy,
    effective_interactive: bool,
    original_output: &str,
    recovery_plan: YayPackageRecoveryPlan,
    original_recovery_plan: Option<&RecoveryPlan>,
) -> Result<Option<TaskResult>> {
    let handled_packages = recovery_plan
        .packages
        .iter()
        .map(|package_plan| package_plan.package.clone())
        .collect::<Vec<_>>();
    let package_list = format_package_list(&handled_packages);
    let cleanup_packages = recovery_plan
        .packages
        .iter()
        .filter(|package_plan| package_plan.kind == YayPackageRecoveryKind::SourceDrift)
        .map(|package_plan| package_plan.package.clone())
        .collect::<Vec<_>>();
    if !cleanup_packages.is_empty() {
        ctx.log_line(
            &spec.id,
            LogLevel::Warn,
            LogStream::Meta,
            format!(
                "yay recovery mode: clearing package cache/worktree for {}",
                format_package_list(&cleanup_packages)
            ),
        );
    }
    ctx.log_line(
        &spec.id,
        LogLevel::Warn,
        LogStream::Meta,
        format!("yay recovery mode: retrying package(s) in isolation: {package_list}"),
    );

    let helper_bin_dir = Path::new(&cmd.program).parent();
    let mut recovery_rows = Vec::new();
    let mut recovered_targets = Vec::new();
    let mut retry_failures = Vec::new();

    for package_plan in &recovery_plan.packages {
        for cleanup_path in &package_plan.cleanup_paths {
            let path = Path::new(cleanup_path);
            if !path.exists() {
                continue;
            }
            let removal_result = remove_yay_cleanup_path(path, &package_plan.package);
            match removal_result {
                Ok(_) => recovery_rows.push(TaskReportRow {
                    name: cleanup_path.clone(),
                    status: TaskReportStatus::Skipped,
                    before: Some("present".to_string()),
                    after: Some("removed".to_string()),
                    note: Some(format!(
                        "cleared package cache/worktree for {}",
                        package_plan.package
                    )),
                }),
                Err(err) => {
                    let mut failed = TaskResult::failed(
                        spec.label.clone(),
                        format!(
                            "command failed: yay recovery could not clear package cache/worktree for {}: {}",
                            package_plan.package, err
                        ),
                    );
                    recovery_rows.push(TaskReportRow {
                        name: cleanup_path.clone(),
                        status: TaskReportStatus::Failed,
                        before: Some("present".to_string()),
                        after: Some("remove failed".to_string()),
                        note: Some(err.to_string()),
                    });
                    failed.report_sections =
                        build_failed_command_report_sections_for_command(cmd, original_output);
                    failed.report_sections.push(TaskReportSection {
                        key: package_recovery_section_key().to_string(),
                        title: package_recovery_section_title().to_string(),
                        rows: recovery_rows,
                    });
                    return Ok(Some(failed));
                }
            }
        }

        let retry_output = run_recovery_command(
            ctx,
            &spec.id,
            policy,
            &cmd.program,
            vec![
                "-S".to_string(),
                "--noconfirm".to_string(),
                "--answerclean".to_string(),
                "All".to_string(),
                "--answerdiff".to_string(),
                "None".to_string(),
                "--answeredit".to_string(),
                "None".to_string(),
                package_plan.package.clone(),
            ],
            effective_interactive,
            false,
            helper_bin_dir,
        );

        match retry_output {
            Ok(_) => {
                recovered_targets.push(package_plan.package.clone());
                recovery_rows.push(TaskReportRow {
                    name: package_plan.package.clone(),
                    status: TaskReportStatus::Updated,
                    before: Some("failed".to_string()),
                    after: Some("installed".to_string()),
                    note: Some(match package_plan.kind {
                        YayPackageRecoveryKind::SourceDrift => {
                            "recovered after clearing package cache/worktree".to_string()
                        }
                        YayPackageRecoveryKind::BuildFailure => {
                            "recovered after isolated package retry".to_string()
                        }
                    }),
                });
            }
            Err(retry_err) => {
                let retry_err_text = process_exit_output(&retry_err)
                    .map(str::to_string)
                    .unwrap_or_else(|| retry_err.to_string());
                ctx.log_line(
                    &spec.id,
                    LogLevel::Warn,
                    LogStream::Meta,
                    format!(
                        "focused recovery retry for {} failed; attempting bulk update with unresolved package ignored",
                        package_plan.package
                    ),
                );
                retry_failures.push(YayPackageRetryFailure {
                    package: package_plan.package.clone(),
                    kind: package_plan.kind,
                    cause_summary: package_plan.cause_summary.clone(),
                    error_text: retry_err_text,
                });
            }
        }
    }

    let mut recovery_ignored_packages =
        recovery_plan_ignore_packages(original_recovery_plan, &handled_packages, original_output);
    let mut ignored_targets = recovered_targets.clone();
    ignored_targets.extend(retry_failures.iter().map(|failure| failure.package.clone()));
    ignored_targets.extend(
        recovery_ignored_packages
            .iter()
            .map(|ignored| ignored.package.clone()),
    );
    ignored_targets = expand_yay_dependency_ignore_targets(original_output, &ignored_targets);
    for package in &ignored_targets {
        if handled_packages.iter().any(|handled| handled == package)
            || recovery_ignored_packages
                .iter()
                .any(|ignored| ignored.package == *package)
        {
            continue;
        }
        recovery_ignored_packages.push(YayIgnoredRecoveryPackage {
            package: package.clone(),
            reason: "dependent package grouped with an unresolved package-level failure"
                .to_string(),
        });
    }
    let ignored_target_list = format_package_list(&ignored_targets);
    let resumed_args = append_ignore_args(args, &ignored_targets);
    ctx.log_line(
        &spec.id,
        LogLevel::Info,
        LogStream::Meta,
        format!(
            "resuming bulk yay update with handled targets ignored: {}",
            ignored_target_list
        ),
    );
    let resumed_output = run_recovery_command(
        ctx,
        &spec.id,
        policy,
        &cmd.program,
        resumed_args,
        effective_interactive,
        false,
        helper_bin_dir,
    );

    match resumed_output {
        Ok(out) => {
            let mut result = TaskResult::completed(spec.label.clone());
            if retry_failures.is_empty() && recovery_ignored_packages.is_empty() {
                result.details.push(format!(
                    "auto-recovered source/build failure for {}",
                    package_list
                ));
            } else {
                for failure in &retry_failures {
                    recovery_rows.push(TaskReportRow {
                        name: failure.package.clone(),
                        status: TaskReportStatus::Info,
                        before: Some("failed".to_string()),
                        after: Some("ignored".to_string()),
                        note: Some(build_yay_package_retry_failure_note(failure)),
                    });
                }
                for ignored in &recovery_ignored_packages {
                    recovery_rows.push(TaskReportRow {
                        name: ignored.package.clone(),
                        status: TaskReportStatus::Info,
                        before: Some("failed".to_string()),
                        after: Some("ignored".to_string()),
                        note: Some(ignored.reason.clone()),
                    });
                }
                let unresolved_packages = retry_failure_packages(&retry_failures);
                let all_unresolved = unresolved_recovery_packages(
                    unresolved_packages.clone(),
                    &recovery_ignored_packages,
                );
                result.details.push(format!(
                    "continued bulk update with unresolved {} excluded: {}",
                    pluralized_package_label(all_unresolved.len()),
                    format_package_list(&all_unresolved)
                ));
                let source_only_exclusions = !retry_failures.is_empty()
                    && retry_failures
                        .iter()
                        .all(|failure| failure.kind == YayPackageRecoveryKind::SourceDrift)
                    && recovery_ignored_packages.is_empty();
                result.advisories.push(TaskAdvisory {
                    severity: AdvisorySeverity::Warning,
                    code: if source_only_exclusions {
                        "upstream-source-drift".to_string()
                    } else {
                        "package-recovery-exclusions".to_string()
                    },
                    summary: if source_only_exclusions {
                        format!(
                            "{} still failed source/build validation and was excluded from the resumed bulk update",
                            format_package_list(&all_unresolved)
                        )
                    } else {
                        format!(
                            "{} had unresolved package-level failures and was excluded from the resumed bulk update",
                            format_package_list(&all_unresolved)
                        )
                    },
                    remediation: build_yay_recovery_exclusions_detail(
                        &retry_failures,
                        &recovery_ignored_packages,
                    ),
                    blocks_dependents: false,
                });
            }
            result.report_sections =
                build_recovered_command_report_sections_for_command(cmd, original_output, &out);
            result.report_sections.push(TaskReportSection {
                key: package_recovery_section_key().to_string(),
                title: package_recovery_section_title().to_string(),
                rows: recovery_rows,
            });
            Ok(Some(result))
        }
        Err(resume_err) => {
            let mut failed = if retry_failures.is_empty() {
                TaskResult::failed(
                    spec.label.clone(),
                    build_command_failure_detail(
                        spec,
                        cmd,
                        &cmd.program,
                        &format!("recovery resumed bulk update failed: {resume_err}"),
                    ),
                )
            } else {
                for failure in &retry_failures {
                    recovery_rows.push(TaskReportRow {
                        name: failure.package.clone(),
                        status: TaskReportStatus::Failed,
                        before: Some("source/build failure".to_string()),
                        after: Some("retry failed".to_string()),
                        note: Some(build_yay_package_retry_failure_note(failure)),
                    });
                }
                let unresolved_packages = retry_failure_packages(&retry_failures);
                let source_only_failures = retry_failures
                    .iter()
                    .all(|failure| failure.kind == YayPackageRecoveryKind::SourceDrift);
                let failure_class = if source_only_failures {
                    "upstream source/checksum drift"
                } else {
                    "package-level build failures"
                };
                let mut failed = TaskResult::failed(
                    spec.label.clone(),
                    format!(
                        "{failure_class} left {} unresolved after automatic recovery; resumed bulk update also failed: {resume_err}",
                        format_package_list(&unresolved_packages)
                    ),
                );
                failed.advisories.push(TaskAdvisory {
                    severity: AdvisorySeverity::Warning,
                    code: if source_only_failures {
                        "upstream-source-drift".to_string()
                    } else {
                        "package-recovery-exclusions".to_string()
                    },
                    summary: format!(
                        "{} still failed after focused package retry",
                        format_package_list(&unresolved_packages)
                    ),
                    remediation: build_yay_package_retry_failures_detail(&retry_failures),
                    blocks_dependents: true,
                });
                failed
            };
            let resume_err_output = process_exit_output(&resume_err)
                .map(str::to_string)
                .unwrap_or_else(|| resume_err.to_string());
            let unresolved_summaries = append_original_recovery_diagnostics(
                &mut recovery_rows,
                original_recovery_plan,
                &handled_packages,
            );
            annotate_unresolved_recovery_diagnostics(&mut failed, &unresolved_summaries);
            let combined_output = join_command_outputs(original_output, &resume_err_output);
            failed.report_sections =
                build_failed_command_report_sections_for_command(cmd, &combined_output);
            failed.report_sections.push(TaskReportSection {
                key: package_recovery_section_key().to_string(),
                title: package_recovery_section_title().to_string(),
                rows: recovery_rows,
            });
            Ok(Some(failed))
        }
    }
}

fn run_recovery_command(
    ctx: &SyncContext,
    task_id: &str,
    policy: &TaskPolicy,
    program: &str,
    args: Vec<String>,
    interactive: bool,
    requires_elevation: bool,
    helper_bin_dir: Option<&Path>,
) -> Result<String> {
    let cmd = CommandTask {
        program: resolve_recovery_program(program, helper_bin_dir),
        args,
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation,
        needs_sudo_session: false,
        interactive,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };
    let (invocation_program, invocation_args) = build_command_invocation(ctx.host_os, &cmd);
    let resolved_program = resolve_recovery_program(&invocation_program, helper_bin_dir);
    ctx.log_line(
        task_id,
        LogLevel::Info,
        LogStream::Meta,
        format!(
            "recovery: {} {}",
            resolved_program,
            invocation_args.join(" ")
        ),
    );
    ctx.run_command_with_policy(
        task_id,
        &resolved_program,
        invocation_args,
        policy,
        command_interactive_mode(ctx.host_os, &cmd),
    )
}

fn resolve_recovery_program(program: &str, helper_bin_dir: Option<&Path>) -> String {
    let path = Path::new(program);
    if path.components().count() > 1 {
        return program.to_string();
    }
    if let Some(dir) = helper_bin_dir {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return candidate.to_string_lossy().to_string();
        }
    }
    which(program)
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or_else(|| program.to_string())
}

fn build_yay_recovery_plan(err_text: &str) -> Option<YayRecoveryPlan> {
    let conflicts = parse_pacman_conflict_records(err_text);
    if conflicts.is_empty() {
        return None;
    }

    let recoverable_targets = collect_recoverable_conflict_targets(&conflicts);
    if recoverable_targets.is_empty() {
        return None;
    }

    let cached_archives = collect_cached_archives_by_target(
        &parse_yay_failed_package_archives(err_text),
        &recoverable_targets,
    );
    let owner_names = recoverable_targets
        .iter()
        .flat_map(|target| target.owners.iter().cloned())
        .collect::<BTreeSet<_>>();
    let owner_archives = collect_cached_archives_by_names(
        &parse_yay_failed_package_archives(err_text),
        &owner_names,
    );
    let mut owner_targets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let targets = recoverable_targets
        .into_iter()
        .map(|target| {
            for owner in &target.owners {
                owner_targets
                    .entry(owner.clone())
                    .or_default()
                    .insert(target.target.clone());
            }
            YayRecoveryTargetPlan {
                cached_archive: cached_archives.get(&target.target).cloned(),
                target: target.target,
                owners: target.owners,
                paths: target.paths,
            }
        })
        .collect::<Vec<_>>();
    let owners_to_remove = owner_targets
        .into_iter()
        .map(|(owner, targets)| YayRecoveryOwnerPlan {
            cached_archive: owner_archives.get(&owner).cloned(),
            owner,
            targets: targets.into_iter().collect(),
        })
        .collect::<Vec<_>>();

    Some(YayRecoveryPlan {
        targets,
        owners_to_remove,
    })
}

fn yay_source_path_matches_package(source_path: &str, package: &str) -> bool {
    Path::new(source_path)
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == package)
}

fn parse_pacman_conflict_records(input: &str) -> Vec<PacmanConflictRecord> {
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        let parsed = if trimmed.contains(" exists in filesystem ") && trimmed.contains("(owned by ")
        {
            parse_pacman_owned_by_conflict(trimmed)
                .map(|(target, path, owner)| (target, path, owner, false))
        } else if trimmed.contains(" exists in both '") {
            parse_pacman_exists_in_both_conflict(trimmed)
        } else {
            None
        };
        let Some((target, path, owner, transaction_internal)) = parsed else {
            continue;
        };
        if target.is_empty() || path.is_empty() || owner.is_empty() {
            continue;
        }
        if !seen.insert((target.to_string(), path.to_string(), owner.to_string())) {
            continue;
        }
        records.push(PacmanConflictRecord {
            target: target.to_string(),
            path: path.to_string(),
            owner: owner.to_string(),
            transaction_internal,
        });
    }
    records
}

fn parse_pacman_owned_by_conflict(line: &str) -> Option<(&str, &str, &str)> {
    let (target, rest) = line.split_once(':')?;
    let (path, owner_part) = rest.split_once(" exists in filesystem ")?;
    let owner_start = owner_part.find("(owned by ")?;
    let owner_part = &owner_part[owner_start + "(owned by ".len()..];
    let owner_end = owner_part.find(')')?;
    Some((target.trim(), path.trim(), owner_part[..owner_end].trim()))
}

fn parse_pacman_exists_in_both_conflict(line: &str) -> Option<(&str, &str, &str, bool)> {
    let (target_seed, rest, transaction_internal) =
        if let Some((target_seed, rest)) = line.split_once(':') {
            (target_seed.trim(), rest, false)
        } else {
            ("", line, true)
        };
    let (path, package_part) = rest.split_once(" exists in both '")?;
    let (first, rest) = package_part.split_once("' and '")?;
    let (second, _) = rest.split_once('\'')?;
    let target = target_seed;
    let target = if target.is_empty() {
        first.trim()
    } else {
        target
    };
    Some((target, path.trim(), second.trim(), transaction_internal))
}

fn collect_recoverable_conflict_targets(
    records: &[PacmanConflictRecord],
) -> Vec<RecoverableConflictTarget> {
    let mut grouped: BTreeMap<String, RecoverableConflictTarget> = BTreeMap::new();
    for record in records {
        if record.transaction_internal {
            continue;
        }
        let entry =
            grouped
                .entry(record.target.clone())
                .or_insert_with(|| RecoverableConflictTarget {
                    target: record.target.clone(),
                    owners: Vec::new(),
                    paths: Vec::new(),
                });
        if !entry.owners.iter().any(|owner| owner == &record.owner) {
            entry.owners.push(record.owner.clone());
        }
        if !entry.paths.iter().any(|path| path == &record.path) {
            entry.paths.push(record.path.clone());
        }
    }

    grouped
        .into_values()
        .filter(|target| {
            target.target.ends_with("-debug")
                && !target.owners.is_empty()
                && target.owners.iter().all(|owner| owner.ends_with("-debug"))
                && target
                    .paths
                    .iter()
                    .all(|path| path.starts_with("/usr/lib/debug/"))
        })
        .collect()
}

fn parse_yay_failed_package_archives(input: &str) -> Vec<String> {
    let Some(error_installing_idx) = input.find("error installing:") else {
        return Vec::new();
    };
    let suffix = &input[error_installing_idx..];
    let Some(open_idx) = suffix.find('[') else {
        return Vec::new();
    };
    let Some(close_idx) = suffix[open_idx + 1..].find(']') else {
        return Vec::new();
    };
    suffix[open_idx + 1..open_idx + 1 + close_idx]
        .split_whitespace()
        .filter(|token| token.contains(".pkg.tar"))
        .map(|token| token.to_string())
        .collect()
}

fn collect_cached_archives_by_target(
    archive_paths: &[String],
    targets: &[RecoverableConflictTarget],
) -> BTreeMap<String, String> {
    let mut by_target = BTreeMap::new();
    let target_names = targets
        .iter()
        .map(|target| target.target.clone())
        .collect::<BTreeSet<_>>();

    for archive in archive_paths {
        if let Some(target) = archive_target_from_path(archive, &target_names) {
            by_target.entry(target).or_insert_with(|| archive.clone());
        }
    }

    by_target
}

fn collect_cached_archives_by_names(
    archive_paths: &[String],
    target_names: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut by_target = BTreeMap::new();
    for archive in archive_paths {
        if let Some(target) = archive_target_from_path(archive, target_names) {
            by_target.entry(target).or_insert_with(|| archive.clone());
        }
    }
    by_target
}

fn archive_target_from_path(archive_path: &str, target_names: &BTreeSet<String>) -> Option<String> {
    let archive = Path::new(archive_path);
    if let Some(parent_name) = archive
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
    {
        let parent_name = parent_name.trim();
        if target_names.contains(parent_name) {
            return Some(parent_name.to_string());
        }
    }

    let file_name = archive.file_name().and_then(|name| name.to_str())?;
    target_names
        .iter()
        .find(|target| {
            file_name.starts_with(&format!("{target}-")) && file_name.contains(".pkg.tar")
        })
        .cloned()
}

fn append_ignore_args(args: &[String], ignored_packages: &[String]) -> Vec<String> {
    let mut merged_ignored = BTreeSet::new();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--ignore" {
            if let Some(existing) = args.get(i + 1) {
                for package in existing
                    .split(',')
                    .map(str::trim)
                    .filter(|pkg| !pkg.is_empty())
                {
                    merged_ignored.insert(package.to_string());
                }
                i += 2;
                continue;
            }
        }
        out.push(args[i].clone());
        i += 1;
    }
    for package in ignored_packages.iter().filter(|pkg| !pkg.trim().is_empty()) {
        merged_ignored.insert(package.trim().to_string());
    }
    if !merged_ignored.is_empty() {
        out.push("--ignore".to_string());
        out.push(merged_ignored.into_iter().collect::<Vec<_>>().join(","));
    }
    out
}

fn build_yay_package_retry_failure_detail(failure: &YayPackageRetryFailure) -> String {
    match failure.kind {
        YayPackageRecoveryKind::SourceDrift
            if is_yay_source_validity_failure(&failure.error_text) =>
        {
            format!(
                "yay recovery cleared the package cache/worktree and retried {}, but source validation still failed; this usually indicates upstream source or checksum drift and needs manual intervention. See task-yay.log for the retry transcript.",
                failure.package
            )
        }
        YayPackageRecoveryKind::SourceDrift => format!(
            "yay recovery could not reinstall {} after clearing the package cache/worktree. See task-yay.log for the retry transcript.",
            failure.package
        ),
        YayPackageRecoveryKind::BuildFailure => format!(
            "the isolated retry for {} failed{}; its cache/worktree was preserved because no source/checksum failure was attributed. See task-yay.log for the retry transcript.",
            failure.package,
            failure
                .cause_summary
                .as_deref()
                .map(|summary| format!(" after the attributed build failure: {summary}"))
                .unwrap_or_default()
        ),
    }
}

fn build_yay_package_retry_failures_detail(failures: &[YayPackageRetryFailure]) -> String {
    if let [failure] = failures {
        return build_yay_package_retry_failure_detail(failure);
    }
    let packages = retry_failure_packages(failures);
    if failures.iter().all(|failure| {
        failure.kind == YayPackageRecoveryKind::SourceDrift
            && is_yay_source_validity_failure(&failure.error_text)
    }) {
        return format!(
            "yay recovery cleared the package cache/worktree and retried {}, but source validation still failed; this usually indicates upstream source or checksum drift and needs manual intervention. See task-yay.log for the retry transcripts.",
            format_package_list(&packages)
        );
    }
    failures
        .iter()
        .map(build_yay_package_retry_failure_detail)
        .collect::<Vec<_>>()
        .join(" ")
}

fn build_yay_package_retry_failure_note(failure: &YayPackageRetryFailure) -> String {
    match failure.kind {
        YayPackageRecoveryKind::SourceDrift
            if is_yay_source_validity_failure(&failure.error_text) =>
        {
            format!(
                "{} still fails source validation after cache/worktree cleanup; likely upstream source/checksum drift. See task-yay.log for retry output.",
                failure.package
            )
        }
        YayPackageRecoveryKind::SourceDrift => format!(
            "{} retry failed after cache/worktree cleanup; see task-yay.log for details.",
            failure.package
        ),
        YayPackageRecoveryKind::BuildFailure => format!(
            "{} isolated build retry failed{}; cache/worktree preserved. See task-yay.log for details.",
            failure.package,
            failure
                .cause_summary
                .as_deref()
                .map(|summary| format!(" after: {summary}"))
                .unwrap_or_default()
        ),
    }
}

fn retry_failure_packages(failures: &[YayPackageRetryFailure]) -> Vec<String> {
    failures
        .iter()
        .map(|failure| failure.package.clone())
        .collect()
}

fn unresolved_recovery_packages(
    mut retry_packages: Vec<String>,
    ignored_packages: &[YayIgnoredRecoveryPackage],
) -> Vec<String> {
    retry_packages.extend(
        ignored_packages
            .iter()
            .map(|ignored| ignored.package.clone()),
    );
    retry_packages
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn recovery_plan_ignore_packages(
    original_recovery_plan: Option<&RecoveryPlan>,
    handled_packages: &[String],
    original_output: &str,
) -> Vec<YayIgnoredRecoveryPackage> {
    let Some(plan) = original_recovery_plan else {
        return Vec::new();
    };
    let mut ignored = Vec::new();
    for cause in &plan.causes {
        match cause {
            RecoveryCause::BuildFailure {
                package: Some(package),
                summary,
            } if !handled_packages.iter().any(|handled| handled == package) => {
                ignored.push(YayIgnoredRecoveryPackage {
                    package: package.clone(),
                    reason: format!("build failure: {summary}"),
                });
            }
            RecoveryCause::SourceChecksumDrift {
                package: Some(package),
            } if !handled_packages.iter().any(|handled| handled == package) => {
                ignored.push(YayIgnoredRecoveryPackage {
                    package: package.clone(),
                    reason: "source/checksum drift".to_string(),
                });
            }
            _ => {}
        }
    }
    let expanded = expand_yay_dependency_ignore_targets(
        original_output,
        &ignored
            .iter()
            .map(|ignored| ignored.package.clone())
            .collect::<Vec<_>>(),
    );
    for package in expanded {
        if ignored.iter().any(|ignored| ignored.package == package) {
            continue;
        }
        ignored.push(YayIgnoredRecoveryPackage {
            package,
            reason: "dependent package grouped with an unresolved package-level failure"
                .to_string(),
        });
    }
    ignored
}

fn expand_yay_dependency_ignore_targets(output: &str, seed_packages: &[String]) -> Vec<String> {
    let mut packages = seed_packages
        .iter()
        .filter(|package| !package.trim().is_empty())
        .cloned()
        .collect::<BTreeSet<_>>();
    if packages.is_empty() {
        return Vec::new();
    }

    let groups = yay_dependency_groups(output);
    let mut changed = true;
    while changed {
        changed = false;
        for group in &groups {
            if group.iter().any(|package| packages.contains(package)) {
                for package in group {
                    changed |= packages.insert(package.clone());
                }
            }
        }
    }
    let mut changed = true;
    while changed {
        changed = false;
        for package in yay_dependency_summary_dependents(output, &packages) {
            changed |= packages.insert(package);
        }
    }
    packages.into_iter().collect()
}

fn yay_dependency_groups(output: &str) -> Vec<Vec<String>> {
    output
        .lines()
        .filter_map(yay_dependency_group_line)
        .collect()
}

fn yay_dependency_group_line(line: &str) -> Option<Vec<String>> {
    let line = strip_ansi(line);
    let start = line.find("dependency of ")?;
    let after = &line[start + "dependency of ".len()..];
    let end = after.find(')')?;
    let packages = after[..end]
        .split(',')
        .map(str::trim)
        .filter(|package| looks_like_plain_package_name(package))
        .map(str::to_string)
        .collect::<Vec<_>>();
    (packages.len() > 1).then_some(packages)
}

fn yay_dependency_summary_dependents(
    output: &str,
    seed_packages: &BTreeSet<String>,
) -> Vec<String> {
    let dependency_summary_packages = yay_aur_summary_package_details(output, "AUR Dependency");
    let dependency_packages = dependency_summary_packages
        .iter()
        .map(|package| package.name.clone())
        .collect::<BTreeSet<_>>();
    if dependency_packages.is_empty()
        || !dependency_packages
            .iter()
            .any(|package| seed_packages.contains(package))
    {
        return Vec::new();
    }

    let source_failure_packages = parse_yay_failed_package_names(output)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let seeded_dependency_versions = dependency_summary_packages
        .iter()
        .filter(|package| seed_packages.contains(&package.name))
        .filter_map(|package| package.version.as_deref())
        .collect::<BTreeSet<_>>();
    let explicit_dependents = yay_aur_summary_package_details(output, "AUR Explicit")
        .into_iter()
        .filter(|package| {
            package
                .version
                .as_deref()
                .is_some_and(|version| seeded_dependency_versions.contains(version))
        })
        .map(|package| package.name);
    let failed_status_dependents = output
        .lines()
        .filter_map(yay_failed_status_package_line)
        .collect::<Vec<_>>();
    explicit_dependents
        .chain(failed_status_dependents)
        .filter(|package| !dependency_packages.contains(package))
        .filter(|package| !source_failure_packages.contains(package))
        .filter(|package| !seed_packages.contains(package))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn yay_aur_summary_packages(output: &str, label: &str) -> BTreeSet<String> {
    yay_aur_summary_package_details(output, label)
        .into_iter()
        .map(|package| package.name)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct YaySummaryPackage {
    name: String,
    version: Option<String>,
}

fn yay_aur_summary_package_details(output: &str, label: &str) -> Vec<YaySummaryPackage> {
    let known_packages = parse_yay_report(output)
        .into_iter()
        .flat_map(|section| section.rows)
        .map(|row| report_package_name(&row.name))
        .collect::<BTreeSet<_>>();
    output
        .lines()
        .flat_map(|line| yay_aur_summary_line_package_details(line, label, &known_packages))
        .collect()
}

fn yay_aur_summary_line_package_details(
    line: &str,
    label: &str,
    known_packages: &BTreeSet<String>,
) -> Vec<YaySummaryPackage> {
    let line = strip_ansi(line);
    let Some((prefix, rest)) = line.split_once(':') else {
        return Vec::new();
    };
    if !prefix.contains(label) {
        return Vec::new();
    }
    rest.split(',')
        .filter_map(|token| yay_summary_token_package_detail(token, known_packages))
        .collect()
}

fn yay_summary_token_package_detail(
    token: &str,
    known_packages: &BTreeSet<String>,
) -> Option<YaySummaryPackage> {
    let token = token
        .trim()
        .trim_end_matches(|c| matches!(c, ',' | ';' | '.'));
    if token.is_empty() {
        return None;
    }
    if let Some(package) = known_packages
        .iter()
        .filter(|package| token == package.as_str() || token.starts_with(&format!("{package}-")))
        .max_by_key(|package| package.len())
    {
        let version = token
            .strip_prefix(package)
            .and_then(|rest| rest.strip_prefix('-'))
            .filter(|rest| !rest.is_empty())
            .map(str::to_string);
        return Some(YaySummaryPackage {
            name: package.clone(),
            version,
        });
    }
    let (without_pkgrel, pkgrel) = token.rsplit_once('-')?;
    let (package, version) = without_pkgrel.rsplit_once('-')?;
    if !version.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        return None;
    }
    looks_like_plain_package_name(package).then(|| YaySummaryPackage {
        name: package.to_string(),
        version: Some(format!("{version}-{pkgrel}")),
    })
}

fn yay_failed_status_package_line(line: &str) -> Option<String> {
    let line = strip_ansi(line);
    let trimmed = line.trim();
    let package = if let Some(package) = parse_yay_error_making_package_line(trimmed) {
        package
    } else if let Some((package, _)) = trimmed
        .split_once(" - exit status")
        .or_else(|| trimmed.split_once("-exit status"))
    {
        package.trim().to_string()
    } else {
        return None;
    };
    looks_like_plain_package_name(&package).then_some(package)
}

fn build_yay_recovery_exclusions_detail(
    retry_failures: &[YayPackageRetryFailure],
    ignored_packages: &[YayIgnoredRecoveryPackage],
) -> String {
    let mut details = Vec::new();
    if !retry_failures.is_empty() {
        details.push(build_yay_package_retry_failures_detail(retry_failures));
    }
    details.extend(
        ignored_packages
            .iter()
            .map(|ignored| format!("{} was excluded: {}", ignored.package, ignored.reason)),
    );
    if details.is_empty() {
        "Review task-yay.log for the package-level failures, then rerun update-all after fixing them."
            .to_string()
    } else {
        details.join(" ")
    }
}

fn pluralized_package_label(count: usize) -> &'static str {
    if count == 1 {
        "package"
    } else {
        "packages"
    }
}

fn format_package_list(packages: &[String]) -> String {
    packages.join(", ")
}

fn is_yay_source_validity_failure(input: &str) -> bool {
    let lower = input.to_ascii_lowercase();
    lower.contains("one or more files did not pass the validity check")
        || lower.contains("error downloading sources:")
}

fn parse_yay_failed_package_name(input: &str) -> Option<String> {
    parse_yay_failed_package_names(input).into_iter().next()
}

fn parse_yay_failed_package_names(input: &str) -> Vec<String> {
    let mut packages = BTreeSet::new();
    for path in parse_yay_failed_source_paths(input) {
        if let Some(package) = Path::new(&path)
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
        {
            packages.insert(package);
        }
    }
    for package in parse_yay_error_making_packages_near_source_failure(input) {
        packages.insert(package);
    }

    packages.into_iter().collect()
}

fn parse_yay_error_making_package_line(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("-> error making:")?.trim();
    let package = rest
        .split_once("-exit status")
        .or_else(|| rest.split_once(" - exit status"))
        .map(|(pkg, _)| pkg.trim())?;
    (!package.is_empty()).then_some(package.to_string())
}

fn parse_yay_error_making_packages_near_source_failure(input: &str) -> Vec<String> {
    let lines = input.lines().collect::<Vec<_>>();
    let mut packages = BTreeSet::new();
    for (idx, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if !lower.contains("one or more files did not pass the validity check")
            && !lower.contains("error downloading sources:")
        {
            continue;
        }
        let end = usize::min(idx + 8, lines.len());
        for candidate in &lines[idx..end] {
            let lower = candidate.to_ascii_lowercase();
            if lower.contains("a failure occurred in build()")
                || lower.contains("error: problem encountered:")
                || lower.contains("meson.build")
                || lower.contains("ninja: build stopped")
            {
                break;
            }
            if let Some(package) = parse_yay_error_making_package_line(candidate) {
                packages.insert(package);
            }
        }
    }
    packages.into_iter().collect()
}

fn parse_yay_failed_source_path(input: &str) -> Option<String> {
    parse_yay_failed_source_paths(input).into_iter().next()
}

fn parse_yay_failed_source_paths(input: &str) -> Vec<String> {
    let mut paths = BTreeSet::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if let Some(path) = trimmed
            .strip_prefix("-> error downloading sources:")
            .or_else(|| trimmed.strip_prefix("error downloading sources:"))
        {
            let path = path.trim();
            if !path.is_empty() {
                paths.insert(path.to_string());
            }
        }
    }
    paths.into_iter().collect()
}

fn remove_yay_cleanup_path(path: &Path, package: &str) -> std::io::Result<()> {
    match remove_path_no_follow(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            if path_is_expected_yay_cache(path, package) {
                repair_yay_cleanup_permissions(path)?;
                remove_path_no_follow(path)
            } else {
                Err(err)
            }
        }
        Err(err) => Err(err),
    }
}

fn remove_path_no_follow(path: &Path) -> std::io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
}

fn path_is_expected_yay_cache(path: &Path, package: &str) -> bool {
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    let expected_root = Path::new(&home).join(".cache").join("yay").join(package);
    path == expected_root || path.starts_with(&expected_root)
}

#[cfg(unix)]
fn repair_yay_cleanup_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let current_uid = current_effective_uid()?;
    repair_yay_cleanup_permissions_inner(path, current_uid)
}

#[cfg(unix)]
fn repair_yay_cleanup_permissions_inner(path: &Path, current_uid: u32) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let meta = fs::symlink_metadata(path)?;
    if meta.uid() != current_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to repair yay cache permissions for path not owned by current user",
        ));
    }
    if !meta.file_type().is_dir() {
        return Ok(());
    }

    let mut perms = meta.permissions();
    let mode = perms.mode();
    let repaired = mode | 0o700;
    if repaired != mode {
        perms.set_mode(repaired);
        fs::set_permissions(path, perms)?;
    }

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let child_path = entry.path();
        let child_meta = fs::symlink_metadata(&child_path)?;
        if child_meta.file_type().is_dir() {
            repair_yay_cleanup_permissions_inner(&child_path, current_uid)?;
        } else if child_meta.uid() != current_uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "refusing to remove yay cache path containing file not owned by current user",
            ));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn current_effective_uid() -> std::io::Result<u32> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "could not determine current user id",
        ));
    }
    let uid_text = String::from_utf8_lossy(&output.stdout);
    uid_text.trim().parse::<u32>().map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("could not parse current user id: {err}"),
        )
    })
}

#[cfg(not(unix))]
fn repair_yay_cleanup_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn command_interactive_mode(host_os: HostOs, cmd: &CommandTask) -> bool {
    if matches!(host_os, HostOs::Windows) && cmd.requires_elevation {
        return false;
    }
    cmd.interactive
}

fn detect_command_output_failure(cmd: &CommandTask, output: &str) -> Option<String> {
    if winget_scope_for_command(cmd).is_some() {
        return output.lines().find_map(|line| {
            let trimmed = line.trim();
            winget_output_failure_marker(trimmed).map(ToString::to_string)
        });
    }
    None
}

fn ensure_sudo_preflight_once(ctx: &SyncContext, spec: &TaskSpec) -> Result<()> {
    #[cfg(unix)]
    {
        if !matches!(ctx.host_os, HostOs::Linux | HostOs::Macos) {
            return Ok(());
        }
        let mut cached = ctx
            .privilege_session
            .sudo_preflight
            .lock()
            .map_err(|_| anyhow::anyhow!("privilege session lock poisoned"))?;
        if let Some(result) = cached.as_ref() {
            return result.clone().map_err(anyhow::Error::msg);
        }

        if which("sudo").is_none() {
            let err = "sudo is required for this run but was not found".to_string();
            *cached = Some(Err(err.clone()));
            bail!(err);
        }

        let preflight = run_sudo_preflight(ctx, spec, false);

        *cached = Some(preflight.clone());
        if preflight.is_ok() {
            clear_sudo_runtime_error(&ctx.privilege_session);
        }
        preflight.map_err(anyhow::Error::msg)
    }
    #[cfg(not(unix))]
    {
        let _ = (ctx, spec);
        Ok(())
    }
}

fn run_sudo_preflight(
    ctx: &SyncContext,
    spec: &TaskSpec,
    noninteractive: bool,
) -> Result<(), String> {
    if noninteractive {
        return Command::new("sudo")
            .args(["-n", "-v"])
            .output()
            .map_err(|e| format!("sudo non-interactive refresh failed: {e}"))
            .and_then(|output| {
                if output.status.success() {
                    Ok(())
                } else {
                    let mut detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    if detail.is_empty() {
                        detail = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    }
                    if detail.is_empty() {
                        detail = format!("exit status {}", output.status);
                    }
                    Err(format!("sudo non-interactive refresh failed: {detail}"))
                }
            });
    }

    let mut preflight_policy = ctx.task_policies.system_update.clone();
    preflight_policy.retries = 0;
    preflight_policy.retry_backoff = Duration::ZERO;
    ctx.run_command_with_policy_foreground(
        &spec.id,
        "sudo",
        vec!["-v".to_string()],
        &preflight_policy,
        true,
    )
    .map(|_| ())
    .map_err(|e| format!("sudo preflight failed: {e}"))
}

fn ensure_sudo_session_fresh(ctx: &SyncContext, spec: &TaskSpec, cmd: &CommandTask) -> Result<()> {
    #[cfg(unix)]
    {
        if !matches!(ctx.host_os, HostOs::Linux | HostOs::Macos) {
            return Ok(());
        }
        if which("sudo").is_none() {
            let err = "sudo is required for this run but was not found".to_string();
            record_sudo_runtime_error(&ctx.privilege_session, err.clone());
            bail!(err);
        }

        let _refresh_guard = ctx
            .privilege_session
            .sudo_refresh_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("privilege session refresh lock poisoned"))?;
        let had_successful_preflight = ctx
            .privilege_session
            .sudo_preflight
            .lock()
            .ok()
            .and_then(|cached| cached.as_ref().map(Result::is_ok))
            .unwrap_or(false);

        match run_sudo_preflight(ctx, spec, true) {
            Ok(()) => {
                if let Ok(mut cached) = ctx.privilege_session.sudo_preflight.lock() {
                    *cached = Some(Ok(()));
                }
                clear_sudo_runtime_error(&ctx.privilege_session);
                return Ok(());
            }
            Err(noninteractive_err) if had_successful_preflight => {
                let err = format!(
                    "{noninteractive_err}; cached sudo session expired before {}",
                    spec.label
                );
                record_sudo_runtime_error(&ctx.privilege_session, err.clone());
                if let Ok(mut cached) = ctx.privilege_session.sudo_preflight.lock() {
                    *cached = Some(Err(err.clone()));
                }
                bail!(err);
            }
            Err(noninteractive_err) => match run_sudo_preflight(ctx, spec, false) {
                Ok(()) => {
                    if let Ok(mut cached) = ctx.privilege_session.sudo_preflight.lock() {
                        *cached = Some(Ok(()));
                    }
                    clear_sudo_runtime_error(&ctx.privilege_session);
                    Ok(())
                }
                Err(interactive_err) => {
                    let err = format!("{noninteractive_err}; {interactive_err}");
                    record_sudo_runtime_error(&ctx.privilege_session, err.clone());
                    if let Ok(mut cached) = ctx.privilege_session.sudo_preflight.lock() {
                        *cached = Some(Err(err.clone()));
                    }
                    bail!(err);
                }
            },
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (ctx, spec, cmd);
        Ok(())
    }
}

fn refresh_sudo_session_after_launch_failure(ctx: &SyncContext, spec: &TaskSpec) -> Result<()> {
    #[cfg(unix)]
    {
        if !matches!(ctx.host_os, HostOs::Linux | HostOs::Macos) {
            return Ok(());
        }
        if which("sudo").is_none() {
            let err = "sudo is required for this run but was not found".to_string();
            record_sudo_runtime_error(&ctx.privilege_session, err.clone());
            bail!(err);
        }

        let _refresh_guard = ctx
            .privilege_session
            .sudo_refresh_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("privilege session refresh lock poisoned"))?;
        match run_sudo_preflight(ctx, spec, false) {
            Ok(()) => {
                if let Ok(mut cached) = ctx.privilege_session.sudo_preflight.lock() {
                    *cached = Some(Ok(()));
                }
                clear_sudo_runtime_error(&ctx.privilege_session);
                Ok(())
            }
            Err(err) => {
                let err = format!(
                    "{err}; cached sudo session expired during {} command launch",
                    spec.label
                );
                record_sudo_runtime_error(&ctx.privilege_session, err.clone());
                if let Ok(mut cached) = ctx.privilege_session.sudo_preflight.lock() {
                    *cached = Some(Err(err.clone()));
                }
                bail!(err);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (ctx, spec);
        Ok(())
    }
}

fn record_sudo_runtime_error(session: &PrivilegeSession, err: impl Into<String>) {
    if let Ok(mut slot) = session.sudo_runtime_error.lock() {
        *slot = Some(err.into());
    }
}

fn clear_sudo_runtime_error(session: &PrivilegeSession) {
    if let Ok(mut slot) = session.sudo_runtime_error.lock() {
        *slot = None;
    }
}

fn sudo_runtime_error(session: &PrivilegeSession) -> Option<String> {
    session
        .sudo_runtime_error
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
}

fn build_command_invocation(host_os: HostOs, cmd: &CommandTask) -> (String, Vec<String>) {
    let mut base_program = cmd.program.clone();
    let mut base_args = cmd.args.clone();
    if cmd.shell {
        #[cfg(windows)]
        {
            let script = windows_cmd_shell_command(&cmd.program, &cmd.args);
            base_program = "cmd".to_string();
            base_args = vec!["/C".to_string(), script];
        }
        #[cfg(not(windows))]
        {
            let mut script = cmd.program.clone();
            if !cmd.args.is_empty() {
                script.push(' ');
                script.push_str(&cmd.args.join(" "));
            }
            base_program = "sh".to_string();
            base_args = vec!["-lc".to_string(), script];
        }
    }
    if !cmd.shell {
        if let Some(resolved) = which(&base_program) {
            base_program = resolved.to_string_lossy().to_string();
        }
    }
    if cmd.requires_elevation {
        #[cfg(unix)]
        {
            if matches!(host_os, HostOs::Linux | HostOs::Macos) {
                if cmd.interactive {
                    let mut args = vec![
                        "-c".to_string(),
                        "sudo -v && exec sudo -n -- \"$@\"".to_string(),
                        "update-all-sudo".to_string(),
                        base_program,
                    ];
                    args.extend(base_args);
                    return ("sh".to_string(), args);
                }
                // Authentication is handled by preflight; the protected command should
                // fail fast if the cached sudo session disappears before launch.
                let mut args = vec!["-n".to_string(), "--".to_string(), base_program];
                args.extend(base_args);
                return ("sudo".to_string(), args);
            }
        }
        #[cfg(windows)]
        {
            if matches!(host_os, HostOs::Windows) {
                return windows_elevated_invocation(base_program, base_args);
            }
        }
    }
    if matches!(host_os, HostOs::Windows) && !cmd.shell && is_windows_cmd_script(&base_program) {
        let mut args = vec!["/C".to_string(), base_program];
        args.extend(base_args);
        return ("cmd".to_string(), args);
    }
    if matches!(host_os, HostOs::Windows) && !cmd.shell {
        if !cmd.requires_elevation && should_windows_host_safe_capture(&base_program) {
            return windows_host_safe_capture_invocation(base_program, base_args);
        }
    }
    if cmd.windows_bridge {
        return wsl_windows_bridge_invocation(base_program, base_args);
    }

    (base_program, base_args)
}

fn should_windows_host_safe_capture(program: &str) -> bool {
    let lower = std::path::Path::new(program)
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| program.to_ascii_lowercase());
    lower.starts_with("scoop")
        || lower.starts_with("winget")
        || lower.starts_with("choco")
        || lower.starts_with("chocolatey")
}

#[cfg(windows)]
fn windows_host_safe_capture_invocation(
    program: String,
    args: Vec<String>,
) -> (String, Vec<String>) {
    let escaped_program = powershell_single_quote(&program);
    let escaped_args: Vec<String> = args.iter().map(|a| powershell_single_quote(a)).collect();
    let arg_list = if escaped_args.is_empty() {
        "@()".to_string()
    } else {
        format!("@('{}')", escaped_args.join("','"))
    };
    let script = format!(
        "$ErrorActionPreference='Continue'; & '{escaped_program}' {arg_list} *>&1; exit $LASTEXITCODE"
    );
    (
        "powershell".to_string(),
        vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-Command".to_string(),
            script,
        ],
    )
}

#[cfg(not(windows))]
fn windows_host_safe_capture_invocation(
    program: String,
    args: Vec<String>,
) -> (String, Vec<String>) {
    (program, args)
}

#[cfg(windows)]
fn windows_elevated_invocation(program: String, args: Vec<String>) -> (String, Vec<String>) {
    let escaped_program = powershell_single_quote(&program);
    let escaped_args: Vec<String> = args.iter().map(|a| powershell_single_quote(a)).collect();
    let arglist = if escaped_args.is_empty() {
        "@()".to_string()
    } else {
        format!("@('{}')", escaped_args.join("','"))
    };
    let script = format!(
        "$ErrorActionPreference='Stop'; function Test-UserCanceledElevation([System.Exception]$ex) {{ while ($null -ne $ex) {{ $hr = $ex.HResult; if ($hr -eq -2147023673 -or $hr -eq 1223 -or $ex.Message -like '*operation was canceled by the user*') {{ return $true }}; $ex = $ex.InnerException }}; return $false }}; try {{ $p = Start-Process -FilePath '{escaped_program}' -ArgumentList {arglist} -Verb RunAs -Wait -PassThru; exit $p.ExitCode }} catch {{ if (Test-UserCanceledElevation $_.Exception) {{ exit 1223 }}; Write-Error $_; exit 1 }}"
    );
    (
        "powershell".to_string(),
        vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-Command".to_string(),
            script,
        ],
    )
}

fn wsl_windows_bridge_invocation(program: String, args: Vec<String>) -> (String, Vec<String>) {
    let escaped_program = powershell_single_quote(&program);
    let escaped_args: Vec<String> = args.iter().map(|a| powershell_single_quote(a)).collect();
    let arglist = if escaped_args.is_empty() {
        "@()".to_string()
    } else {
        format!("@('{}')", escaped_args.join("','"))
    };
    let script = format!("& '{escaped_program}' {arglist}; exit $LASTEXITCODE");
    (
        "powershell.exe".to_string(),
        vec![
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-Command".to_string(),
            script,
        ],
    )
}

fn powershell_single_quote(input: &str) -> String {
    input.replace('\'', "''")
}

#[cfg(windows)]
fn windows_cmd_shell_command(program: &str, args: &[String]) -> String {
    let mut script = program.to_string();
    if !args.is_empty() {
        if !script.is_empty() {
            script.push(' ');
        }
        script.push_str(&args.join(" "));
    }
    script
}

fn is_windows_cmd_script(program: &str) -> bool {
    let ext = Path::new(program)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    matches!(ext.as_deref(), Some("cmd" | "bat"))
}

fn builtin_to_task_spec(detected: BuiltinTask, windows_bridge: bool) -> TaskSpec {
    let id = detected.id;
    let label = detected.label;
    let depends_on = detected
        .depends_on
        .into_iter()
        .chain(
            detected
                .after
                .iter()
                .map(|predecessor| ordering_dependency(predecessor)),
        )
        .collect();
    let category = detected.category;
    let resource_locks = detected.resource_locks.into_iter().collect();
    let report_parser = detected.report_parser;
    let kind = match detected.kind {
        BuiltinTaskKind::Managed { executor } => TaskKind::Managed(match executor {
            BuiltinManagedExecutor::Npm => ManagedTaskExecutor::Npm,
            BuiltinManagedExecutor::Completions => ManagedTaskExecutor::Completions,
            BuiltinManagedExecutor::WindowsFoundations => ManagedTaskExecutor::WindowsFoundations {
                foundations: Vec::new(),
            },
        }),
        BuiltinTaskKind::Command {
            program,
            args,
            mode,
            command_candidates,
            pre_commands,
            report_commands,
            report_patterns,
            report_scoped_deltas,
            policy_key,
            requires_elevation,
            needs_sudo_session,
            interactive,
            external_window,
            shell,
            plain_header,
            plain_start,
            success_details,
            external_manager_skip,
        } => TaskKind::Command(CommandTask {
            program,
            args,
            mode,
            command_candidates,
            pre_commands: builtin_pre_commands(pre_commands),
            report_commands: builtin_report_commands(report_commands),
            report_patterns: builtin_report_patterns(report_patterns),
            report_scoped_deltas: builtin_scoped_deltas(report_scoped_deltas),
            policy_key,
            requires_elevation,
            needs_sudo_session,
            interactive,
            external_window,
            shell,
            windows_bridge,
            report_parser,
            plain_header,
            plain_start,
            success_details,
            external_manager_skip,
            result_protocol: None,
        }),
    };

    TaskSpec {
        id,
        label,
        depends_on,
        kind,
        category,
        resource_locks,
    }
}

fn build_task_specs(
    flags: &Sections,
    host_os: &HostOs,
    updater_cfg: &UpdaterConfig,
) -> Result<Vec<TaskSpec>> {
    let mut specs: Vec<TaskSpec> = Vec::new();
    let only_requested_raw = flags.only.clone().unwrap_or_default();
    let only_requested = only_requested_raw;
    let include_requested = updater_cfg.include.clone();
    let exclude_requested: BTreeSet<String> =
        updater_cfg.exclude.union(&flags.exclude).cloned().collect();
    let builtin_tasks = crate::updaters::builtin_catalog()?;
    let builtin_categories = builtin_tasks
        .iter()
        .map(|task| task.category.clone())
        .collect::<BTreeSet<_>>();
    let explicit_builtin_task_ids = only_requested
        .iter()
        .chain(include_requested.iter())
        .filter(|selector| !builtin_categories.contains(selector.as_str()))
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut selected_dependency_excludes_by_id: BTreeMap<String, BTreeSet<String>> =
        BTreeMap::new();
    let mut selected_ordering_excludes_by_id: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut required_selected_any_by_id: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let mut detection_targets = vec![*host_os];
    let include_windows_bridge =
        *host_os == HostOs::Linux && is_wsl_host() && which("powershell.exe").is_some();
    if include_windows_bridge {
        detection_targets.push(HostOs::Windows);
    }

    for target_os in detection_targets {
        for detected in
            detected_builtin_tasks_with_skip_overrides(target_os, &explicit_builtin_task_ids)?
        {
            record_selected_dependency_rule(
                &mut selected_dependency_excludes_by_id,
                &detected.id,
                detected.depends_on_selected,
                &detected.depends_on_selected_exclude,
            );
            record_required_selected_any(
                &mut required_selected_any_by_id,
                &detected.id,
                &detected.requires_selected_any,
            );
            if include_windows_bridge
                && target_os == HostOs::Windows
                && detected.category != "system"
            {
                continue;
            }
            let explicitly_requested = only_requested.contains(detected.id.as_str())
                || only_requested.contains(detected.category.as_str());
            let explicitly_included = include_requested.contains(detected.id.as_str())
                || include_requested.contains(detected.category.as_str());
            if !detected.enabled_by_default {
                continue;
            }
            if !updater_cfg.run_all_detected && !explicitly_included && !explicitly_requested {
                continue;
            }
            specs.push(builtin_to_task_spec(
                detected,
                include_windows_bridge && target_os == HostOs::Windows,
            ));
        }
    }

    for include_id in &include_requested {
        if specs.iter().any(|s| &s.id == include_id) {
            continue;
        }
        if let Some(custom) = updater_cfg.custom_tasks.get(include_id) {
            if let Some(spec) = custom_to_task_spec(custom, host_os) {
                record_selected_dependency_rule(
                    &mut selected_dependency_excludes_by_id,
                    &custom.id,
                    custom.depends_on_selected,
                    &custom.depends_on_selected_exclude,
                );
                record_selected_ordering_rule(
                    &mut selected_ordering_excludes_by_id,
                    &custom.id,
                    custom.after_selected,
                    &custom.after_selected_exclude,
                );
                record_required_selected_any(
                    &mut required_selected_any_by_id,
                    &custom.id,
                    &custom.requires_selected_any,
                );
                specs.push(spec);
            }
        }
    }

    for custom in updater_cfg.custom_tasks.values() {
        let explicitly_requested =
            only_requested.contains(&custom.id) || only_requested.contains(&custom.category);
        let explicitly_included =
            include_requested.contains(&custom.id) || include_requested.contains(&custom.category);
        if !updater_cfg.run_all_detected && !explicitly_included && !explicitly_requested {
            continue;
        }
        if specs.iter().any(|s| s.id == custom.id) {
            continue;
        }
        if let Some(spec) = custom_to_task_spec(custom, host_os) {
            record_selected_dependency_rule(
                &mut selected_dependency_excludes_by_id,
                &custom.id,
                custom.depends_on_selected,
                &custom.depends_on_selected_exclude,
            );
            record_selected_ordering_rule(
                &mut selected_ordering_excludes_by_id,
                &custom.id,
                custom.after_selected,
                &custom.after_selected_exclude,
            );
            record_required_selected_any(
                &mut required_selected_any_by_id,
                &custom.id,
                &custom.requires_selected_any,
            );
            specs.push(spec);
        }
    }

    if matches!(*host_os, HostOs::Windows) && updater_cfg.bootstrap.enabled {
        specs.push(TaskSpec {
            id: "bootstrap-windows-foundations".to_string(),
            label: "Bootstrap".to_string(),
            depends_on: Vec::new(),
            kind: TaskKind::Managed(ManagedTaskExecutor::WindowsFoundations {
                foundations: updater_cfg.bootstrap.windows_foundations.clone(),
            }),
            category: "system".to_string(),
            resource_locks: BTreeSet::from(["system-packages".to_string()]),
        });
    }

    let known_ids_before_excludes: BTreeSet<String> = specs
        .iter()
        .map(|s| s.id.as_str())
        .map(str::to_string)
        .collect();
    let known_categories_before_excludes: BTreeSet<String> = specs
        .iter()
        .map(|s| s.category.as_str())
        .map(str::to_string)
        .collect();

    specs.retain(|spec| {
        if exclude_requested.contains(&spec.id) || exclude_requested.contains(&spec.category) {
            return false;
        }
        true
    });

    if let Some(only) = &flags.only {
        let mut unknown = Vec::new();
        for id in only {
            if !selector_matches_known(
                id,
                &known_ids_before_excludes,
                &known_categories_before_excludes,
            ) {
                unknown.push(id.clone());
            }
        }
        if !unknown.is_empty() {
            bail!("Unknown section in --only: {}", unknown.join(","));
        }

        specs.retain(|spec| spec_selected_by_selectors(spec, &only_requested));
    }

    prune_specs_without_required_selected_any(
        &mut specs,
        &required_selected_any_by_id,
        &only_requested,
        &include_requested,
    );

    let selected_ids: BTreeSet<String> = specs
        .iter()
        .map(|s| s.id.as_str())
        .map(str::to_string)
        .collect();
    let selected_categories_by_id: BTreeMap<String, String> = specs
        .iter()
        .map(|spec| (spec.id.clone(), spec.category.clone()))
        .collect();
    for spec in &mut specs {
        let ordering_selectors = spec
            .depends_on
            .iter()
            .filter(|dependency| is_ordering_dependency(dependency))
            .map(|dependency| dependency_task_id(dependency).to_string())
            .collect::<Vec<_>>();
        let health_selectors = spec
            .depends_on
            .iter()
            .filter(|dependency| !is_ordering_dependency(dependency))
            .cloned()
            .collect::<Vec<_>>();
        let mut deps = expand_selected_dependency_selectors(
            &health_selectors,
            &selected_ids,
            &selected_categories_by_id,
            &spec.id,
        );
        if let Some(excludes) = selected_dependency_excludes_by_id.get(&spec.id) {
            deps.extend(
                selected_ids
                    .iter()
                    .filter(|id| id.as_str() != spec.id)
                    .filter(|id| !excludes.contains(id.as_str()))
                    .cloned(),
            );
        }
        if let Some(excludes) = selected_ordering_excludes_by_id.get(&spec.id) {
            let ordering_dependencies = selected_ids
                .iter()
                .filter(|id| id.as_str() != spec.id)
                .filter(|id| !excludes.contains(id.as_str()))
                .filter(|id| !deps.contains(id.as_str()))
                .map(|id| ordering_dependency(id))
                .collect::<Vec<_>>();
            deps.extend(ordering_dependencies);
        }
        deps.extend(
            expand_selected_dependency_selectors(
                &ordering_selectors,
                &selected_ids,
                &selected_categories_by_id,
                &spec.id,
            )
            .iter()
            .map(|predecessor| ordering_dependency(predecessor)),
        );
        spec.depends_on = deps.into_iter().collect();
    }
    specs = order_task_specs(specs)?;
    Ok(specs)
}

fn record_selected_dependency_rule(
    selected_dependency_excludes_by_id: &mut BTreeMap<String, BTreeSet<String>>,
    id: &str,
    depends_on_selected: bool,
    depends_on_selected_exclude: &[String],
) {
    if depends_on_selected {
        selected_dependency_excludes_by_id.insert(
            id.to_string(),
            depends_on_selected_exclude.iter().cloned().collect(),
        );
    }
}

fn record_selected_ordering_rule(
    selected_ordering_excludes_by_id: &mut BTreeMap<String, BTreeSet<String>>,
    id: &str,
    after_selected: bool,
    after_selected_exclude: &[String],
) {
    if after_selected {
        selected_ordering_excludes_by_id.insert(
            id.to_string(),
            after_selected_exclude.iter().cloned().collect(),
        );
    }
}

fn record_required_selected_any(
    required_selected_any_by_id: &mut BTreeMap<String, BTreeSet<String>>,
    id: &str,
    requires_selected_any: &[String],
) {
    if !requires_selected_any.is_empty() {
        required_selected_any_by_id.insert(
            id.to_string(),
            requires_selected_any.iter().cloned().collect(),
        );
    }
}

fn spec_selected_by_selectors(spec: &TaskSpec, selectors: &BTreeSet<String>) -> bool {
    if selectors.is_empty() {
        return false;
    }
    selectors.contains(&spec.id) || selectors.contains(&spec.category)
}

fn prune_specs_without_required_selected_any(
    specs: &mut Vec<TaskSpec>,
    required_selected_any_by_id: &BTreeMap<String, BTreeSet<String>>,
    only_requested: &BTreeSet<String>,
    include_requested: &BTreeSet<String>,
) {
    loop {
        let selected_ids: BTreeSet<String> = specs.iter().map(|spec| spec.id.clone()).collect();
        let selected_categories: BTreeSet<String> =
            specs.iter().map(|spec| spec.category.clone()).collect();
        let before = specs.len();
        specs.retain(|spec| {
            let Some(required) = required_selected_any_by_id.get(&spec.id) else {
                return true;
            };
            if spec_explicitly_selected(spec, only_requested, include_requested) {
                return true;
            }
            required.iter().any(|selector| {
                selected_ids.contains(selector.as_str())
                    || selected_categories.contains(selector.as_str())
            })
        });
        if specs.len() == before {
            return;
        }
    }
}

fn spec_explicitly_selected(
    spec: &TaskSpec,
    only_requested: &BTreeSet<String>,
    include_requested: &BTreeSet<String>,
) -> bool {
    only_requested.contains(spec.id.as_str()) || include_requested.contains(spec.id.as_str())
}

fn expand_selected_dependency_selectors(
    dependencies: &[String],
    selected_ids: &BTreeSet<String>,
    selected_categories_by_id: &BTreeMap<String, String>,
    current_id: &str,
) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for dependency in dependencies {
        if selected_ids.contains(dependency.as_str()) {
            if dependency != current_id {
                out.insert(dependency.clone());
            }
            continue;
        }

        for (id, category) in selected_categories_by_id {
            if id != current_id && category == dependency {
                out.insert(id.clone());
            }
        }
    }
    out
}

fn ordering_dependency(task_id: &str) -> String {
    format!("{ORDER_ONLY_DEPENDENCY_PREFIX}{task_id}")
}

fn is_ordering_dependency(dependency: &str) -> bool {
    dependency.starts_with(ORDER_ONLY_DEPENDENCY_PREFIX)
}

fn dependency_task_id(dependency: &str) -> &str {
    dependency
        .strip_prefix(ORDER_ONLY_DEPENDENCY_PREFIX)
        .unwrap_or(dependency)
}

fn selector_matches_known(
    selector: &str,
    known_ids: &BTreeSet<String>,
    known_categories: &BTreeSet<String>,
) -> bool {
    known_ids.contains(selector) || known_categories.contains(selector)
}

fn order_task_specs(specs: Vec<TaskSpec>) -> Result<Vec<TaskSpec>> {
    let spec_by_id: HashMap<String, TaskSpec> = specs
        .into_iter()
        .map(|spec| (spec.id.clone(), spec))
        .collect();
    let all_specs = spec_by_id.clone();
    let mut remaining_deps: HashMap<String, usize> = HashMap::new();
    let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

    for spec in spec_by_id.values() {
        remaining_deps.insert(spec.id.clone(), spec.depends_on.len());
        for dep in &spec.depends_on {
            reverse_deps
                .entry(dependency_task_id(dep).to_string())
                .or_default()
                .push(spec.id.clone());
        }
    }

    let mut available: Vec<String> = spec_by_id
        .values()
        .filter(|spec| spec.depends_on.is_empty())
        .map(|spec| spec.id.clone())
        .collect();
    let mut pending = spec_by_id;
    let mut ordered = Vec::new();

    while !available.is_empty() {
        let Some(next_idx) = available
            .iter()
            .enumerate()
            .min_by_key(|(_, id)| task_order_key(id, &all_specs, &pending))
            .map(|(idx, _)| idx)
        else {
            break;
        };
        let next_id = available.swap_remove(next_idx);
        let Some(spec) = pending.remove(&next_id) else {
            continue;
        };

        if let Some(children) = reverse_deps.get(&next_id) {
            for child_id in children {
                if let Some(dep_count) = remaining_deps.get_mut(child_id) {
                    *dep_count = dep_count.saturating_sub(1);
                    if *dep_count == 0 && pending.contains_key(child_id) {
                        available.push(child_id.clone());
                    }
                }
            }
        }

        ordered.push(spec);
    }

    if !pending.is_empty() {
        let mut ids: Vec<String> = pending.keys().cloned().collect();
        ids.sort();
        bail!("task dependency cycle detected: {}", ids.join(","));
    }

    Ok(ordered)
}

fn task_order_key(
    id: &str,
    all_specs: &HashMap<String, TaskSpec>,
    pending_specs: &HashMap<String, TaskSpec>,
) -> (u8, u16, String, usize, String, String) {
    let Some(spec) = all_specs.get(id) else {
        return (
            u8::MAX,
            u16::MAX,
            String::new(),
            usize::MAX,
            id.to_ascii_lowercase(),
            id.to_string(),
        );
    };
    let root_id = task_root_id(id, all_specs);
    let root_spec = all_specs.get(root_id).unwrap_or(spec);
    (
        task_category_rank(&root_spec.category),
        task_system_order_rank(&spec.id),
        root_spec.label.to_ascii_lowercase(),
        pending_specs
            .get(id)
            .map(|task| task.depends_on.len())
            .unwrap_or(spec.depends_on.len()),
        spec.label.to_ascii_lowercase(),
        spec.id.clone(),
    )
}

fn task_root_id<'a>(id: &'a str, specs: &'a HashMap<String, TaskSpec>) -> &'a str {
    let Some(spec) = specs.get(id) else {
        return id;
    };
    if spec.depends_on.is_empty() {
        return id;
    }

    spec.depends_on
        .iter()
        .filter_map(|dep| {
            let task_id = dependency_task_id(dep);
            specs.get(task_id).map(|_| task_id)
        })
        .map(|dep| task_root_id(dep, specs))
        .min_by_key(|root| {
            let Some(root_spec) = specs.get(*root) else {
                return (u8::MAX, String::new(), String::new());
            };
            (
                task_category_rank(&root_spec.category),
                root_spec.label.to_ascii_lowercase(),
                root_spec.id.clone(),
            )
        })
        .unwrap_or(id)
}

fn task_category_rank(category: &str) -> u8 {
    match category {
        "system" | "system-packages" | "system packages" => 0,
        "language" | "developer-tools" | "developer tools" => 1,
        "agent-tooling" | "agent tooling" => 2,
        "android-mobile" | "mobile-reverse-engineering" | "mobile & reverse engineering" => 3,
        "game-dev" | "game-development" | "game development" => 4,
        "maintenance" => 5,
        "custom" => 6,
        _ => 7,
    }
}

fn task_system_order_rank(id: &str) -> u16 {
    if id == "bootstrap-windows-foundations" {
        return 0;
    }
    crate::updaters::builtin_catalog()
        .ok()
        .and_then(|catalog| {
            catalog
                .into_iter()
                .find(|task| task.id == id)
                .map(|task| task.order_rank)
        })
        .unwrap_or(20)
}

fn custom_to_task_spec(custom: &UpdaterTaskConfig, host_os: &HostOs) -> Option<TaskSpec> {
    let custom = expand_custom_runtime_tokens(custom, *host_os);
    if !custom.enabled {
        return None;
    }
    if !custom
        .os
        .iter()
        .any(|os_name| host_os.matches_name(os_name.as_str()))
    {
        return None;
    }
    if custom
        .skip_if_any
        .iter()
        .any(|probe| custom_probe_present(probe, *host_os))
        || (matches!(*host_os, HostOs::Windows)
            && custom
                .skip_if_any_windows
                .iter()
                .any(|probe| custom_probe_present(probe, *host_os)))
    {
        return None;
    }
    if !custom
        .detect_all
        .iter()
        .all(|probe| custom_probe_present(probe, *host_os))
    {
        return None;
    }
    if matches!(*host_os, HostOs::Windows)
        && !custom
            .detect_all_windows
            .iter()
            .all(|probe| custom_probe_present(probe, *host_os))
    {
        return None;
    }
    match custom.detect_mode {
        UpdaterDetectionMode::AnyPresent => {
            if !custom.detect_any.is_empty()
                && !custom
                    .detect_any
                    .iter()
                    .any(|probe| custom_probe_present(probe, *host_os))
            {
                return None;
            }
        }
        UpdaterDetectionMode::CommandAvailable => {
            if !custom_command_available(&custom, *host_os) {
                return None;
            }
        }
        UpdaterDetectionMode::Always => {}
    }

    Some(TaskSpec {
        id: custom.id.clone(),
        label: custom.label.clone(),
        depends_on: custom
            .depends_on
            .iter()
            .cloned()
            .chain(
                custom
                    .after
                    .iter()
                    .map(|predecessor| ordering_dependency(predecessor)),
            )
            .collect(),
        kind: TaskKind::Command(CommandTask {
            program: custom.command.clone(),
            args: custom.args.clone(),
            mode: custom.mode.clone(),
            command_candidates: custom_command_candidates(&custom.command_candidates),
            pre_commands: custom_pre_commands(&custom.pre_commands),
            report_commands: custom_report_commands(&custom.report_commands),
            report_patterns: custom_report_patterns(&custom.report_patterns),
            report_scoped_deltas: custom_scoped_deltas(&custom.report_scoped_deltas),
            policy_key: custom.policy_key.clone(),
            requires_elevation: custom.requires_elevation,
            needs_sudo_session: custom.needs_sudo_session,
            interactive: custom.interactive,
            external_window: custom.external_window,
            shell: custom.shell,
            windows_bridge: false,
            report_parser: custom.report_parser,
            plain_header: custom.plain_header.clone(),
            plain_start: custom.plain_start.clone(),
            success_details: custom.success_details.clone(),
            external_manager_skip: custom.external_manager_skip,
            result_protocol: custom.result_protocol,
        }),
        category: custom.category.clone(),
        resource_locks: custom.resource_locks.iter().cloned().collect(),
    })
}

fn runtime_user_home(host_os: HostOs) -> Option<PathBuf> {
    if matches!(host_os, HostOs::Windows) {
        std::env::var_os("USERPROFILE")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            })
    } else {
        std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }
}

fn runtime_config_home(host_os: HostOs) -> Option<PathBuf> {
    if matches!(host_os, HostOs::Windows) {
        std::env::var_os("APPDATA")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| runtime_user_home(host_os).map(|home| home.join(".config")))
    }
}

fn runtime_user_libexec(host_os: HostOs) -> Option<PathBuf> {
    if matches!(host_os, HostOs::Windows) {
        std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .map(|root| root.join("libexec"))
    } else {
        runtime_user_home(host_os).map(|home| home.join(".local/libexec"))
    }
}

fn expand_runtime_tokens(value: String, host_os: HostOs) -> String {
    let mut expanded = value;
    for (token, path) in [
        ("{home}", runtime_user_home(host_os)),
        ("{config_home}", runtime_config_home(host_os)),
        ("{user_libexec}", runtime_user_libexec(host_os)),
    ] {
        if let Some(path) = path {
            expanded = expanded.replace(token, path.to_string_lossy().as_ref());
        }
    }
    expanded
}

fn expand_custom_runtime_tokens(custom: &UpdaterTaskConfig, host_os: HostOs) -> UpdaterTaskConfig {
    let mut expanded = custom.clone();
    expanded.command = expand_runtime_tokens(expanded.command, host_os);
    expanded.args = expanded
        .args
        .into_iter()
        .map(|value| expand_runtime_tokens(value, host_os))
        .collect();
    for candidate in &mut expanded.command_candidates {
        candidate.program = expand_runtime_tokens(candidate.program.clone(), host_os);
        candidate.args = candidate
            .args
            .drain(..)
            .map(|value| expand_runtime_tokens(value, host_os))
            .collect();
        candidate.probe_args = candidate
            .probe_args
            .drain(..)
            .map(|value| expand_runtime_tokens(value, host_os))
            .collect();
    }
    for command in &mut expanded.pre_commands {
        command.program = expand_runtime_tokens(command.program.clone(), host_os);
        command.args = command
            .args
            .drain(..)
            .map(|value| expand_runtime_tokens(value, host_os))
            .collect();
    }
    for command in &mut expanded.report_commands {
        command.program = expand_runtime_tokens(command.program.clone(), host_os);
        command.args = command
            .args
            .drain(..)
            .map(|value| expand_runtime_tokens(value, host_os))
            .collect();
    }
    expanded.detect_any = expanded
        .detect_any
        .into_iter()
        .map(|value| expand_runtime_tokens(value, host_os))
        .collect();
    expanded.detect_all = expanded
        .detect_all
        .into_iter()
        .map(|value| expand_runtime_tokens(value, host_os))
        .collect();
    expanded.detect_all_windows = expanded
        .detect_all_windows
        .into_iter()
        .map(|value| expand_runtime_tokens(value, host_os))
        .collect();
    expanded
}

fn custom_probe_present(probe: &str, host_os: HostOs) -> bool {
    command_program_path(probe, host_os).is_some()
}

fn custom_command_available(custom: &UpdaterTaskConfig, host_os: HostOs) -> bool {
    command_program_path(&custom.command, host_os).is_some()
        || custom_command_candidates(&custom.command_candidates)
            .iter()
            .any(|candidate| command_candidate_is_available(candidate, host_os))
}

fn custom_command_candidates(
    candidates: &[UpdaterCommandCandidateConfig],
) -> Vec<BuiltinCommandCandidate> {
    candidates
        .iter()
        .map(|candidate| BuiltinCommandCandidate {
            program: candidate.program.clone(),
            args: candidate.args.clone(),
            probe_args: candidate.probe_args.clone(),
            mode: candidate.mode.clone(),
        })
        .collect()
}

fn builtin_report_commands(commands: Vec<BuiltinReportCommand>) -> Vec<CommandReportCommand> {
    commands
        .into_iter()
        .map(|command| CommandReportCommand {
            program: command.program,
            args: command.args,
            when: builtin_report_command_when(command.when),
            allow_exit_codes: command.allow_exit_codes,
            state_pattern: command.state_pattern.and_then(builtin_state_report_pattern),
        })
        .collect()
}

fn builtin_pre_commands(commands: Vec<BuiltinPreCommand>) -> Vec<CommandPreCommand> {
    commands
        .into_iter()
        .map(|command| CommandPreCommand {
            program: command.program,
            args: command.args,
        })
        .collect()
}

fn custom_pre_commands(commands: &[UpdaterPreCommandConfig]) -> Vec<CommandPreCommand> {
    commands
        .iter()
        .map(|command| CommandPreCommand {
            program: command.program.clone(),
            args: command.args.clone(),
        })
        .collect()
}

fn custom_report_commands(commands: &[UpdaterReportCommandConfig]) -> Vec<CommandReportCommand> {
    commands
        .iter()
        .map(|command| CommandReportCommand {
            program: command.program.clone(),
            args: command.args.clone(),
            when: updater_report_command_when(command.when),
            allow_exit_codes: command.allow_exit_codes.clone(),
            state_pattern: command
                .state_pattern
                .as_ref()
                .and_then(updater_state_report_pattern),
        })
        .collect()
}

fn builtin_report_command_when(when: BuiltinReportCommandWhen) -> CommandReportWhen {
    match when {
        BuiltinReportCommandWhen::Before => CommandReportWhen::Before,
        BuiltinReportCommandWhen::After => CommandReportWhen::After,
        BuiltinReportCommandWhen::BeforeAfter => CommandReportWhen::BeforeAfter,
    }
}

fn updater_report_command_when(when: UpdaterReportCommandWhen) -> CommandReportWhen {
    match when {
        UpdaterReportCommandWhen::Before => CommandReportWhen::Before,
        UpdaterReportCommandWhen::After => CommandReportWhen::After,
        UpdaterReportCommandWhen::BeforeAfter => CommandReportWhen::BeforeAfter,
    }
}

fn builtin_state_report_pattern(
    pattern: BuiltinStateReportPattern,
) -> Option<CommandStateReportPattern> {
    Some(CommandStateReportPattern {
        regex: Regex::new(&pattern.pattern).ok()?,
        section_key: pattern.section_key,
        section_title: pattern.section_title,
        name: pattern.name,
        version: pattern.version,
        include_unchanged: pattern.include_unchanged,
    })
}

fn updater_state_report_pattern(
    pattern: &UpdaterStateReportPatternConfig,
) -> Option<CommandStateReportPattern> {
    Some(CommandStateReportPattern {
        regex: Regex::new(&pattern.pattern).ok()?,
        section_key: pattern.section_key.clone(),
        section_title: pattern.section_title.clone(),
        name: pattern.name.clone(),
        version: pattern.version.clone(),
        include_unchanged: pattern.include_unchanged,
    })
}

fn builtin_report_patterns(patterns: Vec<BuiltinReportPattern>) -> Vec<CommandReportPattern> {
    patterns
        .into_iter()
        .filter_map(|pattern| {
            let regex = Regex::new(&pattern.pattern).ok()?;
            Some(CommandReportPattern {
                regex,
                section_key: pattern.section_key,
                section_title: pattern.section_title,
                status: report_pattern_status(&pattern.status),
                name: pattern.name,
                before: pattern.before,
                after: pattern.after,
                note: pattern.note,
            })
        })
        .collect()
}

fn custom_report_patterns(patterns: &[UpdaterReportPatternConfig]) -> Vec<CommandReportPattern> {
    patterns
        .iter()
        .filter_map(|pattern| {
            let regex = Regex::new(&pattern.pattern).ok()?;
            Some(CommandReportPattern {
                regex,
                section_key: pattern.section_key.clone(),
                section_title: pattern.section_title.clone(),
                status: report_pattern_status(&pattern.status),
                name: pattern.name.clone(),
                before: pattern.before.clone(),
                after: pattern.after.clone(),
                note: pattern.note.clone(),
            })
        })
        .collect()
}

fn builtin_scoped_deltas(deltas: Vec<BuiltinScopedDelta>) -> Vec<CommandScopedDelta> {
    deltas
        .into_iter()
        .filter_map(|delta| {
            Some(CommandScopedDelta {
                scope_regex: Regex::new(&delta.scope_pattern).ok()?,
                before_regex: Regex::new(&delta.before_pattern).ok()?,
                after_regex: Regex::new(&delta.after_pattern).ok()?,
                section_key: delta.section_key,
                section_title: delta.section_title,
                row_name: delta.row_name,
                scope_section_key: delta.scope_section_key,
                scope_section_title: delta.scope_section_title,
                scope_row_name: delta.scope_row_name,
            })
        })
        .collect()
}

fn custom_scoped_deltas(deltas: &[UpdaterScopedDeltaConfig]) -> Vec<CommandScopedDelta> {
    deltas
        .iter()
        .filter_map(|delta| {
            Some(CommandScopedDelta {
                scope_regex: Regex::new(&delta.scope_pattern).ok()?,
                before_regex: Regex::new(&delta.before_pattern).ok()?,
                after_regex: Regex::new(&delta.after_pattern).ok()?,
                section_key: delta.section_key.clone(),
                section_title: delta.section_title.clone(),
                row_name: delta.row_name.clone(),
                scope_section_key: delta.scope_section_key.clone(),
                scope_section_title: delta.scope_section_title.clone(),
                scope_row_name: delta.scope_row_name.clone(),
            })
        })
        .collect()
}

fn report_pattern_status(status: &str) -> TaskReportStatus {
    match status.trim().to_ascii_lowercase().as_str() {
        "updated" => TaskReportStatus::Updated,
        "refreshed" | "refresh" => TaskReportStatus::Refreshed,
        "passed" | "pass" => TaskReportStatus::Passed,
        "unchanged" => TaskReportStatus::Unchanged,
        "skipped" => TaskReportStatus::Skipped,
        "failed" => TaskReportStatus::Failed,
        "blocked" => TaskReportStatus::Blocked,
        "info" => TaskReportStatus::Info,
        _ => TaskReportStatus::Info,
    }
}

fn is_wsl_host() -> bool {
    if std::env::var("WSL_DISTRO_NAME")
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
    {
        return true;
    }
    std::fs::read_to_string("/proc/version")
        .ok()
        .is_some_and(|txt| txt.to_ascii_lowercase().contains("microsoft"))
}

fn next_ready_task(
    pending: &BTreeMap<String, TaskSpec>,
    done: &BTreeMap<String, TaskResult>,
    busy_resources: &BTreeSet<String>,
) -> Option<(String, TaskSpec)> {
    for (id, spec) in pending {
        if !spec.resource_locks.is_disjoint(busy_resources) {
            continue;
        }
        let mut deps_ready = true;
        for dep in &spec.depends_on {
            let dep_id = dependency_task_id(dep);
            let Some(dep_result) = done.get(dep_id) else {
                deps_ready = false;
                break;
            };
            if !is_ordering_dependency(dep)
                && !dependency_ready(spec.id.as_str(), dep_id, dep_result)
            {
                deps_ready = false;
                break;
            }
        }
        if deps_ready {
            return Some((id.clone(), spec.clone()));
        }
    }
    None
}

fn dependency_ready(task_id: &str, dep_id: &str, dep_result: &TaskResult) -> bool {
    let _ = dep_id;
    if task_id == TASK_COMPLETIONS {
        return matches!(
            dep_result.status,
            TaskStatus::Completed | TaskStatus::Skipped | TaskStatus::Failed | TaskStatus::Canceled
        );
    }
    match dep_result.status {
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Canceled => {
            !dep_result.blocks_dependents()
        }
        TaskStatus::Skipped => true,
    }
}

fn blocked_by_failed_dependency(
    pending: &BTreeMap<String, TaskSpec>,
    done: &BTreeMap<String, TaskResult>,
) -> BTreeSet<String> {
    let mut blocked = BTreeSet::new();
    for (id, spec) in pending {
        if id == TASK_COMPLETIONS {
            continue;
        }
        for dep in &spec.depends_on {
            if is_ordering_dependency(dep) {
                continue;
            }
            if let Some(dep_result) = done.get(dependency_task_id(dep)) {
                if dep_result.blocks_dependents() {
                    blocked.insert(id.clone());
                    break;
                }
            }
        }
    }
    blocked
}

fn dependency_blocking_detail(spec: &TaskSpec, done: &BTreeMap<String, TaskResult>) -> String {
    let blocked: Vec<String> = spec
        .depends_on
        .iter()
        .filter_map(|dep| {
            if is_ordering_dependency(dep) {
                return None;
            }
            let dep_id = dependency_task_id(dep);
            let dep_result = done.get(dep_id)?;
            if !dep_result.blocks_dependents() {
                return None;
            }
            let dep_status = match dep_result.status {
                TaskStatus::Completed => "completed_with_issues",
                TaskStatus::Failed => "failed",
                TaskStatus::Canceled => "canceled",
                TaskStatus::Skipped => "skipped",
            };
            Some(format!("{dep_id}={dep_status}"))
        })
        .collect();
    if blocked.is_empty() {
        "blocked by dependency".to_string()
    } else {
        format!("blocked by dependency: {}", blocked.join(", "))
    }
}

fn take_next_finished(
    running: &mut VecDeque<(String, BTreeSet<String>, thread::JoinHandle<TaskResult>)>,
) -> Option<(String, TaskResult)> {
    if running.is_empty() {
        return None;
    }
    let next_idx = running
        .iter()
        .position(|(_, _, handle)| handle.is_finished())?;
    let (joined_label, _, handle) = running.remove(next_idx)?;
    let joined = handle.join().unwrap_or_else(|_| {
        failed_task_error_result(&joined_label, &joined_label, "task panicked")
    });
    Some((joined_label, joined))
}

fn join_forced_canceled_task(
    task_id: String,
    handle: thread::JoinHandle<TaskResult>,
) -> TaskResult {
    match handle.join() {
        Ok(result) => TaskResult::canceled(result.label, FORCED_CANCEL_TIMEOUT_DETAIL),
        Err(_) => failed_task_error_result(
            &task_id,
            &task_id,
            "task panicked after cancel-all grace timeout",
        ),
    }
}

fn bounded_structured_text(value: &str) -> String {
    if value.len() <= STRUCTURED_TEXT_LIMIT_BYTES {
        return value.to_string();
    }
    let suffix = "… [truncated; see task log]";
    let mut end = STRUCTURED_TEXT_LIMIT_BYTES.saturating_sub(suffix.len());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}{}", &value[..end], suffix)
}

fn bounded_task_details(result: &TaskResult) -> Vec<String> {
    result
        .details
        .iter()
        .take(STRUCTURED_DETAIL_LIMIT)
        .map(|detail| bounded_structured_text(detail))
        .collect()
}

fn bounded_task_advisories(result: &TaskResult) -> Vec<TaskAdvisory> {
    result
        .advisories
        .iter()
        .take(STRUCTURED_DETAIL_LIMIT)
        .map(|advisory| TaskAdvisory {
            severity: advisory.severity,
            code: bounded_structured_text(&advisory.code),
            summary: bounded_structured_text(&advisory.summary),
            remediation: bounded_structured_text(&advisory.remediation),
            blocks_dependents: advisory.blocks_dependents,
        })
        .collect()
}

fn bounded_task_report_sections(result: &TaskResult) -> Vec<TaskReportSection> {
    result
        .report_sections
        .iter()
        .take(STRUCTURED_SECTION_LIMIT)
        .map(|section| TaskReportSection {
            key: bounded_structured_text(&section.key),
            title: bounded_structured_text(&section.title),
            rows: section
                .rows
                .iter()
                .take(STRUCTURED_ROW_LIMIT)
                .map(|row| TaskReportRow {
                    name: bounded_structured_text(&row.name),
                    status: row.status,
                    before: row.before.as_deref().map(bounded_structured_text),
                    after: row.after.as_deref().map(bounded_structured_text),
                    note: row.note.as_deref().map(bounded_structured_text),
                })
                .collect(),
        })
        .collect()
}

#[derive(Serialize)]
struct TaskResultArtifact<'a> {
    task_id: &'a str,
    log_file: String,
    label: &'a str,
    status: TaskStatus,
    completed_with_issues: bool,
    detail: String,
    details: Vec<String>,
    advisories: Vec<TaskAdvisory>,
    report_sections: Vec<TaskReportSection>,
}

#[derive(Serialize)]
struct RunTaskArtifact<'a> {
    task_id: &'a str,
    log_file: String,
    label: &'a str,
    status: TaskStatus,
    completed_with_issues: bool,
    detail: String,
    details: Vec<String>,
    advisories: Vec<TaskAdvisory>,
    report_sections: Vec<TaskReportSection>,
}

#[derive(Serialize)]
struct RunArtifact<'a> {
    schema_version: u32,
    run_id: &'a str,
    display_name: String,
    started_unix_ms: u64,
    tasks_ended_unix_ms: u64,
    tasks_completed_unix_ms: u64,
    ended_unix_ms: u64,
    artifact_updated_unix_ms: u64,
    tasks_elapsed_ms: u64,
    ui_wait_ms: u64,
    exit_code: i32,
    completed_with_issues: bool,
    issue_count: usize,
    failed_task_count: usize,
    canceled_task_count: usize,
    host_os: &'a str,
    ui_mode: &'a str,
    engine_mode: &'a str,
    run_dir: String,
    selected_tasks: Vec<String>,
    runtime_advisories: Vec<TaskAdvisory>,
    tasks: Vec<RunTaskArtifact<'a>>,
}

fn write_task_result_artifact(
    run_log: Option<&Arc<RunLogSink>>,
    task_id: &str,
    result: &TaskResult,
) {
    let Some(run_log) = run_log else {
        return;
    };
    let payload = TaskResultArtifact {
        task_id,
        log_file: format!("task-{}.log", task_file_stem(task_id)),
        label: &result.label,
        status: result.status,
        completed_with_issues: result.has_issues() && result.status == TaskStatus::Completed,
        detail: bounded_structured_text(&result.primary_detail()),
        details: bounded_task_details(result),
        advisories: bounded_task_advisories(result),
        report_sections: bounded_task_report_sections(result),
    };
    if let Err(err) =
        run_log.write_json_file(&format!("task-{}.json", task_file_stem(task_id)), &payload)
    {
        run_log.emit_write_warning_once(&err);
    }
}

fn write_run_artifact<'a>(
    run_log: Option<&Arc<RunLogSink>>,
    host_os: &'a str,
    ui_mode: &'a str,
    engine_mode: &'a str,
    selected_tasks: Vec<String>,
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    tasks_ended_unix_ms: u64,
    exit_code: i32,
    tasks_completed_unix_ms: u64,
) {
    let Some(run_log) = run_log else {
        return;
    };
    let tasks = summary
        .into_iter()
        .map(|(task_id, result)| RunTaskArtifact {
            task_id,
            log_file: format!("task-{}.log", task_file_stem(task_id)),
            label: &result.label,
            status: result.status,
            completed_with_issues: result.has_issues() && result.status == TaskStatus::Completed,
            detail: bounded_structured_text(&result.primary_detail()),
            details: bounded_task_details(result),
            advisories: bounded_task_advisories(result),
            report_sections: bounded_task_report_sections(result),
        })
        .collect::<Vec<_>>();
    let completed_with_issues = tasks.iter().any(|task| task.completed_with_issues);
    let failed_task_count = tasks
        .iter()
        .filter(|task| task.status == TaskStatus::Failed)
        .count();
    let canceled_task_count = tasks
        .iter()
        .filter(|task| task.status == TaskStatus::Canceled)
        .count();
    let issue_count = tasks
        .iter()
        .filter(|task| {
            task.completed_with_issues
                || matches!(task.status, TaskStatus::Failed | TaskStatus::Canceled)
        })
        .count();
    let started_unix_ms = run_log.started_unix_ms();
    let artifact_updated_unix_ms = now_unix_ms();
    let status = crate::runs::status_from_exit_code(exit_code);
    let runtime_advisories = run_runtime_advisories(run_log);
    let payload = RunArtifact {
        schema_version: 1,
        run_id: run_log.run_id(),
        display_name: run_log.display_name(),
        started_unix_ms,
        tasks_ended_unix_ms,
        tasks_completed_unix_ms,
        ended_unix_ms: tasks_ended_unix_ms,
        artifact_updated_unix_ms,
        tasks_elapsed_ms: tasks_completed_unix_ms.saturating_sub(started_unix_ms),
        ui_wait_ms: artifact_updated_unix_ms.saturating_sub(tasks_ended_unix_ms),
        exit_code,
        completed_with_issues,
        issue_count,
        failed_task_count,
        canceled_task_count,
        host_os,
        ui_mode,
        engine_mode,
        run_dir: run_log.run_dir().display().to_string(),
        selected_tasks: selected_tasks.clone(),
        runtime_advisories,
        tasks,
    };
    if let Err(err) = run_log.write_metadata(
        &status,
        Some(host_os),
        Some(ui_mode),
        Some(engine_mode),
        selected_tasks.clone(),
        artifact_updated_unix_ms,
    ) {
        run_log.emit_write_warning_once(&err);
    }
    if let Err(err) = run_log.write_json_file("run.json", &payload) {
        run_log.emit_write_warning_once(&err);
    }
}

fn run_runtime_advisories(run_log: &RunLogSink) -> Vec<TaskAdvisory> {
    let raw_path = run_log.run_dir().join("task-runtime.raw.log");
    let Ok(raw) = fs::read_to_string(raw_path) else {
        return Vec::new();
    };
    let mut advisories = Vec::new();
    let mut seen = BTreeSet::new();
    for line in raw.lines() {
        let Some(detail) = parse_runtime_advisory_detail(line) else {
            continue;
        };
        if !seen.insert(detail.clone()) {
            continue;
        }
        advisories.push(TaskAdvisory {
            severity: AdvisorySeverity::Warning,
            code: "runtime-log-viewer-failed".to_string(),
            summary: "log viewer failed".to_string(),
            remediation: format!(
                "{detail}; open the run log file directly from the run directory if the pager cannot be launched."
            ),
            blocks_dependents: false,
        });
        if advisories.len() >= COMMAND_DIAGNOSTIC_SAMPLE_LIMIT {
            break;
        }
    }
    advisories
}

fn parse_runtime_advisory_detail(line: &str) -> Option<String> {
    let marker = "log viewer failed:";
    let idx = line.find(marker)?;
    let detail = line[idx..].trim();
    (!detail.is_empty()).then_some(detail.to_string())
}

fn resolve_parallel_jobs(jobs: &str, task_count: usize) -> Result<usize> {
    if task_count == 0 {
        return Ok(1);
    }
    let jobs = jobs.trim().to_lowercase();
    if jobs.is_empty() || jobs == "auto" {
        let available = thread::available_parallelism().map_or(1, |n| n.get());
        return Ok(available.max(1).min(task_count));
    }
    let parsed = jobs
        .parse::<usize>()
        .with_context(|| format!("invalid jobs value '{jobs}'; expected 'auto' or an integer"))?;
    if parsed == 0 {
        bail!("invalid jobs value '0'; expected 'auto' or an integer >= 1");
    }
    Ok(parsed.min(task_count))
}

fn print_async_task_line(label: &str, r: &TaskResult) {
    let status = match r.status {
        TaskStatus::Completed if r.is_deferred() => "Deferred",
        TaskStatus::Completed if r.has_issues() => "Completed with issues",
        TaskStatus::Completed => "Completed",
        TaskStatus::Failed => "Failed",
        TaskStatus::Canceled => "Canceled",
        TaskStatus::Skipped => "Skipped",
    };
    crate::ua_outln!("[{label}] {status}");
    for d in &r.details {
        crate::ua_outln!("  {d}");
    }
}

fn task_outcome_message(result: &TaskResult) -> String {
    match result.status {
        TaskStatus::Completed if result.is_deferred() => {
            format!("task outcome: deferred - {}", result.primary_detail())
        }
        TaskStatus::Completed if result.has_issues() => {
            format!(
                "task outcome: completed with issues - {}",
                result.primary_detail()
            )
        }
        TaskStatus::Completed => {
            let detail = result.primary_detail();
            if detail == NO_TASK_DETAIL {
                "task outcome: completed".to_string()
            } else {
                format!("task outcome: completed - {detail}")
            }
        }
        TaskStatus::Failed => format!("task outcome: failed - {}", result.primary_detail()),
        TaskStatus::Canceled => format!("task outcome: canceled - {}", result.primary_detail()),
        TaskStatus::Skipped => format!("task outcome: skipped - {}", result.primary_detail()),
    }
}

fn task_outcome_level(result: &TaskResult) -> LogLevel {
    match result.status {
        TaskStatus::Completed if result.has_issues() => LogLevel::Warn,
        TaskStatus::Completed => LogLevel::Info,
        TaskStatus::Failed => LogLevel::Error,
        TaskStatus::Canceled => LogLevel::Warn,
        TaskStatus::Skipped => LogLevel::Info,
    }
}

fn task_detail_log_lines(result: &TaskResult) -> impl Iterator<Item = String> + '_ {
    result.details.iter().flat_map(|detail| {
        detail
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.trim().is_empty())
            .map(|line| format!("task detail: {line}"))
            .collect::<Vec<_>>()
    })
}

fn emit_task_outcome_log_sync(ctx: &SyncContext, task_id: &str, result: &TaskResult) {
    write_task_result_artifact(ctx.run_log.as_ref(), task_id, result);
    for line in task_detail_log_lines(result) {
        ctx.log_line(task_id, task_outcome_level(result), LogStream::Meta, line);
    }
    ctx.log_line(
        task_id,
        task_outcome_level(result),
        LogStream::Meta,
        task_outcome_message(result),
    );
}

fn emit_task_outcome_log_async(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    task_id: &str,
    result: &TaskResult,
) {
    write_task_result_artifact(run_log, task_id, result);
    for line in task_detail_log_lines(result) {
        emit_task_log(
            event_tx,
            run_log,
            task_id,
            task_outcome_level(result),
            LogStream::Meta,
            line,
        );
    }
    emit_task_log(
        event_tx,
        run_log,
        task_id,
        task_outcome_level(result),
        LogStream::Meta,
        task_outcome_message(result),
    );
}

fn build_command_report_sections(
    parser: Option<BuiltinReportParser>,
    output: &str,
) -> Vec<TaskReportSection> {
    match parser {
        Some(BuiltinReportParser::ArchUpdateServices) => parse_arch_update_services_report(output),
        Some(BuiltinReportParser::Scoop) => parse_scoop_report(output),
        Some(BuiltinReportParser::VersionLines) => parse_version_lines_report(output),
        Some(BuiltinReportParser::Winget) => parse_winget_report(&strip_progress_output(output)),
        Some(BuiltinReportParser::Yay) => parse_yay_report(output),
        None => Vec::new(),
    }
}

fn build_command_report_sections_for_command(
    cmd: &CommandTask,
    output: &str,
) -> Vec<TaskReportSection> {
    let mut sections = build_command_report_sections(cmd.report_parser, output);
    append_command_report_pattern_sections(&mut sections, &cmd.report_patterns, output);
    append_command_scoped_delta_sections(&mut sections, &cmd.report_scoped_deltas, output);
    sections
}

#[derive(Clone)]
struct ScopedDeltaRow {
    scope: String,
    name: String,
    before: Option<String>,
    after: Option<String>,
}

fn append_command_scoped_delta_sections(
    sections: &mut Vec<TaskReportSection>,
    deltas: &[CommandScopedDelta],
    output: &str,
) {
    for delta in deltas {
        let rows = scoped_delta_rows(delta, output);
        if rows.is_empty() {
            continue;
        }

        if let (Some(section_key), Some(section_title), Some(scope_row_name)) = (
            delta.scope_section_key.as_deref(),
            delta.scope_section_title.as_deref(),
            delta.scope_row_name.as_deref(),
        ) {
            let mut seen_scopes = BTreeSet::new();
            for row in &rows {
                if !seen_scopes.insert(row.scope.clone()) {
                    continue;
                }
                append_row_to_report_sections(
                    sections,
                    section_key,
                    section_title,
                    TaskReportRow {
                        name: render_scoped_delta_name(scope_row_name, &row.scope, &row.name),
                        status: TaskReportStatus::Updated,
                        before: None,
                        after: None,
                        note: Some("dependencies changed".to_string()),
                    },
                );
            }
        }

        for row in rows {
            let note = match (row.before.is_some(), row.after.is_some()) {
                (true, false) => Some("removed".to_string()),
                (false, true) => Some("added".to_string()),
                _ => None,
            };
            append_row_to_report_sections(
                sections,
                &delta.section_key,
                &delta.section_title,
                TaskReportRow {
                    name: render_scoped_delta_name(&delta.row_name, &row.scope, &row.name),
                    status: TaskReportStatus::Updated,
                    before: row.before,
                    after: row.after,
                    note,
                },
            );
        }
    }
}

fn scoped_delta_rows(delta: &CommandScopedDelta, output: &str) -> Vec<ScopedDeltaRow> {
    let cleaned_output = strip_ansi(output).replace('\r', "\n");
    let mut current_scope: Option<String> = None;
    let mut rows: Vec<ScopedDeltaRow> = Vec::new();

    for line in cleaned_output.lines() {
        if let Some(captures) = delta.scope_regex.captures(line) {
            current_scope = captures
                .name("scope")
                .map(|capture| capture.as_str().trim().to_string())
                .filter(|scope| !scope.is_empty());
            continue;
        }
        let Some(scope) = current_scope.as_deref() else {
            continue;
        };

        if let Some(captures) = delta.before_regex.captures(line) {
            append_scoped_delta_capture(&mut rows, scope, &captures, true);
            continue;
        }
        if let Some(captures) = delta.after_regex.captures(line) {
            append_scoped_delta_capture(&mut rows, scope, &captures, false);
        }
    }

    rows
}

fn append_scoped_delta_capture(
    rows: &mut Vec<ScopedDeltaRow>,
    scope: &str,
    captures: &Captures<'_>,
    before: bool,
) {
    let Some(name) = captures
        .name("name")
        .map(|capture| capture.as_str().trim())
        .filter(|name| !name.is_empty())
    else {
        return;
    };
    let Some(version) = captures
        .name("version")
        .map(|capture| capture.as_str().trim())
        .filter(|version| !version.is_empty())
    else {
        return;
    };

    if let Some(row) = rows
        .iter_mut()
        .find(|row| row.scope == scope && row.name == name)
    {
        if before {
            if row.before.is_none() {
                row.before = Some(version.to_string());
            }
        } else {
            row.after = Some(version.to_string());
        }
        return;
    }

    rows.push(ScopedDeltaRow {
        scope: scope.to_string(),
        name: name.to_string(),
        before: before.then(|| version.to_string()),
        after: (!before).then(|| version.to_string()),
    });
}

fn append_row_to_report_sections(
    sections: &mut Vec<TaskReportSection>,
    section_key: &str,
    section_title: &str,
    row: TaskReportRow,
) {
    if let Some(section) = sections
        .iter_mut()
        .find(|section| section.key == section_key && section.title == section_title)
    {
        append_report_pattern_row(section, row);
        return;
    }
    sections.push(TaskReportSection {
        key: section_key.to_string(),
        title: section_title.to_string(),
        rows: vec![row],
    });
}

fn render_scoped_delta_name(template: &str, scope: &str, name: &str) -> String {
    template.replace("{scope}", scope).replace("{name}", name)
}

fn append_command_report_pattern_sections(
    sections: &mut Vec<TaskReportSection>,
    patterns: &[CommandReportPattern],
    output: &str,
) {
    for pattern in patterns {
        let mut rows = report_pattern_rows(pattern, output);
        if rows.is_empty() {
            continue;
        }
        if let Some(section) = sections.iter_mut().find(|section| {
            section.key == pattern.section_key && section.title == pattern.section_title
        }) {
            for row in rows {
                append_report_pattern_row(section, row);
            }
        } else {
            let mut section = TaskReportSection {
                key: pattern.section_key.clone(),
                title: pattern.section_title.clone(),
                rows: Vec::new(),
            };
            for row in rows {
                append_report_pattern_row(&mut section, row);
            }
            sections.push(TaskReportSection {
                key: section.key,
                title: section.title,
                rows: section.rows,
            });
        }
    }
}

fn append_report_pattern_row(section: &mut TaskReportSection, row: TaskReportRow) {
    if let Some(existing) = section
        .rows
        .iter_mut()
        .find(|existing| existing.name == row.name)
    {
        if report_pattern_status_rank(row.status) > report_pattern_status_rank(existing.status) {
            let mut row = row;
            merge_report_row_values(&mut row, existing);
            *existing = row;
        } else {
            merge_report_row_values(existing, &row);
        }
        reconcile_merged_report_row_status(existing);
        return;
    }
    section.rows.push(row);
}

fn merge_report_row_values(target: &mut TaskReportRow, source: &TaskReportRow) {
    if target.before.is_none() {
        target.before = source.before.clone();
    }
    if target.after.is_none() {
        target.after = source.after.clone();
    }
}

fn reconcile_merged_report_row_status(row: &mut TaskReportRow) {
    if row.status == TaskReportStatus::Updated && report_row_has_same_known_before_after(row) {
        row.status = TaskReportStatus::Refreshed;
    }
}

fn report_row_has_same_known_before_after(row: &TaskReportRow) -> bool {
    let before = known_report_value(row.before.as_deref());
    let after = known_report_value(row.after.as_deref());
    matches!((before, after), (Some(before), Some(after)) if before == after)
}

fn report_pattern_status_rank(status: TaskReportStatus) -> u8 {
    match status {
        TaskReportStatus::Failed => 7,
        TaskReportStatus::Blocked => 6,
        TaskReportStatus::Updated => 5,
        TaskReportStatus::Passed => 4,
        TaskReportStatus::Refreshed => 3,
        TaskReportStatus::Skipped => 2,
        TaskReportStatus::Unchanged => 1,
        TaskReportStatus::Info => 0,
    }
}

fn report_pattern_rows(pattern: &CommandReportPattern, output: &str) -> Vec<TaskReportRow> {
    let cleaned_output = strip_ansi(output).replace('\r', "\n");
    let mut rows = cleaned_output
        .lines()
        .flat_map(|line| pattern.regex.captures_iter(line))
        .map(|captures| build_report_pattern_row(pattern, &captures))
        .collect::<Vec<_>>();
    if rows.is_empty() {
        rows = pattern
            .regex
            .captures_iter(&cleaned_output)
            .map(|captures| build_report_pattern_row(pattern, &captures))
            .collect();
    }
    rows
}

fn build_report_pattern_row(
    pattern: &CommandReportPattern,
    captures: &Captures<'_>,
) -> TaskReportRow {
    let name = render_report_pattern_field(pattern.name.as_deref(), "name", captures)
        .or_else(|| first_report_pattern_capture(captures))
        .unwrap_or_else(|| "match".to_string());
    normalize_report_row(TaskReportRow {
        name,
        status: pattern.status,
        before: render_report_pattern_field(pattern.before.as_deref(), "before", captures),
        after: render_report_pattern_field(pattern.after.as_deref(), "after", captures),
        note: render_report_pattern_field(pattern.note.as_deref(), "note", captures),
    })
}

fn normalize_report_row(mut row: TaskReportRow) -> TaskReportRow {
    (row.before, row.after) = normalize_report_before_after(row.status, row.before, row.after);
    row
}

fn normalize_report_before_after(
    status: TaskReportStatus,
    mut before: Option<String>,
    mut after: Option<String>,
) -> (Option<String>, Option<String>) {
    if matches!(
        status,
        TaskReportStatus::Unchanged | TaskReportStatus::Refreshed
    ) {
        match (
            known_report_value(before.as_deref()),
            known_report_value(after.as_deref()),
        ) {
            (Some(before_value), None) => after = Some(before_value),
            (None, Some(after_value)) => before = Some(after_value),
            _ => {}
        }
    }
    (before, after)
}

fn report_row_display_values(row: &TaskReportRow) -> (String, String) {
    let (before, after) =
        normalize_report_before_after(row.status, row.before.clone(), row.after.clone());
    (
        before.unwrap_or_else(|| "-".to_string()),
        after.unwrap_or_else(|| "-".to_string()),
    )
}

fn known_report_value(value: Option<&str>) -> Option<String> {
    let value = value?;
    let cleaned = sanitize_report_cell_text(value);
    (!cleaned.is_empty() && cleaned != "-").then_some(cleaned)
}

fn render_report_pattern_field(
    template: Option<&str>,
    fallback_capture: &str,
    captures: &Captures<'_>,
) -> Option<String> {
    let value = if let Some(template) = template {
        render_report_pattern_template(template, captures)
    } else {
        captures.name(fallback_capture)?.as_str().to_string()
    };
    non_empty_report_pattern_value(value)
}

fn render_report_pattern_template(template: &str, captures: &Captures<'_>) -> String {
    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open_idx) = rest.find('{') {
        rendered.push_str(&rest[..open_idx]);
        let after_open = &rest[open_idx + 1..];
        let Some(close_idx) = after_open.find('}') else {
            rendered.push_str(&rest[open_idx..]);
            return rendered;
        };
        let key = &after_open[..close_idx];
        if is_report_pattern_capture_key(key) {
            if let Some(value) = captures.name(key) {
                rendered.push_str(value.as_str());
            }
        } else {
            rendered.push('{');
            rendered.push_str(key);
            rendered.push('}');
        }
        rest = &after_open[close_idx + 1..];
    }
    rendered.push_str(rest);
    rendered
}

fn is_report_pattern_capture_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn first_report_pattern_capture(captures: &Captures<'_>) -> Option<String> {
    captures
        .iter()
        .skip(1)
        .flatten()
        .map(|value| value.as_str().to_string())
        .find(|value| !value.trim().is_empty())
        .and_then(non_empty_report_pattern_value)
}

fn non_empty_report_pattern_value(value: String) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn parse_arch_update_services_report(output: &str) -> Vec<TaskReportSection> {
    let mut rows: Vec<TaskReportRow> = Vec::new();
    let mut index_by_name: BTreeMap<String, usize> = BTreeMap::new();
    let mut saw_no_services = false;
    let mut saw_prompt = false;
    let mut restarting_all = false;
    let mut in_services_block = false;

    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("no service requiring a post upgrade restart found") {
            saw_no_services = true;
        }
        if lower == "services:" || lower.starts_with("==> services:") {
            in_services_block = true;
            continue;
        }
        if lower.contains("restart")
            && (lower.contains("service(s)") || lower.contains("services"))
            && (lower.contains("select")
                || lower.contains("choose")
                || lower.contains("press \"enter\" to continue")
                || lower.contains("press enter to continue")
                || lower.contains("continue without restarting"))
        {
            saw_prompt = true;
            in_services_block = false;
        }
        if in_services_block || starts_with_service_list_marker(trimmed) {
            if let Some(service) = extract_systemd_service_name(trimmed) {
                if !index_by_name.contains_key(&service) {
                    index_by_name.insert(service.clone(), rows.len());
                    rows.push(TaskReportRow {
                        name: service,
                        status: TaskReportStatus::Skipped,
                        before: Some("pending".to_string()),
                        after: Some("not restarted".to_string()),
                        note: Some("listed by arch-update".to_string()),
                    });
                }
                continue;
            }
        }
        if lower.contains("service(s) restarted successfully") {
            restarting_all = true;
        }
        if let Some(service) = parse_arch_update_service_restart_success(trimmed) {
            if let Some(idx) = index_by_name.get(&service).copied() {
                rows[idx].status = TaskReportStatus::Updated;
                rows[idx].after = Some("restarted".to_string());
                rows[idx].note = None;
            } else {
                index_by_name.insert(service.clone(), rows.len());
                rows.push(TaskReportRow {
                    name: service,
                    status: TaskReportStatus::Updated,
                    before: Some("pending".to_string()),
                    after: Some("restarted".to_string()),
                    note: None,
                });
            }
        } else if let Some(service) = parse_arch_update_service_restart_failure(trimmed) {
            if let Some(idx) = index_by_name.get(&service).copied() {
                rows[idx].status = TaskReportStatus::Failed;
                rows[idx].after = Some("restart failed".to_string());
                rows[idx].note = Some("arch-update reported restart error".to_string());
            }
        }
    }

    if restarting_all {
        for row in &mut rows {
            if row.status == TaskReportStatus::Skipped {
                row.status = TaskReportStatus::Updated;
                row.after = Some("restarted".to_string());
                row.note = None;
            }
        }
    } else if saw_prompt {
        for row in &mut rows {
            if row.status == TaskReportStatus::Skipped && row.note.is_none() {
                row.note = Some("user skipped restart".to_string());
            }
        }
    }

    if saw_no_services {
        rows.push(TaskReportRow {
            name: "services".to_string(),
            status: TaskReportStatus::Unchanged,
            before: Some("-".to_string()),
            after: Some("-".to_string()),
            note: Some("no services required restart".to_string()),
        });
    }

    if rows.is_empty() {
        return Vec::new();
    }

    vec![TaskReportSection {
        key: "arch_update_services".to_string(),
        title: "Arch-Update Service Results".to_string(),
        rows,
    }]
}

fn parse_arch_update_service_restart_success(line: &str) -> Option<String> {
    let line = line.trim_start_matches("==> ").trim();
    let lower = line.to_ascii_lowercase();
    if lower.contains("successfully restarted") || lower.contains("restarted successfully") {
        return extract_systemd_service_name(line);
    }
    None
}

fn parse_arch_update_service_restart_failure(line: &str) -> Option<String> {
    let line = line
        .trim_start_matches("==> ")
        .trim_start_matches("ERROR: ")
        .trim();
    let lower = line.to_ascii_lowercase();
    if lower.contains("an error has occurred during the restart")
        || lower.contains("failed to restart")
        || lower.contains("error restarting")
    {
        return extract_systemd_service_name(line);
    }
    None
}

fn starts_with_service_list_marker(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some(first) = trimmed.chars().next() else {
        return false;
    };
    first.is_ascii_digit() || first == '-' || first == '*'
}

fn extract_systemd_service_name(line: &str) -> Option<String> {
    let end = line.find(".service")? + ".service".len();
    let mut start = end;
    while start > 0 {
        let ch = line[..start].chars().next_back()?;
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | '@') {
            start -= ch.len_utf8();
        } else {
            break;
        }
    }
    let name = line[start..end].trim();
    (!name.is_empty() && name.ends_with(".service")).then_some(name.to_string())
}

fn parse_version_lines_report(output: &str) -> Vec<TaskReportSection> {
    let mut rows = Vec::new();
    let mut saw_noop = false;
    let mut noop_version: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(name) = parse_version_line_external_manager_skip(trimmed) {
            rows.push(TaskReportRow {
                name,
                status: TaskReportStatus::Skipped,
                before: Some("-".to_string()),
                after: Some("-".to_string()),
                note: Some("managed by external package manager".to_string()),
            });
            continue;
        }
        if let Some((name, before, after)) = parse_version_line_update(trimmed) {
            rows.push(TaskReportRow {
                name,
                status: TaskReportStatus::Updated,
                before: Some(before),
                after: Some(after),
                note: None,
            });
            continue;
        }
        if let Some((name, before, after)) = parse_version_line_arrow(trimmed) {
            rows.push(TaskReportRow {
                name,
                status: TaskReportStatus::Updated,
                before: Some(before),
                after: Some(after),
                note: None,
            });
            continue;
        }
        if let Some((name, version)) = parse_version_line_latest(trimmed) {
            saw_noop = true;
            rows.push(TaskReportRow {
                name,
                status: TaskReportStatus::Unchanged,
                before: Some(version.clone()),
                after: Some(version.clone()),
                note: Some("already up-to-date".to_string()),
            });
            noop_version = Some(version);
            continue;
        }
        if let Some((name, version)) = parse_version_line_simple_current(trimmed) {
            rows.push(TaskReportRow {
                name,
                status: TaskReportStatus::Unchanged,
                before: Some(version.clone()),
                after: Some(version),
                note: Some("reported current version".to_string()),
            });
            continue;
        }
        if let Some(name) = parse_version_line_noop(trimmed) {
            saw_noop = true;
            rows.push(TaskReportRow {
                name,
                status: TaskReportStatus::Unchanged,
                before: Some("-".to_string()),
                after: Some("-".to_string()),
                note: Some("already up-to-date".to_string()),
            });
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains("already up to date") || lower.contains("up-to-date") {
            saw_noop = true;
        }
    }
    if rows.is_empty() {
        let version = noop_version.unwrap_or_else(|| "-".to_string());
        rows.push(TaskReportRow {
            name: "version_lines".to_string(),
            status: if saw_noop {
                TaskReportStatus::Unchanged
            } else {
                TaskReportStatus::Info
            },
            before: Some(version.clone()),
            after: Some(version),
            note: Some(if saw_noop {
                "already up-to-date".to_string()
            } else {
                "no explicit version-line summary".to_string()
            }),
        });
    }
    vec![TaskReportSection {
        key: "version_lines".to_string(),
        title: "Version Line Results".to_string(),
        rows,
    }]
}

fn parse_version_line_update(line: &str) -> Option<(String, String, String)> {
    let lower = line.to_ascii_lowercase();
    let marker = ["upgraded ", "updated ", "downgraded "]
        .into_iter()
        .find_map(|marker| lower.find(marker).map(|idx| (marker, idx)))?;
    let rest = &line[marker.1 + marker.0.len()..];
    if let Some((name, rest)) = rest.split_once(" from ") {
        let (before, after) = rest.split_once(" to ")?;
        let name = normalize_version_line_tool_name(name)?;
        return Some((
            name,
            normalize_version_line_version(before)?,
            normalize_version_line_version(after)?,
        ));
    }
    let (name, after) = rest.split_once(" to ")?;
    let name = normalize_version_line_tool_name(name)?;
    Some((
        name,
        "-".to_string(),
        normalize_version_line_version(after)?,
    ))
}

fn parse_version_line_arrow(line: &str) -> Option<(String, String, String)> {
    let (left, right) = line.split_once("->")?;
    let after = normalize_version_line_version(right)?;
    let left = left
        .trim()
        .trim_start_matches(|c| matches!(c, '-' | '*' | '+'))
        .trim();
    let (name, before) = left.rsplit_once(char::is_whitespace)?;
    Some((
        normalize_version_line_tool_name(name)?,
        normalize_version_line_version(before)?,
        after,
    ))
}

fn parse_version_line_latest(line: &str) -> Option<(String, String)> {
    let lower = line.to_ascii_lowercase();
    if let Some(marker_idx) = lower.find("latest version of ") {
        let rest = &line[marker_idx + "latest version of ".len()..];
        let (name, version) = rest.split_once('(')?;
        let version = version
            .split_once(')')
            .map(|(version, _)| version)
            .unwrap_or(version);
        return normalize_version_line_name_and_version(name, version);
    }

    parse_version_line_marker_suffix(line, &lower, " current version is ")
        .or_else(|| parse_version_line_marker_suffix(line, &lower, " is already installed at "))
        .or_else(|| parse_version_line_marker_suffix(line, &lower, " is already at version "))
        .or_else(|| parse_version_line_latest_available(line, &lower))
}

fn parse_version_line_simple_current(line: &str) -> Option<(String, String)> {
    let lower = line.to_ascii_lowercase();
    for marker in [" version ", " --version "] {
        if let Some(marker_idx) = lower.find(marker) {
            return normalize_simple_version_line_name_and_version(
                &line[..marker_idx],
                &line[marker_idx + marker.len()..],
            );
        }
    }

    if let Some((name, version)) = line.split_once(':') {
        if let Some(parsed) = normalize_simple_version_line_name_and_version(name, version) {
            return Some(parsed);
        }
    }

    let mut parts = line.split_whitespace();
    let name = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    normalize_simple_version_line_name_and_version(name, version)
}

fn parse_version_line_marker_suffix(
    line: &str,
    lower: &str,
    marker: &str,
) -> Option<(String, String)> {
    let marker_idx = lower.find(marker)?;
    normalize_version_line_name_and_version(&line[..marker_idx], &line[marker_idx + marker.len()..])
}

fn parse_version_line_latest_available(line: &str, lower: &str) -> Option<(String, String)> {
    let marker_idx = lower.find(" is the latest version available")?;
    let prefix = line[..marker_idx].trim();
    let (name, version) = prefix.rsplit_once(char::is_whitespace)?;
    normalize_version_line_name_and_version(name, version)
}

fn parse_version_line_noop(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = ["already up to date", "already up-to-date", "up-to-date"]
        .into_iter()
        .find_map(|marker| lower.find(marker).map(|idx| (marker, idx)))?;
    let prefix = line[..marker.1]
        .trim()
        .trim_end_matches(" is")
        .trim_end_matches(" already")
        .trim();
    let name = prefix
        .rsplit_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(prefix)
        .trim();
    normalize_version_line_tool_name(name)
}

fn parse_version_line_external_manager_skip(line: &str) -> Option<String> {
    if !is_external_manager_self_update_unsupported(line) {
        return None;
    }
    parse_external_manager_installed_tool_name(line)
        .or_else(|| parse_standalone_install_required_tool_name(line))
}

fn parse_external_manager_installed_tool_name(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let marker = " installed through an external package manager";
    let marker_idx = lower.find(marker)?;
    let prefix = line[..marker_idx].trim().trim_end_matches(" was").trim();
    let name = prefix
        .rsplit_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(prefix)
        .trim();
    normalize_version_line_tool_name(name)
}

fn parse_standalone_install_required_tool_name(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let start_marker = "self-update is only available for ";
    let end_marker = " binaries installed";
    let start = lower.find(start_marker)? + start_marker.len();
    let end = lower[start..].find(end_marker)? + start;
    normalize_version_line_tool_name(&line[start..end])
}

fn normalize_version_line_tool_name(input: &str) -> Option<String> {
    let name = input
        .trim()
        .trim_matches(|c| matches!(c, ':' | '-' | '!' | ',' | ';' | '.'))
        .trim();
    (!name.is_empty()).then_some(name.to_string())
}

fn normalize_version_line_name_and_version(name: &str, version: &str) -> Option<(String, String)> {
    Some((
        normalize_version_line_tool_name(name)?,
        normalize_version_line_version(version)?,
    ))
}

fn normalize_simple_version_line_name_and_version(
    name: &str,
    version: &str,
) -> Option<(String, String)> {
    let name = normalize_version_line_tool_name(name)?;
    if !looks_like_simple_version_line_tool_name(&name) {
        return None;
    }
    Some((name, normalize_version_line_version(version)?))
}

fn looks_like_simple_version_line_tool_name(name: &str) -> bool {
    !name.starts_with('/')
        && !name.contains("://")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '@' | '_' | '-' | '/'))
}

fn normalize_version_line_version(input: &str) -> Option<String> {
    let version = input
        .trim()
        .split_whitespace()
        .next()?
        .trim_start_matches(|c| matches!(c, '(' | '['))
        .trim_end_matches(|c| matches!(c, ')' | ']' | '!' | ',' | ';' | '.'))
        .trim();
    looks_like_package_version(version).then_some(version.to_string())
}

fn parse_yay_report(output: &str) -> Vec<TaskReportSection> {
    let mut rows = Vec::new();
    let mut row_index = BTreeMap::new();
    let mut saw_noop = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed
            .to_ascii_lowercase()
            .contains("there is nothing to do")
        {
            saw_noop = true;
        }
        if !trimmed.contains("->") {
            continue;
        }
        let parts = trimmed.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 5 {
            continue;
        }
        if parts[0].parse::<usize>().is_err() {
            continue;
        }
        if parts[3] != "->" {
            continue;
        }
        if !looks_like_yay_package_name(parts[1]) {
            continue;
        }
        if !looks_like_package_version(parts[2]) || !looks_like_package_version(parts[4]) {
            continue;
        }
        let name = parts[1].to_string();
        let row = TaskReportRow {
            name: name.clone(),
            status: TaskReportStatus::Updated,
            before: Some(parts[2].to_string()),
            after: Some(parts[4].to_string()),
            note: None,
        };
        if let Some(idx) = row_index.get(&name).copied() {
            rows[idx] = row;
        } else {
            row_index.insert(name, rows.len());
            rows.push(row);
        }
    }
    if rows.is_empty() {
        rows.push(TaskReportRow {
            name: "yay".to_string(),
            status: if saw_noop {
                TaskReportStatus::Unchanged
            } else {
                TaskReportStatus::Info
            },
            before: Some("-".to_string()),
            after: Some("-".to_string()),
            note: Some(if saw_noop {
                "there is nothing to do".to_string()
            } else {
                "no package upgrade rows emitted".to_string()
            }),
        });
    }
    vec![TaskReportSection {
        key: "yay_packages".to_string(),
        title: "Yay Package Results".to_string(),
        rows,
    }]
}

fn format_package_manager_failure(err_text: &str) -> Option<String> {
    if is_pacman_conflicting_files_error(err_text) {
        let owners = collect_conflict_owners(err_text);
        if owners.is_empty() {
            return Some(format!(
                "command failed: package install transaction hit conflicting files; review the task log for the owning package(s). Original error: {err_text}"
            ));
        }

        let owner_list = owners.join(", ");
        return Some(format!(
            "command failed: package install transaction hit conflicting files owned by {owner_list}; remove or reconcile the conflicting package(s), then retry. Original error: {err_text}"
        ));
    }

    if is_yay_source_validity_failure(err_text) {
        return Some(match (
            parse_yay_failed_package_name(err_text),
            parse_yay_failed_source_path(err_text),
        ) {
            (Some(package), Some(source_path)) => format!(
                "command failed: source/build validation failed for {package}; clear the affected yay cache/worktree at {source_path} and retry. Original error: {err_text}"
            ),
            (Some(package), None) => format!(
                "command failed: source/build validation failed for {package}; clear the affected yay cache/worktree and retry. Original error: {err_text}"
            ),
            (None, Some(source_path)) => format!(
                "command failed: source/build validation failed while using yay cache/worktree {source_path}; clear it and retry. Original error: {err_text}"
            ),
            (None, None) => format!(
                "command failed: source/build validation failed during yay package preparation; clear the affected yay cache/worktree and retry. Original error: {err_text}"
            ),
        });
    }

    None
}

fn format_package_manager_timeout_failure(
    spec: &TaskSpec,
    cmd: &CommandTask,
    policy: &TaskPolicy,
    run_log: Option<&RunLogSink>,
    err_text: &str,
) -> Option<String> {
    if !command_reports_aur_helper(cmd) || !is_command_timeout_error(err_text) {
        return None;
    }

    let task_log = run_log
        .map(|log| {
            log.run_dir()
                .join(format!("task-{}.log", task_file_stem(&spec.id)))
                .display()
                .to_string()
        })
        .unwrap_or_else(|| "the per-task log".to_string());

    Some(format!(
        "command failed: AUR update timed out after {}s using task policy `{}`; review {task_log} for the package-level cause. Original error: {err_text}",
        policy.timeout.as_secs(),
        cmd.policy_key
    ))
}

fn is_command_timeout_error(err_text: &str) -> bool {
    err_text.starts_with("timeout running ")
}

fn is_pacman_conflicting_files_error(input: &str) -> bool {
    input
        .to_ascii_lowercase()
        .contains("failed to commit transaction (conflicting files)")
}

fn collect_conflict_owners(input: &str) -> Vec<String> {
    let mut owners = Vec::new();
    let needle = "(owned by ";
    let mut rest = input;
    while let Some(start) = rest.find(needle) {
        let after = &rest[start + needle.len()..];
        let Some(end) = after.find(')') else {
            break;
        };
        let owner = after[..end].trim();
        if !owner.is_empty() && !owners.iter().any(|existing| existing == owner) {
            owners.push(owner.to_string());
        }
        rest = &after[end + 1..];
    }
    owners
}

fn looks_like_yay_package_name(input: &str) -> bool {
    let Some((repo, package)) = input.split_once('/') else {
        return false;
    };
    !repo.is_empty()
        && !package.is_empty()
        && repo
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
        && package
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-' | '@'))
}

fn looks_like_package_version(input: &str) -> bool {
    let has_digit = input.chars().any(|c| c.is_ascii_digit());
    has_digit
        && input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '+' | '_' | '-' | '~'))
}

fn parse_winget_report(output: &str) -> Vec<TaskReportSection> {
    let mut rows: Vec<TaskReportRow> = Vec::new();
    let mut row_index: BTreeMap<String, usize> = BTreeMap::new();
    let mut in_table: Option<WingetTableKind> = None;
    let mut next_table_is_explicit = false;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed
            .to_ascii_lowercase()
            .contains("require explicit targeting")
        {
            next_table_is_explicit = true;
            continue;
        }
        if trimmed.starts_with("Name")
            && trimmed.contains(" Id ")
            && trimmed.contains(" Version")
            && trimmed.contains(" Available")
            && trimmed.contains(" Source")
        {
            in_table = Some(if next_table_is_explicit {
                WingetTableKind::ExplicitTargeting
            } else {
                WingetTableKind::Upgrades
            });
            next_table_is_explicit = false;
            continue;
        }
        let Some(kind) = in_table else {
            continue;
        };
        if trimmed.is_empty() || trimmed.starts_with('-') {
            continue;
        }
        if trimmed.ends_with(" upgrades available.")
            || trimmed.starts_with("Installing ")
            || trimmed.starts_with("This package requires ")
        {
            in_table = None;
            continue;
        }
        if let Some((name, _id, before, after)) = parse_winget_table_row(trimmed) {
            row_index.insert(name.clone(), rows.len());
            let (status, note) = match kind {
                WingetTableKind::Upgrades => (
                    TaskReportStatus::Blocked,
                    Some("update available; no install result observed".to_string()),
                ),
                WingetTableKind::ExplicitTargeting => (
                    TaskReportStatus::Blocked,
                    Some("pinned or explicit-target upgrade required".to_string()),
                ),
            };
            rows.push(TaskReportRow {
                name,
                status,
                before: Some(before),
                after: Some(after),
                note,
            });
        } else {
            in_table = None;
        }
    }

    let mut current_pkg: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(name) = parse_winget_found_package_name(trimmed) {
            current_pkg = Some(name);
            continue;
        }
        if trimmed.eq_ignore_ascii_case("Successfully installed") {
            if let Some(name) = current_pkg.as_ref() {
                if let Some(pkg) = row_index.get(name).copied() {
                    rows[pkg].status = TaskReportStatus::Updated;
                    rows[pkg].note = None;
                } else {
                    row_index.insert(name.clone(), rows.len());
                    rows.push(TaskReportRow {
                        name: name.clone(),
                        status: TaskReportStatus::Updated,
                        before: Some("-".to_string()),
                        after: Some("-".to_string()),
                        note: None,
                    });
                }
            }
            continue;
        }
        if let Some(marker) = winget_output_failure_marker(trimmed) {
            if let Some(name) = current_pkg.as_ref() {
                if let Some(pkg) = row_index.get(name).copied() {
                    rows[pkg].status = TaskReportStatus::Failed;
                    rows[pkg].note = Some(normalize_winget_failure_note(marker));
                } else {
                    row_index.insert(name.clone(), rows.len());
                    rows.push(TaskReportRow {
                        name: name.clone(),
                        status: TaskReportStatus::Failed,
                        before: Some("-".to_string()),
                        after: Some("-".to_string()),
                        note: Some(normalize_winget_failure_note(marker)),
                    });
                }
            } else {
                let label = "winget".to_string();
                if let Some(idx) = row_index.get(&label).copied() {
                    rows[idx].status = TaskReportStatus::Failed;
                    rows[idx].note = Some(normalize_winget_failure_note(marker));
                } else {
                    row_index.insert(label.clone(), rows.len());
                    rows.push(TaskReportRow {
                        name: label,
                        status: TaskReportStatus::Failed,
                        before: Some("-".to_string()),
                        after: Some("-".to_string()),
                        note: Some(normalize_winget_failure_note(marker)),
                    });
                }
            }
        }
    }

    if rows.is_empty() {
        return Vec::new();
    }
    vec![TaskReportSection {
        key: "winget_packages".to_string(),
        title: "Winget Package Results".to_string(),
        rows,
    }]
}

#[derive(Clone, Copy)]
enum WingetTableKind {
    Upgrades,
    ExplicitTargeting,
}

fn parse_winget_table_row(line: &str) -> Option<(String, String, String, String)> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 5 {
        return None;
    }
    if cols.last().copied()? != "winget" {
        return None;
    }
    let id = cols[cols.len() - 4].to_string();
    if !id.contains('.') {
        return None;
    }
    let installed = cols[cols.len() - 3];
    let available = cols[cols.len() - 2];
    if !looks_like_package_version(installed) || !looks_like_package_version(available) {
        return None;
    }
    let name = cols[..cols.len().saturating_sub(4)].join(" ");
    if name.is_empty() {
        return None;
    }
    Some((name, id, installed.to_string(), available.to_string()))
}

fn parse_winget_found_package_name(line: &str) -> Option<String> {
    let found_idx = line.find("Found ")?;
    let suffix = &line[found_idx + "Found ".len()..];
    let (name, _) = suffix.split_once(" [")?;
    let trimmed = name.trim();
    (!trimmed.is_empty()).then_some(trimmed.to_string())
}

fn winget_output_failure_marker(line: &str) -> Option<&str> {
    if line.contains("No suitable installer found for manifest:")
        || line.contains("Error processing package dependencies. Exiting...")
        || line.contains("Installer hash does not match.")
        || line.starts_with("remove: Access is denied.")
        || line.contains("Installer failed with exit code")
    {
        return Some(line);
    }
    None
}

fn normalize_winget_failure_note(line: &str) -> String {
    let trimmed = line.trim();
    if trimmed.starts_with("Installer failed with exit code:") {
        return trimmed.to_string();
    }
    if trimmed.starts_with("remove: Access is denied.") {
        return "access denied while replacing package executable".to_string();
    }
    trimmed.to_string()
}

fn parse_scoop_report(output: &str) -> Vec<TaskReportSection> {
    let mut version_pairs: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut rows = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some((pkg, from, to)) = parse_scoop_version_line(trimmed) {
            version_pairs.insert(pkg, (from, to));
            continue;
        }
        if let Some(pkg) = parse_scoop_running_instance_line(trimmed) {
            let (before, after) = version_pairs
                .get(&pkg)
                .cloned()
                .unwrap_or_else(|| ("-".to_string(), "-".to_string()));
            rows.push(TaskReportRow {
                name: pkg,
                status: TaskReportStatus::Blocked,
                before: Some(before),
                after: Some(after),
                note: Some("running process detected".to_string()),
            });
        }
    }
    for (pkg, (before, after)) in version_pairs {
        if rows.iter().any(|row| row.name == pkg) {
            continue;
        }
        rows.push(TaskReportRow {
            name: pkg,
            status: TaskReportStatus::Updated,
            before: Some(before),
            after: Some(after),
            note: None,
        });
    }
    if rows.is_empty() {
        return Vec::new();
    }
    vec![TaskReportSection {
        key: "scoop_packages".to_string(),
        title: "Scoop Package Results".to_string(),
        rows,
    }]
}

fn parse_scoop_version_line(line: &str) -> Option<(String, String, String)> {
    let (name, rest) = line.split_once(':')?;
    let (from, to) = rest.trim().split_once("->")?;
    let pkg = name.trim();
    if pkg.is_empty() {
        return None;
    }
    Some((
        pkg.to_string(),
        from.trim().to_string(),
        to.trim().to_string(),
    ))
}

fn parse_scoop_running_instance_line(line: &str) -> Option<String> {
    let prefix = "ERROR The following instances of \"";
    let suffix = "\" are still running. Close them and try again.";
    if !line.starts_with(prefix) || !line.ends_with(suffix) {
        return None;
    }
    let body = &line[prefix.len()..line.len() - suffix.len()];
    let trimmed = body.trim();
    (!trimmed.is_empty()).then_some(trimmed.to_string())
}

fn emit_end_of_run_reports_sync(
    ctx: &SyncContext,
    summary: &[(String, TaskResult)],
    task_categories: &BTreeMap<String, String>,
) {
    let footer = render_npm_package_footer(
        summary.iter().map(|(_, result)| result),
        true,
        ctx.note_verbosity,
    );
    for line in &footer {
        crate::ua_outln!("{}", line.text);
    }

    let footer_no_color = render_npm_package_footer(
        summary.iter().map(|(_, result)| result),
        false,
        ctx.note_verbosity,
    );
    for line in footer_no_color {
        ctx.log_line("runtime", line.level, LogStream::Meta, line.text);
    }

    if ctx.debug_report {
        for line in render_per_task_changes(
            summary.iter().map(|(id, result)| (id.as_str(), result)),
            task_categories,
            true,
            ctx.note_verbosity,
            ctx.debug_report,
        ) {
            crate::ua_outln!("{}", line.text);
        }
        for line in render_per_task_changes(
            summary.iter().map(|(id, result)| (id.as_str(), result)),
            task_categories,
            false,
            ctx.note_verbosity,
            ctx.debug_report,
        ) {
            ctx.log_line("runtime", line.level, LogStream::Meta, line.text);
        }
    }

    for line in render_final_task_overview(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        task_categories,
        true,
        ctx.note_verbosity,
        ctx.debug_report,
    ) {
        crate::ua_outln!("{}", line.text);
    }
    for line in render_final_task_overview(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        task_categories,
        false,
        ctx.note_verbosity,
        ctx.debug_report,
    ) {
        ctx.log_line("runtime", line.level, LogStream::Meta, line.text);
    }
    for line in render_attention_required(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        task_categories,
        true,
    ) {
        crate::ua_outln!("{}", line.text);
    }
    for line in render_attention_required(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        task_categories,
        false,
    ) {
        ctx.log_line("runtime", line.level, LogStream::Meta, line.text);
    }
    for line in render_update_details(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        false,
        ctx.note_verbosity,
    ) {
        ctx.log_line("runtime", line.level, LogStream::Meta, line.text);
    }
    for line in render_update_details(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        true,
        ctx.note_verbosity,
    ) {
        crate::ua_outln!("{}", line.text);
    }
}

fn emit_task_report_logs_sync(ctx: &SyncContext, task_id: &str, sections: &[TaskReportSection]) {
    for line in render_task_report_sections(sections, false, ctx.note_verbosity) {
        ctx.log_line(task_id, line.level, LogStream::Meta, line.text);
    }
}

fn emit_end_of_run_reports_async_logs<'a>(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)> + Clone,
    task_categories: &BTreeMap<String, String>,
    note_verbosity: NoteVerbosity,
    debug_report: bool,
) {
    for line in render_package_change_rollup(
        summary.clone(),
        task_categories,
        false,
        note_verbosity,
        debug_report,
    ) {
        emit_task_log(
            event_tx,
            run_log,
            "runtime",
            line.level,
            LogStream::Meta,
            line.text,
        );
    }
    if debug_report {
        for line in render_per_task_changes(
            summary.clone(),
            task_categories,
            false,
            note_verbosity,
            debug_report,
        ) {
            emit_task_log(
                event_tx,
                run_log,
                "runtime",
                line.level,
                LogStream::Meta,
                line.text,
            );
        }
    }
    for line in render_final_task_overview(
        summary.clone(),
        task_categories,
        false,
        note_verbosity,
        debug_report,
    ) {
        emit_task_log(
            event_tx,
            run_log,
            "runtime",
            line.level,
            LogStream::Meta,
            line.text,
        );
    }
    for line in render_attention_required(summary.clone(), task_categories, false) {
        emit_task_log(
            event_tx,
            run_log,
            "runtime",
            line.level,
            LogStream::Meta,
            line.text,
        );
    }
    for line in render_update_details(summary, false, note_verbosity) {
        emit_task_log(
            event_tx,
            run_log,
            "runtime",
            line.level,
            LogStream::Meta,
            line.text,
        );
    }
}

fn emit_async_completion_boundary_and_reports<'a>(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)> + Clone,
    task_categories: &BTreeMap<String, String>,
    note_verbosity: NoteVerbosity,
    debug_report: bool,
    outcome: AsyncRunOutcome,
    completed_at: Instant,
) {
    let _ = event_tx.send(DashboardEvent::RunComplete {
        success: outcome == AsyncRunOutcome::Success,
        completed_at,
    });
    emit_end_of_run_reports_async_logs(
        event_tx,
        run_log,
        summary,
        task_categories,
        note_verbosity,
        debug_report,
    );
}

fn emit_task_report_logs_async(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    task_id: &str,
    sections: &[TaskReportSection],
    note_verbosity: NoteVerbosity,
) {
    for line in render_task_report_sections(sections, false, note_verbosity) {
        emit_task_log(
            event_tx,
            run_log,
            task_id,
            line.level,
            LogStream::Meta,
            line.text,
        );
    }
}

fn print_end_of_run_reports<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)> + Clone,
    task_categories: &BTreeMap<String, String>,
    note_verbosity: NoteVerbosity,
    debug_report: bool,
) {
    for line in render_package_change_rollup(
        summary.clone(),
        task_categories,
        true,
        note_verbosity,
        debug_report,
    ) {
        crate::ua_outln!("{}", line.text);
    }
    if debug_report {
        for line in render_per_task_changes(
            summary.clone(),
            task_categories,
            true,
            note_verbosity,
            debug_report,
        ) {
            crate::ua_outln!("{}", line.text);
        }
    }
    for line in render_final_task_overview(
        summary.clone(),
        task_categories,
        true,
        note_verbosity,
        debug_report,
    ) {
        crate::ua_outln!("{}", line.text);
    }
    for line in render_attention_required(summary.clone(), task_categories, true) {
        crate::ua_outln!("{}", line.text);
    }
    for line in render_update_details(summary, true, note_verbosity) {
        crate::ua_outln!("{}", line.text);
    }
}

fn render_task_report_sections(
    sections: &[TaskReportSection],
    color: bool,
    note_verbosity: NoteVerbosity,
) -> Vec<RenderedReportLine> {
    render_npm_package_footer(
        [TaskResult {
            label: String::new(),
            status: TaskStatus::Completed,
            details: Vec::new(),
            advisories: Vec::new(),
            report_sections: sections.to_vec(),
        }]
        .iter(),
        color,
        note_verbosity,
    )
}

#[derive(Clone, Debug)]
struct RenderedReportLine {
    text: String,
    level: LogLevel,
}

#[derive(Clone, Copy)]
struct TableCell<'a> {
    text: &'a str,
    color: Option<crossterm::style::Color>,
    width: usize,
    overflow_label: Option<&'static str>,
}

struct BoxCell {
    text: String,
    color: Option<crossterm::style::Color>,
    width: usize,
}

impl BoxCell {
    fn plain(text: &str, width: usize) -> Self {
        Self {
            text: text.to_string(),
            color: None,
            width,
        }
    }
}

#[derive(Clone, Debug)]
struct FinalTaskRow {
    category: String,
    task: String,
    status: TaskStatus,
    has_issues: bool,
    deferred: bool,
    items: String,
    notes: String,
}

#[derive(Clone, Debug)]
struct PackageChangeRow {
    category: String,
    task: String,
    item: String,
    before: String,
    after: String,
    result: String,
    note: String,
    status: TaskReportStatus,
}

#[derive(Clone, Debug)]
struct AttentionRow {
    task: String,
    severity: AdvisorySeverity,
    issue: String,
    action: String,
}

struct OrderedTaskResult<'a> {
    task_id: &'a str,
    category: String,
    label: String,
    result: &'a TaskResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InlineNoteKind {
    Failure,
    Skip,
    Recovery,
    Info,
    Overflow,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ReportStatusCounts {
    generated: usize,
    restarted: usize,
    updated: usize,
    refreshed: usize,
    recovered: usize,
    passed: usize,
    failed: usize,
    blocked: usize,
    warned: usize,
    unchanged: usize,
    removed: usize,
    skipped: usize,
    info: usize,
}

impl ReportStatusCounts {
    fn add(&mut self, section_key: &str, row: &TaskReportRow) {
        match (section_key, row.status) {
            ("completion_generation", TaskReportStatus::Updated) => self.generated += 1,
            ("completion_generation", TaskReportStatus::Unchanged) => self.unchanged += 1,
            ("completion_generation", TaskReportStatus::Skipped) => self.skipped += 1,
            ("arch_update_services", TaskReportStatus::Updated) => self.restarted += 1,
            ("completion_audit", TaskReportStatus::Passed) => self.passed += 1,
            ("completion_audit", TaskReportStatus::Blocked) => self.warned += 1,
            ("completion_audit", TaskReportStatus::Skipped) => self.skipped += 1,
            ("package_recovery" | "yay_recovery", TaskReportStatus::Updated) => self.recovered += 1,
            ("package_recovery" | "yay_recovery", TaskReportStatus::Skipped) => self.removed += 1,
            (_, TaskReportStatus::Passed) => self.passed += 1,
            (_, TaskReportStatus::Updated) => self.updated += 1,
            (_, TaskReportStatus::Refreshed) => self.refreshed += 1,
            (_, TaskReportStatus::Unchanged) => self.unchanged += 1,
            (_, TaskReportStatus::Failed) => self.failed += 1,
            (_, TaskReportStatus::Blocked) => self.blocked += 1,
            (_, TaskReportStatus::Skipped) => self.skipped += 1,
            (_, TaskReportStatus::Info) => self.info += 1,
        }
    }

    fn render(self) -> String {
        let mut parts = Vec::new();
        if self.generated > 0 {
            parts.push(format!("generated={}", self.generated));
        }
        if self.restarted > 0 {
            parts.push(format!("restarted={}", self.restarted));
        }
        if self.updated > 0 {
            parts.push(format!("updated={}", self.updated));
        }
        if self.refreshed > 0 {
            parts.push(format!("refreshed={}", self.refreshed));
        }
        if self.recovered > 0 {
            parts.push(format!("recovered={}", self.recovered));
        }
        if self.passed > 0 {
            parts.push(format!("passed={}", self.passed));
        }
        if self.failed > 0 {
            parts.push(format!("failed={}", self.failed));
        }
        if self.warned > 0 {
            parts.push(format!("warn={}", self.warned));
        }
        if self.info > 0 {
            parts.push(format!("info={}", self.info));
        }
        if self.blocked > 0 {
            parts.push(format!("blocked={}", self.blocked));
        }
        if self.unchanged > 0 {
            parts.push(format!("unchanged={}", self.unchanged));
        }
        if self.removed > 0 {
            parts.push(format!("removed={}", self.removed));
        }
        if self.skipped > 0 {
            parts.push(format!("skipped={}", self.skipped));
        }
        if parts.is_empty() {
            "-".to_string()
        } else {
            parts.join(" ")
        }
    }
}

fn render_npm_package_footer<'a>(
    summary: impl IntoIterator<Item = &'a TaskResult>,
    color: bool,
    note_verbosity: NoteVerbosity,
) -> Vec<RenderedReportLine> {
    let mut lines = Vec::new();
    let mut sections: Vec<(String, String, Vec<&TaskReportRow>)> = Vec::new();

    for result in summary {
        for section in &result.report_sections {
            if let Some((_, _, rows)) = sections
                .iter_mut()
                .find(|(key, title, _)| *key == section.key && *title == section.title)
            {
                rows.extend(section.rows.iter());
            } else {
                sections.push((
                    section.key.clone(),
                    section.title.clone(),
                    section.rows.iter().collect(),
                ));
            }
        }
    }

    if sections.is_empty() {
        return lines;
    }

    for (idx, (key, title, rows)) in sections.into_iter().enumerate() {
        if rows.is_empty() {
            continue;
        }
        if idx == 0 {
            lines.push(RenderedReportLine {
                text: String::new(),
                level: LogLevel::Info,
            });
        }
        let (name_header, before_header, after_header, status_header) =
            report_headers_for_section(&key);
        let name_w = rows
            .iter()
            .map(|r| visible_width(&r.name))
            .max()
            .unwrap_or_else(|| visible_width(name_header))
            .max(visible_width(name_header))
            .min(42);
        let (before_cap, after_cap) = report_value_width_caps_for_section(&key);
        let before_w = rows
            .iter()
            .map(|row| {
                let (before, _) = report_row_display_values(row);
                visible_width(&before)
            })
            .max()
            .unwrap_or_else(|| visible_width(before_header))
            .max(visible_width(before_header))
            .min(before_cap);
        let after_w = rows
            .iter()
            .map(|row| {
                let (_, after) = report_row_display_values(row);
                visible_width(&after)
            })
            .max()
            .unwrap_or_else(|| visible_width(after_header))
            .max(visible_width(after_header))
            .min(after_cap);
        let status_w = rows
            .iter()
            .map(|row| visible_width(report_status_cell_for_row(&key, row)))
            .max()
            .unwrap_or_else(|| visible_width(status_header))
            .max(visible_width(status_header));
        lines.push(RenderedReportLine {
            text: title,
            level: LogLevel::Info,
        });
        lines.push(RenderedReportLine {
            text: format_report_row(&[
                (name_header, None, name_w),
                (before_header, None, before_w),
                (after_header, None, after_w),
                (status_header, None, status_w),
            ]),
            level: LogLevel::Info,
        });
        for row in rows {
            let (before, after) = report_row_display_values(row);
            let outcome = report_status_cell_for_row(&key, row);
            let color_enabled = color_output_enabled(color);
            let value_change = report_row_has_value_change(row);
            let before_color = if color_enabled && value_change {
                Some(crossterm::style::Color::Red)
            } else {
                None
            };
            let after_color = if color_enabled && value_change {
                Some(crossterm::style::Color::Green)
            } else {
                None
            };
            let outcome_color = if color_enabled {
                report_status_color_for_row(&key, row)
            } else {
                None
            };
            let (row_text, overflow_notes) = format_table_row(&[
                TableCell {
                    text: &row.name,
                    color: None,
                    width: name_w,
                    overflow_label: Some("package"),
                },
                TableCell {
                    text: &before,
                    color: before_color,
                    width: before_w,
                    overflow_label: Some("before"),
                },
                TableCell {
                    text: &after,
                    color: after_color,
                    width: after_w,
                    overflow_label: Some("after"),
                },
                TableCell {
                    text: outcome,
                    color: outcome_color,
                    width: status_w,
                    overflow_label: None,
                },
            ]);
            lines.push(RenderedReportLine {
                text: row_text,
                level: report_status_level(row.status),
            });
            for note in overflow_notes {
                if !should_render_inline_note(InlineNoteKind::Overflow, row.status, note_verbosity)
                {
                    continue;
                }
                let tag = render_report_note_prefix_for_row(&key, row, color);
                lines.push(RenderedReportLine {
                    text: format!("  {tag} {}", sanitize_report_cell_text(&note)),
                    level: report_status_level(row.status),
                });
            }
            if let Some(note) = &row.note {
                let kind = classify_row_note_kind(&key, row.status);
                if !should_render_inline_note(kind, row.status, note_verbosity) {
                    continue;
                }
                let tag = render_report_note_prefix_for_row(&key, row, color);
                lines.push(RenderedReportLine {
                    text: format!("  {tag} {}", sanitize_report_cell_text(note)),
                    level: report_status_level(row.status),
                });
            }
        }
    }
    lines
}

fn selected_task_ids(specs: &[TaskSpec]) -> Vec<String> {
    let mut ids = Vec::with_capacity(specs.len());
    for spec in specs {
        ids.push(spec.id.clone());
    }
    ids
}

fn task_categories_by_id(specs: &[TaskSpec]) -> BTreeMap<String, String> {
    specs
        .iter()
        .map(|spec| (spec.id.clone(), spec.category.clone()))
        .collect()
}

fn ordered_task_results<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    task_categories: &BTreeMap<String, String>,
) -> Vec<OrderedTaskResult<'a>> {
    let mut rows = Vec::new();
    for (task_id, result) in summary {
        let category = task_categories
            .get(task_id)
            .map(String::as_str)
            .unwrap_or(UNCATEGORIZED_TASK_CATEGORY);
        rows.push(OrderedTaskResult {
            task_id,
            category: category_display_name(category),
            label: result.label.clone(),
            result,
        });
    }
    rows.sort_by(|left, right| {
        task_category_rank(&left.category.to_ascii_lowercase())
            .cmp(&task_category_rank(&right.category.to_ascii_lowercase()))
            .then_with(|| left.category.cmp(&right.category))
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.task_id.cmp(right.task_id))
    });
    rows
}

fn render_package_change_rollup<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    task_categories: &BTreeMap<String, String>,
    color: bool,
    note_verbosity: NoteVerbosity,
    debug_report: bool,
) -> Vec<RenderedReportLine> {
    render_package_change_rollup_with_width(
        summary,
        task_categories,
        color,
        note_verbosity,
        debug_report,
        report_table_target_width(),
    )
}

fn render_package_change_rollup_with_width<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    task_categories: &BTreeMap<String, String>,
    color: bool,
    note_verbosity: NoteVerbosity,
    debug_report: bool,
    target_width: usize,
) -> Vec<RenderedReportLine> {
    let rows = ordered_task_results(summary, task_categories)
        .into_iter()
        .flat_map(|entry| {
            let category = entry.category.clone();
            let task = entry.label.clone();
            entry
                .result
                .report_sections
                .iter()
                .flat_map(move |section| {
                    let category = category.clone();
                    let task = task.clone();
                    section.rows.iter().map(move |row| {
                        let (before, after) = report_row_display_values(row);
                        PackageChangeRow {
                            category: category.clone(),
                            task: task.clone(),
                            item: row.name.clone(),
                            before,
                            after,
                            result: report_status_cell_for_row(&section.key, row).to_string(),
                            note: render_package_rollup_note(&section.key, row),
                            status: row.status,
                        }
                    })
                })
        })
        .collect::<Vec<_>>();

    if rows.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![RenderedReportLine {
        text: String::new(),
        level: LogLevel::Info,
    }];
    lines.push(RenderedReportLine {
        text: "Package Change Rollup".to_string(),
        level: LogLevel::Info,
    });

    let preferred_widths = [
        rows.iter()
            .map(|row| visible_width(&row.category))
            .max()
            .unwrap_or_else(|| visible_width("Group"))
            .max(visible_width("Group"))
            .min(TASK_CATEGORY_COLUMN_MAX_WIDTH),
        rows.iter()
            .map(|row| visible_width(&row.task))
            .max()
            .unwrap_or_else(|| visible_width("Task"))
            .max(visible_width("Task"))
            .min(18),
        rows.iter()
            .map(|row| visible_width(&row.item))
            .max()
            .unwrap_or_else(|| visible_width("Item"))
            .max(visible_width("Item"))
            .min(28),
        rows.iter()
            .map(|row| visible_width(&row.before))
            .max()
            .unwrap_or_else(|| visible_width("Before"))
            .max(visible_width("Before"))
            .min(16),
        rows.iter()
            .map(|row| visible_width(&row.after))
            .max()
            .unwrap_or_else(|| visible_width("After"))
            .max(visible_width("After"))
            .min(16),
        rows.iter()
            .map(|row| visible_width(&row.result))
            .max()
            .unwrap_or_else(|| visible_width("Result"))
            .max(visible_width("Result")),
        rows.iter()
            .map(|row| visible_width(&row.note))
            .max()
            .unwrap_or_else(|| visible_width("Notes"))
            .max(visible_width("Notes"))
            .min(34),
    ];
    let minimum_widths = [5, 6, 10, 8, 8, 7, 12];
    let widths = allocate_box_table_widths(&preferred_widths, &minimum_widths, target_width);
    let [group_w, task_w, item_w, before_w, after_w, result_w, notes_w] = widths;

    lines.push(RenderedReportLine {
        text: render_box_separator(
            '┌',
            '┬',
            '┐',
            &[
                group_w, task_w, item_w, before_w, after_w, result_w, notes_w,
            ],
        ),
        level: LogLevel::Info,
    });
    lines.push(RenderedReportLine {
        text: render_box_row(
            &[
                BoxCell::plain("Group", group_w),
                BoxCell::plain("Task", task_w),
                BoxCell::plain("Item", item_w),
                BoxCell::plain("Before", before_w),
                BoxCell::plain("After", after_w),
                BoxCell::plain("Result", result_w),
                BoxCell::plain("Notes", notes_w),
            ],
            color,
        ),
        level: LogLevel::Info,
    });
    lines.push(RenderedReportLine {
        text: render_box_separator(
            '├',
            '┼',
            '┤',
            &[
                group_w, task_w, item_w, before_w, after_w, result_w, notes_w,
            ],
        ),
        level: LogLevel::Info,
    });

    for row in rows {
        let level = report_status_level(row.status);
        let (group_text, group_overflow) = fit_visible(&row.category, group_w);
        let (task_text, task_overflow) = fit_visible(&row.task, task_w);
        let (item_text, item_overflow) = fit_visible(&row.item, item_w);
        let (before_text, before_overflow) = fit_visible(&row.before, before_w);
        let (after_text, after_overflow) = fit_visible(&row.after, after_w);
        let (note_text, note_overflow) = fit_visible(&row.note, notes_w);
        let color_enabled = color_output_enabled(color);
        let (before_color, after_color) = if color_enabled {
            package_rollup_value_colors(&row)
        } else {
            (None, None)
        };

        lines.push(RenderedReportLine {
            text: render_box_row(
                &[
                    BoxCell::plain(&group_text, group_w),
                    BoxCell::plain(&task_text, task_w),
                    BoxCell::plain(&item_text, item_w),
                    BoxCell {
                        text: before_text,
                        color: before_color,
                        width: before_w,
                    },
                    BoxCell {
                        text: after_text,
                        color: after_color,
                        width: after_w,
                    },
                    BoxCell {
                        text: row.result.clone(),
                        color: if color_enabled {
                            package_rollup_result_color(&row)
                        } else {
                            None
                        },
                        width: result_w,
                    },
                    BoxCell::plain(&note_text, notes_w),
                ],
                color,
            ),
            level,
        });

        if !debug_report {
            continue;
        }
        for (label, overflowed, full) in [
            ("group", group_overflow, row.category.as_str()),
            ("task", task_overflow, row.task.as_str()),
            ("item", item_overflow, row.item.as_str()),
            ("before", before_overflow, row.before.as_str()),
            ("after", after_overflow, row.after.as_str()),
            ("notes", note_overflow, row.note.as_str()),
        ] {
            if overflowed
                && should_render_inline_note(InlineNoteKind::Overflow, row.status, note_verbosity)
            {
                lines.push(RenderedReportLine {
                    text: format!(
                        "  [{}] continued {label}: {full}",
                        if color_output_enabled(color) {
                            row.status.ansi_tag().to_string()
                        } else {
                            row.status.plain_tag().to_string()
                        },
                        full = sanitize_report_cell_text(full),
                    ),
                    level,
                });
            }
        }
    }

    lines.push(RenderedReportLine {
        text: render_box_separator(
            '└',
            '┴',
            '┘',
            &[
                group_w, task_w, item_w, before_w, after_w, result_w, notes_w,
            ],
        ),
        level: LogLevel::Info,
    });

    lines
}

fn package_rollup_value_colors(
    row: &PackageChangeRow,
) -> (
    Option<crossterm::style::Color>,
    Option<crossterm::style::Color>,
) {
    if report_values_are_version_change(&row.before, &row.after) {
        return (
            Some(crossterm::style::Color::Red),
            Some(crossterm::style::Color::Green),
        );
    }

    (None, None)
}

fn package_rollup_result_color(row: &PackageChangeRow) -> Option<crossterm::style::Color> {
    if row.status == TaskReportStatus::Unchanged {
        return None;
    }
    Some(report_status_color(row.status))
}

fn render_final_task_overview<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    task_categories: &BTreeMap<String, String>,
    color: bool,
    note_verbosity: NoteVerbosity,
    debug_report: bool,
) -> Vec<RenderedReportLine> {
    let mut rows: Vec<FinalTaskRow> = ordered_task_results(summary, task_categories)
        .into_iter()
        .map(|entry| FinalTaskRow {
            category: entry.category,
            task: entry.label,
            status: entry.result.status,
            has_issues: entry.result.has_issues(),
            deferred: entry.result.is_deferred(),
            items: summarize_task_items(entry.result),
            notes: summarize_task_notes(entry.result),
        })
        .collect();

    if rows.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![RenderedReportLine {
        text: String::new(),
        level: LogLevel::Info,
    }];
    lines.push(RenderedReportLine {
        text: "Final Task Overview".to_string(),
        level: LogLevel::Info,
    });

    let preferred_widths = [
        rows.iter()
            .map(|row| visible_width(&row.category))
            .max()
            .unwrap_or_else(|| visible_width("Group"))
            .max(visible_width("Group"))
            .min(TASK_CATEGORY_COLUMN_MAX_WIDTH),
        rows.iter()
            .map(|row| visible_width(&row.task))
            .max()
            .unwrap_or_else(|| visible_width("Task"))
            .max(visible_width("Task"))
            .min(28),
        rows.iter()
            .map(|row| {
                visible_width(task_status_cell_from_parts(
                    row.status,
                    row.has_issues,
                    row.deferred,
                ))
            })
            .max()
            .unwrap_or_else(|| visible_width("Outcome"))
            .max(visible_width("Outcome")),
        rows.iter()
            .map(|row| visible_width(&row.items))
            .max()
            .unwrap_or_else(|| visible_width("Items"))
            .max(visible_width("Items"))
            .min(24),
        rows.iter()
            .map(|row| visible_width(&row.notes))
            .max()
            .unwrap_or_else(|| visible_width("Notes"))
            .max(visible_width("Notes"))
            .min(36),
    ];
    let minimum_widths = [5, 8, 7, 10, 12];
    let widths = allocate_box_table_widths(
        &preferred_widths,
        &minimum_widths,
        report_table_target_width(),
    );
    let [category_w, task_w, outcome_w, items_w, notes_w] = widths;

    lines.push(RenderedReportLine {
        text: render_box_separator(
            '┌',
            '┬',
            '┐',
            &[category_w, task_w, outcome_w, items_w, notes_w],
        ),
        level: LogLevel::Info,
    });
    lines.push(RenderedReportLine {
        text: render_box_row(
            &[
                BoxCell::plain("Group", category_w),
                BoxCell::plain("Task", task_w),
                BoxCell::plain("Outcome", outcome_w),
                BoxCell::plain("Items", items_w),
                BoxCell::plain("Notes", notes_w),
            ],
            color,
        ),
        level: LogLevel::Info,
    });
    lines.push(RenderedReportLine {
        text: render_box_separator(
            '├',
            '┼',
            '┤',
            &[category_w, task_w, outcome_w, items_w, notes_w],
        ),
        level: LogLevel::Info,
    });

    for row in rows {
        let level = task_status_level_from_parts(row.status, row.has_issues);
        let (category_text, category_overflow) = fit_visible(&row.category, category_w);
        let (task_text, task_overflow) = fit_visible(&row.task, task_w);
        let (items_text, items_overflow) = fit_visible(&row.items, items_w);
        let (notes_text, notes_overflow) = fit_visible(&row.notes, notes_w);
        let color_enabled = color_output_enabled(color);
        lines.push(RenderedReportLine {
            text: render_box_row(
                &[
                    BoxCell::plain(&category_text, category_w),
                    BoxCell::plain(&task_text, task_w),
                    BoxCell {
                        text: task_status_cell_from_parts(row.status, row.has_issues, row.deferred)
                            .to_string(),
                        color: color_enabled
                            .then_some(task_status_color_from_parts(row.status, row.has_issues)),
                        width: outcome_w,
                    },
                    BoxCell::plain(&items_text, items_w),
                    BoxCell::plain(&notes_text, notes_w),
                ],
                color,
            ),
            level,
        });
        if debug_report
            && category_overflow
            && should_render_task_status_note(row.status, note_verbosity, InlineNoteKind::Overflow)
        {
            lines.push(RenderedReportLine {
                text: format!(
                    "  [{}] continued group: {}",
                    task_status_tag_from_parts(row.status, row.has_issues, color),
                    sanitize_report_cell_text(&row.category)
                ),
                level,
            });
        }
        if debug_report
            && task_overflow
            && should_render_task_status_note(row.status, note_verbosity, InlineNoteKind::Overflow)
        {
            lines.push(RenderedReportLine {
                text: format!(
                    "  [{}] continued task: {}",
                    task_status_tag_from_parts(row.status, row.has_issues, color),
                    sanitize_report_cell_text(&row.task)
                ),
                level,
            });
        }
        if debug_report
            && items_overflow
            && should_render_task_status_note(row.status, note_verbosity, InlineNoteKind::Overflow)
        {
            lines.push(RenderedReportLine {
                text: format!(
                    "  [{}] continued items: {}",
                    task_status_tag_from_parts(row.status, row.has_issues, color),
                    sanitize_report_cell_text(&row.items)
                ),
                level,
            });
        }
        if debug_report
            && notes_overflow
            && should_render_task_status_note(row.status, note_verbosity, InlineNoteKind::Overflow)
        {
            lines.push(RenderedReportLine {
                text: format!(
                    "  [{}] continued notes: {}",
                    task_status_tag_from_parts(row.status, row.has_issues, color),
                    sanitize_report_cell_text(&row.notes)
                ),
                level,
            });
        }
    }
    lines.push(RenderedReportLine {
        text: render_box_separator(
            '└',
            '┴',
            '┘',
            &[category_w, task_w, outcome_w, items_w, notes_w],
        ),
        level: LogLevel::Info,
    });

    lines
}

fn render_attention_required<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    task_categories: &BTreeMap<String, String>,
    color: bool,
) -> Vec<RenderedReportLine> {
    let rows = attention_rows(summary, task_categories);
    if rows.is_empty() {
        return Vec::new();
    }

    let preferred_widths = [
        rows.iter()
            .map(|row| visible_width(&row.task))
            .max()
            .unwrap_or_else(|| visible_width("Task"))
            .max(visible_width("Task"))
            .min(22),
        rows.iter()
            .map(|row| visible_width(advisory_severity_label(row.severity)))
            .max()
            .unwrap_or_else(|| visible_width("Severity"))
            .max(visible_width("Severity")),
        rows.iter()
            .map(|row| visible_width(&row.issue))
            .max()
            .unwrap_or_else(|| visible_width("Issue"))
            .max(visible_width("Issue"))
            .min(48),
        rows.iter()
            .map(|row| visible_width(&row.action))
            .max()
            .unwrap_or_else(|| visible_width("Action"))
            .max(visible_width("Action"))
            .min(48),
    ];
    let minimum_widths = [8, 8, 16, 16];
    let widths = allocate_box_table_widths(
        &preferred_widths,
        &minimum_widths,
        report_table_target_width(),
    );
    let [task_w, severity_w, issue_w, action_w] = widths;

    let mut lines = vec![RenderedReportLine {
        text: String::new(),
        level: LogLevel::Warn,
    }];
    lines.push(RenderedReportLine {
        text: "Needs Attention".to_string(),
        level: LogLevel::Warn,
    });
    lines.push(RenderedReportLine {
        text: format_report_row(&[
            ("Task", None, task_w),
            ("Severity", None, severity_w),
            ("Issue", None, issue_w),
            ("Action", None, action_w),
        ]),
        level: LogLevel::Warn,
    });

    let color_enabled = color_output_enabled(color);
    for row in rows {
        let severity = advisory_severity_label(row.severity);
        let severity_color = color_enabled.then_some(advisory_severity_color(row.severity));
        let (row_text, overflow_notes) = format_table_row(&[
            TableCell {
                text: &row.task,
                color: None,
                width: task_w,
                overflow_label: Some("task"),
            },
            TableCell {
                text: severity,
                color: severity_color,
                width: severity_w,
                overflow_label: None,
            },
            TableCell {
                text: &row.issue,
                color: None,
                width: issue_w,
                overflow_label: Some("issue"),
            },
            TableCell {
                text: &row.action,
                color: None,
                width: action_w,
                overflow_label: Some("action"),
            },
        ]);
        let level = advisory_severity_level(row.severity);
        lines.push(RenderedReportLine {
            text: row_text,
            level,
        });
        for note in overflow_notes {
            lines.push(RenderedReportLine {
                text: format!(
                    "  {} {}",
                    advisory_severity_prefix(row.severity, color),
                    note
                ),
                level,
            });
        }
    }

    lines
}

fn attention_rows<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    task_categories: &BTreeMap<String, String>,
) -> Vec<AttentionRow> {
    let mut rows = Vec::new();
    for entry in ordered_task_results(summary, task_categories) {
        let mut emitted = false;
        for advisory in &entry.result.advisories {
            if advisory.severity == AdvisorySeverity::Info {
                continue;
            }
            emitted = true;
            rows.push(AttentionRow {
                task: sanitize_report_cell_text(&entry.label),
                severity: advisory.severity,
                issue: sanitize_report_cell_text(&advisory.summary),
                action: sanitize_report_cell_text(&advisory.remediation),
            });
        }

        for section in &entry.result.report_sections {
            for row in &section.rows {
                let severity = match row.status {
                    TaskReportStatus::Failed => AdvisorySeverity::Error,
                    TaskReportStatus::Blocked => AdvisorySeverity::Warning,
                    _ => continue,
                };
                emitted = true;
                rows.push(AttentionRow {
                    task: sanitize_report_cell_text(&entry.label),
                    severity,
                    issue: sanitize_report_cell_text(&format!("{}: {}", section.title, row.name)),
                    action: sanitize_report_cell_text(&render_per_task_row_notes(
                        &section.key,
                        row,
                    )),
                });
            }
        }

        if !emitted
            && matches!(
                entry.result.status,
                TaskStatus::Failed | TaskStatus::Canceled
            )
        {
            rows.push(AttentionRow {
                task: sanitize_report_cell_text(&entry.label),
                severity: AdvisorySeverity::Error,
                issue: sanitize_report_cell_text(&entry.result.primary_detail()),
                action: "check task log".to_string(),
            });
        }
    }
    rows
}

fn advisory_severity_label(severity: AdvisorySeverity) -> &'static str {
    match severity {
        AdvisorySeverity::Info => "Info",
        AdvisorySeverity::Warning => "Warning",
        AdvisorySeverity::Error => "Error",
    }
}

fn advisory_severity_level(severity: AdvisorySeverity) -> LogLevel {
    match severity {
        AdvisorySeverity::Info => LogLevel::Info,
        AdvisorySeverity::Warning => LogLevel::Warn,
        AdvisorySeverity::Error => LogLevel::Error,
    }
}

fn advisory_severity_color(severity: AdvisorySeverity) -> crossterm::style::Color {
    match severity {
        AdvisorySeverity::Info => crossterm::style::Color::Cyan,
        AdvisorySeverity::Warning => blocked_report_color(),
        AdvisorySeverity::Error => crossterm::style::Color::Red,
    }
}

fn advisory_severity_prefix(severity: AdvisorySeverity, color: bool) -> String {
    let label = advisory_severity_label(severity);
    if color_output_enabled(color) {
        format!(
            "[{}]",
            colorize_report_cell(label, advisory_severity_color(severity))
        )
    } else {
        format!("[{label}]")
    }
}

fn render_package_rollup_note(section_key: &str, row: &TaskReportRow) -> String {
    row.note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| match (section_key, row.status) {
            ("completion_audit", TaskReportStatus::Passed) => String::new(),
            ("completion_audit", status) => {
                report_status_note_label(section_key, status).to_string()
            }
            ("completion_generation", TaskReportStatus::Updated) => String::new(),
            ("completion_generation", TaskReportStatus::Refreshed) => "refreshed".to_string(),
            ("completion_generation", TaskReportStatus::Unchanged) => "unchanged".to_string(),
            ("completion_generation", TaskReportStatus::Skipped) => "skipped".to_string(),
            (_, TaskReportStatus::Updated) => String::new(),
            (_, TaskReportStatus::Refreshed) => "refreshed".to_string(),
            (_, TaskReportStatus::Passed) => "passed".to_string(),
            (_, TaskReportStatus::Unchanged) => "unchanged".to_string(),
            (_, TaskReportStatus::Blocked) => "blocked".to_string(),
            (_, TaskReportStatus::Skipped) => "skipped".to_string(),
            (_, TaskReportStatus::Failed) => "failed".to_string(),
            (_, TaskReportStatus::Info) => "info".to_string(),
        })
}

fn render_per_task_changes<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    task_categories: &BTreeMap<String, String>,
    color: bool,
    note_verbosity: NoteVerbosity,
    debug_report: bool,
) -> Vec<RenderedReportLine> {
    let entries = ordered_task_results(summary, task_categories);
    if entries.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![RenderedReportLine {
        text: String::new(),
        level: LogLevel::Info,
    }];
    lines.push(RenderedReportLine {
        text: "Per-Task Changes".to_string(),
        level: LogLevel::Info,
    });

    for entry in entries {
        let level = task_status_level_from_parts(entry.result.status, entry.result.has_issues());
        lines.push(RenderedReportLine {
            text: if debug_report {
                format!(
                    "[{}] {} ({})",
                    task_status_tag_from_parts(
                        entry.result.status,
                        entry.result.has_issues(),
                        color,
                    ),
                    entry.label,
                    entry.category
                )
            } else {
                format!("{} ({})", entry.label, entry.category)
            },
            level,
        });
        if entry.result.report_sections.is_empty() {
            let detail = entry
                .result
                .details
                .iter()
                .find(|detail| !detail.trim().is_empty())
                .map(String::as_str)
                .unwrap_or("No changes reported.");
            lines.push(RenderedReportLine {
                text: format!("  {detail}"),
                level,
            });
            continue;
        }

        for section in &entry.result.report_sections {
            if section.rows.is_empty() {
                continue;
            }
            lines.push(RenderedReportLine {
                text: format!("  {}", section.title),
                level: LogLevel::Info,
            });
            let (item_header, before_header, after_header, notes_header) =
                report_headers_for_section(&section.key);
            let (before_cap, after_cap) = report_value_width_caps_for_section(&section.key);
            let item_w = section
                .rows
                .iter()
                .map(|row| visible_width(&row.name))
                .max()
                .unwrap_or_else(|| visible_width(item_header))
                .max(visible_width(item_header))
                .min(28);
            let before_w = section
                .rows
                .iter()
                .map(|row| {
                    let (before, _) = report_row_display_values(row);
                    visible_width(&before)
                })
                .max()
                .unwrap_or_else(|| visible_width(before_header))
                .max(visible_width(before_header))
                .min(before_cap);
            let after_w = section
                .rows
                .iter()
                .map(|row| {
                    let (_, after) = report_row_display_values(row);
                    visible_width(&after)
                })
                .max()
                .unwrap_or_else(|| visible_width(after_header))
                .max(visible_width(after_header))
                .min(after_cap);
            let notes_w = section
                .rows
                .iter()
                .map(|row| visible_width(&render_per_task_row_notes(&section.key, row)))
                .max()
                .unwrap_or_else(|| visible_width(notes_header))
                .max(visible_width(notes_header))
                .min(report_notes_width_cap_for_section(&section.key, 40));
            lines.push(RenderedReportLine {
                text: format!(
                    "  {}",
                    format_report_row(&[
                        (item_header, None, item_w),
                        (before_header, None, before_w),
                        (after_header, None, after_w),
                        (notes_header, None, notes_w),
                    ])
                ),
                level: LogLevel::Info,
            });

            for row in &section.rows {
                let notes = render_per_task_row_notes(&section.key, row);
                let (before, after) = report_row_display_values(row);
                let color_enabled = color_output_enabled(color);
                let value_change = report_row_has_value_change(row);
                let before_color = if color_enabled && value_change {
                    Some(crossterm::style::Color::Red)
                } else {
                    None
                };
                let after_color = if color_enabled && value_change {
                    Some(crossterm::style::Color::Green)
                } else {
                    None
                };
                let notes_color = if color_enabled {
                    report_status_color_for_row(&section.key, row)
                } else {
                    None
                };
                let (row_text, overflow_notes) = format_table_row(&[
                    TableCell {
                        text: &row.name,
                        color: None,
                        width: item_w,
                        overflow_label: Some("item"),
                    },
                    TableCell {
                        text: &before,
                        color: before_color,
                        width: before_w,
                        overflow_label: Some("before"),
                    },
                    TableCell {
                        text: &after,
                        color: after_color,
                        width: after_w,
                        overflow_label: Some("after"),
                    },
                    TableCell {
                        text: &notes,
                        color: notes_color,
                        width: notes_w,
                        overflow_label: Some("notes"),
                    },
                ]);
                lines.push(RenderedReportLine {
                    text: format!("  {row_text}"),
                    level: report_status_level(row.status),
                });
                for note in overflow_notes {
                    if !debug_report
                        || !should_render_inline_note(
                            InlineNoteKind::Overflow,
                            row.status,
                            note_verbosity,
                        )
                    {
                        continue;
                    }
                    lines.push(RenderedReportLine {
                        text: format!(
                            "    {} {}",
                            render_report_note_prefix_for_row(&section.key, row, color),
                            note
                        ),
                        level: report_status_level(row.status),
                    });
                }
                if let Some(note) = row.note.as_deref() {
                    let kind = classify_row_note_kind(&section.key, row.status);
                    if debug_report && should_render_inline_note(kind, row.status, note_verbosity) {
                        lines.push(RenderedReportLine {
                            text: format!(
                                "    {} {}",
                                render_report_note_prefix_for_row(&section.key, row, color),
                                sanitize_report_cell_text(note)
                            ),
                            level: report_status_level(row.status),
                        });
                    }
                }
            }
        }
    }

    lines
}

fn render_update_details<'a>(
    summary: impl IntoIterator<Item = (&'a str, &'a TaskResult)>,
    color: bool,
    note_verbosity: NoteVerbosity,
) -> Vec<RenderedReportLine> {
    let mut sections: Vec<(String, String, Vec<(String, &'a TaskReportRow)>)> = Vec::new();
    for (_, result) in summary {
        for section in &result.report_sections {
            let updated_rows = section
                .rows
                .iter()
                .filter(|row| {
                    row.status == TaskReportStatus::Updated && section.key != "completion_audit"
                })
                .map(|row| (result.label.clone(), row))
                .collect::<Vec<_>>();
            if updated_rows.is_empty() {
                continue;
            }
            if let Some((_, _, rows)) = sections
                .iter_mut()
                .find(|(key, title, _)| *key == section.key && *title == section.title)
            {
                rows.extend(updated_rows);
            } else {
                sections.push((section.key.clone(), section.title.clone(), updated_rows));
            }
        }
    }

    if sections.is_empty() {
        return Vec::new();
    }

    let mut lines = vec![RenderedReportLine {
        text: String::new(),
        level: LogLevel::Info,
    }];
    lines.push(RenderedReportLine {
        text: "Update Details".to_string(),
        level: LogLevel::Info,
    });

    for (key, title, rows) in sections {
        lines.push(RenderedReportLine {
            text: title,
            level: LogLevel::Info,
        });
        let task_header = "Task";
        let (item_header, before_header, after_header, notes_header) =
            report_headers_for_section(&key);
        let (before_cap, after_cap) = report_value_width_caps_for_section(&key);
        let task_w = rows
            .iter()
            .map(|(task, _)| visible_width(task))
            .max()
            .unwrap_or_else(|| visible_width(task_header))
            .max(visible_width(task_header))
            .min(22);
        let item_w = rows
            .iter()
            .map(|(_, row)| visible_width(&row.name))
            .max()
            .unwrap_or_else(|| visible_width(item_header))
            .max(visible_width(item_header))
            .min(28);
        let before_w = rows
            .iter()
            .map(|(_, row)| visible_width(row.before.as_deref().unwrap_or("-")))
            .max()
            .unwrap_or_else(|| visible_width(before_header))
            .max(visible_width(before_header))
            .min(before_cap);
        let after_w = rows
            .iter()
            .map(|(_, row)| visible_width(row.after.as_deref().unwrap_or("-")))
            .max()
            .unwrap_or_else(|| visible_width(after_header))
            .max(visible_width(after_header))
            .min(after_cap);
        let notes_w = rows
            .iter()
            .map(|(_, row)| visible_width(&render_update_details_notes(&key, row)))
            .max()
            .unwrap_or_else(|| visible_width(notes_header))
            .max(visible_width(notes_header))
            .min(report_notes_width_cap_for_section(&key, 36));
        lines.push(RenderedReportLine {
            text: format_report_row(&[
                (task_header, None, task_w),
                (item_header, None, item_w),
                (before_header, None, before_w),
                (after_header, None, after_w),
                (notes_header, None, notes_w),
            ]),
            level: LogLevel::Info,
        });
        for (task_label, row) in rows {
            let notes = render_update_details_notes(&key, row);
            let before = row.before.as_deref().unwrap_or("-");
            let after = row.after.as_deref().unwrap_or("-");
            let color_enabled = color_output_enabled(color);
            let value_change = report_row_has_value_change(row);
            let before_color = if color_enabled && value_change {
                Some(crossterm::style::Color::Red)
            } else {
                None
            };
            let after_color = if color_enabled && value_change {
                Some(crossterm::style::Color::Green)
            } else {
                None
            };
            let (row_text, overflow_notes) = format_table_row(&[
                TableCell {
                    text: &task_label,
                    color: None,
                    width: task_w,
                    overflow_label: Some("task"),
                },
                TableCell {
                    text: &row.name,
                    color: None,
                    width: item_w,
                    overflow_label: Some("item"),
                },
                TableCell {
                    text: before,
                    color: before_color,
                    width: before_w,
                    overflow_label: Some("before"),
                },
                TableCell {
                    text: after,
                    color: after_color,
                    width: after_w,
                    overflow_label: Some("after"),
                },
                TableCell {
                    text: &notes,
                    color: None,
                    width: notes_w,
                    overflow_label: Some("notes"),
                },
            ]);
            lines.push(RenderedReportLine {
                text: row_text,
                level: LogLevel::Info,
            });
            for note in overflow_notes {
                if !should_render_inline_note(InlineNoteKind::Overflow, row.status, note_verbosity)
                {
                    continue;
                }
                lines.push(RenderedReportLine {
                    text: format!(
                        "  {} {}",
                        render_report_note_prefix(row.status, color),
                        note
                    ),
                    level: report_status_level(row.status),
                });
            }
        }
    }

    lines
}

fn report_headers_for_section(
    key: &str,
) -> (&'static str, &'static str, &'static str, &'static str) {
    match key {
        "arch_update_services" => ("Service", "Before", "After", "Result"),
        "package_recovery" | "yay_recovery" => ("Item", "Before", "After", "Result"),
        "task_failures" => ("Task", "Before", "After", "Outcome"),
        "completion_generation" => ("Tool", "Provider", "Artifact", "Outcome"),
        "completion_audit" => ("Check", "Code", "Detail", "Outcome"),
        _ => ("Package", "Before", "After", "Outcome"),
    }
}

fn report_value_width_caps_for_section(key: &str) -> (usize, usize) {
    match key {
        "completion_generation" => (16, 72),
        "completion_audit" => (24, 72),
        _ => (16, 16),
    }
}

fn report_notes_width_cap_for_section(key: &str, default: usize) -> usize {
    match key {
        "completion_generation" => 32,
        "completion_audit" => 56,
        _ => default,
    }
}

fn render_per_task_row_notes(section_key: &str, row: &TaskReportRow) -> String {
    let status = report_status_note_label_for_row(section_key, row);
    match row
        .note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty())
    {
        Some(note) if note.eq_ignore_ascii_case(status) => status.to_string(),
        Some(note) => format!("{status}: {note}"),
        None => status.to_string(),
    }
}

fn render_update_details_notes(section_key: &str, row: &TaskReportRow) -> String {
    let note = row
        .note
        .as_deref()
        .map(str::trim)
        .filter(|note| !note.is_empty());
    if section_key == "completion_generation" {
        let status = report_status_note_label_for_row(section_key, row);
        return match note {
            Some(note) if note.eq_ignore_ascii_case(status) => status.to_string(),
            Some(note) => format!("{status}: {note}"),
            None => status.to_string(),
        };
    }
    note.map(str::to_string)
        .unwrap_or_else(|| report_status_note_label(section_key, row.status).to_string())
}

fn report_status_cell_for_row(key: &str, row: &TaskReportRow) -> &'static str {
    match (key, row.status) {
        ("completion_generation", TaskReportStatus::Updated) => "Generated",
        ("completion_generation", TaskReportStatus::Refreshed) => "Refreshed",
        ("completion_generation", TaskReportStatus::Unchanged) => "Unchanged",
        ("completion_generation", TaskReportStatus::Skipped) => "Skipped",
        ("completion_generation", TaskReportStatus::Blocked) => "Blocked",
        ("completion_generation", TaskReportStatus::Failed) => "Error",
        ("completion_generation", TaskReportStatus::Passed) => "Passed",
        ("completion_generation", TaskReportStatus::Info) => "Info",
        _ => report_status_cell(key, row.status),
    }
}

fn report_status_cell(key: &str, status: TaskReportStatus) -> &'static str {
    match key {
        "package_recovery" | "yay_recovery" => match status {
            TaskReportStatus::Updated => "Recovered",
            TaskReportStatus::Refreshed => "Refreshed",
            TaskReportStatus::Passed => "Passed",
            TaskReportStatus::Unchanged => "Unchanged",
            TaskReportStatus::Blocked => "Blocked",
            TaskReportStatus::Skipped => "Removed",
            TaskReportStatus::Failed => "Error",
            TaskReportStatus::Info => "Info",
        },
        "arch_update_services" => match status {
            TaskReportStatus::Updated => "Restarted",
            TaskReportStatus::Refreshed => "Refreshed",
            TaskReportStatus::Passed => "Passed",
            TaskReportStatus::Unchanged => "No Restart",
            TaskReportStatus::Blocked => "Blocked",
            TaskReportStatus::Skipped => "Not Restarted",
            TaskReportStatus::Failed => "Error",
            TaskReportStatus::Info => "Info",
        },
        "completion_audit" => match status {
            TaskReportStatus::Passed => "Pass",
            TaskReportStatus::Updated => "Updated",
            TaskReportStatus::Refreshed => "Refreshed",
            TaskReportStatus::Unchanged => "Unchanged",
            TaskReportStatus::Blocked => "Warn",
            TaskReportStatus::Skipped => "Skip",
            TaskReportStatus::Failed => "Fail",
            TaskReportStatus::Info => "Info",
        },
        _ => match status {
            TaskReportStatus::Updated => "Updated",
            TaskReportStatus::Refreshed => "Refreshed",
            TaskReportStatus::Passed => "Passed",
            TaskReportStatus::Unchanged => "Unchanged",
            TaskReportStatus::Blocked => "Blocked",
            TaskReportStatus::Skipped => "Skipped",
            TaskReportStatus::Failed => "Error",
            TaskReportStatus::Info => "Info",
        },
    }
}

fn report_status_note_label_for_row(section_key: &str, row: &TaskReportRow) -> &'static str {
    match (section_key, row.status) {
        ("completion_generation", TaskReportStatus::Updated) => "generated",
        ("completion_generation", TaskReportStatus::Refreshed) => "refreshed",
        ("completion_generation", TaskReportStatus::Unchanged) => "unchanged",
        ("completion_generation", TaskReportStatus::Skipped) => "skipped",
        _ => report_status_note_label(section_key, row.status),
    }
}

fn report_status_note_label(section_key: &str, status: TaskReportStatus) -> &'static str {
    match (section_key, status) {
        ("completion_audit", TaskReportStatus::Passed) => "pass",
        ("completion_audit", TaskReportStatus::Blocked) => "warn",
        ("completion_audit", TaskReportStatus::Skipped) => "skip",
        ("completion_audit", TaskReportStatus::Failed) => "fail",
        ("arch_update_services", TaskReportStatus::Updated) => "restarted",
        ("arch_update_services", TaskReportStatus::Refreshed) => "refreshed",
        ("arch_update_services", TaskReportStatus::Unchanged) => "no restart",
        ("arch_update_services", TaskReportStatus::Skipped) => "not restarted",
        ("arch_update_services", TaskReportStatus::Failed) => "restart failed",
        (_, TaskReportStatus::Updated) => "updated",
        (_, TaskReportStatus::Refreshed) => "refreshed",
        (_, TaskReportStatus::Passed) => "passed",
        (_, TaskReportStatus::Unchanged) => "unchanged",
        (_, TaskReportStatus::Blocked) => "blocked",
        (_, TaskReportStatus::Skipped) => "skipped",
        (_, TaskReportStatus::Failed) => "failed",
        (_, TaskReportStatus::Info) => "info",
    }
}

fn render_report_note_prefix_for_row(
    _section_key: &str,
    row: &TaskReportRow,
    color: bool,
) -> String {
    render_report_note_prefix(row.status, color)
}

fn render_report_note_prefix(status: TaskReportStatus, color: bool) -> String {
    let tag = if color_output_enabled(color) {
        status.ansi_tag().to_string()
    } else {
        status.plain_tag().to_string()
    };
    format!("[{tag}]")
}

fn colorize_report_cell(input: &str, color: crossterm::style::Color) -> String {
    let code = match color {
        crossterm::style::Color::Red => "31",
        crossterm::style::Color::Green => "32",
        crossterm::style::Color::Yellow => "33",
        crossterm::style::Color::Cyan => "36",
        crossterm::style::Color::Rgb { r, g, b } => {
            return format!("\x1b[1;38;2;{r};{g};{b}m{input}\x1b[0m");
        }
        _ => "37",
    };
    format!("\x1b[1;{code}m{input}\x1b[0m")
}

fn report_status_color_for_row(
    _section_key: &str,
    row: &TaskReportRow,
) -> Option<crossterm::style::Color> {
    if row.status == TaskReportStatus::Unchanged {
        return None;
    }
    Some(report_status_color(row.status))
}

fn report_status_color(status: TaskReportStatus) -> crossterm::style::Color {
    match status {
        TaskReportStatus::Updated => crossterm::style::Color::Green,
        TaskReportStatus::Refreshed => crossterm::style::Color::Cyan,
        TaskReportStatus::Passed => crossterm::style::Color::Green,
        TaskReportStatus::Unchanged => crossterm::style::Color::Cyan,
        TaskReportStatus::Blocked => blocked_report_color(),
        TaskReportStatus::Skipped => crossterm::style::Color::Yellow,
        TaskReportStatus::Failed => crossterm::style::Color::Red,
        TaskReportStatus::Info => crossterm::style::Color::Cyan,
    }
}

fn blocked_report_color() -> crossterm::style::Color {
    crossterm::style::Color::Rgb {
        r: 255,
        g: 165,
        b: 0,
    }
}

fn report_status_level(status: TaskReportStatus) -> LogLevel {
    match status {
        TaskReportStatus::Failed => LogLevel::Error,
        TaskReportStatus::Blocked => LogLevel::Warn,
        TaskReportStatus::Info => LogLevel::Info,
        TaskReportStatus::Updated
        | TaskReportStatus::Refreshed
        | TaskReportStatus::Passed
        | TaskReportStatus::Unchanged
        | TaskReportStatus::Skipped => LogLevel::Info,
    }
}

fn format_table_row(cells: &[TableCell<'_>]) -> (String, Vec<String>) {
    let mut overflow_notes = Vec::new();
    let text = cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| {
            let (plain, truncated) = fit_visible(cell.text, cell.width);
            if truncated {
                if let Some(label) = cell.overflow_label {
                    overflow_notes.push(format!(
                        "full {label}: {}",
                        sanitize_report_cell_text(cell.text)
                    ));
                }
            }
            let rendered = match cell.color {
                Some(color) => colorize_report_cell(&plain, color),
                None => plain,
            };
            if idx + 1 == cells.len() {
                rendered
            } else {
                format!("{rendered}  ")
            }
        })
        .collect();
    (text, overflow_notes)
}

fn format_report_row(cells: &[(&str, Option<crossterm::style::Color>, usize)]) -> String {
    cells
        .iter()
        .enumerate()
        .map(|(idx, (text, color, width))| {
            let plain = pad_visible(text, *width);
            let cell = match color {
                Some(color) => colorize_report_cell(&plain, *color),
                None => plain,
            };
            if idx + 1 == cells.len() {
                cell
            } else {
                format!("{cell}  ")
            }
        })
        .collect()
}

fn render_box_separator(left: char, mid: char, right: char, widths: &[usize]) -> String {
    let mut out = String::new();
    out.push(left);
    for (idx, width) in widths.iter().enumerate() {
        out.push_str(&"─".repeat(width.saturating_add(2)));
        if idx + 1 == widths.len() {
            out.push(right);
        } else {
            out.push(mid);
        }
    }
    out
}

fn render_box_row(cells: &[BoxCell], color: bool) -> String {
    let color_enabled = color_output_enabled(color);
    let mut out = String::from("│");
    for cell in cells {
        out.push(' ');
        let (plain, _) = fit_visible(&cell.text, cell.width);
        let rendered = match (color_enabled, cell.color) {
            (true, Some(color)) => colorize_report_cell(&plain, color),
            _ => plain,
        };
        out.push_str(&rendered);
        out.push(' ');
        out.push('│');
    }
    out
}

fn report_table_target_width() -> usize {
    std::env::var("UPDATE_ALL_REPORT_WIDTH")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|width| *width >= 40)
        .or_else(|| {
            std::io::stdout()
                .is_terminal()
                .then(|| {
                    crossterm::terminal::size()
                        .ok()
                        .map(|(width, _)| width as usize)
                })
                .flatten()
                .filter(|width| *width >= 40)
        })
        .unwrap_or(120)
}

fn allocate_box_table_widths<const N: usize>(
    preferred: &[usize; N],
    minimums: &[usize; N],
    target_width: usize,
) -> [usize; N] {
    let mut widths = *preferred;
    let target = target_width.max(box_table_width(minimums));

    while box_table_width(&widths) > target {
        let Some((idx, _)) = widths
            .iter()
            .enumerate()
            .filter(|(idx, width)| **width > minimums[*idx])
            .max_by_key(|(_, width)| **width)
        else {
            break;
        };
        widths[idx] -= 1;
    }

    widths
}

fn box_table_width(widths: &[usize]) -> usize {
    widths.iter().sum::<usize>() + (3 * widths.len()) + 1
}

fn report_row_has_value_change(row: &TaskReportRow) -> bool {
    let (before, after) = report_row_display_values(row);
    report_values_are_version_change(&before, &after)
}

fn classify_row_note_kind(section_key: &str, status: TaskReportStatus) -> InlineNoteKind {
    match status {
        TaskReportStatus::Failed => InlineNoteKind::Failure,
        TaskReportStatus::Blocked => InlineNoteKind::Skip,
        TaskReportStatus::Skipped => InlineNoteKind::Skip,
        TaskReportStatus::Unchanged => InlineNoteKind::Info,
        TaskReportStatus::Updated if matches!(section_key, "package_recovery" | "yay_recovery") => {
            InlineNoteKind::Recovery
        }
        TaskReportStatus::Updated
        | TaskReportStatus::Refreshed
        | TaskReportStatus::Passed
        | TaskReportStatus::Info => InlineNoteKind::Info,
    }
}

fn should_render_inline_note(
    kind: InlineNoteKind,
    status: TaskReportStatus,
    note_verbosity: NoteVerbosity,
) -> bool {
    match note_verbosity {
        NoteVerbosity::All => true,
        NoteVerbosity::None => false,
        NoteVerbosity::Failures => {
            kind == InlineNoteKind::Failure || status == TaskReportStatus::Failed
        }
    }
}

fn should_render_task_status_note(
    status: TaskStatus,
    note_verbosity: NoteVerbosity,
    kind: InlineNoteKind,
) -> bool {
    let row_status = match status {
        TaskStatus::Completed => TaskReportStatus::Updated,
        TaskStatus::Failed => TaskReportStatus::Failed,
        TaskStatus::Canceled | TaskStatus::Skipped => TaskReportStatus::Skipped,
    };
    should_render_inline_note(kind, row_status, note_verbosity)
}

fn sanitize_report_cell_text(input: &str) -> String {
    let cleaned = strip_ansi(input);
    let mut out = String::with_capacity(cleaned.len());
    let mut last_was_space = false;
    for ch in cleaned.chars() {
        if matches!(ch, '\n' | '\r' | '\t') || ch.is_control() {
            if !out.is_empty() && !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }
        out.push(ch);
        last_was_space = ch == ' ';
    }
    out.trim().to_string()
}

fn fit_visible(input: &str, width: usize) -> (String, bool) {
    let cleaned = sanitize_report_cell_text(input);
    let input = cleaned.as_str();
    let visible = UnicodeWidthStr::width(input);
    if visible <= width {
        return (pad_visible(input, width), false);
    }
    if width == 0 {
        return (String::new(), true);
    }
    if width <= 3 {
        return (".".repeat(width), true);
    }
    let mut out = String::new();
    let mut remaining = width - 3;
    for ch in input.chars() {
        let ch_w = UnicodeWidthStr::width(ch.encode_utf8(&mut [0; 4]));
        if ch_w > remaining {
            break;
        }
        remaining -= ch_w;
        out.push(ch);
    }
    out.push_str("...");
    (out, true)
}

fn pad_visible(input: &str, width: usize) -> String {
    let cleaned = sanitize_report_cell_text(input);
    let input = cleaned.as_str();
    let visible = UnicodeWidthStr::width(input);
    if visible >= width {
        input.to_string()
    } else {
        format!("{input}{}", " ".repeat(width - visible))
    }
}

fn summarize_task_items(result: &TaskResult) -> String {
    let counts =
        result
            .report_sections
            .iter()
            .fold(ReportStatusCounts::default(), |mut counts, section| {
                for row in &section.rows {
                    counts.add(&section.key, row);
                }
                counts
            });
    let rendered = counts.render();
    if result.advisories.is_empty() {
        return rendered;
    }
    if rendered == "-" {
        format!("advisories={}", result.advisories.len())
    } else {
        format!("{rendered} advisories={}", result.advisories.len())
    }
}

fn summarize_task_notes(result: &TaskResult) -> String {
    if let Some(advisory) = result.advisories.first() {
        return advisory.summary.clone();
    }
    if let Some(detail) = result
        .details
        .iter()
        .find(|detail| !detail.trim().is_empty())
    {
        return detail.clone();
    }
    match result.status {
        TaskStatus::Completed if result.has_issues() => "completed with issues".to_string(),
        TaskStatus::Completed => "completed".to_string(),
        TaskStatus::Failed => "failed".to_string(),
        TaskStatus::Canceled => "canceled".to_string(),
        TaskStatus::Skipped => "skipped".to_string(),
    }
}

fn attach_command_advisories(result: &mut TaskResult) {
    attach_running_process_advisory(result);
}

fn attach_running_process_advisory(result: &mut TaskResult) {
    let locked_rows = result
        .report_sections
        .iter()
        .flat_map(|section| section.rows.iter())
        .filter(|row| {
            row.status == TaskReportStatus::Blocked
                && row
                    .note
                    .as_deref()
                    .is_some_and(|note| note.contains("running process detected"))
        })
        .map(|row| row.name.clone())
        .collect::<Vec<_>>();
    if locked_rows.is_empty() {
        return;
    }
    result.details = vec![format!(
        "running processes blocked {} update item(s): {}",
        locked_rows.len(),
        locked_rows.join(", ")
    )];
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "running-process-detected".to_string(),
        summary: format!(
            "running processes blocked {} update item(s)",
            locked_rows.len()
        ),
        remediation: "Close the listed applications or shells, then rerun update-all.".to_string(),
        blocks_dependents: false,
    });
}

fn category_display_name(category: &str) -> String {
    let category = category.trim();
    let functional = match category {
        "system" | "system-packages" => Some("System Packages"),
        "language" | "developer-tools" => Some("Developer Tools"),
        "agent-tooling" => Some("Agent Tooling"),
        "android-mobile" | "mobile-reverse-engineering" => Some("Mobile & Reverse Engineering"),
        "game-dev" | "game-development" => Some("Game Development"),
        "maintenance" => Some("Maintenance"),
        _ => None,
    };
    if let Some(functional) = functional {
        return functional.to_string();
    }
    let mut chars = category.chars();
    let Some(first) = chars.next() else {
        return UNCATEGORIZED_TASK_CATEGORY_DISPLAY.to_string();
    };
    format!("{}{}", first.to_ascii_uppercase(), chars.as_str())
}

fn task_status_cell_from_parts(
    status: TaskStatus,
    has_issues: bool,
    deferred: bool,
) -> &'static str {
    match status {
        TaskStatus::Completed if deferred => "Deferred",
        TaskStatus::Completed if has_issues => "Completed*",
        TaskStatus::Completed => "Completed",
        TaskStatus::Failed => "Failed",
        TaskStatus::Canceled => "Canceled",
        TaskStatus::Skipped => "Skipped",
    }
}

fn task_status_color(status: TaskStatus) -> crossterm::style::Color {
    match status {
        TaskStatus::Completed => crossterm::style::Color::Green,
        TaskStatus::Failed => crossterm::style::Color::Red,
        TaskStatus::Canceled | TaskStatus::Skipped => crossterm::style::Color::Yellow,
    }
}

fn task_status_level(status: TaskStatus) -> LogLevel {
    match status {
        TaskStatus::Completed => LogLevel::Info,
        TaskStatus::Failed => LogLevel::Error,
        TaskStatus::Canceled | TaskStatus::Skipped => LogLevel::Warn,
    }
}

fn task_status_tag(status: TaskStatus, color: bool) -> &'static str {
    match (status, color_output_enabled(color)) {
        (TaskStatus::Completed, true) => "\x1b[32mOK\x1b[0m",
        (TaskStatus::Failed, true) => "\x1b[31mFAIL\x1b[0m",
        (TaskStatus::Canceled | TaskStatus::Skipped, true) => "\x1b[33mSKIP\x1b[0m",
        (TaskStatus::Completed, false) => "OK",
        (TaskStatus::Failed, false) => "FAIL",
        (TaskStatus::Canceled | TaskStatus::Skipped, false) => "SKIP",
    }
}

fn task_status_color_from_parts(status: TaskStatus, has_issues: bool) -> crossterm::style::Color {
    if status == TaskStatus::Completed && has_issues {
        crossterm::style::Color::Yellow
    } else {
        task_status_color(status)
    }
}

fn task_status_level_from_parts(status: TaskStatus, has_issues: bool) -> LogLevel {
    if status == TaskStatus::Completed && has_issues {
        LogLevel::Warn
    } else {
        task_status_level(status)
    }
}

fn task_status_tag_from_parts(status: TaskStatus, has_issues: bool, color: bool) -> &'static str {
    if status == TaskStatus::Completed && has_issues {
        if color_output_enabled(color) {
            "\x1b[33mWARN\x1b[0m"
        } else {
            "WARN"
        }
    } else {
        task_status_tag(status, color)
    }
}

fn visible_width(input: &str) -> usize {
    UnicodeWidthStr::width(sanitize_report_cell_text(input).as_str())
}

fn color_output_enabled(color_requested: bool) -> bool {
    color_requested && stdout_supports_color()
}

fn stdout_supports_color() -> bool {
    let stdout_is_tty = if std::env::var_os("UPDATE_ALL_TEST_FORCE_COLOR").is_some() {
        true
    } else {
        std::io::stdout().is_terminal()
    };
    let term = std::env::var("TERM").ok();
    terminal_supports_color(
        stdout_is_tty,
        std::env::var_os("NO_COLOR").is_some(),
        term.as_deref(),
        windows_color_hint(),
    )
}

fn terminal_supports_color(
    stdout_is_tty: bool,
    no_color_set: bool,
    term: Option<&str>,
    windows_ansi_hint: bool,
) -> bool {
    if !stdout_is_tty || no_color_set {
        return false;
    }
    if term.is_some_and(|value| value.eq_ignore_ascii_case("dumb")) {
        return false;
    }
    if cfg!(windows) {
        windows_ansi_hint || term.map(|value| !value.trim().is_empty()).unwrap_or(false)
    } else {
        true
    }
}

#[cfg(windows)]
fn windows_color_hint() -> bool {
    std::env::var_os("WT_SESSION").is_some()
        || std::env::var_os("ANSICON").is_some()
        || std::env::var("ConEmuANSI")
            .map(|value| value.eq_ignore_ascii_case("ON"))
            .unwrap_or(false)
}

#[cfg(not(windows))]
fn windows_color_hint() -> bool {
    false
}

fn ctx_clone_for_task(
    ctx: &AsyncContext,
    tx: Option<DashboardSender>,
    runtime_control: Option<Arc<RuntimeControl>>,
    prompt_runtime: Arc<PromptRuntime>,
) -> SyncContext {
    SyncContext {
        flags: ctx.flags.clone(),
        host_os: ctx.host_os,
        updater_config: ctx.updater_config.clone(),
        completions_mode: ctx.completions_mode.clone(),
        completion_providers: ctx.completion_providers.clone(),
        completion_discover: ctx.completion_discover.clone(),
        completion_strict: ctx.completion_strict.clone(),
        completion_report: ctx.completion_report.clone(),
        filter_progress_noise: ctx.filter_progress_noise,
        emit_plain: ctx.ui == UiModeResolved::Plain,
        event_tx: tx,
        run_log: ctx.run_log.clone(),
        rc_root: ctx.rc_root.clone(),
        completion_managed_root: ctx.completion_managed_root.clone(),
        completion_config_path: ctx.completion_config_path.clone(),
        completion_catalog_path: ctx.completion_catalog_path.clone(),
        completion_registry_path: ctx.completion_registry_path.clone(),
        task_policies: ctx.task_policies.clone(),
        interactive_runtime: ctx.interactive_runtime.clone(),
        note_verbosity: ctx.note_verbosity,
        debug_report: ctx.debug_report,
        privilege_session: ctx.privilege_session.clone(),
        runtime_control,
        prompt_runtime,
    }
}

fn emit_runtime_log(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    task_id: &str,
    line: &str,
) {
    emit_task_log(
        event_tx,
        run_log,
        task_id,
        classify_meta_level(line),
        LogStream::Meta,
        line.to_string(),
    );
}

fn emit_task_log(
    event_tx: &DashboardSender,
    run_log: Option<&Arc<RunLogSink>>,
    task_id: &str,
    level: LogLevel,
    stream: LogStream,
    line: String,
) {
    let task_id = if task_id == "runtime" {
        RUN_LOG_SCOPE
    } else {
        task_id
    };
    let rec = LogRecord {
        ts_unix_ms: now_unix_ms(),
        task_id: task_id.to_string(),
        level,
        stream,
        line,
    };
    if let Some(log) = run_log {
        if let Err(err) = log.write_raw(&rec) {
            log.emit_write_warning_once(&err);
        }
        if let Err(err) = log.write_record(&rec) {
            log.emit_write_warning_once(&err);
        }
    }
    let _ = event_tx.send(DashboardEvent::LogLine(rec));
}

fn to_task_state(status: TaskStatus) -> TaskState {
    match status {
        TaskStatus::Completed => TaskState::Completed,
        TaskStatus::Failed => TaskState::Failed,
        TaskStatus::Canceled => TaskState::Canceled,
        TaskStatus::Skipped => TaskState::Skipped,
    }
}

fn capture_guard_reason_label(reason: CaptureGuardReason) -> &'static str {
    match reason {
        CaptureGuardReason::Stall => "stall detected",
        CaptureGuardReason::LineTooLong => "line length exceeded",
        CaptureGuardReason::CaptureLimitExceeded => "capture memory limit exceeded",
    }
}

fn classify_stream_level(kind: StreamKind, line: &str) -> LogLevel {
    if matches!(kind, StreamKind::Stdout) {
        return LogLevel::Info;
    }
    if is_external_manager_self_update_unsupported(line) {
        return LogLevel::Warn;
    }
    let lower = line.trim().to_ascii_lowercase();
    if lower.starts_with("error:")
        || lower.starts_with("error ")
        || lower.starts_with("==> error:")
        || lower.starts_with("==> error ")
        || lower.starts_with("fatal:")
        || lower.starts_with("fatal ")
        || lower.starts_with("panic:")
        || lower.starts_with("panic ")
        || lower.starts_with("thread '")
    {
        return LogLevel::Error;
    }
    if lower.starts_with("warning:")
        || lower.starts_with("warn:")
        || lower.starts_with("warn ")
        || lower.starts_with("npm warn")
        || lower.starts_with("==> warning:")
    {
        return LogLevel::Warn;
    }
    LogLevel::Info
}

fn classify_meta_level(line: &str) -> LogLevel {
    let lower = line.trim().to_ascii_lowercase();
    if lower.contains("error")
        || lower.contains("failed")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("panic")
    {
        return LogLevel::Warn;
    }
    LogLevel::Info
}

fn is_external_manager_self_update_unsupported(err_text: &str) -> bool {
    let lower = err_text.to_ascii_lowercase();
    (lower.contains("self-update is only available for ")
        && lower.contains(" binaries installed via the standalone installation scripts"))
        || (lower.contains("installed through an external package manager")
            && lower.contains("cannot update itself"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExternalManagerOwnership {
    manager: &'static str,
    package: String,
}

fn preflight_external_manager_skip(
    host_os: HostOs,
    spec: &TaskSpec,
    program: &str,
) -> Option<TaskResult> {
    let binary_path = resolve_command_path(program)?;
    let command_name = command_display_name(program);
    let ownership = detect_external_manager_ownership(host_os, &binary_path, &command_name)?;
    let detail = format!(
        "{command_name} is owned by {manager} package {package}; update it via {manager} instead of running self update",
        command_name = command_name,
        manager = ownership.manager,
        package = ownership.package,
    );
    let mut result = TaskResult::skipped(spec.label.clone(), detail);
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Info,
        code: "external-manager-skip".to_string(),
        summary: format!(
            "{} is managed by external package manager {}",
            command_name, ownership.manager
        ),
        remediation: format!(
            "Update {} through {} package {} rather than running self update.",
            command_name, ownership.manager, ownership.package
        ),
        blocks_dependents: false,
    });
    attach_external_manager_skip_report(
        &mut result,
        binary_path.to_string_lossy().as_ref(),
        &command_name,
    );
    Some(result)
}

fn attach_external_manager_skip_report(result: &mut TaskResult, program: &str, command_name: &str) {
    if let Some(section) = external_manager_version_report_section(program, command_name) {
        result.report_sections.push(section);
    }
}

fn external_manager_version_report_section(
    program: &str,
    command_name: &str,
) -> Option<TaskReportSection> {
    let output = run_capture_allow_exit_codes(
        program,
        ["--version"],
        Some(EXTERNAL_MANAGER_VERSION_PROBE_TIMEOUT),
        &[1],
    )
    .ok()?;
    let version = parse_external_manager_version_output(command_name, &output)?;
    Some(TaskReportSection {
        key: "version_lines".to_string(),
        title: "Version Line Results".to_string(),
        rows: vec![TaskReportRow {
            name: command_name.to_string(),
            status: TaskReportStatus::Skipped,
            before: Some(version.clone()),
            after: Some(version),
            note: Some("managed by external package manager".to_string()),
        }],
    })
}

fn parse_external_manager_version_output(command_name: &str, output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| first_version_like_token(command_name, line))
}

fn first_version_like_token(command_name: &str, line: &str) -> Option<String> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    for (idx, token) in tokens.iter().enumerate() {
        if external_version_label_token(token) {
            if let Some(version) = tokens
                .iter()
                .skip(idx + 1)
                .take(4)
                .find_map(|candidate| normalize_external_version_token(command_name, candidate))
            {
                return Some(version);
            }
        }
        if external_command_token_matches(command_name, token) {
            if let Some(version) = tokens
                .iter()
                .skip(idx + 1)
                .take(3)
                .find_map(|candidate| normalize_external_version_token(command_name, candidate))
            {
                return Some(version);
            }
        }
    }
    None
}

fn external_version_label_token(token: &str) -> bool {
    matches!(
        normalize_external_label_token(token).as_str(),
        "version" | "release" | "current" | "latest"
    )
}

fn external_command_token_matches(command_name: &str, token: &str) -> bool {
    let command_name = command_name.trim();
    if command_name.is_empty() {
        return false;
    }
    normalize_external_label_token(token).eq_ignore_ascii_case(command_name)
}

fn normalize_external_label_token(token: &str) -> String {
    token
        .trim_matches(external_token_punctuation)
        .to_ascii_lowercase()
}

fn normalize_external_version_token(command_name: &str, token: &str) -> Option<String> {
    let normalized = token
        .trim_matches(external_token_punctuation)
        .trim_start_matches(['v', 'V']);
    if normalized.is_empty() || normalized.eq_ignore_ascii_case(command_name) {
        return None;
    }
    if is_date_like_version_token(normalized) || !looks_like_package_version(normalized) {
        return None;
    }
    Some(normalized.to_string())
}

fn external_token_punctuation(c: char) -> bool {
    matches!(
        c,
        '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\'' | ',' | ';' | ':'
    )
}

fn is_date_like_version_token(token: &str) -> bool {
    if token.len() == 8
        && token.chars().all(|c| c.is_ascii_digit())
        && (token.starts_with("19") || token.starts_with("20"))
    {
        return true;
    }
    if token.len() == 4
        && token.chars().all(|c| c.is_ascii_digit())
        && (token.starts_with("19") || token.starts_with("20"))
    {
        return true;
    }

    let parts = token
        .split(['-', '.', '/'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() != 3 {
        return false;
    }
    let [year, month, day] = [parts[0], parts[1], parts[2]];
    year.len() == 4
        && (year.starts_with("19") || year.starts_with("20"))
        && month.len() <= 2
        && day.len() <= 2
        && [year, month, day]
            .iter()
            .all(|part| part.chars().all(|c| c.is_ascii_digit()))
}

fn command_display_name(program: &str) -> String {
    Path::new(program)
        .file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| program.to_string())
}

fn resolve_command_path(program: &str) -> Option<PathBuf> {
    let path = Path::new(program);
    let resolved = if path.components().count() > 1 {
        if path.exists() {
            path.to_path_buf()
        } else {
            return None;
        }
    } else {
        which(program)?
    };
    fs::canonicalize(&resolved).ok().or(Some(resolved))
}

fn detect_external_manager_ownership(
    host_os: HostOs,
    binary_path: &Path,
    package_hint: &str,
) -> Option<ExternalManagerOwnership> {
    match host_os {
        HostOs::Linux => detect_linux_package_manager_ownership(binary_path),
        HostOs::Macos => detect_macos_package_manager_ownership(binary_path, package_hint),
        HostOs::Windows | HostOs::Unknown => None,
    }
}

fn detect_linux_package_manager_ownership(binary_path: &Path) -> Option<ExternalManagerOwnership> {
    let path = binary_path.to_string_lossy();

    command_success_stdout("pacman", ["-Qqo", path.as_ref()])
        .map(|package| ExternalManagerOwnership {
            manager: "pacman",
            package,
        })
        .or_else(|| {
            command_success_stdout("dpkg-query", ["-S", path.as_ref()]).and_then(|output| {
                let package = output.split(':').next()?.trim();
                (!package.is_empty()).then(|| ExternalManagerOwnership {
                    manager: "dpkg",
                    package: package.to_string(),
                })
            })
        })
        .or_else(|| {
            command_success_stdout("rpm", ["-qf", path.as_ref()]).map(|package| {
                ExternalManagerOwnership {
                    manager: "rpm",
                    package,
                }
            })
        })
        .or_else(|| {
            command_success_stdout("apk", ["info", "-W", path.as_ref()]).and_then(|output| {
                let marker = " is owned by ";
                let package = output.split_once(marker)?.1.trim();
                (!package.is_empty()).then(|| ExternalManagerOwnership {
                    manager: "apk",
                    package: package.to_string(),
                })
            })
        })
}

fn detect_macos_package_manager_ownership(
    binary_path: &Path,
    package_hint: &str,
) -> Option<ExternalManagerOwnership> {
    let prefix = command_success_stdout("brew", ["--prefix", package_hint])?;
    let prefix_path = PathBuf::from(prefix);
    binary_path
        .starts_with(&prefix_path)
        .then(|| ExternalManagerOwnership {
            manager: "brew",
            package: package_hint.to_string(),
        })
}

fn command_success_stdout<const N: usize>(program: &str, args: [&str; N]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!stdout.is_empty()).then_some(stdout)
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn sanitize_stream_line(input: &str, filter_progress_noise: bool) -> Option<String> {
    let cleaned = strip_ansi(input).replace('\r', "");
    let trimmed_end = cleaned.trim_end().to_string();
    if trimmed_end.trim().is_empty() {
        return None;
    }
    let t = trimmed_end.trim();
    if matches!(t, "-" | "\\" | "|" | "/") {
        return None;
    }
    if filter_progress_noise && looks_like_progress_noise(t) {
        return None;
    }
    Some(trimmed_end)
}

fn looks_like_progress_noise(line: &str) -> bool {
    if line.contains("KB /") || line.contains("MB /") || line.contains("GB /") {
        return true;
    }
    let has_block = line.contains('█') || line.contains('▒') || line.contains('▓');
    if has_block && line.contains('%') {
        return true;
    }
    if line.contains('%')
        && line.chars().all(|c| {
            c.is_ascii_digit() || c.is_ascii_whitespace() || matches!(c, '%' | '█' | '▒' | '▓')
        })
    {
        return true;
    }
    false
}

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }
        if matches!(chars.peek(), Some('[')) {
            let _ = chars.next();
            for c in chars.by_ref() {
                let code = c as u32;
                if (0x40..=0x7e).contains(&code) {
                    break;
                }
            }
            continue;
        }
        if matches!(chars.peek(), Some(']')) {
            let _ = chars.next();
            let mut saw_esc = false;
            for c in chars.by_ref() {
                if c == '\u{7}' {
                    break;
                }
                if saw_esc {
                    if c == '\\' {
                        break;
                    }
                    saw_esc = false;
                } else if c == '\u{1b}' {
                    saw_esc = true;
                }
            }
            continue;
        }
        if matches!(chars.peek(), Some('P' | '^' | '_' | 'X')) {
            let _ = chars.next();
            let mut saw_esc = false;
            for c in chars.by_ref() {
                if saw_esc {
                    if c == '\\' {
                        break;
                    }
                    saw_esc = false;
                } else if c == '\u{1b}' {
                    saw_esc = true;
                }
            }
            continue;
        }
        if chars
            .peek()
            .is_some_and(|c| matches!(*c as u32, 0x20..=0x2f))
        {
            let _ = chars.next();
            for c in chars.by_ref() {
                if matches!(c as u32, 0x30..=0x7e) {
                    break;
                }
            }
            continue;
        }
        if chars
            .peek()
            .is_some_and(|c| matches!(*c as u32, 0x40..=0x5f | 0x60..=0x7e))
        {
            let _ = chars.next();
        }
    }
    out
}

#[cfg(test)]
#[path = "../tests/tasks_cross_platform.rs"]
mod cross_platform_tests;

#[cfg(all(test, windows))]
#[path = "../tests/tasks_windows.rs"]
mod windows_tests;

#[cfg(all(test, unix))]
#[path = "../tests/tasks_unix.rs"]
mod tests;
