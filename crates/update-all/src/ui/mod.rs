mod plain;

#[cfg(feature = "tui")]
mod tui;

use anyhow::Result;
use std::collections::{BTreeMap, VecDeque};
use std::sync::mpsc::{self, Receiver, RecvError, SendError, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

// Bound the entire producer-to-frontend log backlog, including unusually long
// records. Complete evidence is journaled before entering this display channel.
const DASHBOARD_LOG_BACKLOG_BYTES: usize = 8 * 1024 * 1024;
const DASHBOARD_STATE_TEXT_BYTES: usize = 8 * 1024;

enum DashboardMessage {
    Control(DashboardEvent),
    TaskStateReady {
        task_id: String,
        kind: TaskDisplayKind,
    },
    LogsReady,
}

#[derive(Clone, Copy)]
enum TaskDisplayKind {
    State,
    Input,
    Prompt,
}

#[derive(Default)]
struct TaskDisplayState {
    state: Option<DashboardEvent>,
    input: Option<DashboardEvent>,
    prompt: Option<DashboardEvent>,
    prompt_generation: u64,
    prompt_canceled: bool,
}

impl TaskDisplayState {
    fn slot(&mut self, kind: TaskDisplayKind) -> &mut Option<DashboardEvent> {
        match kind {
            TaskDisplayKind::State => &mut self.state,
            TaskDisplayKind::Input => &mut self.input,
            TaskDisplayKind::Prompt => &mut self.prompt,
        }
    }

    fn accepts(&self, event: &DashboardEvent) -> bool {
        match event {
            DashboardEvent::PromptRequested { generation, .. } => {
                *generation > self.prompt_generation
                    || (*generation == self.prompt_generation && !self.prompt_canceled)
            }
            DashboardEvent::PromptCancelled { generation, .. } => {
                *generation >= self.prompt_generation
            }
            _ => true,
        }
    }

    fn replace(&mut self, kind: TaskDisplayKind, mut event: DashboardEvent) {
        match &mut event {
            DashboardEvent::PromptRequested {
                generation, prompt, ..
            } => {
                self.prompt_generation = *generation;
                self.prompt_canceled = false;
                bound_display_text(prompt);
            }
            DashboardEvent::PromptCancelled {
                generation, reason, ..
            } => {
                self.prompt_generation = *generation;
                self.prompt_canceled = true;
                bound_display_text(reason);
            }
            DashboardEvent::TaskStateChanged {
                detail: Some(detail),
                ..
            } => {
                bound_display_text(detail);
            }
            _ => {}
        }
        *self.slot(kind) = Some(event);
    }
}

fn bound_display_text(text: &mut String) {
    if text.len() > DASHBOARD_STATE_TEXT_BYTES {
        let mut end = DASHBOARD_STATE_TEXT_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(" [display truncated; m: full log]");
    }
    text.shrink_to_fit();
}

struct DisplayLogBacklog {
    records: VecDeque<LogRecord>,
    bytes: usize,
    max_records: usize,
    omitted: BTreeMap<String, u64>,
    omission_order: VecDeque<String>,
    omission_next: bool,
    notified: bool,
    receiver_connected: bool,
    task_state: BTreeMap<String, TaskDisplayState>,
}

impl DisplayLogBacklog {
    fn record_bytes(record: &LogRecord) -> usize {
        std::mem::size_of::<LogRecord>()
            .saturating_add(record.task_id.capacity())
            .saturating_add(record.line.capacity())
    }

    fn omit(&mut self, task_id: &str) {
        // The task set is fixed at admission. Unexpected scopes are accounted
        // for globally rather than growing an unbounded map from output.
        let scope = if self.omitted.contains_key(task_id) {
            task_id
        } else {
            RUN_LOG_SCOPE
        };
        if let Some(count) = self.omitted.get_mut(scope) {
            if *count == 0 {
                self.omission_order.push_back(scope.to_string());
            }
            *count = count.saturating_add(1);
        }
    }

    fn push(&mut self, record: LogRecord) {
        let bytes = Self::record_bytes(&record);
        if bytes > DASHBOARD_LOG_BACKLOG_BYTES {
            self.omit(&record.task_id);
            return;
        }
        while self.records.len() >= self.max_records
            || self.bytes.saturating_add(bytes) > DASHBOARD_LOG_BACKLOG_BYTES
        {
            let Some(evicted) = self.records.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(Self::record_bytes(&evicted));
            self.omit(&evicted.task_id);
        }
        self.bytes += bytes;
        self.records.push_back(record);
    }

    fn pop_omission(&mut self) -> Option<DashboardEvent> {
        let task_id = self.omission_order.pop_front()?;
        let count = self.omitted.get_mut(&task_id)?;
        let count = std::mem::take(count);
        self.omission_next = false;
        Some(DashboardEvent::DisplayLogsOmitted { task_id, count })
    }

    fn pop(&mut self) -> Option<DashboardEvent> {
        // Alternate omissions and retained records so a continuous flood cannot
        // starve either the latest output or another task's omission notice.
        if self.omission_next || self.records.is_empty() {
            if let Some(event) = self.pop_omission() {
                return Some(event);
            }
        }
        if let Some(record) = self.records.pop_front() {
            self.bytes = self.bytes.saturating_sub(Self::record_bytes(&record));
            self.omission_next = true;
            return Some(DashboardEvent::LogLine(record));
        }
        self.notified = false;
        None
    }
}

#[derive(Clone)]
enum DashboardTransport {
    Buffered {
        controls: Sender<DashboardMessage>,
        logs: Arc<Mutex<DisplayLogBacklog>>,
    },
    // Existing execution fixtures inspect an ordinary channel directly. This
    // path is deliberately unavailable to production execution.
    #[cfg(test)]
    Fixture(Sender<DashboardEvent>),
}

#[derive(Clone)]
pub(crate) struct DashboardEventSender {
    transport: DashboardTransport,
}

impl DashboardEventSender {
    #[cfg(test)]
    pub(crate) fn fixture(tx: Sender<DashboardEvent>) -> Self {
        Self {
            transport: DashboardTransport::Fixture(tx),
        }
    }

    pub(crate) fn send(&self, event: DashboardEvent) -> Result<(), SendError<DashboardEvent>> {
        let (controls, logs) = match &self.transport {
            DashboardTransport::Buffered { controls, logs } => (controls, logs),
            #[cfg(test)]
            DashboardTransport::Fixture(tx) => return tx.send(event),
        };
        let state_key = match &event {
            DashboardEvent::TaskStateChanged { id, .. } => Some((id, TaskDisplayKind::State)),
            DashboardEvent::TaskInputStateChanged { id, .. } => Some((id, TaskDisplayKind::Input)),
            DashboardEvent::PromptRequested { id, .. }
            | DashboardEvent::PromptCancelled { id, .. } => Some((id, TaskDisplayKind::Prompt)),
            _ => None,
        };
        if let Some((task_id, kind)) = state_key {
            let Ok(mut backlog) = logs.lock() else {
                return Err(SendError(event));
            };
            if !backlog.receiver_connected {
                return Err(SendError(event));
            }
            let Some(state) = backlog.task_state.get_mut(task_id) else {
                return Err(SendError(event));
            };
            if !state.accepts(&event) {
                return Ok(());
            }
            if state.slot(kind).is_none()
                && controls
                    .send(DashboardMessage::TaskStateReady {
                        task_id: task_id.clone(),
                        kind,
                    })
                    .is_err()
            {
                return Err(SendError(event));
            }
            state.replace(kind, event);
            return Ok(());
        }
        if let DashboardEvent::LogLine(record) = event {
            let Ok(mut backlog) = logs.lock() else {
                return Err(SendError(DashboardEvent::LogLine(record)));
            };
            if !backlog.receiver_connected {
                return Err(SendError(DashboardEvent::LogLine(record)));
            }
            if !backlog.notified {
                if controls.send(DashboardMessage::LogsReady).is_err() {
                    return Err(SendError(DashboardEvent::LogLine(record)));
                }
                backlog.notified = true;
            }
            backlog.push(record);
            Ok(())
        } else {
            controls
                .send(DashboardMessage::Control(event))
                .map_err(|err| match err.0 {
                    DashboardMessage::Control(event) => SendError(event),
                    _ => unreachable!("sent a control event"), // INVARIANT: the rejected message is the Control variant sent above.
                })
        }
    }
}

/// The dashboard receives controls before display logs without allowing log
/// producers to block on rendering, input, or suspend/resume acknowledgments.
pub struct DashboardReceiver {
    controls: Receiver<DashboardMessage>,
    logs: Arc<Mutex<DisplayLogBacklog>>,
}

impl DashboardReceiver {
    fn receive_message(
        &self,
        message: DashboardMessage,
    ) -> Result<Option<DashboardEvent>, TryRecvError> {
        match message {
            DashboardMessage::Control(event) => Ok(Some(event)),
            DashboardMessage::LogsReady => Ok(None),
            DashboardMessage::TaskStateReady { task_id, kind } => {
                let mut backlog = self.logs.lock().map_err(|_| TryRecvError::Disconnected)?;
                let state = backlog
                    .task_state
                    .get_mut(&task_id)
                    .ok_or(TryRecvError::Disconnected)?;
                Ok(state.slot(kind).take())
            }
        }
    }

    pub fn try_recv(&self) -> Result<DashboardEvent, TryRecvError> {
        let status = loop {
            match self.controls.try_recv() {
                Ok(message) => {
                    if let Some(event) = self.receive_message(message)? {
                        return Ok(event);
                    }
                }
                Err(status) => break status,
            }
        };
        let mut backlog = self.logs.lock().map_err(|_| TryRecvError::Disconnected)?;
        backlog.pop().ok_or(status)
    }

    pub fn recv(&self) -> Result<DashboardEvent, RecvError> {
        loop {
            match self.try_recv() {
                Ok(event) => return Ok(event),
                Err(TryRecvError::Disconnected) => return Err(RecvError),
                Err(TryRecvError::Empty) => {}
            }
            if let Some(event) = self
                .receive_message(self.controls.recv()?)
                .map_err(|_| RecvError)?
            {
                return Ok(event);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn backlog_size(&self) -> (usize, usize, usize) {
        let backlog = self.logs.lock().expect("display backlog is not poisoned"); // INVARIANT: fixture does not panic while holding the backlog.
        (
            backlog.records.len(),
            backlog.bytes,
            backlog.omission_order.len(),
        )
    }

    #[cfg(test)]
    pub(crate) fn pending_task_states(&self) -> usize {
        let backlog = self.logs.lock().expect("display backlog is not poisoned"); // INVARIANT: fixture does not panic while holding the backlog.
        backlog
            .task_state
            .values()
            .map(|state| {
                usize::from(state.state.is_some())
                    + usize::from(state.input.is_some())
                    + usize::from(state.prompt.is_some())
            })
            .sum()
    }
}

impl Drop for DashboardReceiver {
    fn drop(&mut self) {
        if let Ok(mut backlog) = self.logs.lock() {
            backlog.receiver_connected = false;
            backlog.records.clear();
            backlog.bytes = 0;
            backlog.omission_order.clear();
            backlog.task_state.clear();
        }
    }
}

pub(crate) fn dashboard_channel(
    max_records: usize,
    task_ids: &[String],
) -> (DashboardEventSender, DashboardReceiver) {
    let (control_tx, control_rx) = mpsc::channel();
    let mut omitted = task_ids
        .iter()
        .map(|id| (id.clone(), 0))
        .collect::<BTreeMap<_, _>>();
    omitted.insert(RUN_LOG_SCOPE.to_string(), 0);
    let logs = Arc::new(Mutex::new(DisplayLogBacklog {
        records: VecDeque::new(),
        bytes: 0,
        max_records: max_records.max(1),
        omitted,
        omission_order: VecDeque::new(),
        omission_next: true,
        notified: false,
        receiver_connected: true,
        task_state: task_ids
            .iter()
            .map(|id| (id.clone(), TaskDisplayState::default()))
            .collect(),
    }));
    (
        DashboardEventSender {
            transport: DashboardTransport::Buffered {
                controls: control_tx,
                logs: logs.clone(),
            },
        },
        DashboardReceiver {
            controls: control_rx,
            logs,
        },
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UiModeResolved {
    Plain,
    Dashboard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DashboardQuitBehavior {
    CancelAll,
    Detach,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseRowStride {
    Auto,
    One,
    Two,
}

impl UiModeResolved {
    pub fn as_str(self) -> &'static str {
        match self {
            UiModeResolved::Plain => "plain",
            UiModeResolved::Dashboard => "dashboard",
        }
    }

    #[allow(clippy::too_many_arguments)] // Reason: UI thread wiring requires explicit runtime controls.
    pub fn spawn_ui_thread(
        self,
        rx: DashboardReceiver,
        control_tx: Sender<UiControlEvent>,
        quit_behavior: DashboardQuitBehavior,
        mouse_row_stride: MouseRowStride,
        show_global_log: bool,
        max_in_memory_lines: usize,
        max_events_per_frame: usize,
        task_colors: bool,
    ) -> Result<Option<thread::JoinHandle<Result<()>>>> {
        match self {
            UiModeResolved::Plain => {
                let _ = control_tx;
                let _ = quit_behavior;
                let _ = mouse_row_stride;
                let _ = show_global_log;
                let _ = max_in_memory_lines;
                let _ = max_events_per_frame;
                let _ = task_colors;
                Ok(Some(thread::spawn(move || {
                    while let Ok(event) = rx.recv() {
                        match event {
                            DashboardEvent::UiDone => break,
                            DashboardEvent::UiSuspendRequested { ack, .. }
                            | DashboardEvent::UiResumeRequested { ack } => {
                                // Plain output owns no terminal modes to restore,
                                // but execution still needs its handoff acknowledged.
                                if let Some(ack) = ack {
                                    let _ = ack.send(());
                                }
                            }
                            _ => {}
                        }
                    }
                    Ok(())
                })))
            }
            UiModeResolved::Dashboard => {
                #[cfg(feature = "tui")]
                {
                    Ok(Some(thread::spawn(move || {
                        crate::ui::tui::run_dashboard(
                            rx,
                            control_tx,
                            quit_behavior,
                            mouse_row_stride,
                            show_global_log,
                            max_in_memory_lines,
                            max_events_per_frame,
                            task_colors,
                        )
                    })))
                }
                #[cfg(not(feature = "tui"))]
                {
                    let _ = rx;
                    let _ = control_tx;
                    Ok(None)
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Completed,
    Failed,
    Canceled,
    Skipped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Reason: trace level is reserved for future verbosity controls.
pub enum LogLevel {
    Trace,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
    Stdin,
    Meta,
}

/// Reserved journal scope for records that belong to the run rather than a task.
pub const RUN_LOG_SCOPE: &str = "run/global";

impl LogStream {
    pub fn as_str(self) -> &'static str {
        match self {
            LogStream::Stdout => "OUT",
            LogStream::Stderr => "STDERR",
            LogStream::Stdin => "STDIN",
            LogStream::Meta => "META",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogRecord {
    pub ts_unix_ms: u64,
    pub task_id: String,
    pub level: LogLevel,
    pub stream: LogStream,
    pub line: String,
}

#[derive(Clone, Debug)]
pub enum DashboardEvent {
    RunIdentity {
        run_id: String,
        display_name: String,
    },
    RunRenamed {
        display_name: String,
    },
    TaskRegistered {
        id: String,
        label: String,
        category: String,
        depends_on: Vec<String>,
        accepts_input: bool,
    },
    TaskInputStateChanged {
        id: String,
        enabled: bool,
    },
    PromptRequested {
        id: String,
        generation: u64,
        prompt: String,
    },
    PromptCancelled {
        id: String,
        generation: u64,
        reason: String,
    },
    TaskStateChanged {
        id: String,
        state: TaskState,
        detail: Option<String>,
    },
    LogLine(LogRecord),
    DisplayLogsOmitted {
        task_id: String,
        count: u64,
    },
    RunComplete {
        success: bool,
        canceled: bool,
        had_failures: bool,
        completed_at: Instant,
    },
    UiSuspendRequested {
        reason: String,
        ack: Option<Sender<()>>,
    },
    UiResumeRequested {
        ack: Option<Sender<()>>,
    },
    UiDone,
}

#[derive(Clone, Debug)]
pub enum UiControlEvent {
    CancelTask {
        id: String,
    },
    CancelAll,
    SendStdin {
        id: String,
        generation: u64,
        line: String,
    },
    RenameRun {
        name: String,
    },
    OpenLog {
        target: LogViewTarget,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogViewTarget {
    Task { id: String },
    Run,
}

pub(crate) fn is_report_meta_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || is_report_title_line(trimmed)
        || is_report_note_line(trimmed)
        || trimmed.starts_with('┌')
        || trimmed.starts_with('├')
        || trimmed.starts_with('└')
        || trimmed.starts_with('│')
        || report_column_count(trimmed) >= 4
}

pub(crate) fn is_report_title_line(line: &str) -> bool {
    line.ends_with("Results")
        || line.ends_with("Recovery Actions")
        || matches!(
            line,
            "Package Change Rollup" | "Final Task Overview" | "Needs Attention" | "Update Details"
        )
}

pub(crate) fn is_report_note_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    [
        "[FAIL]",
        "[OK]",
        "[REFRESH]",
        "[PASS]",
        "[SAME]",
        "[BLOCK]",
        "[SKIP]",
        "[INFO]",
        "[WARN]",
        "[ERROR]",
    ]
    .iter()
    .any(|prefix| {
        trimmed
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(' '))
    })
}

pub(crate) fn looks_like_interactive_prompt(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if is_arch_service_restart_prompt_text(&lower) {
        return true;
    }
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

    lower.starts_with("==> ")
        && (lower.contains("packages to exclude")
            || lower.contains("packages to cleanbuild")
            || lower.contains("diffs to show")
            || lower.contains("pkgbuilds to edit")
            || lower.contains("[n]one [a]ll [ab]ort")
            || lower.contains('?'))
}

fn is_arch_service_restart_prompt_text(lower: &str) -> bool {
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

pub(crate) fn report_column_count(line: &str) -> usize {
    let seps = double_space_boundaries(line);
    if seps.is_empty() {
        0
    } else {
        seps.len() + 1
    }
}

pub(crate) fn report_values_are_version_change(before: &str, after: &str) -> bool {
    let before = before.trim();
    let after = after.trim();
    let before_cmp = report_value_for_change_compare(before);
    let after_cmp = report_value_for_change_compare(after);
    !before.is_empty()
        && !after.is_empty()
        && before != "-"
        && after != "-"
        && before_cmp != after_cmp
        && report_value_contains_version_token(before)
        && report_value_contains_version_token(after)
}

fn report_value_for_change_compare(value: &str) -> &str {
    let value = value.trim();
    if let Some(base) = value_without_trailing_parenthetical_note(value) {
        return base;
    }
    value
}

fn value_without_trailing_parenthetical_note(value: &str) -> Option<&str> {
    if !value.ends_with(')') {
        return None;
    }
    let note_start = value.rfind(" (")?;
    let base = value[..note_start].trim();
    let note = value[note_start + 2..value.len() - 1].trim();
    (!base.is_empty() && !note.is_empty()).then_some(base)
}

pub(crate) fn report_value_contains_version_token(value: &str) -> bool {
    if value.contains('/') || value.contains('\\') {
        return false;
    }

    value.split_whitespace().any(|token| {
        let token = token
            .trim_matches(|ch: char| {
                matches!(
                    ch,
                    ',' | ';' | ':' | '(' | ')' | '[' | ']' | '{' | '}' | '"' | '\''
                )
            })
            .trim_end_matches("...");
        report_is_obvious_version_token(token)
    })
}

pub(crate) fn report_is_obvious_version_token(token: &str) -> bool {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return false;
    }
    if !trimmed.chars().all(report_is_version_token_char) {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains('/') || lower.ends_with(".js") || lower.ends_with(".service") {
        return false;
    }
    let first = trimmed.chars().next().unwrap_or_default();
    if !(first.is_ascii_digit()
        || (first == 'v'
            && trimmed
                .chars()
                .nth(1)
                .is_some_and(|next| next.is_ascii_digit())))
    {
        return false;
    }
    trimmed.chars().any(|ch| ch.is_ascii_digit())
}

pub(crate) fn report_is_version_token_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':' | '+' | '~')
}

fn double_space_boundaries(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        if bytes[idx] == b' ' && bytes[idx + 1] == b' ' {
            let start = idx;
            idx += 2;
            while idx < bytes.len() && bytes[idx] == b' ' {
                idx += 1;
            }
            out.push((start, idx));
            continue;
        }
        idx += 1;
    }
    out
}
