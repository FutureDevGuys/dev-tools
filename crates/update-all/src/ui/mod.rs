mod plain;

#[cfg(feature = "tui")]
mod tui;

use anyhow::Result;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::Instant;

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
        rx: Receiver<DashboardEvent>,
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
                        if matches!(event, DashboardEvent::UiDone) {
                            break;
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
    TaskStateChanged {
        id: String,
        state: TaskState,
        detail: Option<String>,
    },
    LogLine(LogRecord),
    RunComplete {
        success: bool,
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
    CancelTask { id: String },
    CancelAll,
    SendStdin { id: String, line: String },
    RenameRun { name: String },
    OpenLog { target: LogViewTarget },
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
    ]
    .iter()
    .any(|prefix| {
        trimmed
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(' '))
    })
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
