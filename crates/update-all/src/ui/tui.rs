use crate::ui::{
    is_report_meta_line, is_report_note_line, DashboardEvent, DashboardQuitBehavior, LogLevel,
    LogRecord, LogStream, LogViewTarget, MouseRowStride, TaskState, UiControlEvent,
};
use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyEventState, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Terminal;
use regex::Regex;
use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Stdout};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Clone)]
struct TaskRow {
    id: String,
    label: String,
    category: String,
    depends_on: Vec<String>,
    accepts_input: bool,
    input_enabled: bool,
    state: TaskState,
    detail: Option<String>,
    logs: VecDeque<LogRecord>,
    logs_dropped: u64,
}

#[derive(Clone)]
struct PendingTaskLogs {
    logs: VecDeque<LogRecord>,
    logs_dropped: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivePane {
    Tasks,
    TaskLogs,
    GlobalLogs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RightPaneMode {
    Split,
    FocusTask,
    FocusGlobal,
}

#[derive(Clone, Copy)]
struct LayoutRects {
    root: Rect,
    header: Rect,
    tasks: Rect,
    tasks_inner: Rect,
    task_logs: Option<Rect>,
    global_logs: Option<Rect>,
    footer: Rect,
}

#[derive(Clone, Default)]
struct SearchSpec {
    query: String,
    regex: Option<Regex>,
    error: Option<String>,
    last_match: Option<usize>,
    restore: Option<SearchRestore>,
}

#[derive(Clone)]
struct SearchEditState {
    target: ActivePane,
    buffer: String,
    error: Option<String>,
}

#[derive(Clone)]
struct PromptEditState {
    task_id: String,
    buffer: String,
}

#[derive(Clone)]
struct RenameEditState {
    buffer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PromptKind {
    Generic,
    ArchServiceRestart,
}

#[derive(Clone, Copy)]
enum SearchRestore {
    Tasks {
        selected_task: usize,
        task_list_offset: usize,
    },
    TaskLogs {
        from_bottom: usize,
    },
    GlobalLogs {
        from_bottom: usize,
    },
}

struct Model {
    started_at: Instant,
    run_id: Option<String>,
    display_name: Option<String>,
    run_completed_at: Option<Instant>,
    run_complete: Option<bool>,
    cancel_requested: bool,
    task_order: Vec<String>,
    tasks: BTreeMap<String, TaskRow>,
    pending_task_logs: BTreeMap<String, PendingTaskLogs>,
    global_logs: VecDeque<LogRecord>,
    global_logs_dropped: u64,
    selected_task: usize,
    task_list_offset: usize,
    active_pane: ActivePane,
    right_pane_mode: RightPaneMode,
    task_log_from_bottom: usize,
    global_log_from_bottom: usize,
    show_help: bool,
    wrap_logs: bool,
    search_edit: Option<SearchEditState>,
    prompt_edit: Option<PromptEditState>,
    rename_edit: Option<RenameEditState>,
    auto_prompt_key: Option<(String, u64)>,
    prompt_scroll_from_bottom: usize,
    task_search: SearchSpec,
    task_log_search: SearchSpec,
    global_log_search: SearchSpec,
    max_in_memory_lines: usize,
    show_global_log: bool,
    task_colors: bool,
    mouse_row_stride_mode: MouseRowStride,
    task_mouse_row_stride: u16,
    last_task_wheel: Option<(bool, u16, u64)>,
}

impl Model {
    fn new(max_in_memory_lines: usize, show_global_log: bool, task_colors: bool) -> Self {
        Self::new_with_mouse_stride(
            max_in_memory_lines,
            show_global_log,
            task_colors,
            MouseRowStride::Auto,
        )
    }

    fn new_with_mouse_stride(
        max_in_memory_lines: usize,
        show_global_log: bool,
        task_colors: bool,
        mouse_row_stride_mode: MouseRowStride,
    ) -> Self {
        let task_mouse_row_stride = match mouse_row_stride_mode {
            MouseRowStride::Auto | MouseRowStride::One => 1,
            MouseRowStride::Two => 2,
        };
        Self {
            started_at: Instant::now(),
            run_id: None,
            display_name: None,
            run_completed_at: None,
            run_complete: None,
            cancel_requested: false,
            task_order: Vec::new(),
            tasks: BTreeMap::new(),
            pending_task_logs: BTreeMap::new(),
            global_logs: VecDeque::new(),
            global_logs_dropped: 0,
            selected_task: 0,
            task_list_offset: 0,
            active_pane: ActivePane::Tasks,
            right_pane_mode: RightPaneMode::Split,
            task_log_from_bottom: 0,
            global_log_from_bottom: 0,
            show_help: false,
            wrap_logs: false,
            search_edit: None,
            prompt_edit: None,
            rename_edit: None,
            auto_prompt_key: None,
            prompt_scroll_from_bottom: 0,
            task_search: SearchSpec::default(),
            task_log_search: SearchSpec::default(),
            global_log_search: SearchSpec::default(),
            max_in_memory_lines,
            show_global_log,
            task_colors,
            mouse_row_stride_mode,
            task_mouse_row_stride,
            last_task_wheel: None,
        }
    }

    fn set_run_identity(&mut self, run_id: String, display_name: String) {
        self.run_id = Some(run_id);
        self.display_name = Some(display_name);
    }

    fn set_display_name(&mut self, display_name: String) {
        self.display_name = Some(display_name);
    }

    fn observe_task_mouse_row(&mut self, tasks_inner: Rect, row: u16) {
        let _ = (tasks_inner, row);
    }

    fn reset_task_mouse_stride_calibration(&mut self) {
        if self.mouse_row_stride_mode != MouseRowStride::Auto {
            return;
        }
        self.task_mouse_row_stride = 1;
        self.last_task_wheel = None;
    }

    fn suppress_duplicate_task_wheel(&mut self, up: bool, row: u16) -> bool {
        let now = now_unix_ms();
        if let Some((prev_up, prev_row, prev_ms)) = self.last_task_wheel {
            if prev_up == up && prev_row == row && now.saturating_sub(prev_ms) <= 40 {
                return true;
            }
        }
        self.last_task_wheel = Some((up, row, now));
        false
    }

    fn selected_task_id(&self) -> Option<&str> {
        self.task_order.get(self.selected_task).map(|s| s.as_str())
    }

    fn selected_task_row(&self) -> Option<&TaskRow> {
        let id = self.selected_task_id()?;
        self.tasks.get(id)
    }

    fn push_task_log(&mut self, mut rec: LogRecord) {
        rec.line = sanitize_log_line(&rec.line);
        if let Some(task) = self.tasks.get_mut(&rec.task_id) {
            push_or_coalesce_log(
                &mut task.logs,
                &mut task.logs_dropped,
                self.max_in_memory_lines,
                rec.clone(),
            );
        } else {
            let pending = self
                .pending_task_logs
                .entry(rec.task_id.clone())
                .or_insert_with(|| PendingTaskLogs {
                    logs: VecDeque::new(),
                    logs_dropped: 0,
                });
            push_or_coalesce_log(
                &mut pending.logs,
                &mut pending.logs_dropped,
                self.max_in_memory_lines,
                rec.clone(),
            );
        }
        push_or_coalesce_log(
            &mut self.global_logs,
            &mut self.global_logs_dropped,
            self.max_in_memory_lines,
            rec,
        );
        self.refresh_prompt_state();
    }

    fn register_task(
        &mut self,
        id: String,
        label: String,
        depends_on: Vec<String>,
        accepts_input: bool,
    ) {
        self.register_task_with_category(
            id,
            label,
            "developer-tools".to_string(),
            depends_on,
            accepts_input,
        );
    }

    fn register_task_with_category(
        &mut self,
        id: String,
        label: String,
        category: String,
        depends_on: Vec<String>,
        accepts_input: bool,
    ) {
        if self.tasks.contains_key(&id) {
            return;
        }
        let pending_logs = self.pending_task_logs.remove(&id);
        self.task_order.push(id.clone());
        self.tasks.insert(
            id.clone(),
            TaskRow {
                id,
                label,
                category,
                depends_on,
                accepts_input,
                input_enabled: false,
                state: TaskState::Pending,
                detail: None,
                logs: pending_logs
                    .as_ref()
                    .map(|pending| pending.logs.clone())
                    .unwrap_or_default(),
                logs_dropped: pending_logs
                    .as_ref()
                    .map(|pending| pending.logs_dropped)
                    .unwrap_or(0),
            },
        );
        self.clamp_task_selection();
    }

    fn set_task_state(&mut self, id: &str, state: TaskState, detail: Option<String>) {
        if let Some(task) = self.tasks.get_mut(id) {
            task.state = state;
            task.detail = detail.map(|d| sanitize_log_line(&d));
        }
        self.refresh_prompt_state();
    }

    fn set_task_input_state(&mut self, id: &str, enabled: bool) {
        if let Some(task) = self.tasks.get_mut(id) {
            task.input_enabled = enabled;
        }
        self.refresh_prompt_state();
    }

    fn refresh_prompt_state(&mut self) {
        let Some((task_id, prompt_ts)) = latest_prompt_signature(self) else {
            self.prompt_edit = None;
            self.auto_prompt_key = None;
            self.prompt_scroll_from_bottom = 0;
            return;
        };
        let prompt_key = (task_id.clone(), prompt_ts);
        let prompt_task_active = self
            .tasks
            .get(&task_id)
            .is_some_and(|task| task.accepts_input && task.input_enabled);

        if !prompt_task_active {
            self.prompt_edit = None;
            self.prompt_scroll_from_bottom = 0;
            return;
        }

        let has_matching_editor = self
            .prompt_edit
            .as_ref()
            .is_some_and(|edit| edit.task_id == task_id);
        if self.auto_prompt_key.as_ref() != Some(&prompt_key) {
            self.prompt_scroll_from_bottom = 0;
        }
        if !has_matching_editor && self.auto_prompt_key.as_ref() != Some(&prompt_key) {
            self.prompt_edit = Some(PromptEditState {
                task_id: task_id.clone(),
                buffer: String::new(),
            });
            self.auto_prompt_key = Some(prompt_key);
        } else if has_matching_editor {
            self.auto_prompt_key = Some(prompt_key);
        }
    }

    fn search_spec(&self, pane: ActivePane) -> &SearchSpec {
        match pane {
            ActivePane::Tasks => &self.task_search,
            ActivePane::TaskLogs => &self.task_log_search,
            ActivePane::GlobalLogs => &self.global_log_search,
        }
    }

    fn search_spec_mut(&mut self, pane: ActivePane) -> &mut SearchSpec {
        match pane {
            ActivePane::Tasks => &mut self.task_search,
            ActivePane::TaskLogs => &mut self.task_log_search,
            ActivePane::GlobalLogs => &mut self.global_log_search,
        }
    }

    fn task_state_counts(&self) -> (usize, usize, usize, usize, usize) {
        let mut pending = 0usize;
        let mut running = 0usize;
        let mut completed = 0usize;
        let mut failed = 0usize;
        let mut canceled = 0usize;
        for task in self.tasks.values() {
            match task.state {
                TaskState::Pending => pending += 1,
                TaskState::Running => running += 1,
                TaskState::Completed => completed += 1,
                TaskState::Failed => failed += 1,
                TaskState::Canceled => canceled += 1,
                TaskState::Skipped => {}
            }
        }
        (pending, running, completed, failed, canceled)
    }

    fn dependency_waiting_on(&self, row: &TaskRow) -> Vec<String> {
        row.depends_on
            .iter()
            .filter_map(|dep| {
                let dep_state = self.tasks.get(dep).map(|t| t.state)?;
                match dep_state {
                    TaskState::Completed
                    | TaskState::Failed
                    | TaskState::Canceled
                    | TaskState::Skipped => None,
                    TaskState::Pending | TaskState::Running => Some(dep.clone()),
                }
            })
            .collect()
    }

    fn clamp_task_selection(&mut self) {
        if self.task_order.is_empty() {
            self.selected_task = 0;
            self.task_list_offset = 0;
            return;
        }
        let max_idx = self.task_order.len() - 1;
        if self.selected_task > max_idx {
            self.selected_task = max_idx;
        }
    }

    fn ensure_selected_visible(&mut self, visible_rows: usize) {
        self.clamp_task_selection();
        if self.task_order.is_empty() || visible_rows == 0 {
            self.task_list_offset = 0;
            return;
        }

        let max_offset = self.task_order.len().saturating_sub(visible_rows);
        if self.task_list_offset > max_offset {
            self.task_list_offset = max_offset;
        }
        if self.selected_task < self.task_list_offset {
            self.task_list_offset = self.selected_task;
        } else if self.selected_task >= self.task_list_offset + visible_rows {
            self.task_list_offset = self.selected_task + 1 - visible_rows;
        }
        if self.task_list_offset > max_offset {
            self.task_list_offset = max_offset;
        }
    }

    fn move_task_selection(&mut self, delta: i32, visible_rows: usize) {
        if self.task_order.is_empty() {
            return;
        }
        if delta < 0 {
            self.selected_task = self
                .selected_task
                .saturating_sub(delta.unsigned_abs() as usize);
        } else {
            self.selected_task =
                (self.selected_task + delta as usize).min(self.task_order.len().saturating_sub(1));
        }
        self.ensure_selected_visible(visible_rows);
    }

    fn select_task(&mut self, idx: usize, visible_rows: usize) {
        if self.task_order.is_empty() {
            self.selected_task = 0;
            self.task_list_offset = 0;
            return;
        }
        self.selected_task = idx.min(self.task_order.len() - 1);
        self.ensure_selected_visible(visible_rows);
    }
}

pub fn run_dashboard(
    rx: Receiver<DashboardEvent>,
    control_tx: Sender<UiControlEvent>,
    quit_behavior: DashboardQuitBehavior,
    mouse_row_stride: MouseRowStride,
    show_global_log: bool,
    max_in_memory_lines: usize,
    max_events_per_frame: usize,
    task_colors: bool,
) -> Result<()> {
    let mut terminal = Some(setup_terminal()?);
    if let Some(t) = terminal.as_mut() {
        let _ = t.clear();
    }
    let result = (|| -> Result<()> {
        let max_events_per_frame = max_events_per_frame.max(1);
        let mut model = Model::new_with_mouse_stride(
            max_in_memory_lines,
            show_global_log,
            task_colors,
            mouse_row_stride,
        );
        let idle_tick = Duration::from_millis(20);
        let mut done = false;
        let mut suspended = false;
        let mut pending_logs: VecDeque<LogRecord> = VecDeque::new();
        let mut layout = layout_for(
            terminal_rect(
                terminal
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("terminal unavailable"))?,
            )?,
            model.show_global_log,
            model.right_pane_mode,
            model.active_pane,
        );

        while !done {
            if !suspended {
                while event::poll(Duration::from_millis(0))? {
                    match event::read()? {
                        Event::Key(k) => {
                            if handle_key_event(&mut model, k, &layout, &control_tx, quit_behavior)
                            {
                                done = true;
                                break;
                            }
                        }
                        Event::Mouse(m) => handle_mouse_event(&mut model, m, &layout),
                        Event::Resize(_, _) => model.reset_task_mouse_stride_calibration(),
                        _ => {}
                    }
                }
            }

            while let Ok(ev) = rx.try_recv() {
                match ev {
                    DashboardEvent::RunIdentity {
                        run_id,
                        display_name,
                    } => model.set_run_identity(run_id, display_name),
                    DashboardEvent::RunRenamed { display_name } => {
                        model.set_display_name(display_name);
                    }
                    DashboardEvent::TaskRegistered {
                        id,
                        label,
                        category,
                        depends_on,
                        accepts_input,
                    } => model.register_task_with_category(
                        id,
                        label,
                        category,
                        depends_on,
                        accepts_input,
                    ),
                    DashboardEvent::TaskInputStateChanged { id, enabled } => {
                        model.set_task_input_state(&id, enabled);
                    }
                    DashboardEvent::TaskStateChanged { id, state, detail } => {
                        model.set_task_state(&id, state, detail);
                    }
                    DashboardEvent::LogLine(rec) => pending_logs.push_back(rec),
                    DashboardEvent::RunComplete {
                        success,
                        completed_at,
                    } => apply_run_complete_event(&mut model, success, completed_at),
                    DashboardEvent::UiSuspendRequested { reason, ack } => {
                        if !suspended {
                            if let Some(mut t) = terminal.take() {
                                let _ = restore_terminal(&mut t);
                            }
                            suspended = true;
                        }
                        let _ = reason;
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                    DashboardEvent::UiResumeRequested { ack } => {
                        if suspended {
                            terminal = Some(setup_terminal()?);
                            if let Some(t) = terminal.as_mut() {
                                let _ = t.clear();
                            }
                            suspended = false;
                        }
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                    DashboardEvent::UiDone => done = true,
                }
            }

            let mut processed = 0usize;
            while processed < max_events_per_frame {
                let Some(rec) = pending_logs.pop_front() else {
                    break;
                };
                model.push_task_log(rec);
                processed += 1;
                if !suspended && processed.is_multiple_of(32) {
                    while event::poll(Duration::from_millis(0))? {
                        match event::read()? {
                            Event::Key(k) => {
                                if handle_key_event(
                                    &mut model,
                                    k,
                                    &layout,
                                    &control_tx,
                                    quit_behavior,
                                ) {
                                    done = true;
                                    break;
                                }
                            }
                            Event::Mouse(m) => handle_mouse_event(&mut model, m, &layout),
                            Event::Resize(_, _) => model.reset_task_mouse_stride_calibration(),
                            _ => {}
                        }
                    }
                    if done {
                        break;
                    }
                }
            }

            normalize_active_pane(&mut model);
            if !suspended {
                layout = layout_for(
                    terminal_rect(
                        terminal
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("terminal unavailable"))?,
                    )?,
                    model.show_global_log,
                    model.right_pane_mode,
                    model.active_pane,
                );
                model.ensure_selected_visible(layout.tasks_inner.height as usize);

                terminal
                    .as_mut()
                    .ok_or_else(|| anyhow::anyhow!("terminal unavailable"))?
                    .draw(|f| draw_dashboard(f, &model, &layout))?;
            }

            if processed == 0 {
                std::thread::sleep(idle_tick);
            } else {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        Ok(())
    })();

    let restore_result = if let Some(mut t) = terminal {
        restore_terminal(&mut t)
    } else {
        Ok(())
    };
    match (result, restore_result) {
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
        (Ok(_), Ok(_)) => Ok(()),
    }
}

fn visible_panes(show_global: bool, right_mode: RightPaneMode) -> Vec<ActivePane> {
    let mut out = vec![ActivePane::Tasks];
    match effective_right_mode(show_global, right_mode) {
        RightPaneMode::Split => {
            out.push(ActivePane::TaskLogs);
            if show_global {
                out.push(ActivePane::GlobalLogs);
            }
        }
        RightPaneMode::FocusTask => out.push(ActivePane::TaskLogs),
        RightPaneMode::FocusGlobal => out.push(ActivePane::GlobalLogs),
    }
    out
}

fn normalize_active_pane(model: &mut Model) {
    let panes = visible_panes(model.show_global_log, model.right_pane_mode);
    if !panes.contains(&model.active_pane) {
        model.active_pane = ActivePane::Tasks;
    }
}

fn apply_run_complete_event(model: &mut Model, success: bool, completed_at: Instant) {
    model.run_complete = Some(success);
    model.run_completed_at.get_or_insert(completed_at);
}

fn cycle_next_pane(active: ActivePane, show_global: bool, right_mode: RightPaneMode) -> ActivePane {
    let panes = visible_panes(show_global, right_mode);
    let idx = panes.iter().position(|p| *p == active).unwrap_or(0);
    panes[(idx + 1) % panes.len()]
}

fn cycle_prev_pane(active: ActivePane, show_global: bool, right_mode: RightPaneMode) -> ActivePane {
    let panes = visible_panes(show_global, right_mode);
    let idx = panes.iter().position(|p| *p == active).unwrap_or(0);
    panes[(idx + panes.len() - 1) % panes.len()]
}

fn toggle_right_pane_mode(model: &mut Model) {
    if !model.show_global_log {
        return;
    }
    model.right_pane_mode = match model.right_pane_mode {
        RightPaneMode::Split => {
            if model.active_pane == ActivePane::GlobalLogs {
                RightPaneMode::FocusGlobal
            } else {
                RightPaneMode::FocusTask
            }
        }
        RightPaneMode::FocusTask | RightPaneMode::FocusGlobal => RightPaneMode::Split,
    };
    normalize_active_pane(model);
}

fn handle_key_event(
    model: &mut Model,
    key: KeyEvent,
    layout: &LayoutRects,
    control_tx: &Sender<UiControlEvent>,
    quit_behavior: DashboardQuitBehavior,
) -> bool {
    if key.kind == KeyEventKind::Release {
        return false;
    }
    if handle_prompt_overlay_input(model, key, layout, control_tx) {
        return false;
    }
    if model.rename_edit.is_some() {
        return handle_rename_edit_input(model, key.code, control_tx);
    }
    if model.search_edit.is_some() {
        return handle_search_edit_input(model, key.code, layout);
    }

    let code = key.code;
    let visible_rows = layout.tasks_inner.height as usize;
    match code {
        KeyCode::Char('?') => model.show_help = !model.show_help,
        KeyCode::Char('/') => {
            ensure_search_restore_snapshot(model, model.active_pane);
            model.search_edit = Some(SearchEditState {
                target: model.active_pane,
                buffer: model.search_spec(model.active_pane).query.clone(),
                error: None,
            });
        }
        KeyCode::Char('r') => {
            model.rename_edit = Some(RenameEditState {
                buffer: model
                    .display_name
                    .as_deref()
                    .or(model.run_id.as_deref())
                    .unwrap_or("")
                    .to_string(),
            });
        }
        KeyCode::Char('n') => {
            jump_search_match(model, model.active_pane, true, layout);
        }
        KeyCode::Char('N') => {
            jump_search_match(model, model.active_pane, false, layout);
        }
        KeyCode::Esc => {
            if model.show_help {
                model.show_help = false;
            } else {
                let should_clear = {
                    let spec = model.search_spec(model.active_pane);
                    !spec.query.is_empty() || spec.regex.is_some() || spec.error.is_some()
                };
                if should_clear {
                    clear_search_and_restore(model, model.active_pane, layout);
                }
            }
        }
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            if quit_behavior == DashboardQuitBehavior::CancelAll && model.run_complete.is_none() {
                if !model.cancel_requested {
                    let _ = control_tx.send(UiControlEvent::CancelAll);
                    model.cancel_requested = true;
                }
                return false;
            }
            return true;
        }
        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') => {
            model.active_pane = cycle_next_pane(
                model.active_pane,
                model.show_global_log,
                model.right_pane_mode,
            )
        }
        KeyCode::Left | KeyCode::Char('h') => {
            model.active_pane = cycle_prev_pane(
                model.active_pane,
                model.show_global_log,
                model.right_pane_mode,
            )
        }
        KeyCode::Enter => {
            if let Some(task_id) = latest_prompt_task(model) {
                model.prompt_edit = Some(PromptEditState {
                    task_id,
                    buffer: String::new(),
                });
            } else if model.active_pane == ActivePane::Tasks {
                let panes = visible_panes(model.show_global_log, model.right_pane_mode);
                if panes.contains(&ActivePane::TaskLogs) {
                    model.active_pane = ActivePane::TaskLogs;
                } else if panes.contains(&ActivePane::GlobalLogs) {
                    model.active_pane = ActivePane::GlobalLogs;
                }
            }
        }
        KeyCode::Up => match model.active_pane {
            ActivePane::Tasks => model.move_task_selection(-1, visible_rows),
            ActivePane::TaskLogs => model.task_log_from_bottom += 1,
            ActivePane::GlobalLogs => model.global_log_from_bottom += 1,
        },
        KeyCode::Down | KeyCode::Char('j') => match model.active_pane {
            ActivePane::Tasks => model.move_task_selection(1, visible_rows),
            ActivePane::TaskLogs => {
                model.task_log_from_bottom = model.task_log_from_bottom.saturating_sub(1)
            }
            ActivePane::GlobalLogs => {
                model.global_log_from_bottom = model.global_log_from_bottom.saturating_sub(1)
            }
        },
        KeyCode::PageUp => match model.active_pane {
            ActivePane::TaskLogs => model.task_log_from_bottom += 10,
            ActivePane::GlobalLogs => model.global_log_from_bottom += 10,
            ActivePane::Tasks => model.move_task_selection(-10, visible_rows),
        },
        KeyCode::PageDown => match model.active_pane {
            ActivePane::TaskLogs => {
                model.task_log_from_bottom = model.task_log_from_bottom.saturating_sub(10)
            }
            ActivePane::GlobalLogs => {
                model.global_log_from_bottom = model.global_log_from_bottom.saturating_sub(10)
            }
            ActivePane::Tasks => model.move_task_selection(10, visible_rows),
        },
        KeyCode::Char('g') => match model.active_pane {
            ActivePane::Tasks => model.select_task(0, visible_rows),
            ActivePane::TaskLogs => model.task_log_from_bottom = usize::MAX / 4,
            ActivePane::GlobalLogs => model.global_log_from_bottom = usize::MAX / 4,
        },
        KeyCode::Char('G') => match model.active_pane {
            ActivePane::Tasks => {
                let last = model.task_order.len().saturating_sub(1);
                model.select_task(last, visible_rows);
            }
            ActivePane::TaskLogs => model.task_log_from_bottom = 0,
            ActivePane::GlobalLogs => model.global_log_from_bottom = 0,
        },
        KeyCode::Home => match model.active_pane {
            ActivePane::Tasks => model.select_task(0, visible_rows),
            ActivePane::TaskLogs => model.task_log_from_bottom = usize::MAX / 4,
            ActivePane::GlobalLogs => model.global_log_from_bottom = usize::MAX / 4,
        },
        KeyCode::End => match model.active_pane {
            ActivePane::Tasks => {
                let last = model.task_order.len().saturating_sub(1);
                model.select_task(last, visible_rows);
            }
            ActivePane::TaskLogs => model.task_log_from_bottom = 0,
            ActivePane::GlobalLogs => model.global_log_from_bottom = 0,
        },
        KeyCode::Char('c') => match model.active_pane {
            ActivePane::TaskLogs => {
                if let Some(task_id) = model.selected_task_id().map(|s| s.to_string()) {
                    if let Some(task) = model.tasks.get_mut(&task_id) {
                        task.logs.clear();
                        task.logs_dropped = 0;
                    }
                }
            }
            ActivePane::GlobalLogs => {
                model.global_logs.clear();
                model.global_logs_dropped = 0;
            }
            ActivePane::Tasks => {}
        },
        KeyCode::Char(' ') | KeyCode::Char('z') | KeyCode::Char('Z') => {
            toggle_right_pane_mode(model)
        }
        KeyCode::Char('m') | KeyCode::Char('M') => {
            if let Some(target) = current_log_view_target(model) {
                let _ = control_tx.send(UiControlEvent::OpenLog { target });
            }
        }
        KeyCode::Char('w') | KeyCode::Char('W') => model.wrap_logs = !model.wrap_logs,
        KeyCode::Char('k') => {
            if let Some(task_id) = model
                .run_complete
                .is_none()
                .then(|| model.selected_task_id().map(|s| s.to_string()))
                .flatten()
            {
                let _ = control_tx.send(UiControlEvent::CancelTask { id: task_id });
            }
        }
        KeyCode::Char('K') => {
            if model.run_complete.is_none() {
                let _ = control_tx.send(UiControlEvent::CancelAll);
            }
        }
        _ => {}
    }
    false
}

fn handle_prompt_overlay_input(
    model: &mut Model,
    key: KeyEvent,
    layout: &LayoutRects,
    control_tx: &Sender<UiControlEvent>,
) -> bool {
    let prompt_visible = find_latest_prompt(model).is_some();
    if !prompt_visible && model.prompt_edit.is_none() {
        return false;
    }

    let page_rows = prompt_overlay_inner_rect(layout.root)
        .height
        .saturating_sub(1) as usize;
    let page_rows = page_rows.max(1);

    if prompt_visible && model.prompt_edit.is_none() {
        match key.code {
            KeyCode::Enter => {
                if let Some(task_id) = latest_prompt_task(model) {
                    let _ = control_tx.send(UiControlEvent::SendStdin {
                        id: task_id,
                        line: String::new(),
                    });
                }
                return true;
            }
            KeyCode::Char(character) if !character.is_control() => {
                if let Some(task_id) = latest_prompt_task(model) {
                    model.prompt_edit = Some(PromptEditState {
                        task_id,
                        buffer: character.to_string(),
                    });
                }
                return true;
            }
            _ => {}
        }
    }

    match key.code {
        KeyCode::Up => {
            model.prompt_scroll_from_bottom += 1;
            true
        }
        KeyCode::PageUp => {
            model.prompt_scroll_from_bottom += page_rows;
            true
        }
        KeyCode::Down => {
            model.prompt_scroll_from_bottom = model.prompt_scroll_from_bottom.saturating_sub(1);
            true
        }
        KeyCode::PageDown => {
            model.prompt_scroll_from_bottom =
                model.prompt_scroll_from_bottom.saturating_sub(page_rows);
            true
        }
        KeyCode::Home | KeyCode::Char('g') => {
            model.prompt_scroll_from_bottom = usize::MAX / 4;
            true
        }
        KeyCode::End | KeyCode::Char('G') => {
            model.prompt_scroll_from_bottom = 0;
            true
        }
        _ if model.prompt_edit.is_some() => {
            handle_prompt_edit_input(model, key, control_tx);
            true
        }
        _ => false,
    }
}

fn handle_prompt_edit_input(
    model: &mut Model,
    key: KeyEvent,
    control_tx: &Sender<UiControlEvent>,
) -> bool {
    let Some(mut edit) = model.prompt_edit.take() else {
        return false;
    };
    match key.code {
        KeyCode::Esc => return false,
        KeyCode::Enter => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                edit.buffer.push('\n');
                model.prompt_edit = Some(edit);
                return false;
            }
            let line = edit.buffer.clone();
            let _ = control_tx.send(UiControlEvent::SendStdin {
                id: edit.task_id,
                line,
            });
            return false;
        }
        KeyCode::Backspace => {
            edit.buffer.pop();
        }
        KeyCode::Char(c) => {
            if !c.is_control() {
                edit.buffer.push(c);
            }
        }
        _ => {}
    }
    model.prompt_edit = Some(edit);
    false
}

fn handle_rename_edit_input(
    model: &mut Model,
    code: KeyCode,
    control_tx: &Sender<UiControlEvent>,
) -> bool {
    let Some(mut edit) = model.rename_edit.take() else {
        return false;
    };
    match code {
        KeyCode::Esc => false,
        KeyCode::Enter => {
            let name = edit.buffer.trim().to_string();
            if !name.is_empty() {
                let _ = control_tx.send(UiControlEvent::RenameRun { name });
            }
            false
        }
        KeyCode::Backspace => {
            edit.buffer.pop();
            model.rename_edit = Some(edit);
            false
        }
        KeyCode::Char(c) => {
            if !c.is_control() {
                edit.buffer.push(c);
            }
            model.rename_edit = Some(edit);
            false
        }
        _ => {
            model.rename_edit = Some(edit);
            false
        }
    }
}

fn handle_search_edit_input(model: &mut Model, code: KeyCode, layout: &LayoutRects) -> bool {
    let Some(mut edit) = model.search_edit.take() else {
        return false;
    };
    match code {
        KeyCode::Esc => {
            return false;
        }
        KeyCode::Enter => {
            let query = edit.buffer.trim().to_string();
            if query.is_empty() {
                clear_search_and_restore(model, edit.target, layout);
                return false;
            }
            match Regex::new(&query) {
                Ok(re) => {
                    ensure_search_restore_snapshot(model, edit.target);
                    let spec = model.search_spec_mut(edit.target);
                    spec.last_match = None;
                    spec.query = query;
                    spec.regex = Some(re);
                    spec.error = None;
                    jump_search_match(model, edit.target, true, layout);
                    return false;
                }
                Err(e) => {
                    let msg = format!("invalid regex: {e}");
                    edit.error = Some(msg.clone());
                    let spec = model.search_spec_mut(edit.target);
                    spec.last_match = None;
                    spec.error = Some(msg);
                    model.search_edit = Some(edit);
                    return false;
                }
            }
        }
        KeyCode::Backspace => {
            edit.buffer.pop();
        }
        KeyCode::Char(c) => {
            if !c.is_control() {
                edit.buffer.push(c);
            }
        }
        _ => {}
    }
    model.search_edit = Some(edit);
    false
}

fn handle_mouse_event(model: &mut Model, mouse: MouseEvent, layout: &LayoutRects) {
    let prompt_visible = find_latest_prompt(model).is_some();
    let prompt_area = prompt_overlay_area(layout.root);
    if prompt_visible && rect_contains(prompt_area, mouse.column, mouse.row) {
        match mouse.kind {
            MouseEventKind::ScrollUp => model.prompt_scroll_from_bottom += 1,
            MouseEventKind::ScrollDown => {
                model.prompt_scroll_from_bottom = model.prompt_scroll_from_bottom.saturating_sub(1)
            }
            MouseEventKind::Down(MouseButton::Left) => {}
            _ => {}
        }
        return;
    }

    let visible_rows = layout.tasks_inner.height as usize;
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let col = mouse.column;
            let row = mouse.row;

            if rect_contains(layout.tasks, col, row) {
                model.active_pane = ActivePane::Tasks;
                model.observe_task_mouse_row(layout.tasks_inner, row);
                if let Some(idx) = task_index_for_mouse(
                    layout.tasks_inner,
                    model.task_list_offset,
                    model.task_order.len(),
                    row,
                    model.task_mouse_row_stride,
                ) {
                    model.select_task(idx, visible_rows);
                }
                return;
            }
            if let Some(task_logs) = layout.task_logs {
                if rect_contains(task_logs, col, row) {
                    model.active_pane = ActivePane::TaskLogs;
                    return;
                }
            }
            if let Some(global_logs) = layout.global_logs {
                if rect_contains(global_logs, col, row) {
                    model.active_pane = ActivePane::GlobalLogs;
                }
            }
        }
        MouseEventKind::ScrollUp => match model.active_pane {
            ActivePane::Tasks => {
                model.observe_task_mouse_row(layout.tasks_inner, mouse.row);
                if !model.suppress_duplicate_task_wheel(true, mouse.row) {
                    model.move_task_selection(-1, visible_rows);
                }
            }
            ActivePane::TaskLogs => model.task_log_from_bottom += 1,
            ActivePane::GlobalLogs => model.global_log_from_bottom += 1,
        },
        MouseEventKind::ScrollDown => match model.active_pane {
            ActivePane::Tasks => {
                model.observe_task_mouse_row(layout.tasks_inner, mouse.row);
                if !model.suppress_duplicate_task_wheel(false, mouse.row) {
                    model.move_task_selection(1, visible_rows);
                }
            }
            ActivePane::TaskLogs => {
                model.task_log_from_bottom = model.task_log_from_bottom.saturating_sub(1)
            }
            ActivePane::GlobalLogs => {
                model.global_log_from_bottom = model.global_log_from_bottom.saturating_sub(1)
            }
        },
        _ => {}
    }
}

fn task_index_for_mouse(
    tasks_inner: Rect,
    task_list_offset: usize,
    total_tasks: usize,
    mouse_row: u16,
    row_stride: u16,
) -> Option<usize> {
    if tasks_inner.height == 0
        || mouse_row < tasks_inner.y
        || mouse_row >= tasks_inner.y + tasks_inner.height
    {
        return None;
    }
    let stride = row_stride.max(1) as usize;
    let rel = (mouse_row - tasks_inner.y) as usize / stride;
    let idx = task_list_offset + rel;
    if idx < total_tasks {
        Some(idx)
    } else {
        None
    }
}

fn rect_contains(rect: Rect, x: u16, y: u16) -> bool {
    x >= rect.x && x < rect.x + rect.width && y >= rect.y && y < rect.y + rect.height
}

fn snapshot_search_restore(model: &Model, pane: ActivePane) -> SearchRestore {
    match pane {
        ActivePane::Tasks => SearchRestore::Tasks {
            selected_task: model.selected_task,
            task_list_offset: model.task_list_offset,
        },
        ActivePane::TaskLogs => SearchRestore::TaskLogs {
            from_bottom: model.task_log_from_bottom,
        },
        ActivePane::GlobalLogs => SearchRestore::GlobalLogs {
            from_bottom: model.global_log_from_bottom,
        },
    }
}

fn ensure_search_restore_snapshot(model: &mut Model, pane: ActivePane) {
    let needs_restore = model.search_spec(pane).restore.is_none();
    if needs_restore {
        let restore = snapshot_search_restore(model, pane);
        model.search_spec_mut(pane).restore = Some(restore);
    }
}

fn clear_search_and_restore(model: &mut Model, pane: ActivePane, layout: &LayoutRects) {
    let restore = model.search_spec(pane).restore;
    *model.search_spec_mut(pane) = SearchSpec::default();
    let Some(restore) = restore else {
        return;
    };

    match restore {
        SearchRestore::Tasks {
            selected_task,
            task_list_offset,
        } => {
            model.selected_task = selected_task.min(model.task_order.len().saturating_sub(1));
            model.task_list_offset = task_list_offset;
            model.ensure_selected_visible(layout.tasks_inner.height as usize);
        }
        SearchRestore::TaskLogs { from_bottom } => {
            model.task_log_from_bottom = from_bottom;
        }
        SearchRestore::GlobalLogs { from_bottom } => {
            model.global_log_from_bottom = from_bottom;
        }
    }
}

fn jump_search_match(model: &mut Model, pane: ActivePane, forward: bool, layout: &LayoutRects) {
    let re = model.search_spec(pane).regex.clone();
    let Some(re) = re else {
        return;
    };
    ensure_search_restore_snapshot(model, pane);

    match pane {
        ActivePane::Tasks => {
            let matches: Vec<usize> = model
                .task_order
                .iter()
                .enumerate()
                .filter_map(|(idx, task_id)| {
                    let row = model.tasks.get(task_id)?;
                    task_matches_regex(row, &re).then_some(idx)
                })
                .collect();
            if matches.is_empty() {
                model.search_spec_mut(pane).last_match = None;
                return;
            }
            let next = pick_next_match(&matches, model.search_spec(pane).last_match, forward);
            model.search_spec_mut(pane).last_match = Some(next);
            model.select_task(next, layout.tasks_inner.height as usize);
        }
        ActivePane::TaskLogs => {
            let task_id = match model.selected_task_id() {
                Some(id) => id.to_string(),
                None => return,
            };
            let (matches, total) = {
                let Some(task) = model.tasks.get(&task_id) else {
                    return;
                };
                let matches: Vec<usize> = task
                    .logs
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, rec)| re.is_match(&rec.line).then_some(idx))
                    .collect();
                (matches, task.logs.len())
            };
            if matches.is_empty() {
                model.search_spec_mut(pane).last_match = None;
                return;
            }
            let next = pick_next_match(&matches, model.search_spec(pane).last_match, forward);
            model.search_spec_mut(pane).last_match = Some(next);
            model.task_log_from_bottom = total.saturating_sub(next + 1);
        }
        ActivePane::GlobalLogs => {
            let matches: Vec<usize> = model
                .global_logs
                .iter()
                .enumerate()
                .filter_map(|(idx, rec)| re.is_match(&rec.line).then_some(idx))
                .collect();
            if matches.is_empty() {
                model.search_spec_mut(pane).last_match = None;
                return;
            }
            let next = pick_next_match(&matches, model.search_spec(pane).last_match, forward);
            model.search_spec_mut(pane).last_match = Some(next);
            let total = model.global_logs.len();
            model.global_log_from_bottom = total.saturating_sub(next + 1);
        }
    }
}

fn pick_next_match(matches: &[usize], last: Option<usize>, forward: bool) -> usize {
    if matches.is_empty() {
        return 0;
    }
    if let Some(last) = last {
        if forward {
            for m in matches {
                if *m > last {
                    return *m;
                }
            }
            matches[0]
        } else {
            for m in matches.iter().rev() {
                if *m < last {
                    return *m;
                }
            }
            *matches.last().unwrap_or(&matches[0])
        }
    } else if forward {
        matches[0]
    } else {
        *matches.last().unwrap_or(&matches[0])
    }
}

fn task_matches_regex(row: &TaskRow, re: &Regex) -> bool {
    if re.is_match(&row.id) || re.is_match(&row.label) {
        return true;
    }
    if let Some(detail) = &row.detail {
        if re.is_match(detail) {
            return true;
        }
    }
    false
}

fn effective_right_mode(show_global: bool, mode: RightPaneMode) -> RightPaneMode {
    if show_global {
        mode
    } else {
        RightPaneMode::FocusTask
    }
}

fn layout_for(
    root: Rect,
    show_global_log: bool,
    right_mode: RightPaneMode,
    active_pane: ActivePane,
) -> LayoutRects {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(6),
        ])
        .split(root);

    let mid = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(67)])
        .split(chunks[1]);

    let right_mode = effective_right_mode(show_global_log, right_mode);

    let (task_logs, global_logs) = match right_mode {
        RightPaneMode::Split => {
            let right = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
                .split(mid[1]);
            (Some(right[0]), show_global_log.then_some(right[1]))
        }
        RightPaneMode::FocusTask => (Some(mid[1]), None),
        RightPaneMode::FocusGlobal => {
            if show_global_log {
                (None, Some(mid[1]))
            } else {
                (Some(mid[1]), None)
            }
        }
    };

    let mut task_logs = task_logs;
    let mut global_logs = global_logs;

    // Keep at least one right pane visible for current active pane transitions.
    if active_pane == ActivePane::TaskLogs && task_logs.is_none() {
        task_logs = Some(mid[1]);
        global_logs = None;
    }
    if active_pane == ActivePane::GlobalLogs && global_logs.is_none() && show_global_log {
        task_logs = None;
        global_logs = Some(mid[1]);
    }

    LayoutRects {
        root,
        header: chunks[0],
        tasks: mid[0],
        tasks_inner: inner_rect(mid[0]),
        task_logs,
        global_logs,
        footer: chunks[2],
    }
}

fn inner_rect(rect: Rect) -> Rect {
    Rect::new(
        rect.x.saturating_add(1),
        rect.y.saturating_add(1),
        rect.width.saturating_sub(2),
        rect.height.saturating_sub(2),
    )
}

fn draw_dashboard(frame: &mut ratatui::Frame<'_>, model: &Model, layout: &LayoutRects) {
    frame.render_widget(Clear, layout.root);

    let status_color = match model.run_complete {
        Some(true) => Color::LightGreen,
        Some(false) => Color::LightRed,
        None => Color::Yellow,
    };
    let (pending, running, completed, failed, canceled) = model.task_state_counts();
    let elapsed = model_elapsed(model);
    let result_label = match model.run_complete {
        Some(true) => " completed ",
        Some(false) => " failed ",
        None => " running ",
    };
    let header = Paragraph::new(Line::from(render_header_spans(
        model,
        result_label,
        status_color,
        elapsed.as_secs(),
        (pending, running, completed, failed, canceled),
        layout.header.width.saturating_sub(2) as usize,
    )))
    .block(Block::default().borders(Borders::ALL).title("Dashboard"));
    frame.render_widget(header, layout.header);

    let tasks_widget = List::new(render_task_items(
        model,
        layout.tasks_inner.height as usize,
        layout.tasks_inner.width as usize,
    ))
    .block(pane_block("Tasks", model.active_pane == ActivePane::Tasks));
    frame.render_widget(tasks_widget, layout.tasks);

    if let Some(rect) = layout.task_logs {
        let inner = inner_rect(rect);
        let task_lines = render_focused_task_logs_viewport(
            model,
            model.task_log_from_bottom,
            inner.width as usize,
            inner.height as usize,
            model.wrap_logs,
        );
        let focused_logs_widget = Paragraph::new(task_lines).block(pane_block(
            "Task Logs",
            model.active_pane == ActivePane::TaskLogs,
        ));
        frame.render_widget(focused_logs_widget, rect);
    }

    if let Some(rect) = layout.global_logs {
        let inner = inner_rect(rect);
        let global_lines = render_global_logs_viewport(
            model,
            model.global_log_from_bottom,
            inner.width as usize,
            inner.height as usize,
            model.wrap_logs,
        );
        let global_widget = Paragraph::new(global_lines).block(pane_block(
            "Global Logs",
            model.active_pane == ActivePane::GlobalLogs,
        ));
        frame.render_widget(global_widget, rect);
    }

    let footer = Paragraph::new(render_footer_lines(model))
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, layout.footer);

    if let Some((task_id, prompt)) = find_latest_prompt(model) {
        let context_lines = prompt_overlay_context_lines(model, &task_id, &prompt);
        draw_prompt_overlay(
            frame,
            layout.root,
            &task_id,
            &prompt,
            &context_lines,
            model.prompt_edit.as_ref(),
            model.prompt_scroll_from_bottom,
        );
    }

    if let Some(edit) = model.rename_edit.as_ref() {
        draw_rename_overlay(frame, layout.root, edit);
    }

    if model.show_help {
        draw_help(frame, layout.root);
    }
}

fn render_header_spans(
    model: &Model,
    result_label: &str,
    status_color: Color,
    elapsed_secs: u64,
    counts: (usize, usize, usize, usize, usize),
    width: usize,
) -> Vec<Span<'static>> {
    let (pending, running, completed, failed, canceled) = counts;
    let mut spans = vec![
        Span::styled(
            " update-all ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            result_label.to_string(),
            Style::default()
                .fg(Color::Black)
                .bg(status_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::styled(
            format!("elapsed={elapsed_secs}s"),
            Style::default().fg(Color::White),
        ),
        Span::raw("  "),
        Span::styled(format!("run={running}"), Style::default().fg(Color::Cyan)),
        Span::raw(" "),
        Span::styled(format!("ok={completed}"), Style::default().fg(Color::Green)),
        Span::raw(" "),
        Span::styled(format!("fail={failed}"), Style::default().fg(Color::Red)),
        Span::raw(" "),
        Span::styled(
            format!("wait={pending}"),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw(" "),
        Span::styled(
            format!("cancel={canceled}"),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("  "),
        Span::styled(
            format!("pane={}", active_pane_name(model.active_pane)),
            Style::default().fg(Color::LightMagenta),
        ),
        Span::raw(" "),
        Span::styled(
            format!("wrap={}", if model.wrap_logs { "on" } else { "off" }),
            Style::default().fg(Color::LightBlue),
        ),
    ];
    let identity = compact_run_identity(model, width);
    while !identity.is_empty()
        && spans_width(&spans) + identity.width() + 2 > width
        && spans.len() > 8
    {
        spans.pop();
    }
    if !identity.is_empty() && spans_width(&spans) + identity.width() + 2 <= width {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            identity,
            Style::default().fg(Color::LightYellow),
        ));
    }
    while spans_width(&spans) > width && spans.len() > 8 {
        spans.pop();
    }
    spans
}

fn compact_run_identity(model: &Model, width: usize) -> String {
    let run_id = model.run_id.as_deref().unwrap_or("");
    if run_id.is_empty() {
        return String::new();
    }
    let display_name = model.display_name.as_deref().unwrap_or(run_id);
    let short_id = short_run_id(run_id);
    let full = format!("name={display_name} id={short_id}");
    if full.width() <= width.saturating_div(3).max(12) {
        return full;
    }
    let name_only = format!("name={display_name}");
    if name_only.width() <= width.saturating_div(4).max(12) {
        return name_only;
    }
    format!("id={short_id}")
}

fn short_run_id(run_id: &str) -> String {
    let compact = run_id.trim();
    if compact.chars().count() <= 12 {
        return compact.to_string();
    }
    let suffix = compact
        .chars()
        .rev()
        .take(12)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    format!("...{suffix}")
}

fn spans_width(spans: &[Span<'_>]) -> usize {
    spans.iter().map(|span| span.content.width()).sum()
}

fn pane_block<'a>(base: &'a str, active: bool) -> Block<'a> {
    let title = if active {
        format!("{base} [active]")
    } else {
        base.to_string()
    };
    let mut block = Block::default().borders(Borders::ALL).title(title);
    if active {
        block = block.border_style(Style::default().fg(Color::LightCyan));
    }
    block
}

fn render_footer_lines(model: &Model) -> Vec<Line<'static>> {
    let cancel_help = if model.run_complete.is_some() {
        vec![
            Span::styled("m", Style::default().fg(Color::Yellow)),
            Span::raw(" open log  "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" close dashboard"),
        ]
    } else {
        vec![
            Span::styled("m", Style::default().fg(Color::Yellow)),
            Span::raw(" open log  "),
            Span::styled("k/K", Style::default().fg(Color::Yellow)),
            Span::raw(" kill one/all  "),
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" exit"),
        ]
    };

    let mut second_line = vec![
        Span::styled("w", Style::default().fg(Color::Yellow)),
        Span::raw(" wrap logs  "),
        Span::styled("z/Space", Style::default().fg(Color::Yellow)),
        Span::raw(" focus logs  "),
    ];
    second_line.extend(cancel_help);
    second_line.extend([
        Span::raw("  "),
        Span::styled("click", Style::default().fg(Color::Yellow)),
        Span::raw(" select  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" close overlay"),
    ]);

    let mut lines = vec![
        Line::from(vec![
            Span::styled("Tab/h/l", Style::default().fg(Color::Yellow)),
            Span::raw(" pane  "),
            Span::styled("↑/↓/j", Style::default().fg(Color::Yellow)),
            Span::raw(" move/scroll  "),
            Span::styled("PgUp/PgDn", Style::default().fg(Color::Yellow)),
            Span::raw(" page  "),
            Span::styled("Home/End", Style::default().fg(Color::Yellow)),
            Span::raw(" top/bottom  "),
            Span::styled("/", Style::default().fg(Color::Yellow)),
            Span::raw(" search(regex)  "),
            Span::styled("n/N", Style::default().fg(Color::Yellow)),
            Span::raw(" next/prev"),
        ]),
        Line::from(second_line),
    ];

    if let Some(edit) = &model.search_edit {
        let pane = pane_name(edit.target);
        lines.push(Line::from(vec![
            Span::styled(
                format!("search({pane})> "),
                Style::default().fg(Color::LightCyan),
            ),
            Span::raw(edit.buffer.clone()),
        ]));
        if let Some(err) = &edit.error {
            lines.push(Line::from(vec![Span::styled(
                err.clone(),
                Style::default().fg(Color::Red),
            )]));
        }
    } else {
        let spec = model.search_spec(model.active_pane);
        if !spec.query.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("active search: ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    format!("/{}/", spec.query),
                    Style::default().fg(Color::LightCyan),
                ),
            ]));
            if let Some(err) = &spec.error {
                lines.push(Line::from(vec![Span::styled(
                    err.clone(),
                    Style::default().fg(Color::Red),
                )]));
            }
        }
    }

    lines
}

fn model_elapsed(model: &Model) -> Duration {
    model
        .run_completed_at
        .map(|completed_at| completed_at.saturating_duration_since(model.started_at))
        .unwrap_or_else(|| model.started_at.elapsed())
}

fn pane_name(pane: ActivePane) -> &'static str {
    match pane {
        ActivePane::Tasks => "tasks",
        ActivePane::TaskLogs => "task-logs",
        ActivePane::GlobalLogs => "global-logs",
    }
}

fn render_task_items(
    model: &Model,
    visible_rows: usize,
    inner_width: usize,
) -> Vec<ListItem<'static>> {
    const TASK_LABEL_WIDTH: usize = 14;
    let mut items = Vec::new();
    if model.task_order.is_empty() {
        items.push(ListItem::new(Line::from("Waiting for tasks...")));
        return items;
    }

    if visible_rows == 0 {
        return items;
    }

    let start = model.task_list_offset.min(model.task_order.len());
    let end = (start + visible_rows).min(model.task_order.len());
    for idx in start..end {
        let task_id = &model.task_order[idx];
        if let Some(row) = model.tasks.get(task_id) {
            let selected = idx == model.selected_task;
            let matched = model
                .task_search
                .regex
                .as_ref()
                .is_some_and(|re| task_matches_regex(row, re));
            let status = match row.state {
                TaskState::Pending => {
                    let waiting = model.dependency_waiting_on(row);
                    if waiting.is_empty() {
                        "Pending".to_string()
                    } else {
                        format!("Pending ({})", waiting.join(","))
                    }
                }
                TaskState::Running => "Running".to_string(),
                TaskState::Completed => "Completed".to_string(),
                TaskState::Failed => "Failed".to_string(),
                TaskState::Canceled => "Canceled".to_string(),
                TaskState::Skipped => "Skipped".to_string(),
            };
            let status_color = state_color(row.state);
            let mut marker_style = Style::default().fg(Color::DarkGray);
            let mut label_style = Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD);
            let mut status_style = Style::default().fg(status_color);
            let mut detail_style = Style::default().fg(match row.state {
                TaskState::Completed => Color::Green,
                TaskState::Failed => Color::Red,
                TaskState::Canceled => Color::Yellow,
                TaskState::Running => Color::Cyan,
                TaskState::Pending => Color::DarkGray,
                TaskState::Skipped => Color::Blue,
            });
            let mut marker = if selected { "▶ " } else { "  " };

            if row.state == TaskState::Running {
                marker = if selected { "▶ " } else { "● " };
                marker_style = marker_style.fg(Color::Cyan);
                status_style = status_style.fg(Color::Cyan).add_modifier(Modifier::BOLD);
            }

            if selected {
                marker_style = marker_style
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD);
                label_style = label_style
                    .fg(Color::White)
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD);
                status_style = status_style.add_modifier(Modifier::REVERSED | Modifier::BOLD);
                detail_style = detail_style
                    .fg(Color::Gray)
                    .add_modifier(Modifier::REVERSED | Modifier::BOLD);
            }
            if matched && !selected {
                label_style = label_style
                    .fg(Color::LightMagenta)
                    .add_modifier(Modifier::UNDERLINED);
                status_style = status_style.add_modifier(Modifier::UNDERLINED);
                detail_style = detail_style.add_modifier(Modifier::UNDERLINED);
            }

            let line = vec![
                Span::styled(marker, marker_style),
                Span::styled(
                    format!(
                        "{:<width$}",
                        fit_task_label(&sanitize_log_line(&row.label), TASK_LABEL_WIDTH),
                        width = TASK_LABEL_WIDTH
                    ),
                    label_style,
                ),
                Span::raw(" "),
                Span::styled(
                    fit_task_status_detail(&status, row.detail.as_deref(), inner_width),
                    status_style,
                ),
            ];
            let _ = detail_style;
            let starts_group = idx == start
                || model
                    .task_order
                    .get(idx.saturating_sub(1))
                    .and_then(|previous_id| model.tasks.get(previous_id))
                    .is_none_or(|previous| previous.category != row.category);
            let task_line = Line::from(line);
            if starts_group {
                items.push(ListItem::new(vec![
                    Line::from(Span::styled(
                        functional_group_label(&row.category),
                        Style::default()
                            .fg(Color::LightBlue)
                            .add_modifier(Modifier::BOLD),
                    )),
                    task_line,
                ]));
            } else {
                items.push(ListItem::new(task_line));
            }
        }
    }
    items
}

fn functional_group_label(category: &str) -> &'static str {
    match category {
        "system" | "system-packages" => "System Packages",
        "language" | "developer-tools" => "Developer Tools",
        "agent-tooling" => "Agent Tooling",
        "android-mobile" | "mobile-reverse-engineering" => "Mobile & Reverse Engineering",
        "game-dev" | "game-development" => "Game Development",
        "maintenance" => "Maintenance",
        _ => "Developer Tools",
    }
}

fn fit_task_status_detail(status: &str, detail: Option<&str>, inner_width: usize) -> String {
    const TASK_PREFIX_WIDTH: usize = 2 + 14 + 1;
    let available = inner_width.saturating_sub(TASK_PREFIX_WIDTH);
    if available == 0 {
        return String::new();
    }
    let status = sanitize_log_line(status);
    let Some(detail) = detail.map(sanitize_log_line).filter(|d| !d.is_empty()) else {
        return fit_display_width(&status, available);
    };
    let full = format!("{status} {detail}");
    if UnicodeWidthStr::width(full.as_str()) <= available {
        return full;
    }
    let status_width = UnicodeWidthStr::width(status.as_str());
    if status_width >= available {
        return fit_display_width(&status, available);
    }
    let detail_width = available.saturating_sub(status_width + 1);
    if detail_width < 4 {
        return status;
    }
    let compact_detail = fit_display_width(&detail, detail_width);
    if compact_detail.is_empty() {
        status
    } else {
        format!("{status} {compact_detail}")
    }
}

fn fit_display_width(input: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(input) <= width {
        return input.to_string();
    }
    if width <= 3 {
        return take_display_width(input, width);
    }
    let mut out = take_display_width(input, width - 3);
    out.push_str("...");
    out
}

fn take_display_width(input: &str, width: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for ch in input.chars() {
        let ch_width = ch.width().unwrap_or(0);
        if used + ch_width > width {
            break;
        }
        out.push(ch);
        used += ch_width;
    }
    out
}

fn fit_task_label(input: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let char_count = input.chars().count();
    if char_count <= width {
        return input.to_string();
    }
    if width <= 3 {
        return input.chars().take(width).collect();
    }
    let mut out: String = input.chars().take(width - 3).collect();
    out.push_str("...");
    out
}

fn render_focused_task_logs(model: &Model) -> Vec<Line<'static>> {
    let Some(task) = model.selected_task_row() else {
        return vec![Line::from("No task selected.")];
    };
    if task.logs.is_empty() {
        return vec![Line::from("No logs yet.")];
    }
    let mut lines = Vec::new();
    if task.logs_dropped > 0 {
        lines.push(task_truncation_banner(task.logs_dropped));
    }
    let mut report_state = ReportHighlightState::None;
    let records = task.logs.iter().cloned().collect::<Vec<_>>();
    for (idx, rec) in records.iter().enumerate() {
        let matched = model
            .task_log_search
            .regex
            .as_ref()
            .is_some_and(|re| re.is_match(&rec.line));
        let line = render_log_record_line(
            rec,
            matched,
            report_state,
            labeled_version_color_mode(&records, idx),
            false,
            model.task_colors,
        );
        report_state = advance_report_highlight_state(report_state, rec);
        lines.push(line);
    }
    lines
}

fn render_focused_task_logs_viewport(
    model: &Model,
    from_bottom: usize,
    width: usize,
    height: usize,
    wrap: bool,
) -> Vec<Line<'static>> {
    let Some(task) = model.selected_task_row() else {
        return vec![Line::from("No task selected.")];
    };
    if task.logs.is_empty() {
        return vec![Line::from("No logs yet.")];
    }
    let records = task.logs.iter().cloned().collect::<Vec<_>>();
    let banner = (task.logs_dropped > 0).then(|| task_truncation_banner(task.logs_dropped));
    let Some(slice) = log_viewport_slice(
        &records,
        banner.as_ref(),
        from_bottom,
        width,
        height,
        wrap,
        false,
    ) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    if slice.banner_visible {
        if let Some(banner) = banner {
            lines.push(banner);
        }
    }

    let mut report_state = report_state_before(&records, slice.record_start);
    for (idx, rec) in records
        .iter()
        .enumerate()
        .take(slice.record_end)
        .skip(slice.record_start)
    {
        let matched = model
            .task_log_search
            .regex
            .as_ref()
            .is_some_and(|re| re.is_match(&rec.line));
        lines.push(render_log_record_line(
            rec,
            matched,
            report_state,
            labeled_version_color_mode(&records, idx),
            false,
            model.task_colors,
        ));
        report_state = advance_report_highlight_state(report_state, rec);
    }
    take_visible_rows(&lines, 0, width, height, wrap)
}

fn render_global_logs(model: &Model) -> Vec<Line<'static>> {
    if model.global_logs.is_empty() {
        return vec![Line::from("No logs yet.")];
    }
    let mut lines = Vec::new();
    if model.global_logs_dropped > 0 {
        lines.push(global_truncation_banner(model.global_logs_dropped));
    }
    let mut report_states: BTreeMap<String, ReportHighlightState> = BTreeMap::new();
    let records = model.global_logs.iter().cloned().collect::<Vec<_>>();
    for (idx, rec) in records.iter().enumerate() {
        let matched = model
            .global_log_search
            .regex
            .as_ref()
            .is_some_and(|re| re.is_match(&rec.line));
        let report_state = report_states
            .get(&rec.task_id)
            .copied()
            .unwrap_or(ReportHighlightState::None);
        let line = render_log_record_line(
            rec,
            matched,
            report_state,
            labeled_version_color_mode(&records, idx),
            true,
            model.task_colors,
        );
        report_states.insert(
            rec.task_id.clone(),
            advance_report_highlight_state(report_state, rec),
        );
        lines.push(line);
    }
    lines
}

fn render_global_logs_viewport(
    model: &Model,
    from_bottom: usize,
    width: usize,
    height: usize,
    wrap: bool,
) -> Vec<Line<'static>> {
    if model.global_logs.is_empty() {
        return vec![Line::from("No logs yet.")];
    }
    let records = model.global_logs.iter().cloned().collect::<Vec<_>>();
    let banner = (model.global_logs_dropped > 0)
        .then(|| global_truncation_banner(model.global_logs_dropped));
    let Some(slice) = log_viewport_slice(
        &records,
        banner.as_ref(),
        from_bottom,
        width,
        height,
        wrap,
        true,
    ) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    if slice.banner_visible {
        if let Some(banner) = banner {
            lines.push(banner);
        }
    }

    let mut report_states = report_states_before(&records, slice.record_start);
    for (idx, rec) in records
        .iter()
        .enumerate()
        .take(slice.record_end)
        .skip(slice.record_start)
    {
        let matched = model
            .global_log_search
            .regex
            .as_ref()
            .is_some_and(|re| re.is_match(&rec.line));
        let report_state = report_states
            .get(&rec.task_id)
            .copied()
            .unwrap_or(ReportHighlightState::None);
        lines.push(render_log_record_line(
            rec,
            matched,
            report_state,
            labeled_version_color_mode(&records, idx),
            true,
            model.task_colors,
        ));
        report_states.insert(
            rec.task_id.clone(),
            advance_report_highlight_state(report_state, rec),
        );
    }
    take_visible_rows(&lines, 0, width, height, wrap)
}

#[derive(Clone, Copy, Debug)]
struct LogViewportSlice {
    banner_visible: bool,
    record_start: usize,
    record_end: usize,
}

fn log_viewport_slice(
    records: &[LogRecord],
    banner: Option<&Line<'static>>,
    from_bottom: usize,
    width: usize,
    height: usize,
    wrap: bool,
    include_task: bool,
) -> Option<LogViewportSlice> {
    if height == 0 {
        return None;
    }

    let banner_rows = banner.map_or(0, |line| line_row_count(line, width, wrap));
    let record_rows = records
        .iter()
        .map(|rec| log_record_row_count(rec, width, wrap, include_task))
        .collect::<Vec<_>>();
    let total_rows = banner_rows + record_rows.iter().sum::<usize>();
    if total_rows == 0 {
        return None;
    }

    let capped_from_bottom = from_bottom.min(total_rows.saturating_sub(height));
    let end = total_rows.saturating_sub(capped_from_bottom);
    let start = end.saturating_sub(height);
    let banner_visible = banner_rows > 0 && start < banner_rows && end > 0;

    let mut cursor = banner_rows;
    let mut record_start = None;
    let mut record_end = 0usize;
    for (idx, rows) in record_rows.iter().copied().enumerate() {
        let next = cursor.saturating_add(rows);
        if cursor < end && next > start {
            if record_start.is_none() {
                record_start = Some(idx);
            }
            record_end = idx + 1;
        }
        cursor = next;
    }

    Some(LogViewportSlice {
        banner_visible,
        record_start: record_start.unwrap_or(0),
        record_end,
    })
}

fn log_record_row_count(rec: &LogRecord, width: usize, wrap: bool, include_task: bool) -> usize {
    if !wrap {
        return 1;
    }
    let visible = log_record_plain_width(rec, include_task).max(1);
    visible.div_ceil(width.max(1))
}

fn log_record_plain_width(rec: &LogRecord, include_task: bool) -> usize {
    let mut width = UnicodeWidthStr::width(fmt_ts(rec.ts_unix_ms).as_str()) + 1;
    if include_task {
        width += UnicodeWidthStr::width(rec.task_id.as_str()) + 1;
    }
    let prompt = looks_like_interactive_prompt(&rec.line);
    if let Some((badge, _)) = log_display_kind(rec, prompt).badge() {
        width += badge.len() + 3;
    }
    width + UnicodeWidthStr::width(rec.line.as_str())
}

fn render_log_record_line(
    rec: &LogRecord,
    matched: bool,
    report_state: ReportHighlightState,
    labeled_version_mode: LabeledVersionColorMode,
    include_task: bool,
    task_colors: bool,
) -> Line<'static> {
    let prompt = looks_like_interactive_prompt(&rec.line);
    let display = log_display_kind(rec, prompt);
    let mut line_style = if matched {
        Style::default().fg(Color::LightMagenta)
    } else {
        Style::default()
    };
    if prompt {
        line_style = Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        if matched {
            line_style = line_style.add_modifier(Modifier::UNDERLINED);
        }
    }

    let mut spans = vec![Span::styled(
        format!("{} ", fmt_ts(rec.ts_unix_ms)),
        Style::default().fg(Color::DarkGray).patch(line_style),
    )];
    if include_task {
        spans.push(Span::styled(
            format!("{} ", rec.task_id),
            Style::default()
                .fg(task_color(&rec.task_id, task_colors))
                .patch(line_style),
        ));
    }
    if let Some((badge, style)) = display.badge() {
        spans.push(Span::styled(format!("[{badge}] "), style.patch(line_style)));
    }
    spans.extend(stylize_log_body(
        &rec.line,
        line_style,
        rec.stream,
        report_state,
        labeled_version_mode,
    ));
    Line::from(spans)
}

fn task_truncation_banner(dropped: u64) -> Line<'static> {
    Line::from(vec![
        Span::styled("[META] ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(
                "[TRUNCATED] dropped {dropped} older lines in this task (press m for full task log; raise logging.max_in_memory_lines to retain more here)"
            ),
            Style::default().fg(Color::Yellow),
        ),
    ])
}

fn global_truncation_banner(dropped: u64) -> Line<'static> {
    Line::from(vec![
        Span::styled("[META] ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!(
                "[TRUNCATED] dropped {dropped} older global lines (press m for full run log; raise logging.max_in_memory_lines to retain more here)"
            ),
            Style::default().fg(Color::Yellow),
        ),
    ])
}

fn report_state_before(records: &[LogRecord], end: usize) -> ReportHighlightState {
    records
        .iter()
        .take(end)
        .fold(ReportHighlightState::None, advance_report_highlight_state)
}

fn report_states_before(
    records: &[LogRecord],
    end: usize,
) -> BTreeMap<String, ReportHighlightState> {
    let mut states = BTreeMap::new();
    for rec in records.iter().take(end) {
        let current = states
            .get(&rec.task_id)
            .copied()
            .unwrap_or(ReportHighlightState::None);
        states.insert(
            rec.task_id.clone(),
            advance_report_highlight_state(current, rec),
        );
    }
    states
}

fn scroll_top_for_lines(
    lines: &[Line<'_>],
    from_bottom: usize,
    width: usize,
    height: usize,
    wrap: bool,
) -> usize {
    if height == 0 || width == 0 || lines.is_empty() {
        return 0;
    }
    let total_rows = lines
        .iter()
        .map(|line| {
            if !wrap {
                1
            } else {
                let w = line.width().max(1);
                w.div_ceil(width)
            }
        })
        .sum::<usize>();
    total_rows.saturating_sub(height.saturating_add(from_bottom))
}

fn line_row_count(line: &Line<'_>, width: usize, wrap: bool) -> usize {
    if !wrap {
        return 1;
    }
    let w = line.width().max(1);
    w.div_ceil(width.max(1))
}

fn count_visual_rows(lines: &[Line<'_>], width: usize, wrap: bool) -> usize {
    lines
        .iter()
        .map(|line| line_row_count(line, width, wrap))
        .sum()
}

fn wrap_line_rows(line: &Line<'static>, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);
    if line.spans.is_empty() {
        return vec![Line::default()];
    }

    let mut rows = Vec::new();
    let mut row_spans = Vec::new();
    let mut row_width = 0usize;

    for span in &line.spans {
        let style = span.style;
        let mut segment = String::new();

        for ch in span.content.chars() {
            let char_width = Line::from(ch.to_string()).width().max(1);
            if row_width > 0 && row_width + char_width > width {
                if !segment.is_empty() {
                    row_spans.push(Span::styled(std::mem::take(&mut segment), style));
                }
                rows.push(Line::from(std::mem::take(&mut row_spans)));
                row_width = 0;
            }

            segment.push(ch);
            row_width += char_width;

            if row_width >= width {
                row_spans.push(Span::styled(std::mem::take(&mut segment), style));
                rows.push(Line::from(std::mem::take(&mut row_spans)));
                row_width = 0;
            }
        }

        if !segment.is_empty() {
            row_spans.push(Span::styled(segment, style));
        }
    }

    if !row_spans.is_empty() || rows.is_empty() {
        rows.push(Line::from(row_spans));
    }
    rows
}

fn take_visible_rows(
    lines: &[Line<'static>],
    from_bottom: usize,
    width: usize,
    height: usize,
    wrap: bool,
) -> Vec<Line<'static>> {
    if lines.is_empty() || height == 0 {
        return Vec::new();
    }

    let total_rows = count_visual_rows(lines, width, wrap);
    if total_rows <= height {
        if wrap {
            return take_bottom_aligned_whole_lines(lines, width, height);
        }
        let mut padded = vec![Line::default(); height.saturating_sub(lines.len())];
        padded.extend(lines.iter().cloned());
        return padded;
    }

    if wrap && from_bottom == 0 {
        let anchored = take_bottom_aligned_whole_lines(lines, width, height);
        if !anchored.is_empty() {
            return anchored;
        }
    }

    let visual_rows = expand_visual_rows(lines, width, wrap);
    let total_rows = visual_rows.len();
    let capped_from_bottom = from_bottom.min(total_rows.saturating_sub(height));
    let end = total_rows.saturating_sub(capped_from_bottom);
    let start = end.saturating_sub(height);
    visual_rows
        .into_iter()
        .skip(start)
        .take(end - start)
        .collect()
}

fn expand_visual_rows(lines: &[Line<'static>], width: usize, wrap: bool) -> Vec<Line<'static>> {
    let mut visual_rows = Vec::with_capacity(count_visual_rows(lines, width, wrap));
    for line in lines {
        if wrap {
            visual_rows.extend(wrap_line_rows(line, width));
        } else {
            visual_rows.push(line.clone());
        }
    }
    visual_rows
}

fn take_bottom_aligned_whole_lines(
    lines: &[Line<'static>],
    width: usize,
    height: usize,
) -> Vec<Line<'static>> {
    let mut collected = Vec::new();
    let mut used_rows = 0usize;

    for line in lines.iter().rev() {
        let wrapped = wrap_line_rows(line, width);
        if wrapped.len() > height {
            return Vec::new();
        }
        if used_rows + wrapped.len() > height {
            break;
        }
        used_rows += wrapped.len();
        collected.extend(wrapped.into_iter().rev());
    }

    if collected.is_empty() {
        return Vec::new();
    }

    collected.reverse();
    let mut padded = vec![Line::default(); height.saturating_sub(collected.len())];
    padded.extend(collected);
    padded
}

fn active_pane_name(pane: ActivePane) -> &'static str {
    match pane {
        ActivePane::Tasks => "tasks",
        ActivePane::TaskLogs => "task-log",
        ActivePane::GlobalLogs => "global-log",
    }
}

fn constrain_scroll_window(
    mut lines: Vec<Line<'static>>,
    top_row: usize,
    width: usize,
    wrap: bool,
) -> (Vec<Line<'static>>, u16) {
    let max = u16::MAX as usize;
    if top_row <= max || lines.is_empty() {
        return (lines, top_row.min(max) as u16);
    }

    let mut rows_to_drop = top_row - max;
    let mut dropped_rows = 0usize;
    let mut drop_lines = 0usize;
    for line in &lines {
        if rows_to_drop == 0 {
            break;
        }
        let row_count = line_row_count(line, width, wrap);
        drop_lines += 1;
        dropped_rows += row_count;
        rows_to_drop = rows_to_drop.saturating_sub(row_count);
    }
    if drop_lines > 0 {
        lines.drain(0..drop_lines);
    }

    let adjusted_top = top_row.saturating_sub(dropped_rows);
    (lines, adjusted_top.min(max) as u16)
}

fn slice_logs(logs: &VecDeque<LogRecord>, from_bottom: usize, height: usize) -> Vec<LogRecord> {
    let total = logs.len();
    if total == 0 || height == 0 {
        return Vec::new();
    }
    // Clamp against the viewport capacity so overscrolling does not shrink
    // the number of rendered rows as we approach the oldest entries.
    let max_from_bottom = total.saturating_sub(height);
    let capped_from_bottom = from_bottom.min(max_from_bottom);
    let end = total.saturating_sub(capped_from_bottom);
    let start = end.saturating_sub(height);
    logs.iter().skip(start).take(end - start).cloned().collect()
}

fn state_color(state: TaskState) -> Color {
    match state {
        TaskState::Pending => Color::DarkGray,
        TaskState::Running => Color::Cyan,
        TaskState::Completed => Color::Green,
        TaskState::Failed => Color::Red,
        TaskState::Canceled => Color::Yellow,
        TaskState::Skipped => Color::Blue,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LogDisplayKind {
    Plain,
    Prompt,
    System,
}

impl LogDisplayKind {
    fn badge(self) -> Option<(&'static str, Style)> {
        match self {
            Self::Plain => None,
            Self::Prompt => Some((
                "PROMPT",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Self::System => Some((
                "SYSTEM",
                Style::default()
                    .fg(Color::LightBlue)
                    .add_modifier(Modifier::BOLD),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabeledVersionColorMode {
    Standalone,
    ChangedPair,
    SamePair,
}

fn log_display_kind(rec: &LogRecord, prompt: bool) -> LogDisplayKind {
    if prompt {
        return LogDisplayKind::Prompt;
    }
    if rec.stream == LogStream::Meta && !is_report_meta_line(&rec.line) {
        return LogDisplayKind::System;
    }
    LogDisplayKind::Plain
}

fn labeled_version_color_mode(records: &[LogRecord], idx: usize) -> LabeledVersionColorMode {
    let current = records
        .get(idx)
        .map(|rec| rec.line.as_str())
        .unwrap_or_default();
    if let Some(before) = labeled_version_value(current, "Before:") {
        if let Some(after) = paired_labeled_version_value(records, idx, idx + 1, "After:") {
            return if before == after {
                LabeledVersionColorMode::SamePair
            } else {
                LabeledVersionColorMode::ChangedPair
            };
        }
    }
    if let Some(after) = labeled_version_value(current, "After:") {
        if let Some(before) = idx
            .checked_sub(1)
            .and_then(|prev| paired_labeled_version_value(records, idx, prev, "Before:"))
        {
            return if before == after {
                LabeledVersionColorMode::SamePair
            } else {
                LabeledVersionColorMode::ChangedPair
            };
        }
    }
    LabeledVersionColorMode::Standalone
}

fn paired_labeled_version_value<'a>(
    records: &'a [LogRecord],
    current_idx: usize,
    adjacent_idx: usize,
    label: &str,
) -> Option<&'a str> {
    let current = records.get(current_idx)?;
    let adjacent = records.get(adjacent_idx)?;
    if current.task_id != adjacent.task_id || current.stream != adjacent.stream {
        return None;
    }
    labeled_version_value(&adjacent.line, label)
}

fn labeled_version_value<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let label_pos = line.find(label)?;
    let value_start = label_pos + label.len();
    let value = line[value_start..].trim();
    if value.is_empty() || value.contains(char::is_whitespace) || !is_obvious_version_token(value) {
        return None;
    }
    Some(value)
}

fn level_color(level: LogLevel) -> Color {
    match level {
        LogLevel::Trace => Color::DarkGray,
        LogLevel::Info => Color::White,
        LogLevel::Warn => Color::Yellow,
        LogLevel::Error => Color::Red,
    }
}

fn stream_tag(stream: LogStream) -> &'static str {
    match stream {
        LogStream::Stdout => "OUT",
        LogStream::Stderr => "STDERR",
        LogStream::Stdin => "STDIN",
        LogStream::Meta => "META",
    }
}

fn stream_color(stream: LogStream) -> Color {
    match stream {
        LogStream::Stdout => Color::DarkGray,
        LogStream::Stderr => Color::LightRed,
        LogStream::Stdin => Color::Magenta,
        LogStream::Meta => Color::Blue,
    }
}

fn task_color(task_id: &str, enabled: bool) -> Color {
    if !enabled {
        return Color::White;
    }
    const COLORS: &[Color] = &[
        Color::LightBlue,
        Color::LightCyan,
        Color::LightGreen,
        Color::LightMagenta,
        Color::LightYellow,
        Color::Cyan,
    ];
    let hash = task_id.bytes().fold(0usize, |acc, b| {
        acc.wrapping_mul(31).wrapping_add(b as usize)
    });
    COLORS[hash % COLORS.len()]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportStyleKind {
    Standard,
    Recovery,
    UpdateDetails,
    StatusOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportHighlightState {
    None,
    AwaitingHeader(ReportStyleKind),
    Active(ReportStyleKind),
}

fn stylize_log_body(
    line: &str,
    base_style: Style,
    stream: LogStream,
    report_state: ReportHighlightState,
    labeled_version_mode: LabeledVersionColorMode,
) -> Vec<Span<'static>> {
    if stream == LogStream::Meta {
        if let Some(spans) = stylize_report_note_line(line, base_style) {
            return spans;
        }
        if let Some(spans) = stylize_box_table_row(line, base_style) {
            return spans;
        }
        if let ReportHighlightState::AwaitingHeader(expected_kind) = report_state {
            if let Some(kind) = parse_report_header_kind(line) {
                if kind == expected_kind {
                    if let Some(spans) = stylize_report_header(line, base_style) {
                        return spans;
                    }
                }
            }
        }
        if let ReportHighlightState::Active(kind) = report_state {
            if let Some(spans) = stylize_report_row(line, base_style, kind) {
                return spans;
            }
        }
    }

    if let Some(spans) = stylize_versioned_dependency_delta(line, base_style) {
        return spans;
    }

    if let Some(spans) = stylize_version_transition_line(line, base_style, labeled_version_mode) {
        return spans;
    }

    let markers = [
        (
            "WARNING",
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        (
            "ERROR",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        (
            "[NEW]",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        (
            "==>",
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ),
        (
            "->",
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD),
        ),
    ];

    let mut spans = Vec::new();
    let mut idx = 0usize;
    let leading_arrow_pos = line.len() - line.trim_start().len();
    while idx < line.len() {
        let next = markers
            .iter()
            .filter_map(|(marker, style)| {
                line[idx..].find(marker).and_then(|pos| {
                    let absolute_pos = idx + pos;
                    if *marker == "->" && absolute_pos != leading_arrow_pos {
                        return None;
                    }
                    Some((absolute_pos, *marker, *style))
                })
            })
            .min_by_key(|(pos, _, _)| *pos);
        let Some((pos, marker, style)) = next else {
            spans.push(Span::styled(line[idx..].to_string(), base_style));
            break;
        };
        if pos > idx {
            spans.push(Span::styled(line[idx..pos].to_string(), base_style));
        }
        spans.push(Span::styled(marker.to_string(), style.patch(base_style)));
        idx = pos + marker.len();
    }
    spans
}

fn stylize_versioned_dependency_delta(line: &str, base_style: Style) -> Option<Vec<Span<'static>>> {
    let leading = line.len().saturating_sub(line.trim_start().len());
    let trimmed = &line[leading..];
    let (color, remainder) = match trimmed.as_bytes().first().copied()? {
        b'-' => (Color::LightRed, &trimmed[1..]),
        b'+' => (Color::LightGreen, &trimmed[1..]),
        _ => return None,
    };
    if !remainder.starts_with(char::is_whitespace) {
        return None;
    }
    let requirement = remainder.trim();
    if requirement.is_empty() || requirement.contains(char::is_whitespace) {
        return None;
    }
    let (name, version) = requirement.split_once("==")?;
    if name.is_empty()
        || version.is_empty()
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        || !is_obvious_version_token(version)
    {
        return None;
    }

    let mut spans = Vec::new();
    if leading > 0 {
        spans.push(Span::styled(line[..leading].to_string(), base_style));
    }
    spans.push(Span::styled(
        trimmed.to_string(),
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD)
            .patch(base_style),
    ));
    Some(spans)
}

fn stylize_version_transition_line(
    line: &str,
    base_style: Style,
    labeled_version_mode: LabeledVersionColorMode,
) -> Option<Vec<Span<'static>>> {
    stylize_labeled_version_line(line, base_style, labeled_version_mode)
        .or_else(|| stylize_arrow_version_line(line, base_style))
}

fn stylize_labeled_version_line(
    line: &str,
    base_style: Style,
    mode: LabeledVersionColorMode,
) -> Option<Vec<Span<'static>>> {
    for (label, color) in [("Before:", Color::LightRed), ("After:", Color::LightGreen)] {
        let Some(label_pos) = line.find(label) else {
            continue;
        };
        let value_start = label_pos + label.len();
        let value = line[value_start..].trim();
        if value.is_empty()
            || value.contains(char::is_whitespace)
            || !is_obvious_version_token(value)
        {
            continue;
        }

        let Some(value_offset) = line[value_start..].find(value) else {
            continue;
        };
        let value_pos = value_offset + value_start;
        let mut spans = Vec::new();
        if value_pos > 0 {
            spans.push(Span::styled(line[..value_pos].to_string(), base_style));
        }
        let highlight = match (label, mode) {
            ("Before:", LabeledVersionColorMode::ChangedPair) => true,
            ("After:", LabeledVersionColorMode::ChangedPair) => true,
            ("Before:", LabeledVersionColorMode::SamePair) => false,
            ("After:", LabeledVersionColorMode::SamePair) => false,
            _ => true,
        };
        spans.push(Span::styled(
            value.to_string(),
            if highlight {
                Style::default()
                    .fg(color)
                    .add_modifier(Modifier::BOLD)
                    .patch(base_style)
            } else {
                base_style
            },
        ));
        let value_end = value_pos + value.len();
        if value_end < line.len() {
            spans.push(Span::styled(line[value_end..].to_string(), base_style));
        }
        return Some(spans);
    }
    None
}

fn stylize_arrow_version_line(line: &str, base_style: Style) -> Option<Vec<Span<'static>>> {
    let arrows = ["->", "→", "⇒", "➜", "⟶", "⟹"];
    for arrow in arrows {
        let Some(arrow_pos) = line.find(arrow) else {
            continue;
        };
        let arrow_end = arrow_pos + arrow.len();
        let left_end = line[..arrow_pos].trim_end().len();
        let left_start = scan_version_token_start(line, left_end)?;
        let right_start = scan_version_token_end_start(line, arrow_end)?;
        let right_end = scan_version_token_end(line, right_start);

        let before = &line[left_start..left_end];
        let after = &line[right_start..right_end];
        if !is_obvious_version_token(before) || !is_obvious_version_token(after) {
            continue;
        }

        let mut spans = Vec::new();
        if left_start > 0 {
            spans.push(Span::styled(line[..left_start].to_string(), base_style));
        }
        spans.push(Span::styled(
            before.to_string(),
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD)
                .patch(base_style),
        ));
        if arrow_pos > left_end {
            spans.push(Span::styled(
                line[left_end..arrow_pos].to_string(),
                base_style,
            ));
        }
        spans.push(Span::styled(
            arrow.to_string(),
            Style::default()
                .fg(Color::LightBlue)
                .add_modifier(Modifier::BOLD)
                .patch(base_style),
        ));
        if right_start > arrow_end {
            spans.push(Span::styled(
                line[arrow_end..right_start].to_string(),
                base_style,
            ));
        }
        spans.push(Span::styled(
            after.to_string(),
            Style::default()
                .fg(Color::LightGreen)
                .add_modifier(Modifier::BOLD)
                .patch(base_style),
        ));
        if right_end < line.len() {
            spans.push(Span::styled(line[right_end..].to_string(), base_style));
        }
        return Some(spans);
    }
    None
}

fn scan_version_token_start(line: &str, end: usize) -> Option<usize> {
    if end == 0 {
        return None;
    }
    let bytes = line.as_bytes();
    let mut idx = end;
    while idx > 0 && is_version_token_char(bytes[idx - 1] as char) {
        idx -= 1;
    }
    (idx < end).then_some(idx)
}

fn scan_version_token_end_start(line: &str, start: usize) -> Option<usize> {
    let bytes = line.as_bytes();
    let mut idx = start;
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    (idx < bytes.len()).then_some(idx)
}

fn scan_version_token_end(line: &str, start: usize) -> usize {
    let bytes = line.as_bytes();
    let mut idx = start;
    while idx < bytes.len() && is_version_token_char(bytes[idx] as char) {
        idx += 1;
    }
    idx
}

fn is_version_token_char(ch: char) -> bool {
    super::report_is_version_token_char(ch)
}

fn is_obvious_version_token(token: &str) -> bool {
    super::report_is_obvious_version_token(token)
}

fn stylize_report_header(line: &str, base_style: Style) -> Option<Vec<Span<'static>>> {
    let kind = parse_report_header_kind(line)?;
    stylize_report_table_columns(line, base_style, kind, true)
}

fn stylize_report_row(
    line: &str,
    base_style: Style,
    kind: ReportStyleKind,
) -> Option<Vec<Span<'static>>> {
    stylize_report_table_columns(line, base_style, kind, false)
}

fn stylize_report_table_columns(
    line: &str,
    base_style: Style,
    kind: ReportStyleKind,
    header: bool,
) -> Option<Vec<Span<'static>>> {
    let layout = report_table_layout(line, kind, header)?;
    let columns = extract_report_columns(line, layout.column_count)?;
    let seps = double_space_boundaries(line);

    let value_change = !header
        && layout
            .before_after_cols
            .map(|(before_col, after_col)| {
                should_highlight_before_after_values(
                    columns[before_col].trim(),
                    columns[after_col].trim(),
                )
            })
            .unwrap_or(false);
    let status_style = layout.status_col.and_then(|idx| {
        report_tail_style(kind, columns[idx].trim()).map(|style| (idx, style.patch(base_style)))
    });

    let mut spans = Vec::new();
    let mut start = 0usize;
    for idx in 0..layout.column_count {
        let end = if idx + 1 == layout.column_count {
            line.len()
        } else {
            seps[idx].0
        };
        if end > start {
            let mut style = base_style;
            if let Some((before_col, after_col)) = layout.before_after_cols {
                if value_change && idx == before_col {
                    style = Style::default().fg(Color::LightRed).patch(base_style);
                } else if value_change && idx == after_col {
                    style = Style::default().fg(Color::LightGreen).patch(base_style);
                }
            }
            if let Some((status_idx, status_style)) = status_style {
                if idx == status_idx {
                    style = status_style;
                }
            }
            spans.push(Span::styled(line[start..end].to_string(), style));
        }
        if idx + 1 < layout.column_count {
            spans.push(Span::styled(
                line[seps[idx].0..seps[idx].1].to_string(),
                base_style,
            ));
            start = seps[idx].1;
        }
    }
    Some(spans)
}

#[derive(Clone, Copy)]
struct ReportTableLayout {
    column_count: usize,
    before_after_cols: Option<(usize, usize)>,
    status_col: Option<usize>,
}

fn report_table_layout(
    line: &str,
    kind: ReportStyleKind,
    header: bool,
) -> Option<ReportTableLayout> {
    match kind {
        ReportStyleKind::Standard => {
            let columns = extract_report_columns(line, 4)?;
            if header {
                if (
                    columns[0].trim(),
                    columns[1].trim(),
                    columns[2].trim(),
                    columns[3].trim(),
                ) != ("Package", "Before", "After", "Outcome")
                {
                    return None;
                }
            } else {
                report_tail_style(kind, columns[3].trim())?;
            }
            Some(ReportTableLayout {
                column_count: 4,
                before_after_cols: Some((1, 2)),
                status_col: Some(3),
            })
        }
        ReportStyleKind::Recovery => {
            let columns = extract_report_columns(line, 4)?;
            if header {
                if (
                    columns[0].trim(),
                    columns[1].trim(),
                    columns[2].trim(),
                    columns[3].trim(),
                ) != ("Item", "Before", "After", "Result")
                {
                    return None;
                }
            } else {
                report_tail_style(kind, columns[3].trim())?;
            }
            Some(ReportTableLayout {
                column_count: 4,
                before_after_cols: Some((1, 2)),
                status_col: Some(3),
            })
        }
        ReportStyleKind::UpdateDetails => {
            let columns = extract_report_columns(line, 5)?;
            if header
                && (columns[0].trim() != "Task"
                    || columns[2].trim() != "Before"
                    || columns[3].trim() != "After")
            {
                return None;
            }
            Some(ReportTableLayout {
                column_count: 5,
                before_after_cols: Some((2, 3)),
                status_col: None,
            })
        }
        ReportStyleKind::StatusOnly => {
            let columns = extract_report_columns(line, 4)?;
            if header {
                if !matches!(columns[3].trim(), "Outcome" | "Result") {
                    return None;
                }
            } else {
                report_tail_style(kind, columns[3].trim())?;
            }
            Some(ReportTableLayout {
                column_count: 4,
                before_after_cols: None,
                status_col: Some(3),
            })
        }
    }
}

fn stylize_report_note_line(line: &str, base_style: Style) -> Option<Vec<Span<'static>>> {
    if !is_report_note_line(line) {
        return None;
    }
    let trimmed_start = line.len() - line.trim_start().len();
    let content = &line[trimmed_start..];
    let tag_end = content.find(']')?;
    let tag = &content[1..tag_end];
    let tag_style = report_note_tag_style(tag)?.patch(base_style);
    let mut spans = Vec::new();
    if trimmed_start > 0 {
        spans.push(Span::styled(line[..trimmed_start].to_string(), base_style));
    }
    spans.push(Span::styled(content[..=tag_end].to_string(), tag_style));
    if tag_end + 1 < content.len() {
        spans.push(Span::styled(content[tag_end + 1..].to_string(), base_style));
    }
    Some(spans)
}

fn stylize_box_table_row(line: &str, base_style: Style) -> Option<Vec<Span<'static>>> {
    if !line.trim_start().starts_with('│') {
        return None;
    }
    let mut cell_styles = box_table_value_column_styles(line);
    cell_styles.extend(box_table_status_column_styles(line));
    let mut cell_idx = 0usize;
    let mut spans = Vec::new();
    for segment in line.split_inclusive('│') {
        if segment == "│" {
            spans.push(Span::styled(segment.to_string(), base_style));
            continue;
        }
        let (cell, trailing_bar) = if let Some(cell) = segment.strip_suffix('│') {
            (cell, true)
        } else {
            (segment, false)
        };
        let style = cell_styles
            .iter()
            .find_map(|(idx, style)| (*idx == cell_idx).then_some(*style))
            .unwrap_or(base_style)
            .patch(base_style);
        spans.push(Span::styled(cell.to_string(), style));
        if trailing_bar {
            spans.push(Span::styled("│".to_string(), base_style));
            cell_idx += 1;
        }
    }
    Some(spans)
}

fn box_table_value_column_styles(line: &str) -> Vec<(usize, Style)> {
    let Some(cells) = box_table_cells(line) else {
        return Vec::new();
    };
    if cells.len() != 7 {
        return Vec::new();
    }
    let before = cells[3].trim();
    let after = cells[4].trim();
    let result = cells[5].trim();
    if before == "Before" && after == "After" && result == "Result" {
        return Vec::new();
    }
    if !is_report_box_status_cell(result) {
        return Vec::new();
    }
    let before_present = !before.is_empty() && before != "-";
    let after_present = !after.is_empty() && after != "-";
    if before_present
        && after_present
        && before != after
        && should_highlight_before_after_values(before, after)
    {
        return vec![
            (
                3,
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                4,
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            ),
        ];
    }
    Vec::new()
}

fn box_table_status_column_styles(line: &str) -> Vec<(usize, Style)> {
    let Some(cells) = box_table_cells(line) else {
        return Vec::new();
    };
    let Some(status_idx) = (match cells.len() {
        7 => Some(5),
        5 => Some(2),
        4 => Some(3),
        _ => None,
    }) else {
        return Vec::new();
    };
    let status = cells[status_idx].trim();
    if matches!(status, "Result" | "Outcome") {
        return Vec::new();
    }
    box_cell_style(status)
        .map(|style| vec![(status_idx, style)])
        .unwrap_or_default()
}

fn should_highlight_before_after_values(before: &str, after: &str) -> bool {
    super::report_values_are_version_change(before, after)
}

fn box_table_cells(line: &str) -> Option<Vec<&str>> {
    let pipe_positions = line
        .char_indices()
        .filter_map(|(idx, ch)| (ch == '│').then_some(idx))
        .collect::<Vec<_>>();
    if pipe_positions.len() < 2 {
        return None;
    }
    Some(
        pipe_positions
            .windows(2)
            .map(|window| &line[window[0] + '│'.len_utf8()..window[1]])
            .collect(),
    )
}

fn report_note_tag_style(tag: &str) -> Option<Style> {
    match tag {
        "FAIL" => report_outcome_style("Fail"),
        "BLOCK" => report_outcome_style("Blocked"),
        "OK" => report_outcome_style("Updated"),
        "PASS" => report_outcome_style("Pass"),
        "REFRESH" => report_outcome_style("Refreshed"),
        "SAME" => report_outcome_style("Unchanged"),
        "SKIP" => report_outcome_style("Skip"),
        "INFO" => report_outcome_style("Info"),
        _ => None,
    }
}

fn box_cell_style(cell: &str) -> Option<Style> {
    report_outcome_style(cell.trim())
}

fn report_outcome_style(outcome: &str) -> Option<Style> {
    match outcome {
        "Completed" | "Passed" | "Pass" | "Updated" | "Generated" | "Recovered" | "Restarted" => {
            Some(
                Style::default()
                    .fg(Color::LightGreen)
                    .add_modifier(Modifier::BOLD),
            )
        }
        "Refreshed" => Some(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        "Completed*" => Some(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        "Failed" | "Error" | "Fail" => {
            Some(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        }
        "Blocked" | "Warn" => Some(blocked_style()),
        "Unchanged" | "No Restart" => Some(Style::default()),
        "Skipped" | "Skip" | "Canceled" | "Removed" | "Not Restarted" => Some(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        "Info" => Some(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        _ => None,
    }
}

fn is_report_box_status_cell(cell: &str) -> bool {
    box_cell_style(cell).is_some()
}

fn advance_report_highlight_state(
    current: ReportHighlightState,
    rec: &LogRecord,
) -> ReportHighlightState {
    if rec.stream != LogStream::Meta {
        return ReportHighlightState::None;
    }

    let line = rec.line.trim();
    if line.is_empty() {
        return ReportHighlightState::None;
    }
    if let Some(kind) = report_style_kind_for_title(line) {
        return ReportHighlightState::AwaitingHeader(kind);
    }
    if let Some(kind) = parse_report_header_kind(line) {
        return ReportHighlightState::Active(kind);
    }

    match current {
        ReportHighlightState::Active(kind)
            if is_report_note_line(line) || matches_report_row_kind(line, kind) =>
        {
            ReportHighlightState::Active(kind)
        }
        _ => ReportHighlightState::None,
    }
}

fn report_style_kind_for_title(line: &str) -> Option<ReportStyleKind> {
    if line.ends_with("Recovery Actions") {
        return Some(ReportStyleKind::Recovery);
    }
    if line == "Update Details" {
        return Some(ReportStyleKind::UpdateDetails);
    }
    if line.ends_with("Results")
        || matches!(
            line,
            "Package Change Rollup" | "Final Task Overview" | "Needs Attention"
        )
    {
        return Some(ReportStyleKind::Standard);
    }
    None
}

fn parse_report_header_kind(line: &str) -> Option<ReportStyleKind> {
    if let Some(columns) = extract_report_columns(line, 4) {
        if let Some(kind) = match (
            columns[0].trim(),
            columns[1].trim(),
            columns[2].trim(),
            columns[3].trim(),
        ) {
            ("Package", "Before", "After", "Outcome") => Some(ReportStyleKind::Standard),
            ("Task", "Severity", "Issue", "Action") => Some(ReportStyleKind::StatusOnly),
            ("Item", "Before", "After", "Result") => Some(ReportStyleKind::Recovery),
            (_, _, _, "Outcome" | "Result") => Some(ReportStyleKind::StatusOnly),
            _ => None,
        } {
            return Some(kind);
        }
    }
    if let Some(columns) = extract_report_columns(line, 5) {
        (columns[0].trim() == "Task"
            && columns[2].trim() == "Before"
            && columns[3].trim() == "After")
            .then_some(ReportStyleKind::UpdateDetails)
    } else {
        None
    }
}

fn extract_report_columns(line: &str, column_count: usize) -> Option<Vec<&str>> {
    let seps = double_space_boundaries(line);
    if column_count == 0 || seps.len() < column_count.saturating_sub(1) {
        return None;
    }
    let mut columns = Vec::with_capacity(column_count);
    let mut start = 0usize;
    for sep in seps.iter().take(column_count - 1) {
        columns.push(&line[start..sep.0]);
        start = sep.1;
    }
    columns.push(&line[start..]);
    Some(columns)
}

fn report_tail_style(kind: ReportStyleKind, trimmed: &str) -> Option<Style> {
    match kind {
        ReportStyleKind::Standard if trimmed == "Outcome" => Some(Style::default()),
        ReportStyleKind::Recovery if trimmed == "Result" => Some(Style::default()),
        ReportStyleKind::Standard | ReportStyleKind::Recovery => report_outcome_style(trimmed),
        ReportStyleKind::UpdateDetails => None,
        ReportStyleKind::StatusOnly => report_status_only_tail_style(trimmed),
    }
}

fn report_status_only_tail_style(trimmed: &str) -> Option<Style> {
    if matches!(trimmed, "Outcome" | "Result") {
        Some(Style::default())
    } else {
        report_outcome_style(trimmed)
    }
}

fn blocked_style() -> Style {
    Style::default()
        .fg(Color::Rgb(255, 165, 0))
        .add_modifier(Modifier::BOLD)
}

fn matches_report_row_kind(line: &str, kind: ReportStyleKind) -> bool {
    report_table_layout(line, kind, false).is_some()
}

fn current_log_view_target(model: &Model) -> Option<LogViewTarget> {
    match model.active_pane {
        ActivePane::GlobalLogs => Some(LogViewTarget::Run),
        ActivePane::Tasks | ActivePane::TaskLogs => model
            .selected_task_id()
            .map(|id| LogViewTarget::Task { id: id.to_string() }),
    }
}

fn double_space_boundaries(line: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        if bytes[idx] == b' ' {
            let start = idx;
            while idx < bytes.len() && bytes[idx] == b' ' {
                idx += 1;
            }
            if idx.saturating_sub(start) >= 2 {
                out.push((start, idx));
            }
        } else {
            idx += 1;
        }
    }
    out
}

fn sanitize_log_line(raw: &str) -> String {
    let no_ansi: Cow<'_, str> = if raw.as_bytes().contains(&0x1b) {
        Cow::Owned(strip_ansi(raw))
    } else {
        Cow::Borrowed(raw)
    };
    let mut out = String::with_capacity(no_ansi.len());
    for ch in no_ansi.chars() {
        match ch {
            '\t' => out.push_str("  "),
            '\r' | '\n' => {}
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn push_or_coalesce_log(
    logs: &mut VecDeque<LogRecord>,
    dropped_count: &mut u64,
    max_in_memory_lines: usize,
    rec: LogRecord,
) {
    if should_coalesce_progress_record(logs.back(), &rec) {
        let _ = logs.pop_back();
        logs.push_back(rec);
        return;
    }

    if logs.len() >= max_in_memory_lines {
        logs.pop_front();
        *dropped_count = dropped_count.saturating_add(1);
    }
    logs.push_back(rec);
}

fn should_coalesce_progress_record(previous: Option<&LogRecord>, next: &LogRecord) -> bool {
    let Some(previous) = previous else {
        return false;
    };
    previous.task_id == next.task_id
        && previous.stream == next.stream
        && is_transient_progress_line(&previous.line)
        && is_transient_progress_line(&next.line)
}

fn is_transient_progress_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.starts_with("% Total") || trimmed.starts_with("Dload  Upload") {
        return true;
    }

    if trimmed.contains("KB /") || trimmed.contains("MB /") || trimmed.contains("GB /") {
        return true;
    }

    let has_block = trimmed.contains('█') || trimmed.contains('▒') || trimmed.contains('▓');
    if has_block && trimmed.contains('%') {
        return true;
    }

    let numeric_progress_chars_only = trimmed.chars().all(|c| {
        c.is_ascii_digit()
            || c.is_ascii_whitespace()
            || matches!(c, '%' | '.' | ':' | '/' | 'k' | 'K' | 'm' | 'M' | 'g' | 'G')
    });

    numeric_progress_chars_only
        && trimmed.chars().any(|c| c.is_ascii_digit())
        && (trimmed.contains('%')
            || trimmed.contains(':')
            || trimmed.contains('k')
            || trimmed.contains('K')
            || trimmed.contains('m')
            || trimmed.contains('M')
            || trimmed.contains('g')
            || trimmed.contains('G'))
}

fn looks_like_interactive_prompt(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if prompt_kind(trimmed) == PromptKind::ArchServiceRestart {
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

    if lower.starts_with("==> ") {
        return lower.contains("packages to exclude")
            || lower.contains("packages to cleanbuild")
            || lower.contains("diffs to show")
            || lower.contains("pkgbuilds to edit")
            || lower.contains("[n]one [a]ll [ab]ort")
            || lower.contains('?');
    }

    false
}

fn prompt_kind(line: &str) -> PromptKind {
    if is_arch_service_restart_prompt(line) {
        PromptKind::ArchServiceRestart
    } else {
        PromptKind::Generic
    }
}

fn is_arch_service_restart_prompt(line: &str) -> bool {
    let lower = line.trim().to_ascii_lowercase();
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

fn find_latest_prompt(model: &Model) -> Option<(String, String)> {
    latest_prompt_record(model).map(|rec| (rec.task_id.to_string(), rec.line.to_string()))
}

fn latest_prompt_signature(model: &Model) -> Option<(String, u64)> {
    latest_prompt_record(model).map(|rec| (rec.task_id.to_string(), rec.ts_unix_ms))
}

fn latest_prompt_record(model: &Model) -> Option<&LogRecord> {
    model.global_logs.iter().rev().find(|rec| {
        if !looks_like_interactive_prompt(&rec.line) {
            return false;
        }
        // Keep prompt overlay tied to a currently waiting task.
        model
            .tasks
            .get(&rec.task_id)
            .filter(|task| {
                task.accepts_input && task.input_enabled && task.state == TaskState::Running
            })
            .and_then(|task| task.logs.back())
            .map(|last| {
                last.ts_unix_ms == rec.ts_unix_ms
                        && last.line == rec.line
                        // Debounce noisy prompt-like lines so popup doesn't flash.
                        && rec.ts_unix_ms.saturating_add(500) <= now_unix_ms()
            })
            .unwrap_or(false)
    })
}

fn latest_prompt_task(model: &Model) -> Option<String> {
    find_latest_prompt(model).map(|(task_id, _)| task_id)
}

fn prompt_overlay_context_lines(model: &Model, task_id: &str, prompt: &str) -> Vec<String> {
    if prompt_kind(prompt) != PromptKind::ArchServiceRestart {
        return Vec::new();
    }
    let Some(task) = model.tasks.get(task_id) else {
        return Vec::new();
    };
    arch_service_prompt_context_lines(&task.logs, prompt)
}

fn arch_service_prompt_context_lines(logs: &VecDeque<LogRecord>, prompt: &str) -> Vec<String> {
    let prompt_idx = logs.iter().rposition(|rec| {
        rec.line == prompt && prompt_kind(&rec.line) == PromptKind::ArchServiceRestart
    });
    let Some(prompt_idx) = prompt_idx else {
        return Vec::new();
    };

    let lines = logs.iter().collect::<Vec<_>>();
    let services_idx = lines[..prompt_idx]
        .iter()
        .rposition(|rec| rec.line.trim().eq_ignore_ascii_case("==> Services:"));

    let start = services_idx.unwrap_or_else(|| prompt_idx.saturating_sub(6));
    let mut out = Vec::new();
    for rec in &lines[start..prompt_idx] {
        let trimmed = rec.line.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_string());
    }

    if services_idx.is_some() && !out.is_empty() {
        return out;
    }

    out.retain(|line| line != prompt);
    out
}

fn strip_ansi(raw: &str) -> String {
    static CSI_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    static OSC_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    static SINGLE_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();

    let csi = match CSI_RE.get_or_init(|| Regex::new(r"\x1b\[[0-9;?]*[ -/]*[@-~]")) {
        Ok(re) => re,
        Err(_) => return raw.to_string(),
    };
    let osc = match OSC_RE.get_or_init(|| Regex::new(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)")) {
        Ok(re) => re,
        Err(_) => return raw.to_string(),
    };
    let single = match SINGLE_RE.get_or_init(|| Regex::new(r"\x1b[@-Z\\-_]")) {
        Ok(re) => re,
        Err(_) => return raw.to_string(),
    };

    let without_csi = csi.replace_all(raw, "");
    let without_osc = osc.replace_all(&without_csi, "");
    single.replace_all(&without_osc, "").into_owned()
}

fn draw_help(frame: &mut ratatui::Frame<'_>, size: Rect) {
    let area = centered_rect(88, 78, size);
    frame.render_widget(Clear, area);
    let help = Paragraph::new(render_help_lines())
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Span::styled(
                    "Dashboard Help",
                    Style::default()
                        .fg(Color::LightCyan)
                        .add_modifier(Modifier::BOLD),
                ))
                .border_style(Style::default().fg(Color::LightCyan)),
        );
    frame.render_widget(help, area);
}

fn render_help_lines() -> Vec<Line<'static>> {
    vec![
        Line::from(vec![
            Span::styled(
                "Reference",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                "Dashboard controls, layout, and color meanings",
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(""),
        help_section("Navigation"),
        help_entry(&["Tab", "h", "l", "Left", "Right"], "cycle panes"),
        help_entry(&["Enter"], "from Tasks, jump into the primary log pane"),
        help_entry(
            &["Up", "Down", "j"],
            "move selection or scroll current pane",
        ),
        help_entry(&["PgUp", "PgDn"], "page through logs or task list"),
        help_entry(&["g", "G", "Home", "End"], "jump to top or bottom"),
        help_entry(&["z", "Space"], "toggle split vs focused log pane"),
        Line::from(""),
        help_section("Search & View"),
        help_entry(&["/"], "regex search in the active pane"),
        help_entry(&["n", "N"], "jump to next or previous search match"),
        help_entry(&["w"], "toggle wrap for task and global logs"),
        help_entry(&["c"], "clear logs in the visible log pane (memory only)"),
        help_entry(&["m"], "open the selected task or run log in a live pager"),
        help_entry(&["r"], "rename this run"),
        help_entry(&["?"], "toggle this help overlay"),
        help_entry(&["Esc"], "close help, search, or prompt editor"),
        Line::from(""),
        help_section("Actions"),
        help_entry(&["k"], "cancel the selected task"),
        help_entry(&["K"], "cancel all tasks"),
        help_entry(
            &["Enter"],
            "on an input prompt, start stdin editor; Shift+Enter inserts newline",
        ),
        help_entry(&["q", "Q"], "close the dashboard"),
        Line::from(""),
        help_section("Mouse"),
        help_entry(&["Click"], "select task and focus pane"),
        help_entry(&["Wheel"], "scroll current pane"),
        Line::from(""),
        help_section("Task State Colors"),
        help_legend_entry(
            state_color(TaskState::Pending),
            "Pending",
            "queued and waiting to start",
        ),
        help_legend_entry(
            state_color(TaskState::Running),
            "Running",
            "currently executing",
        ),
        help_legend_entry(
            state_color(TaskState::Completed),
            "Completed",
            "finished successfully",
        ),
        help_legend_entry(
            state_color(TaskState::Failed),
            "Failed",
            "finished with an error",
        ),
        help_legend_entry(
            state_color(TaskState::Canceled),
            "Canceled",
            "stopped by user or shutdown path",
        ),
        help_legend_entry(
            state_color(TaskState::Skipped),
            "Skipped",
            "intentionally not run",
        ),
        Line::from(""),
        help_section("UI Accent Colors"),
        help_legend_entry(Color::LightCyan, "Active border", "currently focused pane"),
        help_legend_entry(Color::LightMagenta, "Search match", "matched text or rows"),
        help_legend_entry(
            Color::Yellow,
            "Prompt / warning",
            "input prompts and caution states",
        ),
    ]
}

fn help_section(title: &str) -> Line<'static> {
    Line::from(vec![Span::styled(
        title.to_string(),
        Style::default()
            .fg(Color::LightCyan)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
    )])
}

fn help_entry(keys: &[&str], description: &str) -> Line<'static> {
    let mut spans = Vec::new();
    let joined = keys.join(" / ");
    spans.push(Span::styled(
        format!("{joined:<28}"),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(
        description.to_string(),
        Style::default().fg(Color::White),
    ));
    Line::from(spans)
}

fn help_legend_entry(color: Color, label: &str, description: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            "● ",
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{label:<14}"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(description.to_string(), Style::default().fg(Color::White)),
    ])
}

fn draw_prompt_overlay(
    frame: &mut ratatui::Frame<'_>,
    root: Rect,
    task_id: &str,
    prompt: &str,
    context_lines: &[String],
    edit: Option<&PromptEditState>,
    scroll_from_bottom: usize,
) {
    let area = prompt_overlay_area(root);
    frame.render_widget(Clear, area);
    let inner = inner_rect(area);
    let lines = prompt_overlay_lines(task_id, prompt, context_lines, edit);
    let visible_lines = take_visible_rows(
        &lines,
        scroll_from_bottom,
        inner.width as usize,
        inner.height as usize,
        true,
    );
    let can_scroll = count_visual_rows(&lines, inner.width as usize, true) > inner.height as usize;
    let title = if can_scroll {
        "Input Prompt [scrollable]"
    } else {
        "Input Prompt"
    };
    let widget = Paragraph::new(visible_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Yellow)),
        );
    frame.render_widget(widget, area);
}

fn draw_rename_overlay(frame: &mut ratatui::Frame<'_>, root: Rect, edit: &RenameEditState) {
    let area = centered_rect(72, 20, root);
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(vec![Span::styled(
            "Run display name",
            Style::default()
                .fg(Color::LightYellow)
                .add_modifier(Modifier::BOLD),
        )]),
        Line::from(""),
        Line::from(vec![
            Span::styled("name> ", Style::default().fg(Color::Magenta)),
            Span::raw(edit.buffer.clone()),
        ]),
        Line::from(""),
        Line::from("Enter: save   Esc: cancel"),
    ];
    let widget = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Rename Run")
            .border_style(Style::default().fg(Color::LightYellow)),
    );
    frame.render_widget(widget, area);
}

fn prompt_overlay_lines(
    task_id: &str,
    prompt: &str,
    context_lines: &[String],
    edit: Option<&PromptEditState>,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![Span::styled(
        format!("Input expected for active command ({task_id})"),
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )])];
    if !context_lines.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "Recent context",
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )]));
        lines.extend(context_lines.iter().map(|line| Line::from(line.clone())));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(vec![Span::styled(
        "Prompt",
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )]));
    lines.push(Line::from(prompt.to_string()));
    if let Some(edit) = edit {
        let display_buffer = if prompt_expects_secret(prompt) {
            "*".repeat(edit.buffer.chars().count())
        } else {
            edit.buffer.clone()
        };
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("stdin> ", Style::default().fg(Color::Magenta)),
            Span::raw(display_buffer),
        ]));
        lines.push(Line::from(
            "Enter: send   Shift+Enter: newline   Esc: close",
        ));
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from(
            "Enter: start input   Up/Down/PgUp/PgDn/Home/End: scroll",
        ));
    }
    lines
}

fn prompt_expects_secret(prompt: &str) -> bool {
    let lower = prompt.to_ascii_lowercase();
    lower.contains("[sudo] password for")
        || lower.contains("password for ")
        || lower.contains("password:")
}

fn prompt_overlay_area(root: Rect) -> Rect {
    centered_rect(84, 40, root)
}

fn prompt_overlay_inner_rect(root: Rect) -> Rect {
    inner_rect(prompt_overlay_area(root))
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn terminal_rect(terminal: &Terminal<CrosstermBackend<Stdout>>) -> Result<Rect> {
    let size = terminal.size()?;
    Ok(Rect::new(0, 0, size.width, size.height))
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    Ok(())
}

fn fmt_ts(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "../tests/ui_tui.rs"]
mod tests;
