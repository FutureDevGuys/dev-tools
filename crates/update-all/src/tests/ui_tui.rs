use super::*;

#[test]
fn functional_categories_collapse_to_six_dashboard_groups() {
    assert_eq!(functional_group_label("system"), "System Packages");
    assert_eq!(functional_group_label("language"), "Developer Tools");
    assert_eq!(functional_group_label("agent-tooling"), "Agent Tooling");
    assert_eq!(
        functional_group_label("mobile-reverse-engineering"),
        "Mobile & Reverse Engineering"
    );
    assert_eq!(
        functional_group_label("game-development"),
        "Game Development"
    );
    assert_eq!(functional_group_label("maintenance"), "Maintenance");
}
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use std::collections::VecDeque;

#[test]
fn password_prompts_are_treated_as_secret_input() {
    assert!(prompt_expects_secret("[sudo] password for example-user:"));
    assert!(prompt_expects_secret("Password:"));
    assert!(!prompt_expects_secret(
        "-> Select the service(s) to restart:"
    ));
}

#[test]
fn pane_cycle_respects_focus_mode() {
    assert_eq!(
        cycle_next_pane(ActivePane::Tasks, true, RightPaneMode::Split),
        ActivePane::TaskLogs
    );
    assert_eq!(
        cycle_next_pane(ActivePane::TaskLogs, true, RightPaneMode::Split),
        ActivePane::GlobalLogs
    );
    assert_eq!(
        cycle_next_pane(ActivePane::TaskLogs, true, RightPaneMode::FocusTask),
        ActivePane::Tasks
    );
}

#[test]
fn q_and_upper_q_exit() {
    let mut model = Model::new(200, true, true);
    let (tx, _rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    assert!(handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('q')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert!(handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('Q')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
}

#[test]
fn q_emits_cancel_all_when_configured() {
    let mut model = Model::new(200, true, true);
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('q')),
        &layout,
        &tx,
        DashboardQuitBehavior::CancelAll
    ));
    match rx.recv().expect("cancel event") {
        UiControlEvent::CancelAll => {}
        _ => panic!("expected CancelAll"),
    }
    assert!(model.cancel_requested);
}

#[test]
fn q_does_not_emit_cancel_all_after_run_complete() {
    let mut model = Model::new(200, true, true);
    model.run_complete = Some(true);
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('q')),
        &layout,
        &tx,
        DashboardQuitBehavior::CancelAll
    ));
    assert!(rx.try_recv().is_err());
}

#[test]
fn header_includes_compact_run_identity_when_space_allows() {
    let mut model = Model::new(200, true, true);
    model.set_run_identity(
        "12345678-1234-1234-1234-123456789abc".to_string(),
        "daily".to_string(),
    );

    let spans = render_header_spans(
        &model,
        " running ",
        ratatui::style::Color::Yellow,
        42,
        (1, 2, 3, 4, 5),
        120,
    );
    let header = spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();

    assert!(header.contains("name=daily"));
    assert!(header.contains("id=...123456789abc"));
}

#[test]
fn rename_key_sends_rename_control_event() {
    let mut model = Model::new(200, true, true);
    model.set_run_identity("run-id".to_string(), "run-id".to_string());
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('r')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('X')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Enter),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));

    match rx.recv().expect("rename event") {
        UiControlEvent::RenameRun { name } => assert_eq!(name, "run-idX"),
        other => panic!("expected RenameRun, got {other:?}"),
    }
}

#[test]
fn release_key_events_are_ignored() {
    let mut model = Model::new(200, true, true);
    model.register_task("a".into(), "A".into(), Vec::new(), true);
    model.register_task("b".into(), "B".into(), Vec::new(), true);
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    let release_down = KeyEvent {
        code: KeyCode::Down,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Release,
        state: KeyEventState::NONE,
    };
    assert!(!handle_key_event(
        &mut model,
        release_down,
        &layout,
        &tx,
        DashboardQuitBehavior::CancelAll
    ));
    assert_eq!(model.selected_task, 0);

    let release_q = KeyEvent {
        code: KeyCode::Char('q'),
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Release,
        state: KeyEventState::NONE,
    };
    assert!(!handle_key_event(
        &mut model,
        release_q,
        &layout,
        &tx,
        DashboardQuitBehavior::CancelAll
    ));
    assert!(rx.try_recv().is_err());
}

#[test]
fn repeat_key_events_still_navigate() {
    let mut model = Model::new(200, true, true);
    model.register_task("a".into(), "A".into(), Vec::new(), true);
    model.register_task("b".into(), "B".into(), Vec::new(), true);
    let (tx, _rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    let repeat_down = KeyEvent {
        code: KeyCode::Down,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Repeat,
        state: KeyEventState::NONE,
    };
    assert!(!handle_key_event(
        &mut model,
        repeat_down,
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert_eq!(model.selected_task, 1);
}

#[test]
fn mouse_click_selects_task_row() {
    let mut model = Model::new(200, true, true);
    model.register_task("a".into(), "A".into(), Vec::new(), true);
    model.register_task("b".into(), "B".into(), Vec::new(), true);
    model.register_task("c".into(), "C".into(), Vec::new(), true);
    let layout = layout_for(
        Rect::new(0, 0, 120, 30),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    let click = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: layout.tasks_inner.x + 1,
        // The first rendered row is the functional group heading. The third
        // rendered row is therefore task B, not task C.
        row: layout.tasks_inner.y + 2,
        modifiers: KeyModifiers::NONE,
    };
    handle_mouse_event(&mut model, click, &layout);
    assert_eq!(model.selected_task, 1);
    assert_eq!(model.active_pane, ActivePane::Tasks);
}

#[test]
fn every_visible_grouped_task_row_selects_the_rendered_task() {
    let mut model = Model::new(200, true, true);
    for (id, category) in [
        ("yay", "system-packages"),
        ("npm", "developer-tools"),
        ("cargo", "developer-tools"),
        ("skills", "agent-tooling"),
        ("unity", "game-development"),
    ] {
        model.register_task_with_category(
            id.to_string(),
            id.to_uppercase(),
            category.to_string(),
            Vec::new(),
            false,
        );
    }
    let layout = layout_for(
        Rect::new(0, 0, 120, 30),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    let plan = task_render_plan(
        &model,
        layout.tasks_inner.height as usize,
        layout.tasks_inner.width as usize,
    );

    for (rendered_row, expected_task) in plan.row_to_task.iter().enumerate() {
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: layout.tasks_inner.x + 1,
            row: layout.tasks_inner.y + rendered_row as u16,
            modifiers: KeyModifiers::NONE,
        };
        let before = model.selected_task;
        handle_mouse_event(&mut model, click, &layout);
        match expected_task {
            Some(expected_task) => assert_eq!(model.selected_task, *expected_task),
            None => assert_eq!(model.selected_task, before, "group heading selected a task"),
        }
    }
}

#[test]
fn grouped_mouse_mapping_tracks_scroll_resize_and_stride_two() {
    let mut model = Model::new_with_mouse_stride(200, true, true, MouseRowStride::Two);
    for idx in 0..8 {
        model.register_task_with_category(
            format!("task-{idx}"),
            format!("Task {idx}"),
            if idx < 4 { "system" } else { "language" }.to_string(),
            Vec::new(),
            false,
        );
    }
    model.task_list_offset = 3;
    let layout = layout_for(
        Rect::new(0, 0, 80, 21),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    let plan = task_render_plan(
        &model,
        layout.tasks_inner.height as usize,
        layout.tasks_inner.width as usize,
    );
    let (logical_row, expected_task) = plan
        .row_to_task
        .iter()
        .enumerate()
        .find_map(|(row, task)| task.map(|task| (row, task)))
        .expect("visible task row");

    let click = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: layout.tasks_inner.x + 1,
        row: layout.tasks_inner.y + (logical_row as u16 * 2) + 1,
        modifiers: KeyModifiers::NONE,
    };
    handle_mouse_event(&mut model, click, &layout);
    assert_eq!(model.selected_task, expected_task);

    let resized = layout_for(
        Rect::new(0, 0, 80, 18),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    model.ensure_selected_visible(resized.tasks_inner.height as usize);
    let resized_plan = task_render_plan(
        &model,
        resized.tasks_inner.height as usize,
        resized.tasks_inner.width as usize,
    );
    assert!(resized_plan
        .row_to_task
        .iter()
        .any(|task| *task == Some(model.selected_task)));
}

#[test]
fn mouse_click_with_stride_two_maps_odd_rows_correctly() {
    let mut model = Model::new_with_mouse_stride(200, true, true, MouseRowStride::Two);
    model.register_task("a".into(), "A".into(), Vec::new(), true);
    model.register_task("b".into(), "B".into(), Vec::new(), true);
    model.register_task("c".into(), "C".into(), Vec::new(), true);
    let layout = layout_for(
        Rect::new(0, 0, 120, 30),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    let click = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: layout.tasks_inner.x + 1,
        row: layout.tasks_inner.y + 5,
        modifiers: KeyModifiers::NONE,
    };
    handle_mouse_event(&mut model, click, &layout);
    assert_eq!(model.selected_task, 1);
}

#[test]
fn duplicate_task_wheel_events_are_suppressed() {
    let mut model = Model::new(200, true, true);
    model.register_task("a".into(), "A".into(), Vec::new(), true);
    model.register_task("b".into(), "B".into(), Vec::new(), true);
    model.register_task("c".into(), "C".into(), Vec::new(), true);
    model.active_pane = ActivePane::Tasks;
    let layout = layout_for(
        Rect::new(0, 0, 120, 30),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    let scroll = MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: layout.tasks_inner.x + 1,
        row: layout.tasks_inner.y + 2,
        modifiers: KeyModifiers::NONE,
    };
    handle_mouse_event(&mut model, scroll, &layout);
    handle_mouse_event(&mut model, scroll, &layout);
    assert_eq!(model.selected_task, 1);
}

#[test]
fn auto_mouse_stride_keeps_one_to_one_row_mapping() {
    let mut model = Model::new(200, true, true);
    let tasks_inner = Rect::new(1, 10, 40, 20);
    for row in [10u16, 12, 14, 16, 18, 20] {
        model.observe_task_mouse_row(tasks_inner, row);
    }
    assert_eq!(model.task_mouse_row_stride, 1);
}

#[test]
fn resize_keeps_auto_mouse_stride_at_one() {
    let mut model = Model::new(200, true, true);
    let tasks_inner = Rect::new(1, 10, 40, 20);
    for row in [10u16, 12, 14, 16, 18, 20] {
        model.observe_task_mouse_row(tasks_inner, row);
    }

    model.reset_task_mouse_stride_calibration();

    assert_eq!(model.task_mouse_row_stride, 1);
    assert!(model.last_task_wheel.is_none());
}

#[test]
fn explicit_mouse_stride_two_remains_opt_in() {
    let mut model = Model::new_with_mouse_stride(200, true, true, MouseRowStride::Two);
    model.register_task("a".into(), "A".into(), Vec::new(), false);
    model.register_task("b".into(), "B".into(), Vec::new(), false);
    assert_eq!(model.task_mouse_row_stride, 2);
    assert_eq!(
        task_index_for_mouse(&model, Rect::new(1, 10, 40, 20), 14),
        Some(1)
    );
}

#[test]
fn toggle_switches_between_split_and_focused() {
    let mut model = Model::new(200, true, true);
    model.active_pane = ActivePane::GlobalLogs;
    model.right_pane_mode = RightPaneMode::Split;
    toggle_right_pane_mode(&mut model);
    assert_eq!(model.right_pane_mode, RightPaneMode::FocusGlobal);
    toggle_right_pane_mode(&mut model);
    assert_eq!(model.right_pane_mode, RightPaneMode::Split);
}

#[test]
fn sanitize_strips_control_sequences() {
    let raw = "\u{1b}[31merror\u{1b}[0m\tok\r";
    assert_eq!(sanitize_log_line(raw), "error  ok");
}

#[test]
fn stylize_log_body_highlights_arch_update_markers() {
    let spans = stylize_log_body(
        "==> WARNING [NEW] -> Select the service(s) to restart",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    let rendered = spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    assert!(rendered.contains("==>"));
    assert!(rendered.contains("WARNING"));
    assert!(rendered.contains("[NEW]"));
    assert!(rendered.contains("->"));
}

#[test]
fn stylize_log_body_highlights_versioned_dependency_deltas() {
    for (line, expected) in [
        (" - idna==3.18", Color::LightRed),
        (" + idna==3.19", Color::LightGreen),
    ] {
        let spans = stylize_log_body(
            line,
            Style::default(),
            LogStream::Stderr,
            ReportHighlightState::None,
            LabeledVersionColorMode::Standalone,
        );
        let delta = spans
            .iter()
            .find(|span| span.content.as_ref().contains("idna=="))
            .expect("versioned dependency delta span");
        assert_eq!(delta.style.fg, Some(expected));
        assert!(delta.style.add_modifier.contains(Modifier::BOLD));
    }
}

#[test]
fn stylize_log_body_leaves_plain_dash_bullets_neutral() {
    let spans = stylize_log_body(
        "- nano-pdf",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    assert!(spans.iter().all(|span| span.style.fg.is_none()));
}

#[test]
fn stylize_report_row_highlights_version_columns() {
    let spans = stylize_log_body(
        "pkg      1.0.0             1.1.0             Updated",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );
    let rendered = spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    assert_eq!(
        rendered,
        "pkg      1.0.0             1.1.0             Updated"
    );
    assert!(spans
        .iter()
        .any(|span| span.content.as_ref().contains("1.0.0")));
    assert!(spans
        .iter()
        .any(|span| span.content.as_ref().contains("1.1.0")));
}

#[test]
fn stylize_report_row_leaves_unchanged_versions_uncolored() {
    let spans = stylize_log_body(
        "pkg      1.0.0             1.0.0             Unchanged",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );
    assert!(!spans
        .iter()
        .any(|span| span.style.fg == Some(Color::LightRed)));
    assert!(!spans
        .iter()
        .any(|span| span.style.fg == Some(Color::LightGreen)));
}

#[test]
fn stylize_report_row_highlights_blocked_changed_versions() {
    let spans = stylize_log_body(
        "nodejs-lts  24.13.1           24.15.0           Blocked",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );

    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("24.13.1"))
        .expect("before version span");
    let after_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("24.15.0"))
        .expect("after version span");
    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Blocked"))
        .expect("blocked status span");

    assert_eq!(before_span.style.fg, Some(Color::LightRed));
    assert_eq!(after_span.style.fg, Some(Color::LightGreen));
    assert_eq!(status_span.style.fg, Some(Color::Rgb(255, 165, 0)));
}

#[test]
fn stylize_log_body_does_not_color_arbitrary_aligned_tables() {
    let spans = stylize_log_body(
        "Name          Id                      Version    Available  Source",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    let rendered = spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();
    assert_eq!(
        rendered,
        "Name          Id                      Version    Available  Source"
    );
    assert_eq!(spans.len(), 1);
}

#[test]
fn report_classifier_treats_blank_and_named_sections_as_report_content() {
    assert!(is_report_meta_line(""));
    assert!(is_report_meta_line("Final Task Overview"));
    assert!(is_report_meta_line("Update Details"));
    assert!(is_report_meta_line("Yay Recovery Actions"));
    assert!(is_report_meta_line("Task  Item  Before  After  Notes"));
    assert!(!is_report_meta_line("sudo session keepalive started"));
}

#[test]
fn stylize_log_body_colors_report_note_tags_only() {
    let spans = stylize_log_body(
        "  [FAIL] source validation still failed",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Recovery),
        LabeledVersionColorMode::Standalone,
    );

    let fail_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("[FAIL]"))
        .expect("fail tag span");
    let note_span = spans
        .iter()
        .find(|span| {
            span.content
                .as_ref()
                .contains("source validation still failed")
        })
        .expect("note body span");

    assert_eq!(fail_span.style.fg, Some(Color::Red));
    assert_ne!(note_span.style.fg, Some(Color::Red));
}

#[test]
fn block_report_notes_are_report_notes_and_keep_highlight_state() {
    let note = LogRecord {
        ts_unix_ms: 0,
        task_id: "scoop-all".to_string(),
        level: LogLevel::Warn,
        stream: LogStream::Meta,
        line: "  [BLOCK] running process detected".to_string(),
    };

    assert!(is_report_note_line(&note.line));
    assert!(is_report_meta_line(&note.line));

    let spans = stylize_log_body(
        &note.line,
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );
    let block_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("[BLOCK]"))
        .expect("block tag span");
    assert_eq!(block_span.style.fg, Some(Color::Rgb(255, 165, 0)));

    assert_eq!(
        advance_report_highlight_state(
            ReportHighlightState::Active(ReportStyleKind::Standard),
            &note
        ),
        ReportHighlightState::Active(ReportStyleKind::Standard)
    );
}

#[test]
fn pass_and_same_report_notes_are_report_notes_and_keep_highlight_state() {
    let pass_note = LogRecord {
        ts_unix_ms: 0,
        task_id: "completions".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "  [PASS] generated shell completions".to_string(),
    };
    let same_note = LogRecord {
        ts_unix_ms: 1,
        task_id: "cargo".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "  [SAME] trunk stayed at v0.21.14".to_string(),
    };

    for note in [&pass_note, &same_note] {
        assert!(is_report_note_line(&note.line));
        assert!(is_report_meta_line(&note.line));
        assert_eq!(
            advance_report_highlight_state(
                ReportHighlightState::Active(ReportStyleKind::Standard),
                note
            ),
            ReportHighlightState::Active(ReportStyleKind::Standard)
        );
    }

    let pass_spans = stylize_log_body(
        &pass_note.line,
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );
    let same_spans = stylize_log_body(
        &same_note.line,
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );

    let pass_tag_span = pass_spans
        .iter()
        .find(|span| span.content.as_ref().contains("[PASS]"))
        .expect("pass tag span");
    let same_tag_span = same_spans
        .iter()
        .find(|span| span.content.as_ref().contains("[SAME]"))
        .expect("same tag span");
    assert_eq!(pass_tag_span.style.fg, Some(Color::LightGreen));
    assert_ne!(same_tag_span.style.fg, Some(Color::LightRed));
    assert_ne!(same_tag_span.style.fg, Some(Color::LightGreen));
    assert_ne!(same_tag_span.style.fg, Some(Color::Yellow));
}

#[test]
fn stylize_report_row_colors_passed_and_skipped_status_cells() {
    let passed_spans = stylize_log_body(
        "completion  -  -  Passed",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );
    let skipped_spans = stylize_log_body(
        "arch-update-services  -  -  Skipped",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );

    let passed_status = passed_spans
        .iter()
        .find(|span| span.content.as_ref().contains("Passed"))
        .expect("passed status span");
    let skipped_status = skipped_spans
        .iter()
        .find(|span| span.content.as_ref().contains("Skipped"))
        .expect("skipped status span");

    assert_eq!(passed_status.style.fg, Some(Color::LightGreen));
    assert_eq!(skipped_status.style.fg, Some(Color::Yellow));
}

#[test]
fn refreshed_status_uses_distinct_cyan_style_across_report_surfaces() {
    let standard_spans = stylize_log_body(
        "demo  1.2.3  1.2.3  Refreshed",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );
    let status_only_spans = stylize_log_body(
        "demo  refresh_ok  environment reconciled  Refreshed",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::StatusOnly),
        LabeledVersionColorMode::Standalone,
    );
    let box_spans = stylize_log_body(
        "│ Language │ Pipx │ demo │ 1.2.3 │ 1.2.3 │ Refreshed │ environment reconciled │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    let note_spans = stylize_log_body(
        "  [REFRESH] environment reconciled",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Standard),
        LabeledVersionColorMode::Standalone,
    );

    for (surface, spans) in [
        ("standard", standard_spans),
        ("status-only", status_only_spans),
        ("box", box_spans),
        ("note", note_spans),
    ] {
        let refreshed = spans
            .iter()
            .find(|span| {
                let content = span.content.as_ref().trim();
                content.eq_ignore_ascii_case("refreshed") || content.contains("[REFRESH]")
            })
            .unwrap_or_else(|| panic!("{surface} refreshed span"));
        assert_eq!(
            refreshed.style.fg,
            Some(Color::Cyan),
            "{surface} refreshed style"
        );
    }
}

#[test]
fn section_specific_outcomes_use_semantic_colors_in_box_rollups() {
    let cases = [
        (
            "Restarted",
            Color::LightGreen,
            "│ System │ Svc Restart │ sshd │ inactive │ active │ Restarted │ service restarted │",
        ),
        (
            "Not Restarted",
            Color::Yellow,
            "│ System │ Svc Restart │ sshd │ active │ active │ Not Restarted │ deferred │",
        ),
    ];

    for (outcome, expected_color, line) in cases {
        let spans = stylize_log_body(
            line,
            Style::default(),
            LogStream::Meta,
            ReportHighlightState::None,
            LabeledVersionColorMode::Standalone,
        );
        let status = spans
            .iter()
            .find(|span| span.content.as_ref().trim() == outcome)
            .unwrap_or_else(|| panic!("{outcome} status span"));
        assert_eq!(status.style.fg, Some(expected_color), "{outcome} style");
    }
}

#[test]
fn status_only_report_tables_keep_highlight_state_and_color_only_status_cells() {
    let title = LogRecord {
        ts_unix_ms: 1,
        task_id: "completions".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Completion Audit Results".to_string(),
    };
    let header = LogRecord {
        ts_unix_ms: 2,
        task_id: "completions".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Check  Code  Detail  Outcome".to_string(),
    };
    let row = LogRecord {
        ts_unix_ms: 3,
        task_id: "completions".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "codex  managed_overlay_ok  managed catalog overlay shim points at generated payload  Pass".to_string(),
    };

    let mut state = ReportHighlightState::None;
    state = advance_report_highlight_state(state, &title);
    state = advance_report_highlight_state(state, &header);
    assert!(
        matches!(state, ReportHighlightState::Active(_)),
        "{state:?}"
    );
    state = advance_report_highlight_state(state, &row);
    assert!(
        matches!(state, ReportHighlightState::Active(_)),
        "{state:?}"
    );

    let spans = stylize_log_body(
        &row.line,
        Style::default(),
        LogStream::Meta,
        state,
        LabeledVersionColorMode::Standalone,
    );
    let name_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("codex"))
        .expect("name span");
    let code_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("managed_overlay_ok"))
        .expect("code span");
    let detail_span = spans
        .iter()
        .find(|span| {
            span.content
                .as_ref()
                .contains("managed catalog overlay shim")
        })
        .expect("detail span");
    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Pass"))
        .expect("status span");

    assert_eq!(status_span.style.fg, Some(Color::LightGreen));
    assert_ne!(name_span.style.fg, Some(Color::LightGreen));
    assert_ne!(code_span.style.fg, Some(Color::LightGreen));
    assert_ne!(detail_span.style.fg, Some(Color::LightGreen));
    assert_ne!(code_span.style.fg, Some(Color::LightRed));
    assert_ne!(detail_span.style.fg, Some(Color::LightRed));
}

#[test]
fn stylize_log_body_colors_box_table_status_cells_without_tinting_other_cells() {
    let spans = stylize_log_body(
        "│ System   │ Yay         │ Failed    │ failed=1 unchanged=1   │ retry failed │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let failed_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Failed"))
        .expect("failed status span");
    let items_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("failed=1 unchanged=1"))
        .expect("items span");

    assert_eq!(failed_span.style.fg, Some(Color::Red));
    assert_ne!(items_span.style.fg, Some(Color::Red));
    assert_ne!(items_span.style.fg, Some(Color::Yellow));
}

#[test]
fn stylize_log_body_colors_passed_box_table_status_cells_without_tinting_other_cells() {
    let spans = stylize_log_body(
        "│ Completion │ Shell │ generated │ - │ - │ Passed │ completions generated │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let passed_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Passed"))
        .expect("passed status span");
    let detail_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("completions generated"))
        .expect("detail span");

    assert_eq!(passed_span.style.fg, Some(Color::LightGreen));
    assert_ne!(detail_span.style.fg, Some(Color::LightGreen));
}

#[test]
fn stylize_log_body_colors_box_table_short_status_cells() {
    let cases = [
        (
            "Warn",
            "needs attention",
            Color::Rgb(255, 165, 0),
            "│ Maintenance │ Completion Audit │ managed_overlay │ - │ - │ Warn │ needs attention │",
        ),
        (
            "Fail",
            "failed probe",
            Color::Red,
            "│ Maintenance │ Completion Audit │ native_payload │ - │ - │ Fail │ failed probe │",
        ),
        (
            "Skip",
            "disabled by config",
            Color::Yellow,
            "│ Maintenance │ Completion Audit │ optional_tool │ - │ - │ Skip │ disabled by config │",
        ),
        (
            "Generated",
            "completion generated",
            Color::LightGreen,
            "│ Completion │ Shell │ codex │ npm │ generated │ Generated │ completion generated │",
        ),
    ];

    for (status, note, expected_color, line) in cases {
        let spans = stylize_log_body(
            line,
            Style::default(),
            LogStream::Meta,
            ReportHighlightState::None,
            LabeledVersionColorMode::Standalone,
        );

        let status_span = spans
            .iter()
            .find(|span| span.content.as_ref().trim() == status)
            .unwrap_or_else(|| panic!("{status} status span"));
        let note_span = spans
            .iter()
            .find(|span| span.content.as_ref().contains(note))
            .unwrap_or_else(|| panic!("{status} note span"));

        assert_eq!(status_span.style.fg, Some(expected_color));
        assert_ne!(note_span.style.fg, Some(Color::LightGreen));
        assert_ne!(note_span.style.fg, Some(Color::Rgb(255, 165, 0)));
        assert_ne!(note_span.style.fg, Some(Color::Yellow));
        assert_ne!(note_span.style.fg, Some(Color::Red));
    }
}

#[test]
fn stylize_log_body_colors_box_table_status_words_only_in_status_column() {
    let spans = stylize_log_body(
        "│ System │ Yay │ cache cleanup │ present │ removed │ Removed │ Updated │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Removed"))
        .expect("status span");
    let note_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Updated"))
        .expect("note span");

    assert_eq!(status_span.style.fg, Some(Color::Yellow));
    assert_ne!(note_span.style.fg, Some(Color::LightGreen));
    assert_ne!(note_span.style.fg, Some(Color::Yellow));
    assert_ne!(note_span.style.fg, Some(Color::Red));
}

#[test]
fn stylize_log_body_colors_final_overview_completed_with_issues_status_only() {
    let spans = stylize_log_body(
        "│ System │ Yay │ Completed* │ updated=1 failed=1 │ Updated package still blocked │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Completed*"))
        .expect("completed with issues status span");
    let note_span = spans
        .iter()
        .find(|span| {
            span.content
                .as_ref()
                .contains("Updated package still blocked")
        })
        .expect("note span");

    assert_eq!(status_span.style.fg, Some(Color::Yellow));
    assert_ne!(note_span.style.fg, Some(Color::LightGreen));
    assert_ne!(note_span.style.fg, Some(Color::Yellow));
    assert_ne!(note_span.style.fg, Some(Color::Red));
}

#[test]
fn stylize_log_body_colors_blocked_box_table_status_cells() {
    let spans = stylize_log_body(
        "│ System │ Scoop │ nodejs-lts │ 24.13.1 │ 24.15.0 │ Blocked │ running process detected │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let blocked_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Blocked"))
        .expect("blocked status span");

    assert_eq!(blocked_span.style.fg, Some(Color::Rgb(255, 165, 0)));
}

#[test]
fn stylize_log_body_colors_box_rollup_changed_before_after_cells() {
    let spans = stylize_log_body(
        "│ Language │ NPM │ @google/gemini-cli │ 0.40.0 │ 0.40.1 │ Updated │ │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("0.40.0"))
        .expect("before version span");
    let after_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("0.40.1"))
        .expect("after version span");
    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Updated"))
        .expect("status span");

    assert_eq!(before_span.style.fg, Some(Color::LightRed));
    assert_eq!(after_span.style.fg, Some(Color::LightGreen));
    assert_eq!(status_span.style.fg, Some(Color::LightGreen));
}

#[test]
fn stylize_log_body_colors_box_rollup_blocked_before_after_cells() {
    let spans = stylize_log_body(
        "│ System │ Scoop │ nodejs-lts │ 24.13.1 │ 24.15.0 │ Blocked │ running process detected │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("24.13.1"))
        .expect("before version span");
    let after_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("24.15.0"))
        .expect("after version span");

    assert_eq!(before_span.style.fg, Some(Color::LightRed));
    assert_eq!(after_span.style.fg, Some(Color::LightGreen));
}

#[test]
fn stylize_log_body_does_not_tint_unchanged_box_rollup_version_cells() {
    let spans = stylize_log_body(
        "│ Language │ Cargo │ cargo-deny │ 0.19.6 │ 0.19.6 │ Unchanged │ unchanged │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("0.19.6"))
        .expect("before version span");
    let after_span = spans
        .iter()
        .rev()
        .find(|span| span.content.as_ref().contains("0.19.6"))
        .expect("after version span");
    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Unchanged"))
        .expect("status span");

    assert_eq!(before_span.style.fg, None);
    assert_eq!(after_span.style.fg, None);
    assert_eq!(status_span.style.fg, None);
}

#[test]
fn stylize_log_body_does_not_color_box_rollup_provider_artifact_cells_as_versions() {
    let spans = stylize_log_body(
        "│ Mainten... │ Completions │ codex │ npm │ /home/example-user... │ Updated │ │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let provider_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("npm"))
        .expect("provider span");
    let artifact_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("/home/example-user"))
        .expect("artifact span");
    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Updated"))
        .expect("status span");

    assert_ne!(provider_span.style.fg, Some(Color::LightRed));
    assert_ne!(artifact_span.style.fg, Some(Color::LightGreen));
    assert_eq!(status_span.style.fg, Some(Color::LightGreen));
}

#[test]
fn stylize_log_body_does_not_color_non_report_box_table_version_cells() {
    let spans = stylize_log_body(
        "│ Name │ Id │ Version │ 1.0.0 │ 1.1.0 │ Source │ winget │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    let rendered = spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();

    assert_eq!(
        rendered,
        "│ Name │ Id │ Version │ 1.0.0 │ 1.1.0 │ Source │ winget │"
    );
    assert!(
        spans
            .iter()
            .filter(|span| !span.content.as_ref().contains('│'))
            .all(|span| span.style.fg != Some(Color::LightRed)
                && span.style.fg != Some(Color::LightGreen)),
        "non-report box tables should not color arbitrary version-looking cells: {spans:?}"
    );
    assert!(
        spans
            .iter()
            .filter(|span| span.content.as_ref().contains('│'))
            .all(|span| span.style.fg.is_none()),
        "box-table borders should keep the base style: {spans:?}"
    );
}

#[test]
fn stylize_log_body_does_not_color_box_recovery_state_cells_as_versions() {
    let spans = stylize_log_body(
        "│ System │ Yay │ /home/example-user/.cache/yay/... │ present │ removed │ Removed │ cleared package cache/worktree ... │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("present"))
        .expect("before state span");
    let after_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("removed"))
        .expect("after state span");
    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Removed"))
        .expect("status span");

    assert_ne!(before_span.style.fg, Some(Color::LightRed));
    assert_ne!(after_span.style.fg, Some(Color::LightGreen));
    assert_eq!(status_span.style.fg, Some(Color::Yellow));
}

#[test]
fn stylize_log_body_does_not_color_recovery_state_report_columns_as_versions() {
    let spans = stylize_log_body(
        "/home/example-user/.cache/yay/gibo-bin  present           removed           Removed",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::Active(ReportStyleKind::Recovery),
        LabeledVersionColorMode::Standalone,
    );

    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("present"))
        .expect("before state span");
    let after_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("removed"))
        .expect("after state span");
    let status_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Removed"))
        .expect("status span");

    assert_ne!(before_span.style.fg, Some(Color::LightRed));
    assert_ne!(after_span.style.fg, Some(Color::LightGreen));
    assert_eq!(status_span.style.fg, Some(Color::Yellow));
}

#[test]
fn stylize_box_table_row_ignores_parenthetical_available_note_when_base_version_unchanged() {
    let spans = stylize_log_body(
        "│ Language │ Cargo │ trunk │ v0.21.14 │ v0.21.14 (v0.22.0-beta.1 available) │ Unchanged │ unchanged │",
        Style::default(),
        LogStream::Meta,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let before_span = spans
        .iter()
        .find(|span| {
            let content = span.content.as_ref();
            content.contains("v0.21.14") && !content.contains("available")
        })
        .expect("before version span");
    let after_span = spans
        .iter()
        .find(|span| {
            span.content
                .as_ref()
                .contains("v0.21.14 (v0.22.0-beta.1 available)")
        })
        .expect("after version span");

    assert_ne!(before_span.style.fg, Some(Color::LightRed));
    assert_ne!(after_span.style.fg, Some(Color::LightGreen));
}

#[test]
fn stylize_log_body_highlights_update_details_before_after_columns() {
    let title = LogRecord {
        ts_unix_ms: 1,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Update Details".to_string(),
    };
    let header = LogRecord {
        ts_unix_ms: 2,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Task  Package  Before  After  Notes".to_string(),
    };
    let mut state = ReportHighlightState::None;
    state = advance_report_highlight_state(state, &title);
    state = advance_report_highlight_state(state, &header);

    let spans = stylize_log_body(
        "Rustup  stable  1.93.1  1.94.0  updated",
        Style::default(),
        LogStream::Meta,
        state,
        LabeledVersionColorMode::Standalone,
    );

    let task_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("Rustup"))
        .expect("task span");
    let item_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("stable"))
        .expect("item span");
    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("1.93.1"))
        .expect("before version span");
    let after_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("1.94.0"))
        .expect("after version span");
    let notes_span = spans
        .iter()
        .find(|span| span.content.as_ref().contains("updated"))
        .expect("notes span");

    assert_eq!(task_span.style.fg, None);
    assert_eq!(item_span.style.fg, None);
    assert_eq!(before_span.style.fg, Some(Color::LightRed));
    assert_eq!(after_span.style.fg, Some(Color::LightGreen));
    assert_eq!(notes_span.style.fg, None);
}

#[test]
fn stylize_log_body_highlights_before_after_versions() {
    let before = stylize_log_body(
        "  Before: 2026.3.8",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    let after = stylize_log_body(
        "  After: 2026.3.9",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );

    let before_span = before
        .iter()
        .find(|span| span.content.as_ref().contains("2026.3.8"))
        .expect("before version span");
    let after_span = after
        .iter()
        .find(|span| span.content.as_ref().contains("2026.3.9"))
        .expect("after version span");

    assert_eq!(before_span.style.fg, Some(Color::LightRed));
    assert_eq!(after_span.style.fg, Some(Color::LightGreen));
}

#[test]
fn stylize_log_body_leaves_equal_before_after_versions_neutral() {
    let records = vec![
        LogRecord {
            ts_unix_ms: 1,
            task_id: "skills".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "  Before: 2026.3.28".to_string(),
        },
        LogRecord {
            ts_unix_ms: 2,
            task_id: "skills".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "  After: 2026.3.28".to_string(),
        },
    ];

    let before = stylize_log_body(
        &records[0].line,
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        labeled_version_color_mode(&records, 0),
    );
    let after = stylize_log_body(
        &records[1].line,
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        labeled_version_color_mode(&records, 1),
    );

    assert!(!before
        .iter()
        .any(|span| span.style.fg == Some(Color::LightRed)));
    assert!(!after
        .iter()
        .any(|span| span.style.fg == Some(Color::LightGreen)));
}

#[test]
fn labeled_version_color_mode_does_not_pair_across_tasks_or_streams() {
    let records = vec![
        LogRecord {
            ts_unix_ms: 1,
            task_id: "cargo".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "  Before: v0.21.14".to_string(),
        },
        LogRecord {
            ts_unix_ms: 2,
            task_id: "go".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "  After: v0.21.14".to_string(),
        },
        LogRecord {
            ts_unix_ms: 3,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "  Before: 1.2.3".to_string(),
        },
        LogRecord {
            ts_unix_ms: 4,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Meta,
            line: "  After: 1.2.3".to_string(),
        },
    ];

    assert_eq!(
        labeled_version_color_mode(&records, 0),
        LabeledVersionColorMode::Standalone
    );
    assert_eq!(
        labeled_version_color_mode(&records, 1),
        LabeledVersionColorMode::Standalone
    );
    assert_eq!(
        labeled_version_color_mode(&records, 2),
        LabeledVersionColorMode::Standalone
    );
    assert_eq!(
        labeled_version_color_mode(&records, 3),
        LabeledVersionColorMode::Standalone
    );
}

#[test]
fn stylize_log_body_highlights_arrow_versions_conservatively() {
    let spans = stylize_log_body(
        "- @anthropic-ai/claude-code: updated 2.1.73 -> 2.1.74",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    let before_span = spans
        .iter()
        .find(|span| span.content.as_ref() == "2.1.73")
        .expect("before version span");
    let arrow_span = spans
        .iter()
        .find(|span| span.content.as_ref() == "->")
        .expect("arrow span");
    let after_span = spans
        .iter()
        .find(|span| span.content.as_ref() == "2.1.74")
        .expect("after version span");

    assert_eq!(before_span.style.fg, Some(Color::LightRed));
    assert_eq!(arrow_span.style.fg, Some(Color::LightBlue));
    assert_eq!(after_span.style.fg, Some(Color::LightGreen));
}

#[test]
fn stylize_log_body_highlights_unicode_arrow_versions() {
    let spans = stylize_log_body(
        "nodejs-lts: 24.13.1 → 24.14.0",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    assert!(spans.iter().any(|span| {
        span.content.as_ref() == "24.13.1" && span.style.fg == Some(Color::LightRed)
    }));
    assert!(spans
        .iter()
        .any(|span| { span.content.as_ref() == "→" && span.style.fg == Some(Color::LightBlue) }));
    assert!(spans.iter().any(|span| {
        span.content.as_ref() == "24.14.0" && span.style.fg == Some(Color::LightGreen)
    }));
}

#[test]
fn stylize_log_body_ignores_non_version_arrows() {
    let spans = stylize_log_body(
        "  (/home/example-user/.npm-global/lib/node_modules/codex/dist/entry.js -> /home/example-user/.npm-global/lib/node_modules/codex/dist/index.js)",
        Style::default(),
        LogStream::Stdout,
        ReportHighlightState::None,
        LabeledVersionColorMode::Standalone,
    );
    assert_eq!(
        spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>(),
        "  (/home/example-user/.npm-global/lib/node_modules/codex/dist/entry.js -> /home/example-user/.npm-global/lib/node_modules/codex/dist/index.js)"
    );
    assert!(!spans
        .iter()
        .any(|span| span.style.fg == Some(Color::LightRed)));
    assert!(!spans
        .iter()
        .any(|span| span.style.fg == Some(Color::LightGreen)));
    assert!(!spans
        .iter()
        .any(|span| span.style.fg == Some(Color::LightBlue)));
}

#[test]
fn fit_task_label_truncates_long_labels() {
    assert_eq!(fit_task_label("Svc Restart", 14), "Svc Restart");
    assert_eq!(fit_task_label("Arch-Update Services", 14), "Arch-Update...");
}

#[test]
fn fit_task_status_detail_uses_canonical_label_when_narrow() {
    assert_eq!(
        fit_task_status_detail(
            "Completed",
            Some("a very long installer detail that would run beyond the task pane"),
            26
        ),
        "Completed"
    );
}

#[test]
fn fit_task_status_detail_ellipsizes_cleanly_when_space_remains() {
    let rendered = fit_task_status_detail(
        "Failed",
        Some("Cherry Studio installer failed with exit code 2"),
        42,
    );
    assert!(rendered.starts_with("Failed "));
    assert!(rendered.ends_with("..."));
    assert!(UnicodeWidthStr::width(rendered.as_str()) <= 25);
}

#[test]
fn fit_task_status_detail_uses_display_width_for_unicode() {
    let rendered = fit_task_status_detail("Completed", Some("更新が完了しました"), 36);
    assert!(UnicodeWidthStr::width(rendered.as_str()) <= 19);
}

#[test]
fn report_highlight_state_requires_report_title_and_header() {
    let title = LogRecord {
        ts_unix_ms: 1,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Scoop Package Results".to_string(),
    };
    let header = LogRecord {
        ts_unix_ms: 2,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Package  Before  After  Outcome".to_string(),
    };
    let row = LogRecord {
        ts_unix_ms: 3,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "nodejs-lts  24.13.1  24.14.0  Unchanged".to_string(),
    };
    let foreign = LogRecord {
        ts_unix_ms: 4,
        task_id: "scoop-all".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "Name          Id                      Version    Available  Source".to_string(),
    };

    let mut state = ReportHighlightState::None;
    state = advance_report_highlight_state(state, &title);
    assert_eq!(
        state,
        ReportHighlightState::AwaitingHeader(ReportStyleKind::Standard)
    );
    state = advance_report_highlight_state(state, &header);
    assert_eq!(
        state,
        ReportHighlightState::Active(ReportStyleKind::Standard)
    );
    state = advance_report_highlight_state(state, &row);
    assert_eq!(
        state,
        ReportHighlightState::Active(ReportStyleKind::Standard)
    );
    state = advance_report_highlight_state(state, &foreign);
    assert_eq!(state, ReportHighlightState::None);
}

#[test]
fn report_highlight_state_accepts_update_details_header() {
    let title = LogRecord {
        ts_unix_ms: 1,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Update Details".to_string(),
    };
    let header = LogRecord {
        ts_unix_ms: 2,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Task  Package  Before  After  Notes".to_string(),
    };
    let row = LogRecord {
        ts_unix_ms: 3,
        task_id: "runtime".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "Rustup  stable  1.93.1  1.94.0  updated".to_string(),
    };

    let mut state = ReportHighlightState::None;
    state = advance_report_highlight_state(state, &title);
    assert_eq!(
        state,
        ReportHighlightState::AwaitingHeader(ReportStyleKind::UpdateDetails)
    );
    state = advance_report_highlight_state(state, &header);
    assert!(
        matches!(state, ReportHighlightState::Active(_)),
        "{state:?}"
    );
    state = advance_report_highlight_state(state, &row);
    assert!(
        matches!(state, ReportHighlightState::Active(_)),
        "{state:?}"
    );
}

#[test]
fn model_wrap_logs_defaults_to_false() {
    let model = Model::new(200, true, true);
    assert!(!model.wrap_logs);
}

#[test]
fn dashboard_footer_mentions_log_pager_key() {
    let model = Model::new(200, true, true);
    let footer = render_footer_lines(&model)
        .into_iter()
        .map(|line| {
            line.spans
                .into_iter()
                .map(|span| span.content.into_owned())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(footer.contains("m open log"), "{footer}");
}

#[test]
fn dashboard_footer_drops_cancel_actions_after_run_complete() {
    let mut model = Model::new(200, true, true);
    model.run_complete = Some(true);
    model.run_completed_at = Some(std::time::Instant::now());

    let footer = render_footer_lines(&model)
        .into_iter()
        .map(|line| {
            line.spans
                .into_iter()
                .map(|span| span.content.into_owned())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(footer.contains("m open log"), "{footer}");
    assert!(footer.contains("q close dashboard"), "{footer}");
    assert!(!footer.contains("kill one/all"), "{footer}");
}

#[test]
fn model_elapsed_freezes_after_run_complete() {
    let mut model = Model::new(200, true, true);
    let started = std::time::Instant::now() - std::time::Duration::from_secs(30);
    let completed = started + std::time::Duration::from_secs(7);
    model.started_at = started;
    model.run_completed_at = Some(completed);

    assert_eq!(model_elapsed(&model).as_secs(), 7);
}

#[test]
fn run_complete_event_uses_task_completion_instant() {
    let mut model = Model::new(200, true, true);
    let started = std::time::Instant::now() - std::time::Duration::from_secs(30);
    let completed = started + std::time::Duration::from_secs(7);
    model.started_at = started;

    apply_run_complete_event(&mut model, true, completed);

    assert_eq!(model.run_complete, Some(true));
    assert_eq!(model_elapsed(&model).as_secs(), 7);
}

#[test]
fn help_overlay_includes_categories_and_color_sections() {
    let lines = render_help_lines();
    let text = lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Navigation"));
    assert!(text.contains("Search & View"));
    assert!(text.contains("Actions"));
    assert!(text.contains("Mouse"));
    assert!(text.contains("Task State Colors"));
    assert!(text.contains("UI Accent Colors"));
}

#[test]
fn help_overlay_lists_current_task_state_palette() {
    let lines = render_help_lines();
    let text = lines
        .iter()
        .map(|line| {
            line.spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Pending"));
    assert!(text.contains("Running"));
    assert!(text.contains("Completed"));
    assert!(text.contains("Failed"));
    assert!(text.contains("Canceled"));
    assert!(text.contains("Skipped"));

    assert_eq!(state_color(TaskState::Pending), Color::DarkGray);
    assert_eq!(state_color(TaskState::Running), Color::Cyan);
    assert_eq!(state_color(TaskState::Completed), Color::Green);
    assert_eq!(state_color(TaskState::Failed), Color::Red);
    assert_eq!(state_color(TaskState::Canceled), Color::Yellow);
    assert_eq!(state_color(TaskState::Skipped), Color::Blue);
}

#[test]
fn coalesces_consecutive_progress_lines_for_same_task_and_stream() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".into(), "Yay".into(), Vec::new(), false);

    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stderr,
        line: "% Total    % Received % Xferd".to_string(),
    });
    model.push_task_log(LogRecord {
        ts_unix_ms: 2,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stderr,
        line: "  5  6.10M   5 356.4k   0      0".to_string(),
    });
    model.push_task_log(LogRecord {
        ts_unix_ms: 3,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stderr,
        line: "100  6.10M 100  6.10M   0      0".to_string(),
    });

    let task = model.tasks.get("yay").expect("yay task present");
    assert_eq!(task.logs.len(), 1);
    assert_eq!(
        task.logs.back().map(|r| r.line.as_str()),
        Some("100  6.10M 100  6.10M   0      0")
    );
    assert_eq!(model.global_logs.len(), 1);
}

#[test]
fn task_logs_replay_records_received_before_registration() {
    let mut model = Model::new(200, true, true);

    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: "builtin/npm".to_string(),
        level: LogLevel::Warn,
        stream: LogStream::Stderr,
        line: "npm error code ETIMEDOUT".to_string(),
    });
    model.push_task_log(LogRecord {
        ts_unix_ms: 2,
        task_id: "builtin/pipx".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "pipx unrelated".to_string(),
    });

    assert_eq!(model.global_logs.len(), 2);
    assert!(!model.tasks.contains_key("builtin/npm"));

    model.register_task("builtin/npm".into(), "NPM".into(), Vec::new(), false);
    model.selected_task = 0;

    let task = model.tasks.get("builtin/npm").expect("npm task present");
    assert_eq!(task.logs.len(), 1);
    assert_eq!(
        task.logs.front().map(|rec| rec.line.as_str()),
        Some("npm error code ETIMEDOUT")
    );
    let rendered = render_focused_task_logs(&model)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(rendered.contains("npm error code ETIMEDOUT"));
    assert!(!rendered.contains("pipx unrelated"));
}

#[test]
fn run_scoped_logs_stay_global_and_never_become_orphan_tasks() {
    let mut model = Model::new(200, true, true);
    model.register_task("builtin/npm".into(), "NPM".into(), Vec::new(), false);
    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: RUN_LOG_SCOPE.to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "run summary".to_string(),
    });

    assert_eq!(model.global_logs.len(), 1);
    assert!(!model.pending_task_logs.contains_key(RUN_LOG_SCOPE));
    assert!(model.tasks["builtin/npm"].logs.is_empty());
}

#[test]
fn does_not_coalesce_non_progress_or_other_streams() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".into(), "Yay".into(), Vec::new(), false);

    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "core downloading...".to_string(),
    });
    model.push_task_log(LogRecord {
        ts_unix_ms: 2,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stderr,
        line: "  5  6.10M   5 356.4k   0      0".to_string(),
    });
    model.push_task_log(LogRecord {
        ts_unix_ms: 3,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "extra downloading...".to_string(),
    });

    let task = model.tasks.get("yay").expect("yay task present");
    assert_eq!(task.logs.len(), 3);
}

#[test]
fn stderr_stream_tag_is_explicit() {
    assert_eq!(stream_tag(LogStream::Stderr), "STDERR");
}

#[test]
fn detects_interactive_prompt_lines() {
    assert!(looks_like_interactive_prompt(
        "[sudo] password for example-user:"
    ));
    assert!(looks_like_interactive_prompt("==> Packages to exclude:"));
    assert!(looks_like_interactive_prompt(
        "-> Select the service(s) to restart (e.g. 1 3 5), select 0 to restart them all or press \"enter\" to continue without restarting the service(s):"
    ));
    assert!(looks_like_interactive_prompt("==> "));
    assert!(looks_like_interactive_prompt(
        "Select services to restart, or press \"enter\" to continue:"
    ));
    assert!(!looks_like_interactive_prompt("==> Retrieving sources..."));
    assert!(!looks_like_interactive_prompt(
        ":: Synchronizing package databases..."
    ));
}

#[test]
fn arch_service_prompt_context_prefers_services_block() {
    let logs = VecDeque::from([
        LogRecord {
            ts_unix_ms: 1,
            task_id: "arch-update-services".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "checking service restart requirements".to_string(),
        },
        LogRecord {
            ts_unix_ms: 2,
            task_id: "arch-update-services".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "==> Services:".to_string(),
        },
        LogRecord {
            ts_unix_ms: 3,
            task_id: "arch-update-services".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "1 - sshd.service".to_string(),
        },
        LogRecord {
            ts_unix_ms: 4,
            task_id: "arch-update-services".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "2 - docker.service".to_string(),
        },
        LogRecord {
            ts_unix_ms: 5,
            task_id: "arch-update-services".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: "-> Select the service(s) to restart (e.g. 1 3 5), select 0 to restart them all or press \"enter\" to continue without restarting the service(s):".to_string(),
        },
    ]);

    let lines = arch_service_prompt_context_lines(
        &logs,
        "-> Select the service(s) to restart (e.g. 1 3 5), select 0 to restart them all or press \"enter\" to continue without restarting the service(s):",
    );

    assert_eq!(
        lines,
        vec![
            "==> Services:".to_string(),
            "1 - sshd.service".to_string(),
            "2 - docker.service".to_string()
        ]
    );
}

#[test]
fn prompt_overlay_context_lines_only_uses_arch_service_prompts() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "==> Packages to exclude:".to_string(),
    });

    let context = prompt_overlay_context_lines(&model, "yay", "==> Packages to exclude:");
    assert!(context.is_empty());
}

#[test]
fn prompt_like_logs_do_not_create_requests_without_runtime_events() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: ":: Synchronizing package databases...".to_string(),
    });
    model.push_task_log(LogRecord {
        ts_unix_ms: 2,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "==> Packages to exclude:".to_string(),
    });

    assert_eq!(find_latest_prompt(&model), None);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());
    assert_eq!(
        find_latest_prompt(&model).unwrap().1,
        "==> Packages to exclude:"
    );
}

#[test]
fn prompt_modal_auto_opens_for_waiting_input_task() {
    let mut model = Model::new(200, true, true);
    model.register_task(
        "arch-update-services".to_string(),
        "Arch-Update Services".to_string(),
        Vec::new(),
        true,
    );
    model.set_task_state("arch-update-services", TaskState::Running, None);
    model.set_task_input_state("arch-update-services", true);
    model.set_prompt_request(
        "arch-update-services".to_string(),
        4,
        "-> Select the service(s) to restart (e.g. 1 3 5), select 0 to restart them all or press \"enter\" to continue without restarting the service(s):".to_string(),
    );

    let edit = model.prompt_edit.as_ref().expect("prompt editor opened");
    assert_eq!(edit.task_id, "arch-update-services");
    assert_eq!(edit.generation, 4);
    assert!(edit.buffer.is_empty());
}

#[test]
fn first_enter_answers_visible_prompt_exactly_once() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());

    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Enter),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach,
    ));
    assert!(model.prompt_edit.is_none());
    assert!(model.prompt_is_submitted());
    assert!(matches!(
        rx.try_recv(),
        Ok(UiControlEvent::SendStdin { id, generation: 1, line }) if id == "yay" && line.is_empty()
    ));

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Enter),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach,
    ));
    assert!(rx.try_recv().is_err());
    assert_eq!(latest_prompt_task(&model).as_deref(), Some("yay"));

    model.cancel_prompt_request("yay", 1);
    assert_eq!(latest_prompt_task(&model), None);
}

#[test]
fn sequential_prompt_generations_replace_submitted_state_without_log_heuristics() {
    let mut model = Model::new(200, true, true);
    model.register_task(
        "builtin/demo".to_string(),
        "Demo".to_string(),
        Vec::new(),
        true,
    );
    model.set_task_state("builtin/demo", TaskState::Running, None);
    model.set_task_input_state("builtin/demo", true);

    model.set_prompt_request("builtin/demo".to_string(), 11, "First prompt?".to_string());
    assert_eq!(find_latest_prompt(&model).unwrap().1, "First prompt?");
    model.mark_prompt_submitted("builtin/demo", 11);
    assert!(model.prompt_is_submitted());

    model.push_task_log(LogRecord {
        ts_unix_ms: 99,
        task_id: "builtin/demo".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "ordinary output after the answer".to_string(),
    });
    assert_eq!(find_latest_prompt(&model).unwrap().1, "First prompt?");

    model.set_prompt_request("builtin/demo".to_string(), 12, "Second prompt?".to_string());
    assert!(!model.prompt_is_submitted());
    assert_eq!(find_latest_prompt(&model).unwrap().1, "Second prompt?");
    assert_eq!(model.prompt_edit.as_ref().unwrap().generation, 12);

    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    for key in [KeyCode::Char('2'), KeyCode::Char(' '), KeyCode::Char('4')] {
        assert!(!handle_key_event(
            &mut model,
            KeyEvent::from(key),
            &layout,
            &tx,
            DashboardQuitBehavior::Detach,
        ));
    }
    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Enter),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach,
    ));
    assert!(matches!(
        rx.recv().unwrap(),
        UiControlEvent::SendStdin { id, generation: 12, line } if id == "builtin/demo" && line == "2 4"
    ));
    assert!(model.prompt_is_submitted());
}

#[test]
fn prompt_overlay_scroll_keys_adjust_scroll_from_bottom() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());

    let (tx, _rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(handle_prompt_overlay_input(
        &mut model,
        KeyEvent::from(KeyCode::Up),
        &layout,
        &tx,
    ));
    assert_eq!(model.prompt_scroll_from_bottom, 1);

    assert!(handle_prompt_overlay_input(
        &mut model,
        KeyEvent::from(KeyCode::PageUp),
        &layout,
        &tx,
    ));
    assert!(model.prompt_scroll_from_bottom > 1);

    assert!(handle_prompt_overlay_input(
        &mut model,
        KeyEvent::from(KeyCode::End),
        &layout,
        &tx,
    ));
    assert_eq!(model.prompt_scroll_from_bottom, 0);
}

#[test]
fn prompt_overlay_scroll_resets_for_new_prompt() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());
    model.prompt_scroll_from_bottom = 7;

    model.set_prompt_request("yay".to_string(), 2, "==> Diffs to show?".to_string());

    assert_eq!(model.prompt_scroll_from_bottom, 0);
}

#[test]
fn mouse_wheel_over_prompt_overlay_scrolls_modal() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());

    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );
    let overlay = prompt_overlay_area(layout.root);
    let wheel_up = MouseEvent {
        kind: MouseEventKind::ScrollUp,
        column: overlay.x + 1,
        row: overlay.y + 1,
        modifiers: KeyModifiers::NONE,
    };

    handle_mouse_event(&mut model, wheel_up, &layout);

    assert_eq!(model.prompt_scroll_from_bottom, 1);
    assert_eq!(model.selected_task, 0);
}

#[test]
fn prompt_modal_stays_closed_after_manual_dismiss_until_new_prompt() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());
    assert!(model.prompt_edit.is_some());

    model.prompt_edit = None;
    model.set_task_input_state("yay", true);
    assert!(model.prompt_edit.is_none());

    model.set_prompt_request("yay".to_string(), 2, "==> Diffs to show?".to_string());
    assert!(model.prompt_edit.is_some());
}

#[test]
fn prompt_modal_clears_when_task_stops_accepting_input() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());

    model.cancel_prompt_request("yay", 1);
    model.set_task_input_state("yay", false);
    assert!(model.prompt_edit.is_none());
}

#[test]
fn prompt_request_remains_until_explicit_cancellation() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());
    model.push_task_log(LogRecord {
        ts_unix_ms: 2,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "==> Retrieving sources...".to_string(),
    });

    assert!(find_latest_prompt(&model).is_some());
    model.cancel_prompt_request("yay", 1);
    assert_eq!(find_latest_prompt(&model), None);
}

#[test]
fn prompt_remains_visible_when_other_tasks_log() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.register_task("npm".to_string(), "NPM".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_task_input_state("yay", true);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());
    model.push_task_log(LogRecord {
        ts_unix_ms: 2,
        task_id: "npm".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "checking npm outdated packages".to_string(),
    });

    assert_eq!(
        find_latest_prompt(&model)
            .as_ref()
            .map(|(_, line)| line.as_str()),
        Some("==> Packages to exclude:")
    );
}

#[test]
fn prompt_is_hidden_without_active_input_channel() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".to_string(), "Yay".to_string(), Vec::new(), true);
    model.set_task_state("yay", TaskState::Running, None);
    model.set_prompt_request("yay".to_string(), 1, "==> Packages to exclude:".to_string());
    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "==> Packages to exclude:".to_string(),
    });

    assert_eq!(find_latest_prompt(&model), None);
}

#[test]
fn k_and_upper_k_emit_cancel_controls() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('k')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    let first = rx.recv().expect("control event");
    match first {
        UiControlEvent::CancelTask { id } => assert_eq!(id, "npm"),
        _ => panic!("expected CancelTask event"),
    }

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('K')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    let second = rx.recv().expect("control event");
    match second {
        UiControlEvent::CancelAll => {}
        _ => panic!("expected CancelAll event"),
    }
}

#[test]
fn k_and_upper_k_do_not_emit_cancel_controls_after_run_complete() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.run_complete = Some(true);
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('k')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert!(rx.try_recv().is_err());

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('K')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert!(rx.try_recv().is_err());
}

#[test]
fn m_emits_open_log_for_selected_task() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('m')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    match rx.recv().expect("control event") {
        UiControlEvent::OpenLog {
            target: LogViewTarget::Task { id },
        } => assert_eq!(id, "npm"),
        other => panic!("expected task log open event, got {other:?}"),
    }
}

#[test]
fn m_emits_open_log_for_run_when_global_log_is_active() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.active_pane = ActivePane::GlobalLogs;
    let (tx, rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::GlobalLogs,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('m')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    match rx.recv().expect("control event") {
        UiControlEvent::OpenLog {
            target: LogViewTarget::Run,
        } => {}
        other => panic!("expected run log open event, got {other:?}"),
    }
}

#[test]
fn esc_clears_search_without_exiting() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.task_search.query = "npm".to_string();
    model.task_search.regex = Regex::new("npm").ok();
    model.task_search.restore = Some(SearchRestore::Tasks {
        selected_task: 0,
        task_list_offset: 0,
    });
    let (tx, _rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Esc),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert!(model.task_search.query.is_empty());
    assert!(model.task_search.regex.is_none());
    assert!(model.task_search.restore.is_none());
}

#[test]
fn esc_restores_task_log_offset_after_search_jump() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.active_pane = ActivePane::TaskLogs;
    model.task_log_from_bottom = 0;

    for i in 0..30u64 {
        model.push_task_log(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: format!("log line {i}"),
        });
    }

    let (tx, _rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::TaskLogs,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('/')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    for ch in "log line 5".chars() {
        assert!(!handle_key_event(
            &mut model,
            KeyEvent::from(KeyCode::Char(ch)),
            &layout,
            &tx,
            DashboardQuitBehavior::Detach
        ));
    }
    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Enter),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));

    assert!(model.task_log_search.regex.is_some());
    assert!(model.task_log_from_bottom > 0);

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Esc),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert_eq!(model.task_log_from_bottom, 0);
    assert!(model.task_log_search.query.is_empty());
    assert!(model.task_log_search.regex.is_none());
    assert!(model.task_log_search.restore.is_none());
}

#[test]
fn esc_restores_global_log_offset_after_search_jump() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.active_pane = ActivePane::GlobalLogs;
    model.global_log_from_bottom = 0;

    for i in 0..30u64 {
        model.push_task_log(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: format!("global line {i}"),
        });
    }

    let (tx, _rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::GlobalLogs,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('/')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    for ch in "global line 5".chars() {
        assert!(!handle_key_event(
            &mut model,
            KeyEvent::from(KeyCode::Char(ch)),
            &layout,
            &tx,
            DashboardQuitBehavior::Detach
        ));
    }
    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Enter),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));

    assert!(model.global_log_search.regex.is_some());
    assert!(model.global_log_from_bottom > 0);

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Esc),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert_eq!(model.global_log_from_bottom, 0);
    assert!(model.global_log_search.query.is_empty());
    assert!(model.global_log_search.regex.is_none());
    assert!(model.global_log_search.restore.is_none());
}

#[test]
fn esc_restores_task_selection_after_task_search() {
    let mut model = Model::new(200, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.register_task("pipx".into(), "Pipx".into(), Vec::new(), true);
    model.register_task("system".into(), "System".into(), Vec::new(), true);
    model.selected_task = 2;
    model.task_list_offset = 0;
    model.active_pane = ActivePane::Tasks;

    let (tx, _rx) = std::sync::mpsc::channel::<UiControlEvent>();
    let layout = layout_for(
        Rect::new(0, 0, 120, 40),
        true,
        RightPaneMode::Split,
        ActivePane::Tasks,
    );

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Char('/')),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    for ch in "NPM".chars() {
        assert!(!handle_key_event(
            &mut model,
            KeyEvent::from(KeyCode::Char(ch)),
            &layout,
            &tx,
            DashboardQuitBehavior::Detach
        ));
    }
    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Enter),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert_eq!(model.selected_task, 0);

    assert!(!handle_key_event(
        &mut model,
        KeyEvent::from(KeyCode::Esc),
        &layout,
        &tx,
        DashboardQuitBehavior::Detach
    ));
    assert_eq!(model.selected_task, 2);
    assert!(model.task_search.query.is_empty());
    assert!(model.task_search.regex.is_none());
    assert!(model.task_search.restore.is_none());
}

#[test]
fn slice_logs_overscroll_keeps_full_top_viewport() {
    let mut logs = VecDeque::new();
    for i in 0..10u64 {
        logs.push_back(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: format!("line-{i}"),
        });
    }

    let visible = slice_logs(&logs, 999, 4);
    let rendered: Vec<String> = visible.into_iter().map(|r| r.line).collect();
    assert_eq!(rendered, vec!["line-0", "line-1", "line-2", "line-3"]);
}

#[test]
fn slice_logs_bottom_and_one_step_up_are_stable() {
    let mut logs = VecDeque::new();
    for i in 0..8u64 {
        logs.push_back(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: format!("line-{i}"),
        });
    }

    let bottom: Vec<String> = slice_logs(&logs, 0, 3)
        .into_iter()
        .map(|r| r.line)
        .collect();
    assert_eq!(bottom, vec!["line-5", "line-6", "line-7"]);

    let up_one: Vec<String> = slice_logs(&logs, 1, 3)
        .into_iter()
        .map(|r| r.line)
        .collect();
    assert_eq!(up_one, vec!["line-4", "line-5", "line-6"]);
}

#[test]
fn task_log_view_shows_truncation_banner() {
    let mut model = Model::new(2, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.selected_task = 0;
    for i in 0..5u64 {
        model.push_task_log(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: format!("line-{i}"),
        });
    }

    let rendered = render_focused_task_logs(&model);
    let text = rendered[0].to_string();
    assert!(text.contains("[TRUNCATED]"));
    assert!(text.contains("press m"));
    assert!(text.contains("full task log"));
}

#[test]
fn global_log_view_shows_truncation_pager_hint() {
    let mut model = Model::new(2, true, true);
    for i in 0..5u64 {
        model.push_task_log(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "runtime".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Meta,
            line: format!("line-{i}"),
        });
    }

    let rendered = render_global_logs(&model);
    let text = rendered[0].to_string();
    assert!(text.contains("[TRUNCATED]"));
    assert!(text.contains("press m"));
    assert!(text.contains("full run log"));
}

#[test]
fn constrain_scroll_window_keeps_scroll_within_u16() {
    let lines = (0..80_000)
        .map(|i| Line::from(format!("line-{i}")))
        .collect::<Vec<_>>();
    let (trimmed, scroll) = constrain_scroll_window(lines, 70_000, 100, false);
    assert!(scroll <= u16::MAX);
    assert!(!trimmed.is_empty());
}

#[test]
fn wrapped_viewport_scroll_uses_visual_rows() {
    let lines = vec![
        Line::from("ABCDEFGHI"),
        Line::from("delta"),
        Line::from("omega"),
    ];

    let bottom = take_visible_rows(&lines, 0, 3, 3, true)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    assert_eq!(bottom, vec!["", "ome", "ga"]);

    let scrolled_up = take_visible_rows(&lines, 1, 3, 3, true)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    assert_eq!(scrolled_up, vec!["del", "ta", "ome"]);

    let overscrolled = take_visible_rows(&lines, 999, 3, 3, true)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    assert_eq!(overscrolled, vec!["ABC", "DEF", "GHI"]);
}

#[test]
fn wrapped_underfilled_viewport_does_not_jump_when_scrolled() {
    let lines = vec![Line::from("alpha"), Line::from("beta")];

    let bottom = take_visible_rows(&lines, 0, 12, 6, true)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    let scrolled = take_visible_rows(&lines, 3, 12, 6, true)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert_eq!(bottom, scrolled);
    assert_eq!(bottom, vec!["", "", "", "", "alpha", "beta"]);
}

#[test]
fn prompt_lines_render_with_single_prompt_badge() {
    let mut model = Model::new(200, true, true);
    model.register_task("yay".into(), "Yay".into(), Vec::new(), true);
    model.selected_task = 0;
    model.push_task_log(LogRecord {
        ts_unix_ms: 1,
        task_id: "yay".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: "==> Packages to exclude:".to_string(),
    });

    let rendered = render_focused_task_logs(&model);
    let text = rendered
        .last()
        .expect("prompt line")
        .spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>();

    assert!(text.contains("[PROMPT] ==> Packages to exclude:"), "{text}");
    assert!(!text.contains("[INFO]"), "{text}");
    assert!(!text.contains("[OUT]"), "{text}");
    assert!(!text.contains("[META]"), "{text}");
}

#[test]
fn wrapped_viewport_bottom_keeps_latest_rows_visible() {
    let lines = vec![
        Line::from(vec![
            Span::raw("02:34:18 "),
            Span::raw("[INFO] "),
            Span::raw("[STDERR] "),
            Span::raw("insync-dolphin: /usr/share/icons/hicolor/scalable/emblems/emblem-insync-syncing.svg exists in filesystem"),
        ]),
        Line::from("Errors occurred, no packages were upgraded."),
        Line::from("-> error installing transaction"),
    ];

    let bottom = take_visible_rows(&lines, 0, 40, 4, true)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert_eq!(bottom.len(), 4);
    assert_eq!(bottom[1], "Errors occurred, no packages were upgrad");
    assert_eq!(bottom[2], "ed.");
    assert_eq!(bottom[3], "-> error installing transaction");
}

#[test]
fn focused_task_logs_render_bounded_viewport_from_large_retention() {
    let mut model = Model::new(20_000, true, true);
    model.register_task("npm".into(), "NPM".into(), Vec::new(), true);
    model.selected_task = 0;
    for i in 0..1_000u64 {
        model.push_task_log(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "npm".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Stdout,
            line: format!("task-line-{i}"),
        });
    }

    let bottom = render_focused_task_logs_viewport(&model, 0, 120, 5, false)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    let scrolled = render_focused_task_logs_viewport(&model, 2, 120, 5, false)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert_eq!(bottom.len(), 5);
    assert!(bottom[0].contains("task-line-995"), "{bottom:?}");
    assert!(bottom[4].contains("task-line-999"), "{bottom:?}");
    assert_eq!(scrolled.len(), 5);
    assert!(scrolled[0].contains("task-line-993"), "{scrolled:?}");
    assert!(scrolled[4].contains("task-line-997"), "{scrolled:?}");
}

#[test]
fn global_logs_render_bounded_viewport_from_large_retention() {
    let mut model = Model::new(20_000, true, true);
    for i in 0..1_000u64 {
        model.push_task_log(LogRecord {
            ts_unix_ms: i * 1000,
            task_id: "runtime".to_string(),
            level: LogLevel::Info,
            stream: LogStream::Meta,
            line: format!("global-line-{i}"),
        });
    }

    let bottom = render_global_logs_viewport(&model, 0, 120, 4, false)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    let scrolled = render_global_logs_viewport(&model, 3, 120, 4, false)
        .into_iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    assert_eq!(bottom.len(), 4);
    assert!(bottom[0].contains("global-line-996"), "{bottom:?}");
    assert!(bottom[3].contains("global-line-999"), "{bottom:?}");
    assert_eq!(scrolled.len(), 4);
    assert!(scrolled[0].contains("global-line-993"), "{scrolled:?}");
    assert!(scrolled[3].contains("global-line-996"), "{scrolled:?}");
}
