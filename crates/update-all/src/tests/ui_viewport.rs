use super::*;

fn viewport_record(line: String, level: LogLevel) -> LogRecord {
    LogRecord {
        ts_unix_ms: 0,
        task_id: "t".into(),
        level,
        stream: LogStream::Stdout,
        line,
    }
}

fn viewport_model() -> Model {
    let mut model = Model::new(200, true, true);
    model.register_task("t".into(), "Test".into(), Vec::new(), false);
    model.wrap_logs = true;
    model
}

fn viewport_text(lines: Vec<Line<'static>>) -> Vec<String> {
    lines.into_iter().map(|line| line.to_string()).collect()
}

fn viewport_screen(model: &Model, size: Rect) -> String {
    let backend = ratatui::backend::TestBackend::new(size.width, size.height);
    let mut terminal = Terminal::new(backend).unwrap();
    let layout = layout_for(
        size,
        model.show_global_log,
        model.right_pane_mode,
        model.active_pane,
    );
    terminal
        .draw(|frame| draw_dashboard(frame, model, &layout))
        .unwrap();
    terminal
        .backend()
        .buffer()
        .content
        .chunks(size.width as usize)
        .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn actual_log_viewports_scroll_within_one_ten_row_record() {
    for include_task in [false, true] {
        let width = if include_task { 12 } else { 10 };
        let mut model = viewport_model();
        let mut body = String::from("x");
        for digit in '1'..='9' {
            body.extend(std::iter::repeat_n(digit, width));
        }
        model.push_task_log(viewport_record(body, LogLevel::Info));
        let render = |offset| {
            viewport_text(if include_task {
                render_global_logs_viewport(&model, offset, width, 3, true)
            } else {
                render_focused_task_logs_viewport(&model, offset, width, 3, true)
            })
        };
        let rows = |start: u8| {
            (start..start + 3)
                .map(|digit| char::from(b'0' + digit).to_string().repeat(width))
                .collect::<Vec<_>>()
        };
        assert_eq!(render(0), rows(7), "tail, global={include_task}");
        assert_eq!(render(1), rows(6), "one row up, global={include_task}");
        assert_eq!(render(3), rows(4), "one page up, global={include_task}");
        let top = render(usize::MAX);
        assert!(top[0].ends_with('x'), "{top:?}");
        assert_eq!(top[1..], rows(1)[..2]);
        assert_eq!(render(0), rows(7), "return to tail");
    }
}

#[test]
fn wrapped_log_keyboard_pages_and_home_use_the_visible_row_range() {
    for pane in [ActivePane::TaskLogs, ActivePane::GlobalLogs] {
        let width = if pane == ActivePane::GlobalLogs {
            12
        } else {
            10
        };
        let mut model = viewport_model();
        model.active_pane = pane;
        let mut body = String::from("x");
        for digit in '1'..='9' {
            body.extend(std::iter::repeat_n(digit, width));
        }
        model.push_task_log(viewport_record(body, LogLevel::Info));
        let mut layout = layout_for(Rect::new(0, 0, 80, 24), true, model.right_pane_mode, pane);
        let rect = Some(Rect::new(0, 0, width as u16 + 2, 5));
        layout.task_logs = rect;
        layout.global_logs = rect;
        let (tx, _rx) = std::sync::mpsc::channel();
        for (key, expected_first) in [
            (KeyCode::Up, "6"),
            (KeyCode::PageUp, "3"),
            (KeyCode::Home, "00:00:00 "),
            (KeyCode::Down, "1"),
            (KeyCode::End, "7"),
        ] {
            handle_key_event(
                &mut model,
                KeyEvent::from(key),
                &layout,
                &tx,
                DashboardQuitBehavior::Detach,
            );
            let rows = viewport_text(if pane == ActivePane::TaskLogs {
                render_focused_task_logs_viewport(
                    &model,
                    model.task_log_from_bottom,
                    width,
                    3,
                    true,
                )
            } else {
                render_global_logs_viewport(&model, model.global_log_from_bottom, width, 3, true)
            });
            assert!(
                rows[0].starts_with(expected_first),
                "key={key:?}, pane={pane:?}, rows={rows:?}"
            );
        }
    }
}

#[test]
fn actual_log_viewports_share_unicode_badge_banner_and_resize_geometry() {
    let mut model = viewport_model();
    for body in [
        "old 界界界界界界界界界界界界界界界界",
        "warning: 界界界界界界界界界界界界界界界界",
        "new 👑👑👑👑👑👑👑👑👑👑👑",
    ] {
        model.push_task_log(viewport_record(body.into(), LogLevel::Warn));
    }
    model.tasks.get_mut("t").unwrap().logs_dropped = 5;
    model.global_logs_dropped = 5;
    for include_task in [false, true] {
        for width in [9, 13, 29] {
            let all_lines = if include_task {
                render_global_logs(&model)
            } else {
                render_focused_task_logs(&model)
            };
            let all_rows = viewport_text(expand_visual_rows(&all_lines, width, true));
            for offset in 0..=all_rows.len() + 1 {
                let end = all_rows.len() - offset.min(all_rows.len().saturating_sub(3));
                let expected = &all_rows[end.saturating_sub(3)..end];
                let actual = viewport_text(if include_task {
                    render_global_logs_viewport(&model, offset, width, 3, true)
                } else {
                    render_focused_task_logs_viewport(&model, offset, width, 3, true)
                });
                assert_eq!(
                    actual, expected,
                    "global={include_task}, width={width}, offset={offset}"
                );
            }
        }
    }
}

#[test]
fn wrapped_search_renders_match_behind_newer_output_and_restores_position() {
    for pane in [ActivePane::TaskLogs, ActivePane::GlobalLogs] {
        for size in [Rect::new(0, 0, 80, 24), Rect::new(0, 0, 120, 40)] {
            for prefix in ["".to_string(), "界".repeat(400)] {
                let mut model = viewport_model();
                model.active_pane = pane;
                model.push_task_log(viewport_record(
                    format!("{prefix}NEEDLE {}", "old".repeat(400)),
                    LogLevel::Warn,
                ));
                model.push_task_log(viewport_record("new".repeat(1500), LogLevel::Info));
                model.tasks.get_mut("t").unwrap().logs_dropped = 7;
                model.global_logs_dropped = 7;
                model.task_log_from_bottom = 2;
                model.global_log_from_bottom = 2;
                let layout = layout_for(size, true, model.right_pane_mode, pane);
                let (tx, _rx) = std::sync::mpsc::channel();
                for code in std::iter::once(KeyCode::Char('/'))
                    .chain("NEEDLE".chars().map(KeyCode::Char))
                    .chain(std::iter::once(KeyCode::Enter))
                {
                    handle_key_event(
                        &mut model,
                        KeyEvent::from(code),
                        &layout,
                        &tx,
                        DashboardQuitBehavior::Detach,
                    );
                }
                let rect = inner_rect(match pane {
                    ActivePane::TaskLogs => layout.task_logs.unwrap(),
                    ActivePane::GlobalLogs => layout.global_logs.unwrap(),
                    ActivePane::Tasks => unreachable!(),
                });
                let actual = if pane == ActivePane::TaskLogs {
                    render_focused_task_logs_viewport(
                        &model,
                        model.task_log_from_bottom,
                        rect.width as usize,
                        rect.height as usize,
                        true,
                    )
                } else {
                    render_global_logs_viewport(
                        &model,
                        model.global_log_from_bottom,
                        rect.width as usize,
                        rect.height as usize,
                        true,
                    )
                };
                assert!(
                    viewport_text(actual).join("").contains("NEEDLE"),
                    "match hidden, pane={pane:?}, size={size:?}"
                );
                handle_key_event(
                    &mut model,
                    KeyEvent::from(KeyCode::Esc),
                    &layout,
                    &tx,
                    DashboardQuitBehavior::Detach,
                );
                assert_eq!(model.task_log_from_bottom, 2);
                assert_eq!(model.global_log_from_bottom, 2);
            }
        }
    }
}

#[test]
fn dashboard_search_editor_and_error_are_visible_at_small_and_large_sizes() {
    for size in [Rect::new(0, 0, 80, 24), Rect::new(0, 0, 120, 40)] {
        let mut model = viewport_model();
        model.search_edit = Some(SearchEditState {
            target: ActivePane::TaskLogs,
            buffer: format!("{}[", "query".repeat(100)),
            error: Some("INVALID REGEX: unclosed character class".into()),
        });
        let screen = viewport_screen(&model, size);
        assert!(screen.contains("search(task-logs)>"), "{screen}");
        assert!(screen.contains("INVALID REGEX"), "{screen}");
    }
}

#[test]
fn help_end_reaches_final_entry_without_moving_underlying_panes() {
    for size in [Rect::new(0, 0, 80, 24), Rect::new(0, 0, 120, 40)] {
        let mut model = viewport_model();
        model.register_task("other".into(), "Other".into(), Vec::new(), false);
        model.selected_task = 0;
        model.task_log_from_bottom = 3;
        model.global_log_from_bottom = 4;
        let layout = layout_for(size, true, model.right_pane_mode, model.active_pane);
        let (tx, _rx) = std::sync::mpsc::channel();
        for code in [
            KeyCode::Char('?'),
            KeyCode::Down,
            KeyCode::PageDown,
            KeyCode::End,
        ] {
            handle_key_event(
                &mut model,
                KeyEvent::from(code),
                &layout,
                &tx,
                DashboardQuitBehavior::Detach,
            );
            assert_eq!(model.selected_task, 0);
            assert_eq!(model.task_log_from_bottom, 3);
            assert_eq!(model.global_log_from_bottom, 4);
        }
        let screen = viewport_screen(&model, size);
        assert!(
            screen.contains("input prompts and caution states"),
            "{screen}"
        );
        assert_eq!(model.selected_task, 0);
        assert_eq!(model.task_log_from_bottom, 3);
        assert_eq!(model.global_log_from_bottom, 4);
        for kind in [MouseEventKind::ScrollUp, MouseEventKind::ScrollDown] {
            handle_mouse_event(
                &mut model,
                MouseEvent {
                    kind,
                    column: layout.tasks_inner.x,
                    row: layout.tasks_inner.y,
                    modifiers: KeyModifiers::NONE,
                },
                &layout,
            );
            assert_eq!(model.selected_task, 0);
            assert_eq!(model.task_log_from_bottom, 3);
            assert_eq!(model.global_log_from_bottom, 4);
        }
        for code in [KeyCode::PageUp, KeyCode::Up, KeyCode::Home] {
            handle_key_event(
                &mut model,
                KeyEvent::from(code),
                &layout,
                &tx,
                DashboardQuitBehavior::Detach,
            );
        }
        let screen = viewport_screen(&model, size);
        assert!(screen.contains("Reference"), "{screen}");
        assert_eq!(model.selected_task, 0);
    }
}

#[test]
fn native_e2e_footer_keeps_complete_shortcuts_at_standard_terminal_sizes() {
    for size in [Rect::new(0, 0, 80, 24), Rect::new(0, 0, 120, 40)] {
        for complete in [false, true] {
            let mut model = viewport_model();
            model.run_complete = complete.then_some(true);
            let screen = viewport_screen(&model, size);
            for hint in [
                "? help",
                "n/N next/prev",
                "click select",
                "Esc close overlay",
            ] {
                assert!(screen.contains(hint), "missing {hint}:\n{screen}");
            }
        }
    }
}

#[test]
fn native_e2e_prompt_hints_keep_cancellation_words_together() {
    for size in [Rect::new(0, 0, 80, 24), Rect::new(0, 0, 120, 40)] {
        for (editing, submitted) in [(true, false), (false, false), (false, true)] {
            let backend = ratatui::backend::TestBackend::new(size.width, size.height);
            let mut terminal = Terminal::new(backend).unwrap();
            let edit = PromptEditState {
                task_id: "t".into(),
                generation: 1,
                buffer: "".into(),
            };
            terminal
                .draw(|frame| {
                    draw_prompt_overlay(
                        frame,
                        size,
                        "t",
                        "Proceed?",
                        &[],
                        editing.then_some(&edit),
                        submitted,
                        0,
                    )
                })
                .unwrap();
            let screen = terminal
                .backend()
                .buffer()
                .content
                .chunks(size.width as usize)
                .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(screen.contains("Ctrl+C: cancel all"), "{screen}");
        }
    }
}
