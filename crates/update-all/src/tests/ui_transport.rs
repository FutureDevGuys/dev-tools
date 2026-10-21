use super::*;
use tempfile::TempDir;

fn display_record(task_id: &str, line: impl Into<String>) -> DashboardEvent {
    DashboardEvent::LogLine(LogRecord {
        ts_unix_ms: 0,
        task_id: task_id.to_string(),
        level: LogLevel::Info,
        stream: LogStream::Stdout,
        line: line.into(),
    })
}

#[test]
fn dashboard_transport_bounds_flood_and_accounts_for_every_omitted_record() {
    let (tx, rx) = DashboardSender::bounded(None, 7, &["a".into(), "b".into()]);
    for index in 0..100_000 {
        let id = if index % 2 == 0 { "a" } else { "b" };
        tx.send(display_record(id, index.to_string())).unwrap();
    }
    let (records, bytes, omission_scopes) = rx.backlog_size();
    assert_eq!(records, 7);
    assert!(bytes <= 8 * 1024 * 1024);
    assert_eq!(omission_scopes, 2);
    let mut omitted = 0;
    let mut retained = Vec::new();
    while let Ok(event) = rx.try_recv() {
        match event {
            DashboardEvent::LogLine(record) => retained.push(record.line.parse::<usize>().unwrap()),
            DashboardEvent::DisplayLogsOmitted { count, .. } => omitted += count,
            other => panic!("unexpected display event: {other:?}"),
        }
    }
    assert_eq!(retained, (99_993..100_000).collect::<Vec<_>>());
    assert_eq!(omitted + retained.len() as u64, 100_000);
    assert_eq!(rx.backlog_size(), (0, 0, 0));
}

#[test]
fn dashboard_transport_bounds_bytes_and_unknown_omission_scopes() {
    let (tx, rx) = DashboardSender::bounded(None, 100, &["known".into()]);
    for index in 0..100 {
        tx.send(display_record(
            &format!("unexpected-{index}"),
            "x".repeat(1024 * 1024),
        ))
        .unwrap();
    }
    tx.send(display_record("known", "x".repeat(9 * 1024 * 1024)))
        .unwrap();
    let (records, bytes, scopes) = rx.backlog_size();
    assert!(records < 8);
    assert!(bytes <= 8 * 1024 * 1024);
    assert_eq!(scopes, 2);
    let mut total = 0;
    while let Ok(event) = rx.try_recv() {
        match event {
            DashboardEvent::DisplayLogsOmitted { task_id, count } => {
                assert!(task_id == "known" || task_id == RUN_LOG_SCOPE);
                total += count;
            }
            DashboardEvent::LogLine(_) => total += 1,
            other => panic!("unexpected display event: {other:?}"),
        }
    }
    assert_eq!(total, 101);
}

#[test]
fn dashboard_transport_coalesces_prompt_flood_without_losing_current_generation() {
    let (tx, rx) = DashboardSender::bounded(None, 4, &["task".into()]);
    tx.send(DashboardEvent::TaskRegistered {
        id: "task".into(),
        label: "Fixture".into(),
        category: "fixture".into(),
        depends_on: Vec::new(),
        accepts_input: true,
    })
    .unwrap();
    for generation in 1..=100_000 {
        tx.send(DashboardEvent::TaskInputStateChanged {
            id: "task".into(),
            enabled: true,
        })
        .unwrap();
        tx.send(DashboardEvent::TaskStateChanged {
            id: "task".into(),
            state: TaskState::Running,
            detail: Some(generation.to_string()),
        })
        .unwrap();
        tx.send(DashboardEvent::PromptRequested {
            id: "task".into(),
            generation,
            prompt: format!("Answer {generation}:"),
        })
        .unwrap();
        tx.send(DashboardEvent::PromptCancelled {
            id: "task".into(),
            generation: generation - 1,
            reason: "stale cancellation".into(),
        })
        .unwrap();
    }
    assert_eq!(rx.pending_task_states(), 3);
    assert!(matches!(
        rx.try_recv().unwrap(),
        DashboardEvent::TaskRegistered { .. }
    ));
    let mut prompt = None;
    let mut count = 0;
    while let Ok(event) = rx.try_recv() {
        count += 1;
        match event {
            DashboardEvent::PromptRequested {
                generation,
                prompt: text,
                ..
            } => {
                prompt = Some((generation, text));
            }
            DashboardEvent::TaskStateChanged { detail, .. } => {
                assert_eq!(detail.as_deref(), Some("100000"));
            }
            DashboardEvent::TaskInputStateChanged { enabled, .. } => assert!(enabled),
            other => panic!("unexpected display event: {other:?}"),
        }
    }
    assert_eq!(count, 3, "one queued token per task-state kind");
    assert_eq!(prompt, Some((100_000, "Answer 100000:".into())));

    tx.send(DashboardEvent::PromptCancelled {
        id: "task".into(),
        generation: 100_000,
        reason: "closed".into(),
    })
    .unwrap();
    assert!(matches!(
        rx.try_recv().unwrap(),
        DashboardEvent::PromptCancelled {
            generation: 100_000,
            ..
        }
    ));
    tx.send(DashboardEvent::PromptRequested {
        id: "task".into(),
        generation: 100_000,
        prompt: "must not resurrect".into(),
    })
    .unwrap();
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}

#[test]
fn dashboard_transport_delivers_suspend_resume_and_completion_ahead_of_flood() {
    let (tx, rx) = DashboardSender::bounded(None, 2, &["task".into()]);
    for index in 0..10_000 {
        tx.send(display_record("task", index.to_string())).unwrap();
    }
    let (suspend_tx, suspend_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    tx.send(DashboardEvent::UiSuspendRequested {
        reason: "fixture viewer".into(),
        ack: Some(suspend_tx),
    })
    .unwrap();
    tx.send(DashboardEvent::UiResumeRequested {
        ack: Some(resume_tx),
    })
    .unwrap();
    tx.send(DashboardEvent::RunComplete {
        success: true,
        canceled: false,
        had_failures: false,
        completed_at: Instant::now(),
    })
    .unwrap();
    match rx.try_recv().unwrap() {
        DashboardEvent::UiSuspendRequested { ack: Some(ack), .. } => ack.send(()).unwrap(),
        other => panic!("suspend must not wait for log drain: {other:?}"),
    }
    suspend_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    match rx.try_recv().unwrap() {
        DashboardEvent::UiResumeRequested { ack: Some(ack) } => ack.send(()).unwrap(),
        other => panic!("resume must not wait for log drain: {other:?}"),
    }
    resume_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(matches!(
        rx.try_recv().unwrap(),
        DashboardEvent::RunComplete { success: true, .. }
    ));
    assert_eq!(rx.backlog_size().0, 2);
    drop(rx);
    assert!(tx.send(display_record("task", "detached")).is_err());
    assert!(tx.is_detached());
}

#[test]
fn dashboard_transport_journals_full_ordered_output_before_eviction() {
    let temp = TempDir::new().unwrap();
    let log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (tx, rx) = DashboardSender::bounded(Some(log.clone()), 3, &["fixture".into()]);
    for index in 0..512 {
        emit_task_log(
            &tx,
            Some(&log),
            "fixture",
            LogLevel::Info,
            LogStream::Stdout,
            format!("marker-{index:04}"),
        );
    }
    assert_eq!(rx.backlog_size().0, 3);
    let events = fs::read_to_string(log.run_dir().join("events.jsonl")).unwrap();
    let markers = events
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["kind"] == "log_line")
        .map(|event| event["payload"]["line"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        markers,
        (0..512)
            .map(|i| format!("marker-{i:04}"))
            .collect::<Vec<_>>()
    );
    let raw = fs::read_to_string(log.run_dir().join("task-fixture.raw.log")).unwrap();
    assert_eq!(raw.lines().count(), 512);
    for (line, marker) in raw.lines().zip(&markers) {
        assert!(line.ends_with(marker));
    }
    log.inject_journal_fault_for_test();
    assert!(tx.send(display_record("fixture", "not admitted")).is_err());
    let mut retained = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let DashboardEvent::LogLine(record) = event {
            retained.push(record.line);
        }
    }
    assert_eq!(retained, ["marker-0509", "marker-0510", "marker-0511"]);
}

#[test]
fn dashboard_transport_recv_wakes_for_logs_and_drains_after_sender_disconnect() {
    let (tx, rx) = DashboardSender::bounded(None, 2, &["task".into()]);
    let (done_tx, done_rx) = mpsc::channel();
    let receiver = thread::spawn(move || {
        let mut lines = Vec::new();
        while let Ok(event) = rx.recv() {
            if let DashboardEvent::LogLine(record) = event {
                lines.push(record.line);
            }
        }
        done_tx.send(lines).unwrap();
    });
    tx.send(display_record("task", "first")).unwrap();
    tx.send(display_record("task", "second")).unwrap();
    drop(tx);
    assert_eq!(
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
        ["first", "second"]
    );
    receiver.join().unwrap();
}

#[test]
fn dashboard_transport_keeps_superseded_prompt_journal_and_bounds_display_text() {
    let temp = TempDir::new().unwrap();
    let log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (tx, rx) = DashboardSender::bounded(Some(log.clone()), 1, &["fixture".into()]);
    let prompt = "λ".repeat(10_000);
    for generation in 1..=5 {
        tx.send(DashboardEvent::PromptRequested {
            id: "fixture".into(),
            generation,
            prompt: prompt.clone(),
        })
        .unwrap();
    }
    match rx.try_recv().unwrap() {
        DashboardEvent::PromptRequested {
            generation, prompt, ..
        } => {
            assert_eq!(generation, 5);
            assert!(prompt.len() < 9 * 1024);
            assert!(prompt.ends_with(" [display truncated; m: full log]"));
        }
        other => panic!("expected latest prompt: {other:?}"),
    }
    let events = fs::read_to_string(log.run_dir().join("events.jsonl")).unwrap();
    let prompts = events
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|event| event["kind"] == "prompt_requested")
        .collect::<Vec<_>>();
    assert_eq!(prompts.len(), 5);
    for (index, event) in prompts.iter().enumerate() {
        assert_eq!(event["payload"]["generation"], index + 1);
        assert_eq!(event["payload"]["prompt"], prompt);
    }
    for event in [
        DashboardEvent::PromptCancelled {
            id: "fixture".into(),
            generation: 5,
            reason: "superseded".into(),
        },
        DashboardEvent::PromptRequested {
            id: "fixture".into(),
            generation: 6,
            prompt: "new request".into(),
        },
        DashboardEvent::PromptCancelled {
            id: "fixture".into(),
            generation: 6,
            reason: "input closed".into(),
        },
    ] {
        tx.send(event).unwrap();
    }
    assert_eq!(rx.pending_task_states(), 1);
    assert!(matches!(
        rx.try_recv().unwrap(),
        DashboardEvent::PromptCancelled { generation: 6, .. }
    ));
}

#[test]
fn dashboard_transport_shutdown_wakes_frontend_after_journal_failure() {
    let temp = TempDir::new().unwrap();
    let log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (tx, rx) = DashboardSender::bounded(Some(log.clone()), 1, &["fixture".into()]);
    let (done_tx, done_rx) = mpsc::channel();
    let frontend = thread::spawn(move || {
        while let Ok(event) = rx.recv() {
            if matches!(event, DashboardEvent::UiDone) {
                done_tx.send(()).unwrap();
                return;
            }
        }
        panic!("frontend disconnected without receiving shutdown");
    });
    log.inject_journal_fault_for_test();
    assert!(tx.send(display_record("fixture", "not admitted")).is_err());
    assert!(tx.journal_error().is_some());
    tx.shutdown_ui().unwrap();
    done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    frontend.join().unwrap();
}

#[test]
fn native_e2e_plain_frontend_acknowledges_foreground_handoffs() {
    let (tx, rx) = DashboardSender::bounded(None, 2, &["fixture".into()]);
    let (control_tx, _control_rx) = mpsc::channel();
    let frontend = UiModeResolved::Plain
        .spawn_ui_thread(
            rx,
            control_tx,
            DashboardQuitBehavior::Detach,
            MouseRowStride::Auto,
            true,
            2,
            2,
            false,
        )
        .unwrap()
        .unwrap();
    let (suspend_tx, suspend_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    tx.send(DashboardEvent::UiSuspendRequested {
        reason: "harmless foreground task".into(),
        ack: Some(suspend_tx),
    })
    .unwrap();
    tx.send(DashboardEvent::UiResumeRequested {
        ack: Some(resume_tx),
    })
    .unwrap();
    tx.shutdown_ui().unwrap();
    frontend.join().unwrap().unwrap();
    assert_eq!(suspend_rx.try_recv(), Ok(()));
    assert_eq!(resume_rx.try_recv(), Ok(()));
}
