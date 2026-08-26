use super::{resolve_run_query, scan_runs, write_metadata_atomic, RunArtifactStatus, RunMetadata};
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

#[test]
fn scan_reads_new_metadata_and_sorts_by_updated_time() {
    let temp = TempDir::new().unwrap();
    let older = temp.path().join("run-old");
    let newer = temp.path().join("run-new");
    write_metadata_atomic(
        &older,
        &RunMetadata {
            schema_version: 1,
            run_id: "older-id".to_string(),
            display_name: "older".to_string(),
            created_unix_ms: 10,
            updated_unix_ms: 20,
            status: "completed".to_string(),
            run_dir: older.display().to_string(),
            pid: 1,
            host_os: Some("linux".to_string()),
            ui_mode: Some("plain".to_string()),
            engine_mode: Some("sync".to_string()),
            selected_tasks: vec!["yay".to_string()],
        },
    )
    .unwrap();
    write_metadata_atomic(
        &newer,
        &RunMetadata {
            schema_version: 1,
            run_id: "newer-id".to_string(),
            display_name: "newer".to_string(),
            created_unix_ms: 10,
            updated_unix_ms: 30,
            status: "failed".to_string(),
            run_dir: newer.display().to_string(),
            pid: 2,
            host_os: Some("linux".to_string()),
            ui_mode: Some("dashboard".to_string()),
            engine_mode: Some("async".to_string()),
            selected_tasks: vec!["cargo".to_string()],
        },
    )
    .unwrap();

    let runs = scan_runs(temp.path()).unwrap();

    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].metadata.run_id, "newer-id");
}

#[test]
fn metadata_write_replaces_existing_metadata() {
    let temp = TempDir::new().unwrap();
    let run_dir = temp.path().join("run-demo");
    write_metadata_atomic(
        &run_dir,
        &RunMetadata {
            schema_version: 1,
            run_id: "id-demo".to_string(),
            display_name: "first".to_string(),
            created_unix_ms: 10,
            updated_unix_ms: 20,
            status: "running".to_string(),
            run_dir: run_dir.display().to_string(),
            pid: 7,
            host_os: Some("linux".to_string()),
            ui_mode: Some("plain".to_string()),
            engine_mode: Some("sync".to_string()),
            selected_tasks: vec!["first-task".to_string()],
        },
    )
    .unwrap();

    write_metadata_atomic(
        &run_dir,
        &RunMetadata {
            schema_version: 1,
            run_id: "id-demo".to_string(),
            display_name: "second".to_string(),
            created_unix_ms: 10,
            updated_unix_ms: 30,
            status: "completed".to_string(),
            run_dir: run_dir.display().to_string(),
            pid: 7,
            host_os: Some("linux".to_string()),
            ui_mode: Some("dashboard".to_string()),
            engine_mode: Some("async".to_string()),
            selected_tasks: vec!["second-task".to_string()],
        },
    )
    .unwrap();

    let metadata_path = run_dir.join("run-meta.json");
    let payload: RunMetadata = serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
    assert_eq!(payload.display_name, "second");
    assert_eq!(payload.status, "completed");
    assert_eq!(payload.selected_tasks, ["second-task"]);
}

#[test]
fn scan_skips_unowned_run_json_without_blocking_history() {
    let temp = TempDir::new().unwrap();
    let bad_run = temp.path().join("run-bad");
    let good_run = temp.path().join("run-good");
    fs::create_dir_all(&bad_run).unwrap();
    fs::write(bad_run.join("run.json"), "{not json").unwrap();
    write_metadata_atomic(
        &good_run,
        &RunMetadata {
            schema_version: 1,
            run_id: "good-id".to_string(),
            display_name: "good".to_string(),
            created_unix_ms: 10,
            updated_unix_ms: 20,
            status: "completed".to_string(),
            run_dir: good_run.display().to_string(),
            pid: 1,
            host_os: Some("linux".to_string()),
            ui_mode: Some("plain".to_string()),
            engine_mode: Some("sync".to_string()),
            selected_tasks: vec!["yay".to_string()],
        },
    )
    .unwrap();

    let runs = scan_runs(temp.path()).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].metadata.run_id, "good-id");
}

#[test]
fn scan_keeps_metadata_run_when_run_json_is_malformed() {
    let temp = TempDir::new().unwrap();
    let run_dir = temp.path().join("run-with-bad-artifact");
    write_metadata_atomic(
        &run_dir,
        &RunMetadata {
            schema_version: 1,
            run_id: "metadata-id".to_string(),
            display_name: "metadata survives".to_string(),
            created_unix_ms: 10,
            updated_unix_ms: 20,
            status: "completed".to_string(),
            run_dir: run_dir.display().to_string(),
            pid: 1,
            host_os: Some("linux".to_string()),
            ui_mode: Some("plain".to_string()),
            engine_mode: Some("sync".to_string()),
            selected_tasks: vec!["yay".to_string()],
        },
    )
    .unwrap();
    fs::write(run_dir.join("run.json"), "{not json").unwrap();

    let runs = scan_runs(temp.path()).unwrap();

    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].metadata.run_id, "metadata-id");
    assert_eq!(runs[0].task_count, 0);
    assert_eq!(runs[0].run_json_status, RunArtifactStatus::Malformed);
}

#[test]
fn scan_records_run_json_fallback_reason() {
    let temp = TempDir::new().unwrap();
    let missing_run = temp.path().join("run-missing-artifact");
    let malformed_run = temp.path().join("run-malformed-artifact");
    let loaded_run = temp.path().join("run-loaded-artifact");

    for (run_dir, run_id) in [
        (&missing_run, "missing-id"),
        (&malformed_run, "malformed-id"),
        (&loaded_run, "loaded-id"),
    ] {
        write_metadata_atomic(
            run_dir,
            &RunMetadata {
                schema_version: 1,
                run_id: run_id.to_string(),
                display_name: run_id.to_string(),
                created_unix_ms: 10,
                updated_unix_ms: 20,
                status: "completed".to_string(),
                run_dir: run_dir.display().to_string(),
                pid: 1,
                host_os: Some("linux".to_string()),
                ui_mode: Some("plain".to_string()),
                engine_mode: Some("sync".to_string()),
                selected_tasks: vec!["yay".to_string()],
            },
        )
        .unwrap();
    }
    fs::write(malformed_run.join("run.json"), "{not json").unwrap();
    fs::write(
        loaded_run.join("run.json"),
        r#"{"exit_code":0,"tasks_elapsed_ms":42,"tasks":[]}"#,
    )
    .unwrap();

    let runs = scan_runs(temp.path()).unwrap();

    let status_for = |run_id: &str| {
        runs.iter()
            .find(|run| run.metadata.run_id == run_id)
            .map(|run| run.run_json_status)
            .unwrap()
    };
    assert_eq!(status_for("missing-id"), RunArtifactStatus::Missing);
    assert_eq!(status_for("malformed-id"), RunArtifactStatus::Malformed);
    assert_eq!(status_for("loaded-id"), RunArtifactStatus::Loaded);
}

#[test]
fn resolve_query_prefers_exact_match_then_fuzzy_tasks() {
    let temp = TempDir::new().unwrap();
    let run_dir = temp.path().join("run-demo");
    write_metadata_atomic(
        &run_dir,
        &RunMetadata {
            schema_version: 1,
            run_id: "id-demo".to_string(),
            display_name: "daily work refresh".to_string(),
            created_unix_ms: 10,
            updated_unix_ms: 20,
            status: "completed".to_string(),
            run_dir: run_dir.display().to_string(),
            pid: 7,
            host_os: Some("linux".to_string()),
            ui_mode: Some("dashboard".to_string()),
            engine_mode: Some("async".to_string()),
            selected_tasks: vec!["arch-update-services".to_string()],
        },
    )
    .unwrap();

    let exact = resolve_run_query(temp.path(), "daily work refresh").unwrap();
    let fuzzy = resolve_run_query(temp.path(), "services").unwrap();

    assert_eq!(exact.len(), 1);
    assert_eq!(fuzzy.len(), 1);
    assert_eq!(fuzzy[0].metadata.run_id, "id-demo");
}

#[test]
fn concurrent_metadata_writes_use_distinct_temp_paths() {
    let temp = TempDir::new().unwrap();
    let run_dir = temp.path().join("run-demo");
    let workers = 16;
    let barrier = Arc::new(Barrier::new(workers));
    let handles = (0..workers)
        .map(|idx| {
            let run_dir = run_dir.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let metadata = RunMetadata {
                    schema_version: 1,
                    run_id: "id-demo".to_string(),
                    display_name: format!("name-{idx}"),
                    created_unix_ms: 10,
                    updated_unix_ms: 20 + idx as u64,
                    status: "running".to_string(),
                    run_dir: run_dir.display().to_string(),
                    pid: 7,
                    host_os: Some("linux".to_string()),
                    ui_mode: Some("dashboard".to_string()),
                    engine_mode: Some("async".to_string()),
                    selected_tasks: vec!["yay".to_string()],
                };
                barrier.wait();
                write_metadata_atomic(&run_dir, &metadata)
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    let metadata_path = run_dir.join("run-meta.json");
    let payload: RunMetadata = serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
    assert_eq!(payload.run_id, "id-demo");
    assert!(payload.display_name.starts_with("name-"));
}
