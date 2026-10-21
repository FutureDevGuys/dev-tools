use super::{
    prune_runs, resolve_run_query, scan_runs, write_metadata_atomic, RunArtifactStatus,
    RunMetadata, RunRetentionPolicy,
};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

fn completed_run(root: &Path, name: &str, updated_unix_ms: u64, payload_bytes: usize) -> u64 {
    let run_dir = root.join(name);
    write_metadata_atomic(
        &run_dir,
        &RunMetadata {
            schema_version: 1,
            run_id: format!("id-{name}"),
            display_name: name.to_string(),
            created_unix_ms: updated_unix_ms.saturating_sub(1),
            updated_unix_ms,
            status: "completed".to_string(),
            run_dir: run_dir.display().to_string(),
            pid: 1,
            host_os: Some("linux".to_string()),
            ui_mode: Some("plain".to_string()),
            engine_mode: Some("sync".to_string()),
            selected_tasks: Vec::new(),
        },
    )
    .unwrap();
    fs::write(run_dir.join("payload.log"), vec![b'x'; payload_bytes]).unwrap();
    ["run-meta.json", "payload.log"]
        .into_iter()
        .map(|name| fs::metadata(run_dir.join(name)).unwrap().len())
        .sum()
}

#[test]
fn run_retention_prunes_age_count_and_bytes_without_touching_active_or_unowned() {
    let temp = TempDir::new().unwrap();
    assert_retention_with_measured_byte_budget(temp.path());
}

#[test]
fn run_retention_byte_budget_is_independent_of_fixture_path_length() {
    let temp = TempDir::new().unwrap();
    let short_bytes = assert_retention_with_measured_byte_budget(&temp.path().join("short"));
    let long_bytes =
        assert_retention_with_measured_byte_budget(&temp.path().join("long-root-".repeat(12)));

    assert!(long_bytes > short_bytes);
    // This root must exercise the case the old fixed byte budget could not retain.
    assert!(long_bytes > 1_100);
}

fn assert_retention_with_measured_byte_budget(root: &Path) -> u64 {
    let now = 2_000_000_000_000_u64;
    completed_run(root, "run-old", now - 40 * 24 * 60 * 60 * 1000, 10);
    let first_bytes = completed_run(root, "run-first", now - 2_000, 700);
    let second_bytes = completed_run(root, "run-second", now - 1_000, 700);
    let active = root.join("run-active");
    write_metadata_atomic(
        &active,
        &RunMetadata {
            schema_version: 1,
            run_id: "active".to_string(),
            display_name: "active".to_string(),
            created_unix_ms: 1,
            updated_unix_ms: 1,
            status: "running".to_string(),
            run_dir: active.display().to_string(),
            pid: 1,
            host_os: None,
            ui_mode: None,
            engine_mode: None,
            selected_tasks: Vec::new(),
        },
    )
    .unwrap();
    let unowned = root.join("unowned");
    fs::create_dir(&unowned).unwrap();
    fs::write(unowned.join("notes"), "keep").unwrap();

    let policy = RunRetentionPolicy {
        max_age_days: 30,
        max_runs: 2,
        // Include the serialized absolute run_dir instead of assuming its length.
        max_bytes: second_bytes,
    };
    // After age pruning, both completed runs fit the count limit and each fits
    // the byte limit alone. Their aggregate must require oldest-first byte pruning.
    assert!(2 <= policy.max_runs);
    assert!(first_bytes <= policy.max_bytes);
    assert!(second_bytes <= policy.max_bytes);
    assert!(first_bytes + second_bytes > policy.max_bytes);

    let report = prune_runs(root, policy, now, None, false).unwrap();

    assert!(report.removed.contains(&"run-old".to_string()));
    assert!(report.removed.contains(&"run-first".to_string()));
    assert!(root.join("run-second").exists());
    assert!(active.exists());
    assert!(unowned.exists());
    second_bytes
}

#[test]
fn run_retention_dry_run_reports_without_mutation_and_protects_current_run() {
    let temp = TempDir::new().unwrap();
    completed_run(temp.path(), "run-first", 10, 100);
    completed_run(temp.path(), "run-current", 20, 100);
    let current = temp.path().join("run-current");

    let report = prune_runs(
        temp.path(),
        RunRetentionPolicy {
            max_age_days: 0,
            max_runs: 0,
            max_bytes: 0,
        },
        100,
        Some(&current),
        true,
    )
    .unwrap();

    assert!(report.dry_run);
    assert_eq!(report.removed, ["run-first"]);
    assert!(temp.path().join("run-first").exists());
    assert!(current.exists());
}

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
    assert_eq!(runs[0].task_count, None);
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

fn staged_metadata_fixture(run_dir: &Path) -> RunMetadata {
    RunMetadata {
        schema_version: 1,
        run_id: "staging-fixture".to_string(),
        display_name: "staging fixture".to_string(),
        created_unix_ms: 10,
        updated_unix_ms: 20,
        status: "finalizing".to_string(),
        run_dir: run_dir.display().to_string(),
        pid: std::process::id(),
        host_os: None,
        ui_mode: None,
        engine_mode: None,
        selected_tasks: Vec::new(),
    }
}

fn directory_names(path: &Path) -> Vec<std::ffi::OsString> {
    let mut names = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[cfg(target_os = "linux")]
fn isolated_metadata_test(test_name: &str) -> bool {
    use std::process::{Command, Stdio};
    use std::time::Duration;
    use wait_timeout::ChildExt;

    const CHILD: &str = "UPDATE_ALL_METADATA_STAGING_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let root = TempDir::new().unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_name, "--nocapture"])
        .env_clear()
        .env(CHILD, "1")
        .env("HOME", root.path())
        .env("TMPDIR", root.path())
        .env("PATH", "")
        .current_dir(root.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if child
        .wait_timeout(Duration::from_secs(15))
        .unwrap()
        .is_none()
    {
        let _ = child.kill();
        let _ = child.wait();
        panic!("owned metadata staging test exceeded its bound");
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

#[cfg(target_os = "linux")]
#[test]
#[allow(unsafe_code)]
fn metadata_staging_cleans_partial_writes_without_changing_prior_evidence() {
    use std::os::unix::fs::PermissionsExt;

    if isolated_metadata_test(
        "runs::tests::metadata_staging_cleans_partial_writes_without_changing_prior_evidence",
    ) {
        return;
    }
    struct LimitGuard(libc::rlimit, libc::sighandler_t);
    impl Drop for LimitGuard {
        fn drop(&mut self) {
            // SAFETY: restore only this isolated test process's saved limit and handler.
            unsafe {
                assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &self.0), 0);
                libc::signal(libc::SIGXFSZ, self.1);
            }
        }
    }

    let root = TempDir::new().unwrap();
    let existing = root.path().join("existing");
    let absent = root.path().join("absent");
    let mut metadata = staged_metadata_fixture(&existing);
    write_metadata_atomic(&existing, &metadata).unwrap();
    fs::create_dir(&absent).unwrap();
    let path = existing.join("run-meta.json");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let before_bytes = fs::read(&path).unwrap();
    let before_metadata = fs::metadata(&path).unwrap();
    for dir in [&existing, &absent] {
        fs::write(dir.join(".run-meta.unknown.tmp"), b"unowned metadata stage").unwrap();
        fs::write(
            dir.join(".update-all-artifact-unknown-run.json"),
            b"unowned artifact stage",
        )
        .unwrap();
    }
    let existing_names = directory_names(&existing);
    let absent_names = directory_names(&absent);
    metadata.status = "failed".to_string();

    // SAFETY: a self-spawned exact-test process owns this limit and signal disposition.
    let guard = unsafe {
        let mut old_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut old_limit), 0);
        let old_handler = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        assert_ne!(old_handler, libc::SIG_ERR);
        let guard = LimitGuard(old_limit, old_handler);
        let limit = libc::rlimit {
            rlim_cur: 1,
            rlim_max: guard.0.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
        guard
    };
    let existing_error = write_metadata_atomic(&existing, &metadata).unwrap_err();
    let absent_error = write_metadata_atomic(&absent, &metadata).unwrap_err();
    drop(guard);
    for error in [&existing_error, &absent_error] {
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EFBIG)
        );
        assert!(format!("{error:#}").contains("write "));
    }
    assert_eq!(fs::read(&path).unwrap(), before_bytes);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode(),
        before_metadata.permissions().mode()
    );
    assert_eq!(
        fs::metadata(&path).unwrap().modified().unwrap(),
        before_metadata.modified().unwrap()
    );
    assert!(!absent.join("run-meta.json").exists());
    for dir in [&existing, &absent] {
        assert_eq!(
            fs::read(dir.join(".run-meta.unknown.tmp")).unwrap(),
            b"unowned metadata stage"
        );
        assert_eq!(
            fs::read(dir.join(".update-all-artifact-unknown-run.json")).unwrap(),
            b"unowned artifact stage"
        );
    }
    // Keep both causal errors alive: cleanup must finish before returning them.
    assert_eq!(directory_names(&existing), existing_names);
    assert_eq!(directory_names(&absent), absent_names);
}

#[cfg(target_os = "linux")]
#[test]
fn metadata_staging_open_collision_preserves_the_unowned_file() {
    if isolated_metadata_test(
        "runs::tests::metadata_staging_open_collision_preserves_the_unowned_file",
    ) {
        return;
    }
    let root = TempDir::new().unwrap();
    let metadata = staged_metadata_fixture(root.path());
    // This exact-test subprocess has no other metadata writer advancing the sequence.
    let sequence = super::METADATA_WRITE_SEQ.load(std::sync::atomic::Ordering::SeqCst);
    let collision = root
        .path()
        .join(format!(".run-meta.{}.{}.tmp", std::process::id(), sequence));
    fs::write(&collision, b"unowned collision sentinel").unwrap();
    let before = fs::metadata(&collision).unwrap();
    let error = write_metadata_atomic(root.path(), &metadata).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(&collision).unwrap(), b"unowned collision sentinel");
    assert_eq!(
        fs::metadata(&collision).unwrap().permissions(),
        before.permissions()
    );
    assert_eq!(
        fs::metadata(&collision).unwrap().modified().unwrap(),
        before.modified().unwrap()
    );
    assert!(!root.path().join("run-meta.json").exists());
    assert_eq!(directory_names(root.path()).len(), 1);

    write_metadata_atomic(root.path(), &metadata).unwrap();
    assert_eq!(fs::read(&collision).unwrap(), b"unowned collision sentinel");
    assert_eq!(directory_names(root.path()).len(), 2);
}

#[test]
fn metadata_staging_cleans_publication_failure_and_success_only() {
    let root = TempDir::new().unwrap();
    let obstructed = root.path().join("obstructed");
    let destination = obstructed.join("run-meta.json");
    fs::create_dir_all(&destination).unwrap();
    fs::write(destination.join("child"), b"preserved obstruction").unwrap();
    let unknown = obstructed.join(".run-meta.unknown.tmp");
    fs::write(&unknown, b"unowned sibling").unwrap();
    let before_names = directory_names(&obstructed);
    let error =
        write_metadata_atomic(&obstructed, &staged_metadata_fixture(&obstructed)).unwrap_err();
    assert!(format!("{error:#}").contains("run-meta.json"));
    assert_eq!(
        fs::read(destination.join("child")).unwrap(),
        b"preserved obstruction"
    );
    assert_eq!(fs::read(&unknown).unwrap(), b"unowned sibling");
    assert_eq!(directory_names(&obstructed), before_names);

    let successful = root.path().join("successful");
    let metadata = staged_metadata_fixture(&successful);
    write_metadata_atomic(&successful, &metadata).unwrap();
    write_metadata_atomic(&successful, &metadata).unwrap();
    assert_eq!(
        fs::read(successful.join("run-meta.json")).unwrap(),
        serde_json::to_vec_pretty(&metadata).unwrap()
    );
    assert_eq!(
        directory_names(&successful),
        vec![std::ffi::OsString::from("run-meta.json")]
    );
}
