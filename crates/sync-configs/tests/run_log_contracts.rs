use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::{json, Value};
use sync_configs::run_logs::{
    list_runs, prune_runs_at, resolve_log_root_with, show_run, LogLevel, LogLimits, LogStyle,
    Platform, RecorderOptions, RetentionPolicy, RunRecorder, RunStatus,
};
use tempfile::TempDir;

fn environment(values: &[(&str, &Path)]) -> HashMap<String, OsString> {
    values
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.as_os_str().to_owned()))
        .collect()
}

fn run_options(root: &Path, style: LogStyle) -> RecorderOptions {
    RecorderOptions {
        root: root.to_owned(),
        style,
        level: LogLevel::Info,
        dry_run: false,
        parent_run_id: None,
        limits: LogLimits::default(),
    }
}

fn only_run(root: &Path) -> PathBuf {
    let runs: Vec<_> = fs::read_dir(root)
        .expect("read run root")
        .map(|entry| entry.expect("read run entry").path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(runs.len(), 1, "expected exactly one run directory");
    runs.into_iter().next().expect("one run")
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read JSON file")).expect("parse JSON file")
}

#[test]
fn root_resolution_obeys_cli_environment_and_platform_precedence() {
    let temp = TempDir::new().expect("tempdir");
    let cli = temp.path().join("cli");
    let configured = temp.path().join("configured");
    let xdg = temp.path().join("state");
    let home = temp.path().join("home");
    let vars = environment(&[
        ("SYNC_CONFIGS_LOG_ROOT", &configured),
        ("XDG_STATE_HOME", &xdg),
        ("HOME", &home),
    ]);

    let resolved =
        resolve_log_root_with(Some(&cli), Platform::Unix, |name| vars.get(name).cloned())
            .expect("CLI root");
    assert_eq!(resolved, cli);

    let resolved = resolve_log_root_with(None, Platform::Unix, |name| vars.get(name).cloned())
        .expect("environment root");
    assert_eq!(resolved, configured);

    let vars = environment(&[("XDG_STATE_HOME", &xdg), ("HOME", &home)]);
    let resolved = resolve_log_root_with(None, Platform::Unix, |name| vars.get(name).cloned())
        .expect("XDG state root");
    assert_eq!(resolved, xdg.join("sync-configs/runs"));

    let vars = environment(&[("HOME", &home)]);
    let resolved = resolve_log_root_with(None, Platform::Unix, |name| vars.get(name).cloned())
        .expect("home fallback");
    assert_eq!(resolved, home.join(".local/state/sync-configs/runs"));
}

#[test]
fn windows_root_resolution_is_testable_without_running_on_windows() {
    let temp = TempDir::new().expect("tempdir");
    let local = temp.path().join("LocalAppData");
    let profile = temp.path().join("profile");
    let vars = environment(&[("LOCALAPPDATA", &local), ("USERPROFILE", &profile)]);
    assert_eq!(
        resolve_log_root_with(None, Platform::Windows, |name| vars.get(name).cloned())
            .expect("LOCALAPPDATA root"),
        local.join("sync-configs/runs")
    );

    let vars = environment(&[("USERPROFILE", &profile)]);
    assert_eq!(
        resolve_log_root_with(None, Platform::Windows, |name| vars.get(name).cloned())
            .expect("profile fallback"),
        profile.join("AppData/Local/sync-configs/runs")
    );
}

#[test]
fn explicit_and_sync_configs_environment_roots_must_be_absolute() {
    let relative = Path::new("relative/runs");
    let empty = HashMap::<String, OsString>::new();
    let error = resolve_log_root_with(Some(relative), Platform::Unix, |name| {
        empty.get(name).cloned()
    })
    .expect_err("relative CLI root must fail");
    assert!(error.to_string().contains("absolute"));

    let vars = HashMap::from([(
        "SYNC_CONFIGS_LOG_ROOT".to_owned(),
        OsString::from("relative/runs"),
    )]);
    let error = resolve_log_root_with(None, Platform::Unix, |name| vars.get(name).cloned())
        .expect_err("relative environment root must fail");
    assert!(error.to_string().contains("absolute"));
}

#[test]
fn off_style_is_a_true_no_op() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let mut recorder = RunRecorder::start(run_options(&root, LogStyle::Off)).expect("off recorder");
    assert!(!recorder.enabled());
    recorder.record_summary(BTreeMap::from([("performed".to_owned(), 1)]), 1);
    recorder.finish(0, false);
    assert!(!root.exists());
}

#[test]
fn events_are_owner_only_bounded_and_value_free() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let mut options = run_options(&root, LogStyle::Events);
    options.limits.event_bytes = 700;
    let mut recorder = RunRecorder::start(options).expect("start recorder");
    for _ in 0..30 {
        recorder.record_entry_status(
            "scope-DO_NOT_PERSIST",
            "entry-DO_NOT_PERSIST",
            "performed",
            Some("post_script"),
        );
    }
    recorder.record_summary(BTreeMap::from([("performed".to_owned(), 30)]), 30);
    recorder.finish(0, false);

    let run = only_run(&root);
    let persisted = fs::read_to_string(run.join("events.jsonl")).expect("events");
    assert!(!persisted.contains("DO_NOT_PERSIST"));
    assert!(persisted.contains("entry_id"));
    assert!(persisted.len() <= 700);
    assert!(!run.join("console.log").exists());
    let metadata = read_json(&run.join("run.json"));
    assert_eq!(metadata["status"], "completed");
    assert_eq!(metadata["exit_code"], 0);
    assert_eq!(metadata["events_truncated"], true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&root)
                .expect("root metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&run)
                .expect("run metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(run.join("run.json"))
                .expect("metadata file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(run.join("events.jsonl"))
                .expect("events file")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn event_level_filters_and_unknown_statuses_do_not_become_log_values() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let mut options = run_options(&root, LogStyle::Events);
    options.level = LogLevel::Warning;
    let mut recorder = RunRecorder::start(options).expect("start recorder");
    recorder.record_entry_status("scope", "entry", "performed", None);
    recorder.record_entry_status("scope", "entry", "secret-status", None);
    recorder.record_entry_status("scope", "entry", "errors", None);
    recorder.finish(1, false);

    let events = fs::read_to_string(only_run(&root).join("events.jsonl")).expect("events");
    assert!(!events.contains("performed"));
    assert!(!events.contains("secret-status"));
    assert!(events.contains("\"status\":\"unknown\""));
    assert!(events.contains("errors"));
}

#[test]
fn transcript_is_explicit_shared_between_streams_and_bounded_on_utf8_boundaries() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let mut options = run_options(&root, LogStyle::Both);
    options.limits.transcript_bytes = 80;
    let mut recorder = RunRecorder::start(options).expect("start recorder");
    recorder.record_transcript("stdout 🙂".as_bytes());
    recorder.record_transcript(" stderr 🙂".repeat(30).as_bytes());
    recorder.finish(0, false);

    let run = only_run(&root);
    let transcript = fs::read(run.join("console.log")).expect("transcript");
    assert!(transcript.len() <= 80);
    let text = String::from_utf8(transcript).expect("valid UTF-8 transcript");
    assert!(text.contains("truncated"));
    assert_eq!(
        read_json(&run.join("run.json"))["transcript_truncated"],
        true
    );
}

#[test]
fn parent_run_id_is_accepted_only_in_the_exact_generated_shape() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let parent = "run-20260901T120000.000000Z-7-deadbeef";
    let mut options = run_options(&root, LogStyle::Events);
    options.parent_run_id = Some(parent.to_owned());
    let mut recorder = RunRecorder::start(options).expect("start recorder");
    recorder.finish(0, false);
    assert_eq!(
        read_json(&only_run(&root).join("run.json"))["parent_run_id"],
        parent
    );

    let second_root = temp.path().join("second-runs");
    let mut options = run_options(&second_root, LogStyle::Events);
    options.parent_run_id = Some("not safe\nDO_NOT_PERSIST".to_owned());
    let mut recorder = RunRecorder::start(options).expect("start recorder");
    recorder.finish(0, false);
    let metadata = read_json(&only_run(&second_root).join("run.json"));
    assert!(metadata.get("parent_run_id").is_none());
    assert!(!fs::read_to_string(only_run(&second_root).join("run.json"))
        .expect("metadata")
        .contains("DO_NOT_PERSIST"));
}

#[test]
fn terminal_metadata_records_failed_and_interrupted_outcomes() {
    let temp = TempDir::new().expect("tempdir");
    for (leaf, code, interrupted, status) in [
        ("failed", 9, false, "failed"),
        ("interrupted", 130, true, "interrupted"),
    ] {
        let root = temp.path().join(leaf);
        let mut recorder =
            RunRecorder::start(run_options(&root, LogStyle::Events)).expect("start recorder");
        recorder.finish(code, interrupted);
        let metadata = read_json(&only_run(&root).join("run.json"));
        assert_eq!(metadata["status"], status);
        assert_eq!(metadata["exit_code"], code);
        assert!(metadata["ended_at"].as_str().is_some());
    }
}

fn write_run(root: &Path, id: &str, started_at: &str, status: RunStatus, bytes: usize) -> PathBuf {
    let run = root.join(id);
    fs::create_dir_all(&run).expect("create fixture run");
    let metadata = json!({
        "schema_version": 1,
        "run_id": id,
        "product": "sync-configs",
        "status": status,
        "started_at": started_at,
        "dry_run": false,
        "log_style": "events",
        "log_level": "info",
        "events_truncated": false,
        "transcript_truncated": false,
        "ended_at": if status == RunStatus::Running { Value::Null } else { Value::String(started_at.to_owned()) },
        "exit_code": if status == RunStatus::Running { Value::Null } else { Value::from(if status == RunStatus::Completed { 0 } else { 1 }) }
    });
    fs::write(
        run.join("run.json"),
        serde_json::to_vec(&metadata).expect("serialize fixture"),
    )
    .expect("write fixture metadata");
    if bytes > 0 {
        fs::write(run.join("payload"), vec![b'x'; bytes]).expect("write payload");
    }
    run
}

#[test]
fn list_and_show_are_read_only_sorted_and_reject_escapes_and_malformed_state() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("absent-runs");
    assert!(list_runs(&root)
        .expect("missing root lists empty")
        .is_empty());
    assert!(
        !root.exists(),
        "log management must not self-log or create state"
    );

    let older = write_run(
        &root,
        "run-20260830T000000.000000Z-1-00000001",
        "2026-08-30T00:00:00.000000Z",
        RunStatus::Completed,
        0,
    );
    let newer = write_run(
        &root,
        "run-20260831T000000.000000Z-1-00000002",
        "2026-08-31T00:00:00.000000Z",
        RunStatus::Failed,
        0,
    );
    let malformed = root.join("run-20260829T000000.000000Z-1-00000003");
    fs::create_dir(&malformed).expect("malformed dir");
    fs::write(malformed.join("run.json"), b"not-json").expect("malformed metadata");

    let listed = list_runs(&root).expect("list runs");
    assert_eq!(listed.len(), 2);
    assert_eq!(
        listed[0].run_id,
        newer.file_name().expect("name").to_string_lossy()
    );
    assert_eq!(
        listed[1].run_id,
        older.file_name().expect("name").to_string_lossy()
    );
    assert_eq!(
        show_run(&root, "run-20260830T000000.000000Z-1-00000001")
            .expect("show run")
            .status,
        RunStatus::Completed
    );
    assert!(show_run(&root, "../run.json").is_err());
    assert!(show_run(&root, "run-20260829T000000.000000Z-1-00000003").is_err());
}

#[test]
fn retention_applies_age_count_and_bytes_oldest_first() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let old = write_run(
        &root,
        "run-20260701T000000.000000Z-1-00000001",
        "2026-07-01T00:00:00.000000Z",
        RunStatus::Completed,
        20,
    );
    let first = write_run(
        &root,
        "run-20260830T000000.000000Z-1-00000002",
        "2026-08-30T00:00:00.000000Z",
        RunStatus::Completed,
        200,
    );
    let second = write_run(
        &root,
        "run-20260831T000000.000000Z-1-00000003",
        "2026-08-31T00:00:00.000000Z",
        RunStatus::Completed,
        20,
    );
    let second_size = fs::read_dir(&second)
        .expect("second dir")
        .map(|entry| {
            fs::metadata(entry.expect("entry").path())
                .expect("metadata")
                .len()
        })
        .sum();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_788_220_800); // 2026-09-01T00:00:00Z
    let policy = RetentionPolicy {
        max_age_days: 30,
        max_runs: 2,
        max_bytes: second_size,
    };

    let preview = prune_runs_at(&root, policy, now, true).expect("preview prune");
    assert_eq!(
        preview.removed,
        vec![
            old.file_name().unwrap().to_string_lossy().into_owned(),
            first.file_name().unwrap().to_string_lossy().into_owned()
        ]
    );
    assert!(old.exists() && first.exists() && second.exists());
    let applied = prune_runs_at(&root, policy, now, false).expect("apply prune");
    assert_eq!(applied.removed, preview.removed);
    assert!(!old.exists() && !first.exists() && second.exists());
}

#[test]
fn retention_preserves_running_malformed_and_symlinked_run_candidates() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let running = write_run(
        &root,
        "run-20260801T000000.000000Z-1-00000001",
        "2026-08-01T00:00:00.000000Z",
        RunStatus::Running,
        10,
    );
    let malformed = root.join("run-20260801T000000.000000Z-1-00000002");
    fs::create_dir(&malformed).expect("malformed dir");
    fs::write(malformed.join("run.json"), b"{}").expect("malformed metadata");

    #[cfg(unix)]
    let (symlink, victim) = {
        use std::os::unix::fs::symlink as create_symlink;
        let victim = temp.path().join("victim");
        fs::create_dir(&victim).expect("victim");
        fs::write(victim.join("keep"), b"keep").expect("victim payload");
        let symlink = root.join("run-20260801T000000.000000Z-1-00000003");
        create_symlink(&victim, &symlink).expect("run symlink");
        (symlink, victim)
    };

    let report = prune_runs_at(
        &root,
        RetentionPolicy {
            max_age_days: 0,
            max_runs: 0,
            max_bytes: 0,
        },
        SystemTime::now(),
        false,
    )
    .expect("prune protected state");
    assert!(report.removed.is_empty());
    assert!(running.exists());
    assert!(malformed.exists());
    #[cfg(unix)]
    {
        assert!(symlink.exists());
        assert!(victim.join("keep").exists());
    }
}

#[test]
fn logging_start_failure_can_be_downgraded_without_mutating_the_bad_root() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("occupied");
    fs::write(&root, b"not a directory").expect("occupied root");
    let recorder = RunRecorder::start_safely(run_options(&root, LogStyle::Events));
    assert!(!recorder.enabled());
    assert_eq!(fs::read(&root).expect("root retained"), b"not a directory");
}
