use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;
use std::time::SystemTime;

#[cfg(unix)]
use serde_json::{json, Value};
#[cfg(unix)]
use sync_configs::run_logs::RunStatus;
use sync_configs::run_logs::{
    list_runs, prune_runs_at, resolve_log_root_with, show_run, LogLevel, LogLimits, LogStyle,
    Platform, RecorderOptions, RetentionPolicy, RunRecorder,
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

#[cfg(unix)]
fn only_run(root: &Path) -> PathBuf {
    let runs: Vec<_> = fs::read_dir(root)
        .expect("read run root")
        .map(|entry| entry.expect("read run entry").path())
        .filter(|path| path.is_dir())
        .collect();
    assert_eq!(runs.len(), 1, "expected exactly one run directory");
    runs.into_iter().next().expect("one run")
}

#[cfg(unix)]
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
#[cfg(unix)]
fn root_resolution_rejects_parent_traversal_before_symlink_ancestry_can_be_erased() {
    let temp = TempDir::new().expect("tempdir");
    let target = temp.path().join("target");
    fs::create_dir(&target).expect("symlink target");
    let link = temp.path().join("link");
    symlink(&target, &link).expect("symlink fixture");
    let escaped = link.join("..").join("runs");
    let empty = HashMap::<String, OsString>::new();

    let explicit_error = resolve_log_root_with(Some(&escaped), Platform::Unix, |name| {
        empty.get(name).cloned()
    })
    .expect_err("explicit parent traversal must not be normalized away");
    assert!(explicit_error.to_string().contains("parent-directory"));

    let vars = HashMap::from([(
        "SYNC_CONFIGS_LOG_ROOT".to_owned(),
        escaped.as_os_str().to_owned(),
    )]);
    let environment_error =
        resolve_log_root_with(None, Platform::Unix, |name| vars.get(name).cloned())
            .expect_err("environment parent traversal must not be normalized away");
    assert!(environment_error.to_string().contains("parent-directory"));
}

#[test]
#[cfg(unix)]
fn absolute_dot_component_root_resolves_and_records_consistently() {
    let temp = TempDir::new().expect("tempdir");
    let dotted_root = temp.path().join("state").join(".").join("runs");
    assert!(
        dotted_root.as_os_str().to_string_lossy().contains("/./"),
        "fixture must retain the dot component spelling"
    );
    let empty = HashMap::<String, OsString>::new();
    let resolved = resolve_log_root_with(Some(&dotted_root), Platform::Unix, |name| {
        empty.get(name).cloned()
    })
    .expect("absolute dot-component override");
    assert_eq!(resolved, dotted_root);

    let mut recorder = RunRecorder::start(run_options(&resolved, LogStyle::Events))
        .expect("record through dot-component root");
    recorder.finish(0, false);
    let run_id = only_run(&resolved)
        .file_name()
        .expect("run id")
        .to_str()
        .expect("UTF-8 run id")
        .to_owned();

    assert_eq!(list_runs(&resolved).expect("list dotted root").len(), 1);
    assert_eq!(
        show_run(&resolved, &run_id)
            .expect("show dotted root run")
            .run_id,
        run_id
    );
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(any(debug_assertions, feature = "test-support"))]
#[cfg(unix)]
#[test]
fn terminal_metadata_survives_a_run_finished_event_append_failure() {
    let temp = TempDir::new().expect("tempdir");
    for (leaf, code, interrupted, status) in [
        ("failed", 9, false, "failed"),
        ("interrupted", 130, true, "interrupted"),
    ] {
        let root = temp.path().join(leaf);
        let mut recorder =
            RunRecorder::start(run_options(&root, LogStyle::Events)).expect("start recorder");
        recorder.fail_event_writes_for_test();

        recorder.finish(code, interrupted);

        let metadata = read_json(&only_run(&root).join("run.json"));
        assert_eq!(metadata["status"], status);
        assert_eq!(metadata["exit_code"], code);
        assert!(metadata["ended_at"].as_str().is_some());
        assert!(
            !recorder.enabled(),
            "the failed event channel stays disabled"
        );
    }
}

#[cfg(unix)]
fn write_run(root: &Path, id: &str, started_at: &str, status: RunStatus, bytes: usize) -> PathBuf {
    let run = root.join(id);
    fs::create_dir_all(&run).expect("create fixture run");
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .expect("make fixture run root private");
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
#[cfg(unix)]
fn nested_private_root_is_created_component_by_component() {
    let temp = TempDir::new().expect("tempdir");
    let first = temp.path().join("state");
    let second = first.join("sync-configs");
    let root = second.join("runs");

    let mut recorder =
        RunRecorder::start(run_options(&root, LogStyle::Events)).expect("private nested root");
    recorder.finish(0, false);

    for path in [&first, &second, &root] {
        let metadata = fs::symlink_metadata(path).expect("created component metadata");
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }
    assert_eq!(list_runs(&root).expect("list private root").len(), 1);
}

#[test]
#[cfg(unix)]
fn every_public_log_surface_rejects_a_symlinked_root_ancestor() {
    let temp = TempDir::new().expect("tempdir");
    let real_parent = temp.path().join("real-state");
    let real_root = real_parent.join("runs");
    let run_id = "run-20260830T000000.000000Z-1-00000001";
    let run = write_run(
        &real_root,
        run_id,
        "2026-08-30T00:00:00.000000Z",
        RunStatus::Completed,
        8,
    );
    let linked_parent = temp.path().join("linked-state");
    symlink(&real_parent, &linked_parent).expect("symlinked ancestor");
    let linked_root = linked_parent.join("runs");
    let before = fs::read_dir(&real_root).expect("run root").count();

    let start_error = match RunRecorder::start(run_options(&linked_root, LogStyle::Events)) {
        Ok(_) => panic!("recording through a symlinked ancestor must fail"),
        Err(error) => error,
    };
    assert!(start_error.to_string().contains("symbolic link"));
    assert!(list_runs(&linked_root)
        .expect_err("list through symlink")
        .to_string()
        .contains("symbolic link"));
    assert!(show_run(&linked_root, run_id)
        .expect_err("show through symlink")
        .to_string()
        .contains("symbolic link"));
    assert!(prune_runs_at(
        &linked_root,
        RetentionPolicy {
            max_age_days: 0,
            max_runs: 0,
            max_bytes: 0,
        },
        SystemTime::now(),
        false,
    )
    .expect_err("prune through symlink")
    .to_string()
    .contains("symbolic link"));
    assert!(run.exists(), "unproven root must never be deleted through");
    assert_eq!(
        fs::read_dir(&real_root).expect("run root").count(),
        before,
        "recording rejection must not create a run through the link"
    );
}

#[test]
#[cfg(unix)]
fn existing_shared_root_is_rejected_without_chmod_or_deletion() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let run_id = "run-20260830T000000.000000Z-1-00000001";
    let run = write_run(
        &root,
        run_id,
        "2026-08-30T00:00:00.000000Z",
        RunStatus::Completed,
        8,
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750))
        .expect("make fixture root shared");

    let start_error = match RunRecorder::start(run_options(&root, LogStyle::Events)) {
        Ok(_) => panic!("recording into a shared root must fail"),
        Err(error) => error,
    };
    assert!(start_error.to_string().contains("broader than 0700"));
    assert!(list_runs(&root)
        .expect_err("list shared root")
        .to_string()
        .contains("broader than 0700"));
    assert!(show_run(&root, run_id)
        .expect_err("show shared root")
        .to_string()
        .contains("broader than 0700"));
    assert!(prune_runs_at(
        &root,
        RetentionPolicy {
            max_age_days: 0,
            max_runs: 0,
            max_bytes: 0,
        },
        SystemTime::now(),
        false,
    )
    .expect_err("prune shared root")
    .to_string()
    .contains("broader than 0700"));
    assert_eq!(
        fs::symlink_metadata(&root)
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777,
        0o750,
        "rejection must not silently chmod caller-owned state"
    );
    assert!(run.exists(), "unproven root contents must be retained");
}

#[test]
#[cfg(unix)]
fn existing_root_rejects_special_permission_bits_outside_0700() {
    let temp = TempDir::new().expect("tempdir");
    for (leaf, mode) in [("sticky", 0o1700), ("setgid", 0o2700)] {
        let root = temp.path().join(leaf);
        fs::create_dir(&root).expect("fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(mode))
            .expect("set special fixture mode");
        assert_eq!(
            fs::symlink_metadata(&root)
                .expect("fixture metadata")
                .permissions()
                .mode()
                & 0o7777,
            mode
        );

        let start_error = match RunRecorder::start(run_options(&root, LogStyle::Events)) {
            Ok(_) => panic!("recording into a special-bit root must fail"),
            Err(error) => error,
        };
        assert!(start_error.to_string().contains("broader than 0700"));
        assert!(list_runs(&root)
            .expect_err("management of special-bit root")
            .to_string()
            .contains("broader than 0700"));
        assert!(
            fs::read_dir(&root)
                .expect("rejected root remains readable")
                .next()
                .is_none(),
            "rejection must not create a run"
        );
    }
}

#[test]
#[cfg(unix)]
fn non_sticky_shared_writable_ancestor_is_rejected_without_mutation() {
    let temp = TempDir::new().expect("tempdir");
    let mutable_ancestor = temp.path().join("shared");
    let owned_child = mutable_ancestor.join("owned-child");
    fs::create_dir(&mutable_ancestor).expect("shared ancestor");
    fs::create_dir(&owned_child).expect("owned child");
    fs::set_permissions(&mutable_ancestor, fs::Permissions::from_mode(0o777))
        .expect("make ancestor non-sticky shared writable");
    fs::set_permissions(&owned_child, fs::Permissions::from_mode(0o700))
        .expect("make child private");
    let sentinel = owned_child.join("DO_NOT_TOUCH");
    fs::write(&sentinel, b"retained").expect("sentinel");
    let root = owned_child.join("runs");

    let start_error = match RunRecorder::start(run_options(&root, LogStyle::Events)) {
        Ok(_) => panic!("recording beneath a mutable ancestor must fail"),
        Err(error) => error,
    };
    assert!(start_error.to_string().contains("shared-writable ancestor"));
    assert!(list_runs(&root)
        .expect_err("management beneath mutable ancestor")
        .to_string()
        .contains("shared-writable ancestor"));
    assert!(!root.exists(), "rejection must precede root creation");
    assert_eq!(fs::read(&sentinel).expect("sentinel retained"), b"retained");
}

#[test]
#[cfg(unix)]
fn sticky_shared_ancestor_accepts_only_a_private_effective_user_child() {
    let temp = TempDir::new().expect("tempdir");
    let sticky = temp.path().join("sticky-shared");
    fs::create_dir(&sticky).expect("sticky ancestor");
    fs::set_permissions(&sticky, fs::Permissions::from_mode(0o1777))
        .expect("make sticky ancestor shared writable");

    let private_child = sticky.join("private-child");
    fs::create_dir(&private_child).expect("private child");
    fs::set_permissions(&private_child, fs::Permissions::from_mode(0o700))
        .expect("make child private");
    let accepted_root = private_child.join("runs");
    let mut recorder = RunRecorder::start(run_options(&accepted_root, LogStyle::Events))
        .expect("sticky shared boundary with private owned child");
    recorder.finish(0, false);
    assert_eq!(
        list_runs(&accepted_root).expect("list accepted sticky-root run"),
        vec![show_run(
            &accepted_root,
            only_run(&accepted_root)
                .file_name()
                .expect("run id")
                .to_str()
                .expect("UTF-8 run id")
        )
        .expect("show accepted sticky-root run")]
    );

    let writable_child = sticky.join("writable-child");
    fs::create_dir(&writable_child).expect("writable child");
    fs::set_permissions(&writable_child, fs::Permissions::from_mode(0o720))
        .expect("make child group writable");
    let rejected_root = writable_child.join("runs");
    let error = match RunRecorder::start(run_options(&rejected_root, LogStyle::Events)) {
        Ok(_) => panic!("sticky boundary with a shared-writable child must fail"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("sticky shared ancestor"));
    assert!(
        !rejected_root.exists(),
        "rejection must precede root creation"
    );
}

#[test]
#[cfg(unix)]
fn wrong_owner_root_is_rejected_when_the_fixture_user_is_non_root() {
    let root = Path::new("/");
    let metadata = fs::symlink_metadata(root).expect("filesystem root metadata");
    if metadata.uid() == rustix::process::geteuid().as_raw() {
        return;
    }

    let error = list_runs(root).expect_err("another user's root must be rejected");
    assert!(error.to_string().contains("owned by the effective user"));
}

#[test]
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(windows)]
#[test]
fn windows_public_logging_and_management_surfaces_fail_closed() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("runs");
    let expected = "owner-only diagnostic storage is unavailable on Windows";

    let start_error = match RunRecorder::start(run_options(&root, LogStyle::Both)) {
        Ok(_) => panic!("Windows recording must be rejected"),
        Err(error) => error,
    };
    assert_eq!(start_error.to_string(), expected);
    assert!(!root.exists(), "rejection must precede root creation");

    let recorder = RunRecorder::start_safely(run_options(&root, LogStyle::Transcript));
    assert!(!recorder.enabled(), "safe startup must disable logging");
    assert!(!root.exists(), "safe startup must not create log storage");

    fs::create_dir(&root).expect("untrusted fixture root");
    let sentinel = root.join("DO_NOT_TOUCH");
    fs::write(&sentinel, b"retained").expect("fixture sentinel");
    assert_eq!(
        list_runs(&root)
            .expect_err("list must reject unverified Windows storage")
            .to_string(),
        expected
    );
    assert_eq!(
        show_run(&root, "run-20260901T120000.000000Z-7-deadbeef")
            .expect_err("show must reject unverified Windows storage")
            .to_string(),
        expected
    );
    assert_eq!(
        prune_runs_at(
            &root,
            RetentionPolicy {
                max_age_days: 0,
                max_runs: 0,
                max_bytes: 0,
            },
            SystemTime::now(),
            false,
        )
        .expect_err("prune must reject unverified Windows storage")
        .to_string(),
        expected
    );
    assert_eq!(fs::read(&sentinel).expect("sentinel retained"), b"retained");
}
