use super::{
    install_dir_is_ephemeral, resolve_ui_with_tty, select_run_match_for_rename_with_tty,
    source_newer_than_expected_for_kind, stale_binary_refresh_hint, ExpectedBinaryKind, RenameCli,
    RunCli, UiMode,
};
use crate::config::{default_run_root, resolve_config_path, resolve_config_write_path};
use crate::config::{
    load_runtime_config, validate_config, BootstrapConfig, CompletionConfig, DashboardQuitBehavior,
    EngineConfig, InstallCheckMode, InstallConfig, InteractiveExecutionMode,
    InteractiveRuntimeConfig, LoggingConfig, RuntimeConfig, TaskPolicy, UiConfig, UpdaterConfig,
};
use crate::runs::{write_metadata_atomic, RunArtifactStatus, RunMetadata, RunSummary};
use crate::test_support::env_guard;
use crate::ui::UiModeResolved;
use crate::updaters::BuiltinReportParser;
use clap::Parser;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn runtime_config_with_tasks(tasks: BTreeMap<String, TaskPolicy>) -> RuntimeConfig {
    RuntimeConfig {
        ui: UiConfig {
            mode: UiMode::Dashboard,
            persist_until_exit: true,
            show_global_log: true,
            max_events_per_frame: 120,
            dashboard_quit_behavior: DashboardQuitBehavior::CancelAll,
            quit_cancel_grace_ms: 3000,
            mouse_row_stride: crate::config::MouseRowStrideMode::Auto,
            note_verbosity: crate::config::NoteVerbosity::Failures,
        },
        engine: EngineConfig {
            mode: super::EngineMode::Async,
            jobs: "auto".to_string(),
            fail_fast: false,
        },
        install: InstallConfig {
            dir: None,
            auto_update: true,
            check_mode: InstallCheckMode::SourceFingerprint,
        },
        interactive: InteractiveRuntimeConfig {
            mode: InteractiveExecutionMode::AutoFallback,
            stall_seconds: 20,
            max_line_bytes: 262_144,
            max_capture_bytes: 16_777_216,
            retry_once: true,
        },
        logging: LoggingConfig {
            run_dir: std::env::temp_dir().join("update-all-test-runs"),
            max_in_memory_lines: 20_000,
            filter_progress_noise: false,
            timestamps: true,
            task_colors: true,
        },
        tasks,
        updaters: UpdaterConfig {
            run_all_detected: true,
            include: BTreeSet::new(),
            exclude: BTreeSet::new(),
            privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
            custom_tasks: BTreeMap::new(),
            bootstrap: BootstrapConfig {
                enabled: false,
                windows_foundations: Vec::new(),
            },
        },
        completions: CompletionConfig { tools: Vec::new() },
        source_path: None,
    }
}

#[test]
fn auto_ui_defaults_to_dashboard_in_tty() {
    assert_eq!(
        resolve_ui_with_tty(UiMode::Auto, true),
        UiModeResolved::Dashboard
    );
}

#[test]
fn relative_time_label_formats_past_future_and_missing_values() {
    assert_eq!(super::relative_time_label(0, 10_000), "-");
    assert_eq!(super::relative_time_label(10_000, 10_000), "now");
    assert_eq!(super::relative_time_label(5_000, 10_000), "5s ago");
    assert_eq!(super::relative_time_label(10_000, 75_000), "1m ago");
    assert_eq!(super::relative_time_label(7_210_000, 10_000), "in 2h");
}

#[test]
fn auto_ui_defaults_to_plain_in_non_tty() {
    assert_eq!(
        resolve_ui_with_tty(UiMode::Auto, false),
        UiModeResolved::Plain
    );
}

#[test]
fn source_dist_uses_dist_staleness_flag() {
    assert!(source_newer_than_expected_for_kind(
        ExpectedBinaryKind::SourceDist,
        true,
        false
    ));
    assert!(!source_newer_than_expected_for_kind(
        ExpectedBinaryKind::SourceDist,
        false,
        true
    ));
}

#[test]
fn current_exe_uses_current_exe_staleness_flag() {
    assert!(source_newer_than_expected_for_kind(
        ExpectedBinaryKind::CurrentExe,
        false,
        true
    ));
    assert!(!source_newer_than_expected_for_kind(
        ExpectedBinaryKind::CurrentExe,
        true,
        false
    ));
}

#[test]
fn stale_running_install_reexecs_expected_binary_before_replace() {
    let temp = TempDir::new().unwrap();
    let install_dir = temp.path().join("bin");
    let release_dir = temp.path().join("dist").join("bin");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::create_dir_all(&release_dir).unwrap();
    let binary_name = format!("update-all{}", std::env::consts::EXE_SUFFIX);
    let target = install_dir.join(&binary_name);
    let expected = release_dir.join(&binary_name);
    std::fs::write(&target, b"old").unwrap();
    std::fs::write(&expected, b"new").unwrap();

    let status = super::InstallStatusReport {
        status: super::InstallStatusKind::StaleInstall,
        target_path: target.clone(),
        install_dir,
        configured_dir: None,
        effective_dir_source: "config".to_string(),
        expected_binary: expected.clone(),
        expected_kind: "source_dist".to_string(),
        check_mode: "source_fingerprint".to_string(),
        in_path: true,
        source_newer_than_expected: false,
    };

    assert!(super::should_reexec_expected_binary_for_self_replace(
        &status, &target
    ));

    let up_to_date = super::InstallStatusReport {
        status: super::InstallStatusKind::UpToDate,
        ..status
    };
    assert!(!super::should_reexec_expected_binary_for_self_replace(
        &up_to_date,
        &target
    ));
}

#[test]
fn stale_warning_hint_recommends_self_repair_and_dist_build() {
    let source_root = Path::new("/tmp/update-all-src");
    let hint = stale_binary_refresh_hint(source_root);
    assert!(hint.contains("automatic self-refresh"));
    assert!(hint.contains("update-all self repair"));
    assert!(!hint.contains("update-all config install"));
    assert!(hint.contains("python3 /tmp/install_rust_tool.py build update-all"));
    assert!(hint.contains("dist binary"));
}

#[test]
fn install_status_json_preserves_status_and_adds_diagnostics() {
    let status = super::InstallStatusReport {
        status: super::InstallStatusKind::UpToDate,
        target_path: PathBuf::from("/tmp/bin/update-all"),
        install_dir: PathBuf::from("/tmp/bin"),
        configured_dir: Some(PathBuf::from("/tmp/bin")),
        effective_dir_source: "config".to_string(),
        expected_binary: PathBuf::from("/tmp/dist/bin/update-all"),
        expected_kind: "source_dist".to_string(),
        check_mode: "source_fingerprint".to_string(),
        in_path: true,
        source_newer_than_expected: false,
    };
    let diagnostics = super::InstallStatusDiagnostics {
        source_root: PathBuf::from("/tmp/src"),
        source_fingerprint: Some("abc123".to_string()),
        expected_binary_source_fingerprint: Some("abc123".to_string()),
        target_binary_source_fingerprint: Some("abc123".to_string()),
        latest_source_mtime_unix_ms: Some(100),
        expected_binary_mtime_unix_ms: Some(200),
        target_binary_mtime_unix_ms: Some(300),
    };

    let value = serde_json::to_value(super::InstallStatusJson {
        status: &status,
        diagnostics,
    })
    .unwrap();

    assert_eq!(value["status"], "up_to_date");
    assert_eq!(value["target_path"], "/tmp/bin/update-all");
    assert_eq!(value["check_mode"], "source_fingerprint");
    assert_eq!(value["diagnostics"]["source_root"], "/tmp/src");
    assert_eq!(value["diagnostics"]["source_fingerprint"], "abc123");
    assert_eq!(
        value["diagnostics"]["expected_binary_source_fingerprint"],
        "abc123"
    );
    assert_eq!(
        value["diagnostics"]["target_binary_source_fingerprint"],
        "abc123"
    );
    assert_eq!(value["diagnostics"]["latest_source_mtime_unix_ms"], 100);
    assert_eq!(value["diagnostics"]["expected_binary_mtime_unix_ms"], 200);
    assert_eq!(value["diagnostics"]["target_binary_mtime_unix_ms"], 300);
}

#[test]
fn install_status_diagnostics_reports_binary_mtimes() {
    let temp = TempDir::new().unwrap();
    let install_dir = temp.path().join("bin");
    let release_dir = temp.path().join("dist").join("bin");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::create_dir_all(&release_dir).unwrap();
    let target = install_dir.join("update-all");
    let expected = release_dir.join("update-all");
    std::fs::write(&target, b"installed").unwrap();
    std::fs::write(&expected, b"release").unwrap();
    let status = super::InstallStatusReport {
        status: super::InstallStatusKind::StaleInstall,
        target_path: target,
        install_dir,
        configured_dir: None,
        effective_dir_source: "config".to_string(),
        expected_binary: expected,
        expected_kind: "source_dist".to_string(),
        check_mode: "source_fingerprint".to_string(),
        in_path: true,
        source_newer_than_expected: true,
    };

    let diagnostics = super::install_status_diagnostics(&status);

    assert!(diagnostics.expected_binary_mtime_unix_ms.is_some());
    assert!(diagnostics.target_binary_mtime_unix_ms.is_some());
}

fn run_summary_for_selection(run_id: &str, display_name: &str, task: &str) -> RunSummary {
    RunSummary {
        metadata: run_metadata_for_selection(run_id, display_name, task),
        path: PathBuf::from(format!("/tmp/{run_id}")),
        legacy: false,
        run_json_status: RunArtifactStatus::Loaded,
        task_count: 1,
        issue_count: 0,
        exit_code: Some(0),
        elapsed_ms: Some(100),
    }
}

fn run_metadata_for_selection(run_id: &str, display_name: &str, task: &str) -> RunMetadata {
    RunMetadata {
        schema_version: 1,
        run_id: run_id.to_string(),
        display_name: display_name.to_string(),
        created_unix_ms: 10,
        updated_unix_ms: 20,
        status: "completed".to_string(),
        run_dir: format!("/tmp/{run_id}"),
        pid: 1,
        host_os: Some("linux".to_string()),
        ui_mode: Some("plain".to_string()),
        engine_mode: Some("sync".to_string()),
        selected_tasks: vec![task.to_string()],
    }
}

fn toml_basic_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[test]
fn non_tty_rename_selection_rejects_ambiguous_fuzzy_matches() {
    let matches = vec![
        run_summary_for_selection("run-a", "daily services", "arch-update-services"),
        run_summary_for_selection("run-b", "weekly services", "arch-update-services"),
    ];

    let err = select_run_match_for_rename_with_tty(&matches, "services", false, false).unwrap_err();

    assert!(
        err.to_string()
            .contains("multiple update-all runs matched 'services'"),
        "{err}"
    );
}

#[test]
fn non_tty_rename_selection_accepts_one_exact_match_among_multiple_matches() {
    let matches = vec![
        run_summary_for_selection("run-a", "daily services", "arch-update-services"),
        run_summary_for_selection("run-b", "weekly services", "arch-update-services"),
    ];

    let selected = select_run_match_for_rename_with_tty(&matches, "run-b", false, false)
        .unwrap()
        .unwrap();

    assert_eq!(selected.metadata.run_id, "run-b");
}

#[test]
fn rename_command_rejects_ambiguous_non_tty_fuzzy_match() {
    let temp = TempDir::new().unwrap();
    let run_root = temp.path().join("runs");
    let first_run = run_root.join("run-a");
    let second_run = run_root.join("run-b");
    write_metadata_atomic(
        &first_run,
        &run_metadata_for_selection("run-a", "daily services", "arch-update-services"),
    )
    .unwrap();
    write_metadata_atomic(
        &second_run,
        &run_metadata_for_selection("run-b", "weekly services", "arch-update-services"),
    )
    .unwrap();
    let cfg_path = temp.path().join("config.toml");
    std::fs::write(
        &cfg_path,
        format!("[logging]\nrun_dir = \"{}\"\n", toml_basic_path(&run_root)),
    )
    .unwrap();

    let err = RenameCli {
        query: "services".to_string(),
        display_name: "renamed".to_string(),
    }
    .run(Some(cfg_path))
    .unwrap_err();

    assert!(
        err.to_string()
            .contains("multiple update-all runs matched 'services'"),
        "{err}"
    );
    let metadata: RunMetadata =
        serde_json::from_slice(&std::fs::read(first_run.join("run-meta.json")).unwrap()).unwrap();
    assert_eq!(metadata.display_name, "daily services");
}

#[test]
fn command_output_summary_includes_stdout_and_stderr() {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;

    let output = std::process::Output {
        #[cfg(unix)]
        status: std::process::ExitStatus::from_raw(1 << 8),
        #[cfg(windows)]
        status: std::process::ExitStatus::from_raw(1),
        stdout: b"built target\ninstaller path /tmp/update-all\n".to_vec(),
        stderr: b"warning: install failed\n".to_vec(),
    };

    let summary = super::command_output_summary(&output);

    assert!(summary.contains("stdout:"), "{summary}");
    assert!(summary.contains("built target"), "{summary}");
    assert!(
        summary.contains("installer path /tmp/update-all"),
        "{summary}"
    );
    assert!(summary.contains("stderr:"), "{summary}");
    assert!(summary.contains("warning: install failed"), "{summary}");
}

#[test]
fn aur_update_policy_parses_from_config() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("update-all.toml");
    std::fs::write(
        &cfg_path,
        r#"[tasks.aur_update]
timeout_secs = 7200
retries = 1
retry_backoff_secs = 30
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(Some(cfg_path)).unwrap();
    let policy = cfg.tasks.get("aur_update").expect("aur_update policy");

    assert_eq!(policy.timeout.as_secs(), 7200);
    assert_eq!(policy.retries, 1);
    assert_eq!(policy.retry_backoff.as_secs(), 30);
}

#[test]
fn install_check_mode_defaults_to_source_fingerprint_and_accepts_mtime() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("update-all.toml");
    std::fs::write(&cfg_path, "").unwrap();

    let cfg = load_runtime_config(Some(cfg_path.clone())).unwrap();
    assert_eq!(cfg.install.check_mode, InstallCheckMode::SourceFingerprint);

    std::fs::write(
        &cfg_path,
        r#"[install]
check_mode = "source_mtime"
"#,
    )
    .unwrap();
    let cfg = load_runtime_config(Some(cfg_path)).unwrap();
    assert_eq!(cfg.install.check_mode, InstallCheckMode::SourceMtime);
}

#[test]
fn runtime_config_rejects_invalid_completion_tool_entries() {
    let cases = [
        (
            "missing-name",
            r#"[[completions.tools]]
provider = "path"
"#,
            "completions.tools[0].name is required",
        ),
        (
            "empty-name",
            r#"[[completions.tools]]
name = ""
provider = "path"
"#,
            "completions.tools[0].name is required",
        ),
        (
            "missing-provider",
            r#"[[completions.tools]]
name = "privatebin"
"#,
            "completions.tools[0].provider is required",
        ),
        (
            "empty-provider",
            r#"[[completions.tools]]
name = "privatebin"
provider = ""
"#,
            "completions.tools[0].provider is required",
        ),
        (
            "unsupported-provider",
            r#"[[completions.tools]]
name = "privatebin"
provider = "gem"
"#,
            "invalid completions.tools[0].provider 'gem'",
        ),
    ];

    for (name, config, expected) in cases {
        let tmp = TempDir::new().unwrap();
        let cfg_path = tmp.path().join(format!("{name}.toml"));
        std::fs::write(&cfg_path, config).unwrap();

        let err = load_runtime_config(Some(cfg_path))
            .expect_err("runtime config should reject invalid completion tool entries")
            .to_string();
        assert!(err.contains(expected), "{name}: {err}");
    }
}

#[test]
fn runtime_config_accepts_and_normalizes_completion_tool_entries() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("completion-tool.toml");
    std::fs::write(
        &cfg_path,
        r#"[[completions.tools]]
name = "  privatebin  "
provider = "PATH"
enabled = false
managed_required = true
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(Some(cfg_path)).expect("runtime config");
    assert_eq!(cfg.completions.tools.len(), 1);
    let tool = &cfg.completions.tools[0];
    assert_eq!(tool.name, "privatebin");
    assert_eq!(tool.provider, "path");
    assert!(!tool.enabled);
    assert!(tool.managed_required);
}

#[test]
fn runtime_config_rejects_empty_custom_updater_list_entries() {
    let cases = [
        (
            "detect",
            "detect = [\"\"]",
            "invalid updaters.tasks.notes.detect entry ''; expected non-empty command name",
        ),
        (
            "requires-selected-any",
            "requires_selected_any = [\"\"]",
            "invalid updaters.tasks.notes.requires_selected_any entry ''; expected non-empty task selector",
        ),
        (
            "depends-on",
            "depends_on = [\"\"]",
            "invalid updaters.tasks.notes.depends_on entry ''; expected non-empty task selector",
        ),
        (
            "after",
            "after = [\"\"]",
            "invalid updaters.tasks.notes.after entry ''; expected non-empty task selector",
        ),
        (
            "success-details",
            "success_details = [\"\"]",
            "invalid updaters.tasks.notes.success_details entry ''; expected non-empty detail text",
        ),
        (
            "pre-command-args",
            "[[updaters.tasks.notes.pre_commands]]\nprogram = \"notes-sync\"\nargs = [\"\"]",
            "invalid updaters.tasks.notes.pre_commands[0].args entry ''; expected non-empty value",
        ),
    ];

    for (name, custom_field, expected) in cases {
        let tmp = TempDir::new().unwrap();
        let cfg_path = tmp.path().join(format!("{name}.toml"));
        std::fs::write(
            &cfg_path,
            format!(
                r#"[updaters.tasks.notes]
label = "Notes Sync"
command = "notes-sync"
{custom_field}
"#
            ),
        )
        .unwrap();

        let err = load_runtime_config(Some(cfg_path))
            .expect_err("runtime config should reject empty custom updater values")
            .to_string();
        assert!(err.contains(expected), "{name}: {err}");
    }
}

#[test]
fn runtime_config_rejects_unknown_custom_updater_after_reference() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("unknown-after.toml");
    std::fs::write(
        &cfg_path,
        r#"[updaters.tasks.notes]
command = "notes-sync"
after = ["missing-updater"]
"#,
    )
    .unwrap();

    let err = load_runtime_config(Some(cfg_path))
        .expect_err("runtime config should reject an unknown ordering reference")
        .to_string();
    assert!(
        err.contains("updaters.tasks.notes.after")
            && err.contains("unknown task selector 'missing-updater'"),
        "{err}"
    );
}

#[test]
fn runtime_config_rejects_invalid_custom_updater_shape() {
    let cases = [
        (
            "empty-label",
            "label = \"\"",
            "invalid updaters.tasks.notes.label ''; expected non-empty label",
        ),
        (
            "empty-category",
            "category = \"\"",
            "invalid updaters.tasks.notes.category ''; expected non-empty category",
        ),
        (
            "empty-policy-key",
            "policy_key = \"\"",
            "invalid updaters.tasks.notes.policy_key ''; expected non-empty task policy key",
        ),
        (
            "empty-os",
            "os = []",
            "invalid updaters.tasks.notes.os; expected at least one OS",
        ),
        (
            "unknown-os",
            "os = [\"linx\"]",
            "invalid updaters.tasks.notes.os entry 'linx'; expected linux|macos|windows",
        ),
    ];

    for (name, custom_field, expected) in cases {
        let tmp = TempDir::new().unwrap();
        let cfg_path = tmp.path().join(format!("{name}.toml"));
        std::fs::write(
            &cfg_path,
            format!(
                r#"[updaters.tasks.notes]
command = "notes-sync"
{custom_field}
"#
            ),
        )
        .unwrap();

        let err = load_runtime_config(Some(cfg_path))
            .expect_err("runtime config should reject invalid custom updater shape")
            .to_string();
        assert!(err.contains(expected), "{name}: {err}");
    }
}

#[test]
fn runtime_config_rejects_program_specific_custom_report_parsers() {
    for parser in ["pipx", "cargo", "go", "rustup"] {
        let tmp = TempDir::new().unwrap();
        let cfg_path = tmp.path().join(format!("custom-{parser}-parser.toml"));
        std::fs::write(
            &cfg_path,
            format!(
                r#"[updaters.tasks.wrapper]
label = "Wrapper"
command = "wrapper"
args = ["upgrade-all"]
report_parser = "{parser}"
"#
            ),
        )
        .unwrap();

        let err = load_runtime_config(Some(cfg_path)).unwrap_err().to_string();
        assert!(
            err.contains(&format!(
                "invalid updaters.tasks.wrapper.report_parser '{parser}'"
            )),
            "{parser}: {err}"
        );
        assert!(
            !err.contains(&format!("expected one of: {parser}")),
            "{parser}: {err}"
        );
    }
}

#[test]
fn runtime_config_accepts_custom_pre_commands() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("custom-pre-command.toml");
    std::fs::write(
        &cfg_path,
        r#"[updaters.tasks.notes]
label = "Notes Sync"
command = "notes-sync"
args = ["sync"]

[[updaters.tasks.notes.pre_commands]]
program = "notes-sync"
args = ["refresh-index"]
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(Some(cfg_path)).expect("runtime config");
    let task = cfg.updaters.custom_tasks.get("notes").expect("custom task");
    assert_eq!(task.pre_commands.len(), 1);
    assert_eq!(task.pre_commands[0].program, "notes-sync");
    assert_eq!(task.pre_commands[0].args, vec!["refresh-index".to_string()]);
}

#[test]
fn runtime_config_loads_external_updater_catalog_relative_to_config() {
    let tmp = TempDir::new().unwrap();
    let cfg_dir = tmp.path().join("config");
    let catalog_dir = cfg_dir.join("catalogs");
    std::fs::create_dir_all(&catalog_dir).unwrap();
    let cfg_path = cfg_dir.join("update-all.toml");
    let catalog_path = catalog_dir.join("updaters.toml");
    std::fs::write(
        &cfg_path,
        r#"[updaters]
catalogs = ["catalogs/updaters.toml"]
"#,
    )
    .unwrap();
    std::fs::write(
        &catalog_path,
        r#"[tasks.notes]
label = "Notes Sync"
command = "notes-sync"
args = ["sync"]
report_parser = "version_lines"
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(Some(cfg_path)).expect("runtime config");
    let task = cfg.updaters.custom_tasks.get("notes").expect("notes task");

    assert_eq!(task.label, "Notes Sync");
    assert_eq!(task.command, "notes-sync");
    assert_eq!(task.args, vec!["sync".to_string()]);
    assert_eq!(task.report_parser, Some(BuiltinReportParser::VersionLines));
}

#[test]
fn runtime_config_discovers_managed_and_local_catalog_directories() {
    let tmp = TempDir::new().unwrap();
    let cfg_dir = tmp.path().join("update-all");
    let managed_dir = cfg_dir.join("catalog.d/syscfg");
    let local_dir = cfg_dir.join("catalog.d/local");
    std::fs::create_dir_all(&managed_dir).unwrap();
    std::fs::create_dir_all(&local_dir).unwrap();
    let cfg_path = cfg_dir.join("config.toml");
    std::fs::write(&cfg_path, "[updaters]\nrun_all_detected = true\n").unwrap();
    std::fs::write(
        managed_dir.join("desktop.toml"),
        r#"[tasks."syscfg/desktop"]
label = "Desktop"
command = "desktop-refresh"
"#,
    )
    .unwrap();
    std::fs::write(
        local_dir.join("notes.toml"),
        r#"[tasks."local/notes"]
label = "Notes"
command = "notes-sync"
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(Some(cfg_path)).expect("runtime config");
    assert!(cfg.updaters.custom_tasks.contains_key("syscfg/desktop"));
    assert!(cfg.updaters.custom_tasks.contains_key("local/notes"));
}

#[test]
fn runtime_config_accepts_updaters_task_shape_in_external_catalog() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("update-all.toml");
    let catalog_path = tmp.path().join("updaters.toml");
    std::fs::write(
        &cfg_path,
        r#"[updaters]
catalogs = ["updaters.toml"]
"#,
    )
    .unwrap();
    std::fs::write(
        &catalog_path,
        r#"[updaters.tasks.notes]
label = "Notes Sync"
command = "notes-sync"
"#,
    )
    .unwrap();

    let cfg = load_runtime_config(Some(cfg_path)).expect("runtime config");
    assert!(cfg.updaters.custom_tasks.contains_key("notes"));
}

#[test]
fn runtime_config_rejects_duplicate_external_updater_task_ids() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("update-all.toml");
    let catalog_path = tmp.path().join("updaters.toml");
    std::fs::write(
        &cfg_path,
        r#"[updaters]
catalogs = ["updaters.toml"]

[updaters.tasks.notes]
label = "Inline Notes"
command = "notes-sync"
"#,
    )
    .unwrap();
    std::fs::write(
        &catalog_path,
        r#"[tasks.notes]
label = "Catalog Notes"
command = "notes-sync"
"#,
    )
    .unwrap();

    let err = load_runtime_config(Some(cfg_path))
        .expect_err("runtime config should reject duplicate external catalog task ids")
        .to_string();
    assert!(err.contains("duplicate updater task id 'notes'"), "{err}");
    assert!(err.contains("already defined in updater catalog"), "{err}");
}

#[test]
fn validate_config_rejects_missing_external_updater_catalog() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("update-all.toml");
    std::fs::write(
        &cfg_path,
        r#"[updaters]
catalogs = ["missing.toml"]
"#,
    )
    .unwrap();

    let err = match validate_config(Some(cfg_path), true) {
        Ok(_) => panic!("validation should reject missing updater catalog"),
        Err(err) => err.to_string(),
    };
    assert!(err.contains("read updater catalog"), "{err}");
    assert!(err.contains("missing.toml"), "{err}");
}

#[test]
fn runtime_config_external_catalog_task_errors_include_source_path() {
    let tmp = TempDir::new().unwrap();
    let cfg_path = tmp.path().join("update-all.toml");
    let catalog_path = tmp.path().join("updaters.toml");
    std::fs::write(
        &cfg_path,
        r#"[updaters]
catalogs = ["updaters.toml"]
"#,
    )
    .unwrap();
    std::fs::write(
        &catalog_path,
        r#"[tasks.notes]
label = "Notes Sync"
"#,
    )
    .unwrap();

    let err = load_runtime_config(Some(cfg_path))
        .expect_err("runtime config should reject invalid external catalog task")
        .to_string();
    assert!(
        err.contains("validate updater task 'notes' from updater catalog"),
        "{err}"
    );
    assert!(err.contains("updaters.toml"), "{err}");
    assert!(
        err.contains("updaters.tasks.notes.command is required"),
        "{err}"
    );
}

#[test]
fn runtime_config_rejects_invalid_custom_updater_identity() {
    let cases = [
        (
            "empty-id",
            r#"[updaters.tasks.""]
command = "notes-sync"
"#,
            "invalid updaters.tasks task id ''; expected non-empty task id",
        ),
        (
            "empty-command",
            r#"[updaters.tasks.notes]
command = ""
"#,
            "invalid updaters.tasks.notes.command ''; expected non-empty command name",
        ),
    ];

    for (name, config, expected) in cases {
        let tmp = TempDir::new().unwrap();
        let cfg_path = tmp.path().join(format!("{name}.toml"));
        std::fs::write(&cfg_path, config).unwrap();

        let err = load_runtime_config(Some(cfg_path))
            .expect_err("runtime config should reject invalid custom updater identity")
            .to_string();
        assert!(err.contains(expected), "{name}: {err}");
    }
}

#[test]
fn runtime_config_rejects_invalid_core_config_values() {
    let cases = [
        (
            "ui-mode",
            r#"[ui]
mode = "fancy"
"#,
            "invalid ui.mode 'fancy'; expected auto|plain|dashboard",
        ),
        (
            "engine-mode",
            r#"[engine]
mode = "parallel"
"#,
            "invalid engine.mode 'parallel'; expected sync|async",
        ),
        (
            "dashboard-quit-behavior",
            r#"[ui.dashboard]
quit_behavior = "sleep"
"#,
            "invalid ui.dashboard.quit_behavior 'sleep'; expected cancel_all|detach",
        ),
        (
            "dashboard-quit-grace",
            r#"[ui.dashboard]
quit_cancel_grace_ms = 100
"#,
            "invalid ui.dashboard.quit_cancel_grace_ms '100'; expected >= 500",
        ),
        (
            "dashboard-mouse-row-stride",
            r#"[ui.dashboard]
mouse_row_stride = "three"
"#,
            "invalid ui.dashboard.mouse_row_stride 'three'; expected auto|1|2",
        ),
        (
            "dashboard-note-verbosity",
            r#"[ui.dashboard]
note_verbosity = "chatty"
"#,
            "invalid ui.dashboard.note_verbosity 'chatty'; expected failures|all|none",
        ),
        (
            "runtime-interactive-mode",
            r#"[runtime.interactive]
mode = "pty"
"#,
            "invalid runtime.interactive.mode 'pty'; expected auto_fallback|capture|direct_tty",
        ),
        (
            "runtime-stall",
            r#"[runtime.interactive]
stall_seconds = 0
"#,
            "invalid runtime.interactive.stall_seconds '0'; expected >= 1",
        ),
        (
            "runtime-max-line",
            r#"[runtime.interactive]
max_line_bytes = 1024
"#,
            "invalid runtime.interactive.max_line_bytes '1024'; expected >= 4096",
        ),
        (
            "runtime-max-capture",
            r#"[runtime.interactive]
max_line_bytes = 8192
max_capture_bytes = 4096
"#,
            "invalid runtime.interactive.max_capture_bytes '4096'; expected >= max_line_bytes (8192)",
        ),
        (
            "install-check-mode",
            r#"[install]
check_mode = "always"
"#,
            "invalid install.check_mode 'always'; expected source_fingerprint|source_mtime",
        ),
        (
            "install-dir",
            r#"[install]
dir = ""
"#,
            "invalid install.dir ''; expected non-empty path",
        ),
        (
            "privilege-mode",
            r#"[updaters]
privilege_mode = "admin"
"#,
            "invalid updaters.privilege_mode 'admin'; expected skip|prompt_tty|fail",
        ),
    ];

    for (name, config, expected) in cases {
        let tmp = TempDir::new().unwrap();
        let cfg_path = tmp.path().join(format!("{name}.toml"));
        std::fs::write(&cfg_path, config).unwrap();

        let err = load_runtime_config(Some(cfg_path))
            .expect_err("runtime config should reject invalid core config values")
            .to_string();
        assert!(err.contains(expected), "{name}: {err}");
    }
}

#[test]
fn aur_update_policy_defaults_to_three_hours_when_omitted() {
    let cfg = runtime_config_with_tasks(BTreeMap::new());
    let policies = super::resolve_task_policies(&cfg);

    assert_eq!(policies.aur_update.timeout.as_secs(), 10800);
    assert_eq!(policies.aur_update.retries, 0);
    assert_eq!(policies.aur_update.retry_backoff.as_secs(), 0);
    assert_eq!(policies.system_update.timeout.as_secs(), 3600);
}

#[test]
fn aur_update_policy_uses_configured_runtime_policy() {
    let mut tasks = BTreeMap::new();
    tasks.insert("aur_update".to_string(), TaskPolicy::new(7200, 1, 30));
    let cfg = runtime_config_with_tasks(tasks);
    let policies = super::resolve_task_policies(&cfg);

    assert_eq!(policies.aur_update.timeout.as_secs(), 7200);
    assert_eq!(policies.aur_update.retries, 1);
    assert_eq!(policies.aur_update.retry_backoff.as_secs(), 30);
}

#[test]
fn tool_update_policy_uses_generic_key_without_legacy_alias() {
    let mut legacy_tasks = BTreeMap::new();
    legacy_tasks.insert("skills_update".to_string(), TaskPolicy::new(450, 1, 5));
    let legacy_cfg = runtime_config_with_tasks(legacy_tasks);
    let legacy_policies = super::resolve_task_policies(&legacy_cfg);
    assert_eq!(legacy_policies.tool_update.timeout.as_secs(), 600);
    assert_eq!(
        legacy_policies
            .by_key("skills_update", TaskPolicy::new(1, 0, 0))
            .timeout
            .as_secs(),
        450
    );

    let mut generic_tasks = BTreeMap::new();
    generic_tasks.insert("skills_update".to_string(), TaskPolicy::new(450, 1, 5));
    generic_tasks.insert("tool_update".to_string(), TaskPolicy::new(300, 2, 10));
    let generic_cfg = runtime_config_with_tasks(generic_tasks);
    let generic_policies = super::resolve_task_policies(&generic_cfg);
    assert_eq!(generic_policies.tool_update.timeout.as_secs(), 300);
    assert_eq!(generic_policies.tool_update.retries, 2);
    assert_eq!(generic_policies.tool_update.retry_backoff.as_secs(), 10);
}

#[test]
fn temp_install_dirs_are_treated_as_ephemeral() {
    let temp_bin = std::env::temp_dir()
        .join("update-all-test-ephemeral")
        .join("bin");
    assert!(install_dir_is_ephemeral(&temp_bin));
}

#[test]
#[cfg(not(windows))]
fn home_local_bin_is_not_treated_as_ephemeral_even_under_temp_home() {
    let _guard = env_guard();
    let old_home = std::env::var_os("HOME");
    let home = std::env::temp_dir().join("update-all-home-test");
    std::fs::create_dir_all(home.join(".local/bin")).unwrap();
    std::env::set_var("HOME", &home);

    let result = install_dir_is_ephemeral(&home.join(".local/bin"));

    if let Some(value) = old_home {
        std::env::set_var("HOME", value);
    } else {
        std::env::remove_var("HOME");
    }

    assert!(!result);
}

#[test]
#[cfg(not(windows))]
fn resolve_install_dir_ignores_ephemeral_config_dir_and_prefers_home_local_bin() {
    let _guard = env_guard();
    let old_home = std::env::var_os("HOME");
    let old_path = std::env::var_os("PATH");
    let old_install = std::env::var_os("UPDATE_ALL_INSTALL_DIR");
    let home = std::env::temp_dir().join("update-all-resolve-install-home");
    let stable_dir = home.join(".local/bin");
    let ephemeral_dir = std::env::temp_dir()
        .join("update-all-ephemeral-config")
        .join("bin");
    std::fs::create_dir_all(&stable_dir).unwrap();
    std::fs::create_dir_all(&ephemeral_dir).unwrap();
    std::env::set_var("HOME", &home);
    std::env::set_var("PATH", stable_dir.as_os_str());
    std::env::remove_var("UPDATE_ALL_INSTALL_DIR");

    let cfg = RuntimeConfig {
        ui: UiConfig {
            mode: UiMode::Dashboard,
            persist_until_exit: true,
            show_global_log: true,
            max_events_per_frame: 120,
            dashboard_quit_behavior: DashboardQuitBehavior::CancelAll,
            quit_cancel_grace_ms: 3000,
            mouse_row_stride: crate::config::MouseRowStrideMode::Auto,
            note_verbosity: crate::config::NoteVerbosity::Failures,
        },
        engine: EngineConfig {
            mode: super::EngineMode::Async,
            jobs: "auto".to_string(),
            fail_fast: false,
        },
        install: InstallConfig {
            dir: Some(ephemeral_dir),
            auto_update: true,
            check_mode: InstallCheckMode::SourceFingerprint,
        },
        interactive: InteractiveRuntimeConfig {
            mode: InteractiveExecutionMode::AutoFallback,
            stall_seconds: 20,
            max_line_bytes: 262_144,
            max_capture_bytes: 16_777_216,
            retry_once: true,
        },
        logging: LoggingConfig {
            run_dir: home.join(".local/state/update-all/runs"),
            max_in_memory_lines: 20_000,
            filter_progress_noise: false,
            timestamps: true,
            task_colors: true,
        },
        tasks: BTreeMap::new(),
        updaters: UpdaterConfig {
            run_all_detected: true,
            include: BTreeSet::new(),
            exclude: BTreeSet::new(),
            privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
            custom_tasks: BTreeMap::new(),
            bootstrap: BootstrapConfig {
                enabled: false,
                windows_foundations: Vec::new(),
            },
        },
        completions: CompletionConfig { tools: Vec::new() },
        source_path: None,
    };

    let resolved = super::resolve_install_dir(Some(&cfg), None).unwrap();

    if let Some(value) = old_home {
        std::env::set_var("HOME", value);
    } else {
        std::env::remove_var("HOME");
    }
    if let Some(value) = old_path {
        std::env::set_var("PATH", value);
    } else {
        std::env::remove_var("PATH");
    }
    if let Some(value) = old_install {
        std::env::set_var("UPDATE_ALL_INSTALL_DIR", value);
    } else {
        std::env::remove_var("UPDATE_ALL_INSTALL_DIR");
    }

    assert_eq!(resolved.dir, stable_dir);
}

#[cfg(windows)]
#[test]
fn windows_profile_local_bin_is_not_treated_as_ephemeral_even_under_temp_profile() {
    let _guard = env_guard();
    let old_profile = std::env::var_os("USERPROFILE");
    let profile = std::env::temp_dir().join("update-all-userprofile-test");
    std::fs::create_dir_all(profile.join(".local/bin")).unwrap();
    std::env::set_var("USERPROFILE", &profile);

    let result = install_dir_is_ephemeral(&profile.join(".local/bin"));

    if let Some(value) = old_profile {
        std::env::set_var("USERPROFILE", value);
    } else {
        std::env::remove_var("USERPROFILE");
    }

    assert!(!result);
}

#[cfg(windows)]
#[test]
fn windows_resolve_install_dir_ignores_ephemeral_config_dir_and_prefers_profile_local_bin() {
    let _guard = env_guard();
    let old_profile = std::env::var_os("USERPROFILE");
    let old_path = std::env::var_os("PATH");
    let old_install = std::env::var_os("UPDATE_ALL_INSTALL_DIR");
    let profile = std::env::temp_dir().join("update-all-resolve-install-userprofile");
    let stable_dir = profile.join(".local/bin");
    let ephemeral_dir = std::env::temp_dir()
        .join("update-all-ephemeral-config")
        .join("bin");
    std::fs::create_dir_all(&stable_dir).unwrap();
    std::fs::create_dir_all(&ephemeral_dir).unwrap();
    std::env::set_var("USERPROFILE", &profile);
    std::env::set_var("PATH", stable_dir.as_os_str());
    std::env::remove_var("UPDATE_ALL_INSTALL_DIR");

    let cfg = RuntimeConfig {
        ui: UiConfig {
            mode: UiMode::Dashboard,
            persist_until_exit: true,
            show_global_log: true,
            max_events_per_frame: 120,
            dashboard_quit_behavior: DashboardQuitBehavior::CancelAll,
            quit_cancel_grace_ms: 3000,
            mouse_row_stride: crate::config::MouseRowStrideMode::Auto,
            note_verbosity: crate::config::NoteVerbosity::Failures,
        },
        engine: EngineConfig {
            mode: super::EngineMode::Async,
            jobs: "auto".to_string(),
            fail_fast: false,
        },
        install: InstallConfig {
            dir: Some(ephemeral_dir),
            auto_update: true,
            check_mode: InstallCheckMode::SourceFingerprint,
        },
        interactive: InteractiveRuntimeConfig {
            mode: InteractiveExecutionMode::AutoFallback,
            stall_seconds: 20,
            max_line_bytes: 262_144,
            max_capture_bytes: 16_777_216,
            retry_once: true,
        },
        logging: LoggingConfig {
            run_dir: profile.join("AppData/Roaming/update-all/runs"),
            max_in_memory_lines: 20_000,
            filter_progress_noise: false,
            timestamps: true,
            task_colors: true,
        },
        tasks: BTreeMap::new(),
        updaters: UpdaterConfig {
            run_all_detected: true,
            include: BTreeSet::new(),
            exclude: BTreeSet::new(),
            privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
            custom_tasks: BTreeMap::new(),
            bootstrap: BootstrapConfig {
                enabled: false,
                windows_foundations: Vec::new(),
            },
        },
        completions: CompletionConfig { tools: Vec::new() },
        source_path: None,
    };

    let resolved = super::resolve_install_dir(Some(&cfg), None).unwrap();

    if let Some(value) = old_profile {
        std::env::set_var("USERPROFILE", value);
    } else {
        std::env::remove_var("USERPROFILE");
    }
    if let Some(value) = old_path {
        std::env::set_var("PATH", value);
    } else {
        std::env::remove_var("PATH");
    }
    if let Some(value) = old_install {
        std::env::set_var("UPDATE_ALL_INSTALL_DIR", value);
    } else {
        std::env::remove_var("UPDATE_ALL_INSTALL_DIR");
    }

    assert_eq!(resolved.dir, stable_dir);
}

#[cfg(windows)]
#[test]
fn windows_resolve_install_dir_skips_current_exe_dir_in_path_candidates() {
    let _guard = env_guard();
    let old_profile = std::env::var_os("USERPROFILE");
    let old_path = std::env::var_os("PATH");
    let profile = std::env::temp_dir().join("update-all-resolve-install-current-exe");
    let stable_dir = profile.join(".local/bin");
    let current_exe_dir = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .expect("current exe dir");
    std::fs::create_dir_all(&stable_dir).unwrap();
    std::env::set_var("USERPROFILE", &profile);
    std::env::set_var("PATH", &current_exe_dir);
    std::env::remove_var("UPDATE_ALL_INSTALL_DIR");

    let cfg = RuntimeConfig {
        ui: UiConfig {
            mode: UiMode::Dashboard,
            persist_until_exit: true,
            show_global_log: true,
            max_events_per_frame: 120,
            dashboard_quit_behavior: DashboardQuitBehavior::CancelAll,
            quit_cancel_grace_ms: 3000,
            mouse_row_stride: crate::config::MouseRowStrideMode::Auto,
            note_verbosity: crate::config::NoteVerbosity::Failures,
        },
        engine: EngineConfig {
            mode: super::EngineMode::Async,
            jobs: "auto".to_string(),
            fail_fast: false,
        },
        install: InstallConfig {
            dir: None,
            auto_update: true,
            check_mode: InstallCheckMode::SourceFingerprint,
        },
        interactive: InteractiveRuntimeConfig {
            mode: InteractiveExecutionMode::AutoFallback,
            stall_seconds: 20,
            max_line_bytes: 262_144,
            max_capture_bytes: 16_777_216,
            retry_once: true,
        },
        logging: LoggingConfig {
            run_dir: profile.join("AppData/Roaming/update-all/runs"),
            max_in_memory_lines: 20_000,
            filter_progress_noise: false,
            timestamps: true,
            task_colors: true,
        },
        tasks: BTreeMap::new(),
        updaters: UpdaterConfig {
            run_all_detected: true,
            include: BTreeSet::new(),
            exclude: BTreeSet::new(),
            privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
            custom_tasks: BTreeMap::new(),
            bootstrap: BootstrapConfig {
                enabled: false,
                windows_foundations: Vec::new(),
            },
        },
        completions: CompletionConfig { tools: Vec::new() },
        source_path: None,
    };

    let resolved = super::resolve_install_dir(Some(&cfg), None).unwrap();

    if let Some(value) = old_profile {
        std::env::set_var("USERPROFILE", value);
    } else {
        std::env::remove_var("USERPROFILE");
    }
    if let Some(value) = old_path {
        std::env::set_var("PATH", value);
    } else {
        std::env::remove_var("PATH");
    }

    assert_eq!(resolved.dir, stable_dir);
}

#[test]
fn run_cli_parses_debug_report_flag() {
    let cli = RunCli::parse_from(["update-all", "--debug-report"]);
    assert!(cli.debug_report);
}

#[test]
fn auto_update_lock_blocks_when_owner_is_active() {
    let temp = TempDir::new().unwrap();
    let lock_path = temp.path().join(".update-all-self-update.lock");
    std::fs::write(
        &lock_path,
        format!("pid={}\ncreated_unix_ms=1\n", std::process::id()),
    )
    .unwrap();

    let err = match super::try_acquire_auto_update_lock(temp.path()) {
        Ok(lock) => {
            drop(lock);
            panic!("active lock should block acquisition")
        }
        Err(err) => err,
    };

    assert!(
        err.to_string().contains("auto-update lock is held"),
        "{err:#}"
    );
    assert!(lock_path.is_file());
}

#[cfg(target_os = "linux")]
#[test]
fn auto_update_lock_reclaims_dead_owner() {
    let temp = TempDir::new().unwrap();
    let lock_path = temp.path().join(".update-all-self-update.lock");
    std::fs::write(&lock_path, "pid=999999999\ncreated_unix_ms=1\n").unwrap();

    let lock = super::try_acquire_auto_update_lock(temp.path()).unwrap();
    let payload = std::fs::read_to_string(&lock_path).unwrap();

    assert!(payload.contains(&format!("pid={}", std::process::id())));
    assert!(payload.contains("created_unix_ms="));
    drop(lock);
    assert!(!lock_path.exists());
}

#[test]
fn auto_update_lock_reclaims_old_incomplete_payload() {
    let temp = TempDir::new().unwrap();
    let lock_path = temp.path().join(".update-all-self-update.lock");
    let old_created = super::now_unix_ms() - u128::from(7 * 60 * 60 * 1000_u64);
    std::fs::write(&lock_path, format!("created_unix_ms={old_created}\n")).unwrap();

    let lock = super::try_acquire_auto_update_lock(temp.path()).unwrap();
    let payload = std::fs::read_to_string(&lock_path).unwrap();

    assert!(payload.contains(&format!("pid={}", std::process::id())));
    assert!(payload.contains("created_unix_ms="));
    drop(lock);
    assert!(!lock_path.exists());
}

#[test]
fn auto_update_lock_reclaims_old_pid_payload_when_liveness_is_not_authoritative() {
    let temp = TempDir::new().unwrap();
    let lock_path = temp.path().join(".update-all-self-update.lock");
    let old_created = super::now_unix_ms() - u128::from(7 * 60 * 60 * 1000_u64);
    std::fs::write(
        &lock_path,
        format!("pid=42\ncreated_unix_ms={old_created}\n"),
    )
    .unwrap();

    assert!(super::remove_stale_auto_update_lock_with_probe(
        &lock_path,
        false,
        |_| true
    ));
    assert!(!lock_path.exists());
}

#[cfg(windows)]
#[test]
fn windows_locked_rebuild_skips_when_paths_match() {
    use super::should_skip_windows_locked_rebuild;
    let exe = Path::new(r"C:\Users\me\update-all.exe");
    assert!(should_skip_windows_locked_rebuild(exe, exe));
}

#[cfg(windows)]
#[test]
fn windows_preferred_install_dirs_use_profile_local_bin_only() {
    use super::preferred_install_dirs;

    let old_profile = std::env::var_os("USERPROFILE");
    let profile = std::env::temp_dir().join("update-all-userprofile-test");
    std::env::set_var("USERPROFILE", &profile);

    let dirs = preferred_install_dirs();
    assert_eq!(dirs.first(), Some(&profile.join(".local").join("bin")));
    assert_eq!(dirs.len(), 1);

    if let Some(value) = old_profile {
        std::env::set_var("USERPROFILE", value);
    } else {
        std::env::remove_var("USERPROFILE");
    }
}

#[cfg(windows)]
#[test]
fn windows_default_run_root_prefers_appdata_over_home() {
    let _guard = env_guard();
    let old_appdata = std::env::var_os("APPDATA");
    let old_home = std::env::var_os("HOME");
    let old_xdg = std::env::var_os("XDG_STATE_HOME");
    let appdata = std::env::temp_dir().join("update-all-appdata-test");
    let home = std::env::temp_dir().join("update-all-home-test");
    let xdg = std::env::temp_dir().join("update-all-xdg-test");

    std::env::set_var("APPDATA", &appdata);
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_STATE_HOME", &xdg);

    let root = default_run_root();

    if let Some(value) = old_appdata {
        std::env::set_var("APPDATA", value);
    } else {
        std::env::remove_var("APPDATA");
    }
    if let Some(value) = old_home {
        std::env::set_var("HOME", value);
    } else {
        std::env::remove_var("HOME");
    }
    if let Some(value) = old_xdg {
        std::env::set_var("XDG_STATE_HOME", value);
    } else {
        std::env::remove_var("XDG_STATE_HOME");
    }

    assert_eq!(root, appdata.join("update-all").join("runs"));
}

#[cfg(windows)]
#[test]
fn windows_config_path_prefers_appdata_over_home_and_xdg() {
    let _guard = env_guard();
    let old_appdata = std::env::var_os("APPDATA");
    let old_home = std::env::var_os("HOME");
    let old_xdg = std::env::var_os("XDG_CONFIG_HOME");
    let appdata = std::env::temp_dir().join("update-all-config-appdata-test");
    let home = std::env::temp_dir().join("update-all-config-home-test");
    let xdg = std::env::temp_dir().join("update-all-config-xdg-test");
    let app_cfg = appdata.join("update-all").join("config.toml");
    std::fs::create_dir_all(app_cfg.parent().unwrap()).unwrap();
    std::fs::write(&app_cfg, "[ui]\nmode = \"plain\"\n").unwrap();
    std::env::set_var("APPDATA", &appdata);
    std::env::set_var("HOME", &home);
    std::env::set_var("XDG_CONFIG_HOME", &xdg);

    let resolved = resolve_config_path(None).unwrap();
    let write_path = resolve_config_write_path(None).unwrap();

    if let Some(value) = old_appdata {
        std::env::set_var("APPDATA", value);
    } else {
        std::env::remove_var("APPDATA");
    }
    if let Some(value) = old_home {
        std::env::set_var("HOME", value);
    } else {
        std::env::remove_var("HOME");
    }
    if let Some(value) = old_xdg {
        std::env::set_var("XDG_CONFIG_HOME", value);
    } else {
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    assert_eq!(resolved, Some(app_cfg.clone()));
    assert_eq!(write_path, app_cfg);
}
