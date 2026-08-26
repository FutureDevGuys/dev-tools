use super::*;
use crate::completions::CompletionSyncRecordStatus;
use crate::config::{BootstrapConfig, UpdaterDetectionMode, UpdaterTaskConfig};
use crate::logging::RunLogSink;
use crate::test_support::{env_guard, write_executable as write_executable_atomic};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use unicode_width::UnicodeWidthStr;

fn write_executable(path: &Path, content: &str) {
    write_executable_atomic(path, content).unwrap();
}

#[test]
fn external_catalog_runtime_tokens_expand_without_a_source_checkout() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let original_home = std::env::var_os("HOME");
    let original_xdg_config_home = std::env::var_os("XDG_CONFIG_HOME");
    std::env::set_var("HOME", temp.path());
    std::env::remove_var("XDG_CONFIG_HOME");

    let expanded = expand_runtime_tokens(
        "{user_libexec}/syscfg/tool --config {config_home}/syscfg/tool.toml".to_string(),
        HostOs::Linux,
    );

    match original_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
    match original_xdg_config_home {
        Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
    assert_eq!(
        expanded,
        format!(
            "{}/.local/libexec/syscfg/tool --config {}/.config/syscfg/tool.toml",
            temp.path().display(),
            temp.path().display()
        )
    );
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if path.is_file() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {}", path.display());
}

#[test]
fn expand_alias_ids_maps_winget_to_scope_tasks() {
    let mut input = BTreeSet::new();
    input.insert("winget".to_string());
    input.insert("rust".to_string());
    input.insert("builtin/pipx".to_string());

    let expanded = expand_alias_ids(&input);
    assert!(expanded.contains("builtin/winget-user"));
    assert!(expanded.contains("builtin/winget-machine"));
    assert!(expanded.contains("builtin/rustup"));
    assert!(expanded.contains("builtin/cargo"));
    assert!(expanded.contains("builtin/pipx"));
    assert!(!expanded.contains("winget"));
    assert!(!expanded.contains("rust"));
}

#[test]
fn build_task_specs_accepts_rust_only_alias() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("rustup"), "#!/bin/sh\nexit 0\n");
    write_executable(
        &temp.path().join("cargo-install-update"),
        "#!/bin/sh\nexit 0\n",
    );
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());

    let updater_config = UpdaterConfig {
        run_all_detected: false,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from(["rust".to_string()])),
    };

    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let ids: BTreeSet<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(ids, BTreeSet::from(["builtin/cargo", "builtin/rustup"]));
    let cargo = specs
        .iter()
        .find(|spec| spec.id == "builtin/cargo")
        .expect("cargo spec");
    assert_eq!(cargo.depends_on, vec!["builtin/rustup".to_string()]);
    let order: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert!(
        order
            .iter()
            .position(|id| *id == "builtin/rustup")
            .unwrap()
            < order
                .iter()
                .position(|id| *id == "builtin/cargo")
                .unwrap(),
        "rustup should complete before cargo install-update when both rust tasks are selected: {order:?}"
    );
}

#[test]
fn build_task_specs_allows_config_exclude_to_prune_direct_only_selector_without_unknown_error() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("gup"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("go"), "#!/bin/sh\nexit 0\n");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());

    let updater_config = UpdaterConfig {
        run_all_detected: false,
        include: BTreeSet::new(),
        exclude: BTreeSet::from(["builtin/go".to_string()]),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from(["builtin/go".to_string()])),
    };

    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert!(
        ids.is_empty(),
        "excluded direct selector should prune the task without becoming unknown: {ids:?}"
    );
}

#[test]
fn build_task_specs_allows_config_exclude_to_prune_only_alias_without_unknown_error() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("rustup"), "#!/bin/sh\nexit 0\n");
    write_executable(
        &temp.path().join("cargo-install-update"),
        "#!/bin/sh\nexit 0\n",
    );
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());

    let updater_config = UpdaterConfig {
        run_all_detected: false,
        include: BTreeSet::new(),
        exclude: BTreeSet::from(["rust".to_string()]),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from(["rust".to_string()])),
    };

    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert!(
        ids.is_empty(),
        "excluded alias selector should prune expanded tasks without becoming unknown: {ids:?}"
    );
}

#[test]
fn custom_task_windows_detection_gates_are_windows_only() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    write_executable(
        &temp.path().join("primary.cmd"),
        "@echo off\r\nexit /b 0\r\n",
    );
    write_executable(
        &temp.path().join("shadow.cmd"),
        "@echo off\r\nexit /b 0\r\n",
    );

    let original_path = std::env::var_os("PATH");
    let original_pathext = std::env::var_os("PATHEXT");
    std::env::set_var("PATH", temp.path());
    std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");

    let custom = UpdaterTaskConfig {
        id: "custom-tool".to_string(),
        label: "Custom Tool".to_string(),
        os: vec!["linux".to_string(), "windows".to_string()],
        detect_mode: UpdaterDetectionMode::Always,
        detect_any: Vec::new(),
        detect_all: Vec::new(),
        detect_all_windows: vec!["helper".to_string()],
        skip_if_any: Vec::new(),
        skip_if_any_windows: vec!["shadow".to_string()],
        depends_on: Vec::new(),
        after: Vec::new(),
        requires_selected_any: Vec::new(),
        depends_on_selected: false,
        depends_on_selected_exclude: Vec::new(),
        resource_locks: Vec::new(),
        authority: None,
        command: "primary".to_string(),
        args: Vec::new(),
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        enabled: true,
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: false,
        external_window: false,
        shell: false,
        policy_key: "system_update".to_string(),
        category: "custom".to_string(),
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };

    assert!(
        custom_to_task_spec(&custom, &HostOs::Linux).is_some(),
        "Windows-only detection gates should not affect Linux eligibility"
    );
    assert!(
        custom_to_task_spec(&custom, &HostOs::Windows).is_none(),
        "missing detect_all_windows helper should block Windows eligibility"
    );

    write_executable(
        &temp.path().join("helper.cmd"),
        "@echo off\r\nexit /b 0\r\n",
    );
    assert!(
        custom_to_task_spec(&custom, &HostOs::Windows).is_none(),
        "skip_if_any_windows shadow should block Windows eligibility"
    );

    fs::remove_file(temp.path().join("shadow.cmd")).unwrap();
    assert!(
        custom_to_task_spec(&custom, &HostOs::Windows).is_some(),
        "Windows eligibility should pass once required helper exists and shadow is absent"
    );

    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }
    if let Some(pathext) = original_pathext {
        std::env::set_var("PATHEXT", pathext);
    } else {
        std::env::remove_var("PATHEXT");
    }
}

#[test]
fn custom_uv_task_is_not_suppressed_by_builtin_windows_skip_rule() {
    let _lock = env_guard();

    let temp = TempDir::new().unwrap();
    write_executable(
        &temp.path().join("winget.cmd"),
        "@echo off\r\nexit /b 0\r\n",
    );

    let original_path = std::env::var_os("PATH");
    let original_pathext = std::env::var_os("PATHEXT");
    std::env::set_var("PATH", temp.path());
    std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");

    let mut custom_tasks = BTreeMap::new();
    custom_tasks.insert(
        "uv".to_string(),
        UpdaterTaskConfig {
            id: "uv".to_string(),
            label: "Custom UV".to_string(),
            os: vec!["windows".to_string()],
            detect_mode: UpdaterDetectionMode::Always,
            detect_any: Vec::new(),
            detect_all: Vec::new(),
            detect_all_windows: Vec::new(),
            skip_if_any: Vec::new(),
            skip_if_any_windows: Vec::new(),
            depends_on: Vec::new(),
            after: Vec::new(),
            requires_selected_any: Vec::new(),
            depends_on_selected: false,
            depends_on_selected_exclude: Vec::new(),
            resource_locks: Vec::new(),
            authority: None,
            command: "custom-uv".to_string(),
            args: vec!["refresh".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            enabled: true,
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            policy_key: "system_update".to_string(),
            category: "custom".to_string(),
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        },
    );
    let updater_config = UpdaterConfig {
        run_all_detected: false,
        include: BTreeSet::from(["uv".to_string()]),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks,
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: None,
    };

    let specs = build_task_specs(&flags, &HostOs::Windows, &updater_config).expect("build specs");

    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }
    if let Some(pathext) = original_pathext {
        std::env::set_var("PATHEXT", pathext);
    } else {
        std::env::remove_var("PATHEXT");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(ids, vec!["uv"]);
    assert_eq!(specs[0].label, "Custom UV");
}

#[test]
fn windows_manager_order_gates_machine_winget_after_user_scope() {
    let specs = vec![
        TaskSpec {
            id: "scoop-self".to_string(),
            label: "Scoop Self".to_string(),
            depends_on: vec![],
            kind: TaskKind::Command(CommandTask {
                program: "scoop".to_string(),
                args: vec!["update".to_string()],
                mode: None,
                command_candidates: Vec::new(),
                pre_commands: Vec::new(),
                report_commands: Vec::new(),
                report_patterns: Vec::new(),
                report_scoped_deltas: Vec::new(),
                policy_key: "system_update".to_string(),
                requires_elevation: false,
                needs_sudo_session: false,
                interactive: false,
                external_window: false,
                shell: false,
                windows_bridge: false,
                report_parser: None,
                plain_header: None,
                plain_start: None,
                success_details: Vec::new(),
                external_manager_skip: false,
                result_protocol: None,
            }),
            category: "system".to_string(),
            resource_locks: BTreeSet::new(),
        },
        TaskSpec {
            id: "scoop-all".to_string(),
            label: "Scoop".to_string(),
            depends_on: vec!["scoop-self".to_string()],
            kind: TaskKind::Command(CommandTask {
                program: "scoop".to_string(),
                args: vec!["update".to_string(), "*".to_string()],
                mode: None,
                command_candidates: Vec::new(),
                pre_commands: Vec::new(),
                report_commands: Vec::new(),
                report_patterns: Vec::new(),
                report_scoped_deltas: Vec::new(),
                policy_key: "system_update".to_string(),
                requires_elevation: false,
                needs_sudo_session: false,
                interactive: false,
                external_window: false,
                shell: false,
                windows_bridge: false,
                report_parser: None,
                plain_header: None,
                plain_start: None,
                success_details: Vec::new(),
                external_manager_skip: false,
                result_protocol: None,
            }),
            category: "system".to_string(),
            resource_locks: BTreeSet::new(),
        },
        TaskSpec {
            id: "winget-user".to_string(),
            label: "Winget (User)".to_string(),
            depends_on: vec![],
            kind: TaskKind::Command(CommandTask {
                program: "winget".to_string(),
                args: vec!["upgrade".to_string()],
                mode: None,
                command_candidates: Vec::new(),
                pre_commands: Vec::new(),
                report_commands: Vec::new(),
                report_patterns: Vec::new(),
                report_scoped_deltas: Vec::new(),
                policy_key: "system_update".to_string(),
                requires_elevation: false,
                needs_sudo_session: false,
                interactive: false,
                external_window: false,
                shell: false,
                windows_bridge: false,
                report_parser: None,
                plain_header: None,
                plain_start: None,
                success_details: Vec::new(),
                external_manager_skip: false,
                result_protocol: None,
            }),
            category: "system".to_string(),
            resource_locks: BTreeSet::new(),
        },
        TaskSpec {
            id: "winget-machine".to_string(),
            label: "Winget (Machine)".to_string(),
            depends_on: vec!["winget-user".to_string()],
            kind: TaskKind::Command(CommandTask {
                program: "winget".to_string(),
                args: vec!["upgrade".to_string()],
                mode: None,
                command_candidates: Vec::new(),
                pre_commands: Vec::new(),
                report_commands: Vec::new(),
                report_patterns: Vec::new(),
                report_scoped_deltas: Vec::new(),
                policy_key: "system_update".to_string(),
                requires_elevation: true,
                needs_sudo_session: false,
                interactive: false,
                external_window: false,
                shell: false,
                windows_bridge: false,
                report_parser: None,
                plain_header: None,
                plain_start: None,
                success_details: Vec::new(),
                external_manager_skip: false,
                result_protocol: None,
            }),
            category: "system".to_string(),
            resource_locks: BTreeSet::new(),
        },
    ];

    let ordered = order_task_specs(specs).expect("order specs");
    let ids: Vec<&str> = ordered.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["scoop-self", "scoop-all", "winget-user", "winget-machine"]
    );
    let find = |id: &str| ordered.iter().find(|s| s.id == id).unwrap();
    assert!(find("winget-user").depends_on.is_empty());
    assert_eq!(
        find("winget-machine").depends_on,
        vec!["winget-user".to_string()]
    );
}

#[test]
fn failed_dependencies_block_unless_task_is_independent() {
    let failed = TaskResult::failed("Winget (User)", "failed");
    let canceled = TaskResult::canceled("Winget (Machine)", "canceled");

    assert!(!dependency_ready("winget-machine", "winget-user", &failed));
    assert!(!dependency_ready(
        "winget-machine",
        "winget-user",
        &canceled
    ));
    assert!(dependency_ready(TASK_COMPLETIONS, "winget-user", &failed));
    assert!(dependency_ready(
        TASK_COMPLETIONS,
        "winget-machine",
        &canceled
    ));
}

#[test]
fn completed_report_blockers_block_dependents() {
    let mut yay = TaskResult::completed("Yay");
    yay.report_sections.push(TaskReportSection {
        key: "package_recovery".to_string(),
        title: "Package Recovery Actions".to_string(),
        rows: vec![TaskReportRow {
            name: "gibo-bin".to_string(),
            status: TaskReportStatus::Failed,
            before: Some("source/build failure".to_string()),
            after: Some("retry failed".to_string()),
            note: Some("manual intervention required".to_string()),
        }],
    });

    assert!(!dependency_ready("arch-update-services", "yay", &yay));
    assert!(dependency_ready(TASK_COMPLETIONS, "yay", &yay));
}

#[test]
fn winget_machine_is_not_ready_until_user_scope_finishes() {
    let winget_user = TaskSpec {
        id: "winget-user".to_string(),
        label: "Winget (User)".to_string(),
        depends_on: vec![],
        kind: TaskKind::Command(CommandTask {
            program: "winget".to_string(),
            args: vec!["upgrade".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let winget_machine = TaskSpec {
        id: "winget-machine".to_string(),
        label: "Winget (Machine)".to_string(),
        depends_on: vec!["winget-user".to_string()],
        kind: TaskKind::Command(CommandTask {
            program: "winget".to_string(),
            args: vec!["upgrade".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };

    let mut pending = BTreeMap::new();
    pending.insert(winget_user.id.clone(), winget_user);
    pending.insert(winget_machine.id.clone(), winget_machine.clone());
    let done = BTreeMap::new();
    let (id, _) = next_ready_task(&pending, &done, &BTreeSet::new())
        .expect("user winget should be ready first");
    assert_eq!(id, "winget-user");

    let mut pending = BTreeMap::new();
    pending.insert(winget_machine.id.clone(), winget_machine.clone());
    assert!(next_ready_task(&pending, &done, &BTreeSet::new()).is_none());

    let mut done = BTreeMap::new();
    done.insert(
        "winget-user".to_string(),
        TaskResult::completed("Winget (User)"),
    );
    let (id, _) = next_ready_task(&pending, &done, &BTreeSet::new())
        .expect("machine winget should be unblocked");
    assert_eq!(id, "winget-machine");
}

#[test]
fn resource_locks_prevent_parallel_authority_mutation() {
    let task = TaskSpec {
        id: "team/index".to_string(),
        label: "Index".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Managed(ManagedTaskExecutor::Completions),
        category: "maintenance".to_string(),
        resource_locks: BTreeSet::from(["index-database".to_string()]),
    };
    let pending = BTreeMap::from([(task.id.clone(), task)]);
    let done = BTreeMap::new();

    assert!(next_ready_task(
        &pending,
        &done,
        &BTreeSet::from(["index-database".to_string()]),
    )
    .is_none());
    assert!(
        next_ready_task(&pending, &done, &BTreeSet::from(["unrelated".to_string()]),).is_some()
    );
}

#[test]
fn failed_dependencies_block_even_when_their_advisory_is_non_blocking() {
    let service_restart = TaskSpec {
        id: "arch-update-services".to_string(),
        label: "Svc Restart".to_string(),
        depends_on: vec!["yay".to_string()],
        kind: TaskKind::Managed(ManagedTaskExecutor::Completions),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let mut pending = BTreeMap::new();
    pending.insert(service_restart.id.clone(), service_restart);

    let mut yay = TaskResult::failed("Yay", "source validation failed");
    yay.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "upstream-source-drift".to_string(),
        summary: "gibo-bin source validation failed".to_string(),
        remediation: "fix the package checksum and retry".to_string(),
        blocks_dependents: false,
    });
    let done = BTreeMap::from([("yay".to_string(), yay)]);

    assert!(next_ready_task(&pending, &done, &BTreeSet::new()).is_none());
    assert_eq!(
        blocked_by_failed_dependency(&pending, &done),
        BTreeSet::from(["arch-update-services".to_string()])
    );
}

#[test]
fn ordering_predecessor_failure_does_not_block_successor() {
    let successor = TaskSpec {
        id: "skills".to_string(),
        label: "Skills".to_string(),
        depends_on: vec![ordering_dependency("npm")],
        kind: TaskKind::Managed(ManagedTaskExecutor::Completions),
        category: "language".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let pending = BTreeMap::from([("skills".to_string(), successor)]);
    let done = BTreeMap::from([(
        "npm".to_string(),
        TaskResult::failed("NPM", "package health failed"),
    )]);

    let (id, _) =
        next_ready_task(&pending, &done, &BTreeSet::new()).expect("ordering edge should be ready");
    assert_eq!(id, "skills");
    assert!(blocked_by_failed_dependency(&pending, &done).is_empty());
}

#[test]
fn health_dependency_failure_reports_precise_blocking_detail() {
    let successor = TaskSpec {
        id: "arch-update-services".to_string(),
        label: "Svc Restart".to_string(),
        depends_on: vec!["yay".to_string()],
        kind: TaskKind::Managed(ManagedTaskExecutor::Completions),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let done = BTreeMap::from([(
        "yay".to_string(),
        TaskResult::failed("Yay", "system update failed"),
    )]);

    assert_eq!(
        dependency_blocking_detail(&successor, &done),
        "blocked by dependency: yay=failed"
    );
}

#[test]
fn health_dependency_completed_with_blocking_issues_is_named_accurately() {
    let successor = TaskSpec {
        id: "consumer".to_string(),
        label: "Consumer".to_string(),
        depends_on: vec!["producer".to_string()],
        kind: TaskKind::Managed(ManagedTaskExecutor::Completions),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let mut producer = TaskResult::completed("Producer");
    producer.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "capability-unavailable".to_string(),
        summary: "required capability was not produced".to_string(),
        remediation: "repair producer".to_string(),
        blocks_dependents: true,
    });
    let done = BTreeMap::from([("producer".to_string(), producer)]);

    assert_eq!(
        dependency_blocking_detail(&successor, &done),
        "blocked by dependency: producer=completed_with_issues"
    );
}

#[test]
fn mixed_ordering_and_health_dependency_cycle_is_rejected() {
    let specs = vec![
        TaskSpec {
            id: "npm".to_string(),
            label: "NPM".to_string(),
            depends_on: vec!["skills".to_string()],
            kind: TaskKind::Managed(ManagedTaskExecutor::Npm),
            category: "language".to_string(),
            resource_locks: BTreeSet::new(),
        },
        TaskSpec {
            id: "skills".to_string(),
            label: "Skills".to_string(),
            depends_on: vec![ordering_dependency("npm")],
            kind: TaskKind::Managed(ManagedTaskExecutor::Completions),
            category: "language".to_string(),
            resource_locks: BTreeSet::new(),
        },
    ];

    let error = match order_task_specs(specs) {
        Ok(_) => panic!("mixed dependency graph should detect a cycle"),
        Err(error) => error.to_string(),
    };
    assert_eq!(error, "task dependency cycle detected: npm,skills");
}

#[test]
fn stderr_log_level_is_content_based() {
    assert_eq!(
        classify_stream_level(StreamKind::Stderr, "error: command failed"),
        LogLevel::Error
    );
    assert_eq!(
        classify_stream_level(
            StreamKind::Stderr,
            "==> ERROR: One or more files did not pass the validity check!"
        ),
        LogLevel::Error
    );
    assert_eq!(
        classify_stream_level(StreamKind::Stderr, "ERROR The install failed"),
        LogLevel::Error
    );
    assert_eq!(
        classify_stream_level(StreamKind::Stderr, "warning: package is deprecated"),
        LogLevel::Warn
    );
    assert_eq!(
        classify_stream_level(
            StreamKind::Stderr,
            "  0      0   0      0   0      0      0      0           00:01              0"
        ),
        LogLevel::Info
    );
    assert_eq!(
        classify_stream_level(
            StreamKind::Stderr,
            "error: uv was installed through an external package manager and cannot update itself"
        ),
        LogLevel::Warn
    );
}

#[test]
fn command_output_diagnostics_dedupes_and_caps_warning_samples() {
    let output = [
        "warning: alpha package is deprecated",
        "warning: alpha package is deprecated",
        "npm WARN deprecated uuid@10.0.0: use a newer release",
        "No debugging symbols found in /usr/lib/foo",
        "No debugging symbols found in /usr/lib/bar",
        "No debugging symbols found in /usr/lib/baz",
        "error: package hook failed",
    ]
    .join("\n");
    let mut result = TaskResult::completed("Diagnostics");

    attach_command_output_diagnostics(&mut result, &output);

    assert!(result.advisories.iter().any(|advisory| {
        advisory.code == "command-output-diagnostics"
            && advisory.severity == AdvisorySeverity::Warning
            && !advisory.blocks_dependents
            && advisory.summary.contains("warning/error diagnostics")
    }));
    let section = result
        .report_sections
        .iter()
        .find(|section| section.key == "command_diagnostics")
        .expect("diagnostic report section");
    assert!(
        section.rows.len() <= COMMAND_DIAGNOSTIC_SAMPLE_LIMIT,
        "{section:#?}"
    );
    assert_eq!(
        section
            .rows
            .iter()
            .filter(|row| row.name == "warning")
            .count(),
        3,
        "duplicate warning lines should be deduped while distinct npm and grouped debug-symbol warnings remain visible"
    );
    assert!(section.rows.iter().any(|row| {
        row.name == "warning"
            && row.note.as_deref().is_some_and(|note| {
                note.contains("No debugging symbols") && note.contains("3 occurrences")
            })
    }));
    assert!(section.rows.iter().any(
        |row| row.name == "error" && row.note.as_deref() == Some("error: package hook failed")
    ));
    assert!(
        !result.blocks_dependents(),
        "diagnostic samples from a completed task should not block dependents"
    );
}

#[test]
fn command_output_diagnostics_surface_npm_allow_scripts_warning() {
    let output = "npm warn Unknown env config \"allow-scripts\". This will stop working in the next major version of npm.\n";
    let mut result = TaskResult::completed("NPM");

    attach_command_output_diagnostics(&mut result, output);

    assert!(result.advisories.iter().any(|advisory| {
        advisory.code == "command-output-diagnostics"
            && advisory.severity == AdvisorySeverity::Warning
            && advisory.summary.contains("warning/error diagnostics")
    }));
    let section = result
        .report_sections
        .iter()
        .find(|section| section.key == "command_diagnostics")
        .expect("diagnostic report section");
    assert!(section.rows.iter().any(|row| {
        row.note
            .as_deref()
            .is_some_and(|note| note.contains("allow-scripts"))
    }));
}

#[test]
fn external_manager_self_update_messages_are_detected() {
    assert!(is_external_manager_self_update_unsupported(
            "Self-update is only available for uv binaries installed via the standalone installation scripts"
        ));
    assert!(is_external_manager_self_update_unsupported(
            "Self-update is only available for qwen-code binaries installed via the standalone installation scripts"
        ));
    assert!(is_external_manager_self_update_unsupported(
            "error: uv was installed through an external package manager and cannot update itself. Please use your package manager to update uv."
        ));
    assert!(!is_external_manager_self_update_unsupported(
        "error: network unreachable while downloading release metadata"
    ));
}

#[test]
fn sanitize_stream_line_keeps_progress_when_filter_disabled() {
    let line = " 42% █████████████ 12MB / 50MB ";
    assert_eq!(
        sanitize_stream_line(line, false),
        Some(" 42% █████████████ 12MB / 50MB".to_string())
    );
}

#[test]
fn sanitize_stream_line_drops_progress_when_filter_enabled() {
    let line = " 42% █████████████ 12MB / 50MB ";
    assert_eq!(sanitize_stream_line(line, true), None);
}

#[test]
fn strip_ansi_removes_osc_and_single_escape_sequences() {
    let input =
        "\x1b]8;;https://example.invalid\x07link\x1b]8;;\x07 \x1b(Bplain \x1b[31mred\x1b[0m";

    assert_eq!(strip_ansi(input), "link plain red");
}

#[test]
fn fit_visible_truncates_ansi_cells_without_escape_fragments() {
    let (text, truncated) = fit_visible("\x1b[31mabcdef\x1b[0m", 5);

    assert!(truncated);
    assert_eq!(text, "ab...");
    assert_eq!(visible_width(&text), 5);
    assert!(!text.contains('\u{1b}'));
}

#[test]
fn format_table_row_strips_ansi_from_cells_and_overflow_notes() {
    let (text, notes) = format_table_row(&[
        TableCell {
            text: "\x1b]8;;https://example.invalid\x07package-name\x1b]8;;\x07",
            width: 7,
            color: None,
            overflow_label: Some("package"),
        },
        TableCell {
            text: "\x1b[32mupdated\x1b[0m",
            width: 7,
            color: Some(crossterm::style::Color::Green),
            overflow_label: None,
        },
    ]);

    assert_eq!(visible_width(&text), 16);
    assert!(!strip_ansi(&text).contains('\u{1b}'));
    assert_eq!(notes, vec!["full package: package-name"]);
}

#[test]
fn box_table_renderer_truncates_cells_to_allocated_width() {
    let rendered = render_box_row(
        &[
            BoxCell {
                text: "Recovered".to_string(),
                color: None,
                width: 7,
            },
            BoxCell::plain("ok", 2),
        ],
        false,
    );

    assert_eq!(visible_width(&rendered), box_table_width(&[7, 2]));
    assert!(
        rendered.contains("Reco..."),
        "wide cell should be truncated inside its allocated width:\n{rendered}"
    );
}

#[test]
fn task_report_sections_render_table_header_and_row() {
    let section = TaskReportSection {
        key: "cargo".to_string(),
        title: "Cargo Package Results".to_string(),
        rows: vec![TaskReportRow {
            name: "foo".to_string(),
            status: TaskReportStatus::Updated,
            before: Some("1.0.0".to_string()),
            after: Some("1.2.0".to_string()),
            note: None,
        }],
    };

    let lines = render_task_report_sections(&[section], false, crate::config::NoteVerbosity::All);
    assert!(lines
        .iter()
        .any(|l| l.text.contains("Cargo Package Results")));
    assert!(lines.iter().any(|l| l.text.contains("Package")));
    assert!(lines.iter().any(|l| l.text.contains("Before")));
    assert!(lines.iter().any(|l| l.text.contains("After")));
    assert!(lines.iter().any(|l| l.text.contains("Outcome")));
    assert!(lines.iter().any(|l| l.text.contains("Updated")));
    assert!(lines.iter().any(|l| l.text.contains("foo")));
}

#[test]
fn report_footer_alignment_matches_when_color_is_enabled() {
    let result = TaskResult {
        label: "Cargo".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "cargo".to_string(),
            title: "Cargo Package Results".to_string(),
            rows: vec![
                TaskReportRow {
                    name: "alpha".to_string(),
                    status: TaskReportStatus::Updated,
                    before: Some("1.0.0".to_string()),
                    after: Some("1.2.0".to_string()),
                    note: None,
                },
                TaskReportRow {
                    name: "beta-tool".to_string(),
                    status: TaskReportStatus::Unchanged,
                    before: Some("2.0.0".to_string()),
                    after: Some("2.0.0".to_string()),
                    note: None,
                },
            ],
        }],
    };

    let color_lines = render_npm_package_footer([&result], true, crate::config::NoteVerbosity::All);
    let plain_lines =
        render_npm_package_footer([&result], false, crate::config::NoteVerbosity::All);

    let color_stripped: Vec<String> = color_lines
        .iter()
        .map(|line| strip_ansi(&line.text))
        .collect();
    let plain_text: Vec<&str> = plain_lines.iter().map(|line| line.text.as_str()).collect();

    assert_eq!(color_stripped, plain_text);
}

#[test]
fn report_footer_runtime_levels_do_not_mark_non_issue_rows_as_warnings() {
    let result = TaskResult {
        label: "Pipx".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "pipx".to_string(),
            title: "Pipx Package Results".to_string(),
            rows: vec![
                TaskReportRow {
                    name: "pipx".to_string(),
                    status: TaskReportStatus::Unchanged,
                    before: Some("-".to_string()),
                    after: Some("-".to_string()),
                    note: Some("no updates".to_string()),
                },
                TaskReportRow {
                    name: "audit".to_string(),
                    status: TaskReportStatus::Info,
                    before: Some("mode=fast".to_string()),
                    after: Some("strict=warn".to_string()),
                    note: Some(
                        "Completion Audit Summary: pass=17 warn=0 fail=0 skip=0".to_string(),
                    ),
                },
                TaskReportRow {
                    name: "broken".to_string(),
                    status: TaskReportStatus::Failed,
                    before: Some("1.0.0".to_string()),
                    after: Some("1.0.0".to_string()),
                    note: Some("network failure".to_string()),
                },
            ],
        }],
    };

    let lines = render_npm_package_footer([&result], false, crate::config::NoteVerbosity::All);
    let unchanged = lines
        .iter()
        .find(|line| line.text.contains("Unchanged"))
        .expect("expected unchanged row");
    let info = lines
        .iter()
        .find(|line| line.text.contains("Info"))
        .expect("expected info row");
    let failed = lines
        .iter()
        .find(|line| line.text.contains("Error"))
        .expect("expected failed row");

    assert_eq!(unchanged.level, LogLevel::Info);
    assert_eq!(info.level, LogLevel::Info);
    assert_eq!(failed.level, LogLevel::Error);
}

#[test]
fn report_footer_hides_non_failure_notes_when_failure_only_is_enabled() {
    let result = TaskResult {
        label: "Pipx".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "pipx".to_string(),
            title: "Pipx Package Results".to_string(),
            rows: vec![
                TaskReportRow {
                    name: "pipx".to_string(),
                    status: TaskReportStatus::Unchanged,
                    before: Some("-".to_string()),
                    after: Some("-".to_string()),
                    note: Some("no updates".to_string()),
                },
                TaskReportRow {
                    name: "broken".to_string(),
                    status: TaskReportStatus::Failed,
                    before: Some("1.0.0".to_string()),
                    after: Some("1.0.0".to_string()),
                    note: Some("network failure".to_string()),
                },
            ],
        }],
    };

    let lines = render_npm_package_footer([&result], false, crate::config::NoteVerbosity::Failures);
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!text.contains("no updates"), "{text}");
    assert!(text.contains("network failure"), "{text}");
}

#[test]
fn report_footer_truncates_long_cells_and_emits_full_value_notes() {
    let result = TaskResult {
        label: "Rustup".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "rustup_channels".to_string(),
            title: "Rustup Channel Results".to_string(),
            rows: vec![TaskReportRow {
                name: "stable-x86_64-unknown-linux-gnu-with-extra-long-suffix".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("rustc 1.93.1-nightly-with-very-long-build-metadata".to_string()),
                after: Some("rustc 1.94.0-nightly-with-very-long-build-metadata".to_string()),
                note: None,
            }],
        }],
    };

    let lines = render_npm_package_footer([&result], false, crate::config::NoteVerbosity::All);
    let row = lines
        .iter()
        .find(|line| line.text.contains("Updated"))
        .expect("expected data row");
    assert!(
        row.text.contains("..."),
        "expected truncation in row: {}",
        row.text
    );
    assert!(lines.iter().any(|line| line
        .text
        .contains("full before: rustc 1.93.1-nightly-with-very-long-build-metadata")));
    assert!(lines.iter().any(|line| line
        .text
        .contains("full after: rustc 1.94.0-nightly-with-very-long-build-metadata")));
}

#[test]
fn final_task_overview_groups_by_category_and_summarizes_items() {
    let language = TaskResult {
        label: "Rustup".to_string(),
        status: TaskStatus::Completed,
        details: vec!["toolchains refreshed".to_string()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "rustup_channels".to_string(),
            title: "Rustup Channel Results".to_string(),
            rows: vec![
                TaskReportRow {
                    name: "stable".to_string(),
                    status: TaskReportStatus::Updated,
                    before: Some("rustc 1.93.1".to_string()),
                    after: Some("rustc 1.94.0".to_string()),
                    note: None,
                },
                TaskReportRow {
                    name: "beta".to_string(),
                    status: TaskReportStatus::Unchanged,
                    before: Some("rustc 1.94.0-beta".to_string()),
                    after: Some("rustc 1.94.0-beta".to_string()),
                    note: None,
                },
            ],
        }],
    };
    let system = TaskResult::failed("Winget (Machine)", "elevation required");
    let categories = BTreeMap::from([
        ("rustup".to_string(), "language".to_string()),
        ("winget-machine".to_string(), "system".to_string()),
    ]);

    let lines = render_final_task_overview(
        [("rustup", &language), ("winget-machine", &system)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    let system_pos = text.find("│ System ").expect("system row");
    let language_pos = text.find("│ Developer Tools ").expect("language row");
    assert!(system_pos < language_pos, "{text}");
    assert!(text.contains("┌"), "{text}");
    assert!(text.contains("Group"), "{text}");
    assert!(text.contains("updated=1"), "{text}");
    assert!(text.contains("elevation"), "{text}");
}

#[test]
fn final_task_overview_uses_uncategorized_for_missing_category() {
    let mut result = TaskResult::completed("External Tool");
    result.details.push("completed".to_string());
    let categories = BTreeMap::new();

    let lines = render_final_task_overview(
        [("external-tool", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Uncategorized"), "{text}");
    assert!(
        !text.contains("Unknown"),
        "missing task categories should not leak unknown labels:\n{text}"
    );
}

#[test]
fn final_task_overview_truncates_long_notes_with_follow_up_note() {
    let result = TaskResult {
        label: "Cargo".to_string(),
        status: TaskStatus::Completed,
        details: vec!["this is a deliberately very long summary detail that should not fit in the notes column without truncation".to_string()],
        advisories: Vec::new(),
        report_sections: Vec::new(),
    };
    let categories = BTreeMap::from([("cargo".to_string(), "language".to_string())]);

    let lines = render_final_task_overview(
        [("cargo", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        true,
    );
    let row = lines
        .iter()
        .find(|line| line.text.contains("Cargo"))
        .expect("expected cargo row");
    assert!(
        row.text.contains("..."),
        "expected truncated notes row: {}",
        row.text
    );
    assert!(lines.iter().any(|line| line
        .text
        .contains("continued notes: this is a deliberately very long summary detail")));
}

#[test]
fn final_task_overview_suppresses_debug_annotations_by_default() {
    let result = TaskResult {
        label: "Cargo".to_string(),
        status: TaskStatus::Completed,
        details: vec!["this is a deliberately very long summary detail that should not fit in the notes column without truncation".to_string()],
        advisories: Vec::new(),
        report_sections: Vec::new(),
    };
    let categories = BTreeMap::from([("cargo".to_string(), "language".to_string())]);

    let lines = render_final_task_overview(
        [("cargo", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!text.contains("[OK]"), "{text}");
    assert!(!text.contains("continued notes:"), "{text}");
}

#[test]
fn final_task_overview_truncates_wide_task_labels_without_breaking_box_alignment() {
    let wide = TaskResult {
        label: "更新管理サービス再起動確認🚀-with-extra-suffix".to_string(),
        status: TaskStatus::Completed,
        details: vec!["已更新核心组件、工具链与服务定义，并保留额外说明以触发注释截断".to_string()],
        advisories: Vec::new(),
        report_sections: Vec::new(),
    };
    let short = TaskResult::completed("Go");
    let categories = BTreeMap::from([
        ("wide-task".to_string(), "system".to_string()),
        ("go".to_string(), "language".to_string()),
    ]);

    let lines = render_final_task_overview(
        [("wide-task", &wide), ("go", &short)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        true,
    );
    let table_lines = lines
        .iter()
        .map(|line| strip_ansi(&line.text))
        .filter(|line| matches!(line.chars().next(), Some('┌' | '├' | '│' | '└')))
        .collect::<Vec<_>>();
    let row = table_lines
        .iter()
        .find(|line| line.contains("更新管理"))
        .expect("wide task row");
    let widths = table_lines
        .iter()
        .map(|line| UnicodeWidthStr::width(line.as_str()))
        .collect::<Vec<_>>();
    let task_cell = row.split('│').nth(2).map(str::trim).expect("task cell");

    assert!(
        widths.windows(2).all(|pair| pair[0] == pair[1]),
        "expected aligned box widths:\n{}",
        table_lines.join("\n")
    );
    assert!(
        task_cell.contains("..."),
        "expected wide task label truncation in task cell:\n{row}"
    );
    assert!(
        !task_cell.contains("with-extra-suffix"),
        "expected truncated task cell to exclude the full suffix:\n{row}"
    );
    assert!(lines
        .iter()
        .any(|line| line.text.contains("continued notes: 已更新核心组件")));
}

#[test]
fn final_task_overview_hides_overflow_notes_when_note_verbosity_is_failures() {
    let result = TaskResult {
        label: "Cargo".to_string(),
        status: TaskStatus::Completed,
        details: vec!["this is a deliberately very long summary detail that should not fit in the notes column without truncation".to_string()],
        advisories: Vec::new(),
        report_sections: Vec::new(),
    };
    let categories = BTreeMap::from([("cargo".to_string(), "language".to_string())]);

    let lines = render_final_task_overview(
        [("cargo", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!text.contains("[OK] "), "{text}");
    assert!(!text.contains("continued notes:"), "{text}");
}

#[test]
fn per_task_changes_hides_overflow_notes_when_note_verbosity_is_failures() {
    let result = TaskResult {
        label: "Cargo".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "cargo".to_string(),
            title: "Cargo Package Results".to_string(),
            rows: vec![TaskReportRow {
                name: "extremely-long-package-name-that-should-trigger-truncation".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("1.0.0-long-build-metadata".to_string()),
                after: Some("2.0.0-long-build-metadata".to_string()),
                note: Some("selected for update".to_string()),
            }],
        }],
    };
    let categories = BTreeMap::from([("cargo".to_string(), "language".to_string())]);

    let lines = render_per_task_changes(
        [("cargo", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Per-Task Changes"), "{text}");
    assert!(!text.contains("[OK] selected for update"), "{text}");
    assert!(!text.contains("full before:"), "{text}");
}

#[test]
fn clean_report_omits_status_prefixes_but_debug_report_restores_them() {
    let result = TaskResult {
        label: "Cargo".to_string(),
        status: TaskStatus::Completed,
        details: vec!["updated package index".to_string()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "cargo".to_string(),
            title: "Cargo Package Results".to_string(),
            rows: vec![TaskReportRow {
                name: "extremely-long-package-name-that-should-trigger-truncation".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("1.0.0-long-build-metadata".to_string()),
                after: Some("2.0.0-long-build-metadata".to_string()),
                note: Some("selected for update".to_string()),
            }],
        }],
    };
    let categories = BTreeMap::from([("cargo".to_string(), "language".to_string())]);

    let clean_lines = render_per_task_changes(
        [("cargo", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
    );
    let clean_text = clean_lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        clean_text.contains("Cargo (Developer Tools)"),
        "{clean_text}"
    );
    assert!(
        !clean_text.contains("[OK] Cargo (Developer Tools)"),
        "{clean_text}"
    );
    assert!(
        !clean_text.contains("[OK] selected for update"),
        "{clean_text}"
    );

    let debug_lines = render_per_task_changes(
        [("cargo", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        true,
    );
    let debug_text = debug_lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        debug_text.contains("[OK] Cargo (Developer Tools)"),
        "{debug_text}"
    );
    assert!(
        debug_text.contains("[OK] selected for update"),
        "{debug_text}"
    );
}

#[test]
fn update_details_only_shows_updated_rows_grouped_by_section() {
    let a = TaskResult {
        label: "Yay".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "yay".to_string(),
            title: "Yay Package Results".to_string(),
            rows: vec![
                TaskReportRow {
                    name: "kitty".to_string(),
                    status: TaskReportStatus::Updated,
                    before: Some("0.46.1-1".to_string()),
                    after: Some("0.46.2-1".to_string()),
                    note: None,
                },
                TaskReportRow {
                    name: "kitty-shell-integration".to_string(),
                    status: TaskReportStatus::Unchanged,
                    before: Some("0.46.2-1".to_string()),
                    after: Some("0.46.2-1".to_string()),
                    note: None,
                },
            ],
        }],
    };
    let b = TaskResult {
        label: "Rustup".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "rustup_channels".to_string(),
            title: "Rustup Channel Results".to_string(),
            rows: vec![TaskReportRow {
                name: "stable".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("rustc 1.93.1".to_string()),
                after: Some("rustc 1.94.0".to_string()),
                note: None,
            }],
        }],
    };

    let lines = render_update_details(
        [("yay", &a), ("rustup", &b)],
        false,
        crate::config::NoteVerbosity::Failures,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Update Details"), "{text}");
    assert!(text.contains("Yay Package Results"), "{text}");
    assert!(text.contains("Rustup Channel Results"), "{text}");
    assert!(text.contains("kitty"), "{text}");
    assert!(text.contains("stable"), "{text}");
    assert!(!text.contains("kitty-shell-integration"), "{text}");
    assert!(!text.contains("unchanged"), "{text}");
}

#[test]
fn async_end_reports_include_update_details_for_generated_completion_rows() {
    let completions = TaskResult {
        label: "Completions".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "completion_generation".to_string(),
            title: "Completion Generation Results".to_string(),
            rows: vec![TaskReportRow {
                name: "codex".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("npm".to_string()),
                after: Some("/repo/home/.shellrc.d/shell/completions-managed/_codex".to_string()),
                note: None,
            }],
        }],
    };
    let summary = vec![("completions".to_string(), completions)];
    let task_categories = BTreeMap::from([("completions".to_string(), "maintenance".to_string())]);
    let (raw_tx, rx) = mpsc::channel();
    let tx = DashboardSender::new(raw_tx, None);

    emit_end_of_run_reports_async_logs(
        &tx,
        None,
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        &task_categories,
        crate::config::NoteVerbosity::All,
        false,
    );

    let text = rx
        .try_iter()
        .filter_map(|event| match event {
            DashboardEvent::LogLine(record) => Some(record.line),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Package Change Rollup"), "{text}");
    assert!(!text.contains("Per-Task Changes"), "{text}");
    assert!(text.contains("Final Task Overview"), "{text}");
    assert!(text.contains("Update Details"), "{text}");
    assert!(text.contains("Completion Generation Results"), "{text}");
    assert!(text.contains("codex"), "{text}");
}

#[test]
fn update_details_color_only_marks_version_changes() {
    let _lock = env_guard();
    let original_force_color = std::env::var_os("UPDATE_ALL_TEST_FORCE_COLOR");
    let original_no_color = std::env::var_os("NO_COLOR");
    let original_term = std::env::var_os("TERM");
    std::env::set_var("UPDATE_ALL_TEST_FORCE_COLOR", "1");
    std::env::remove_var("NO_COLOR");
    std::env::set_var("TERM", "xterm-256color");

    let completions = TaskResult {
        label: "Completions".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "completion_generation".to_string(),
            title: "Completion Generation Results".to_string(),
            rows: vec![TaskReportRow {
                name: "codex".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("npm".to_string()),
                after: Some(
                    "/home/example-user/.shellrc.d/shell/completions/_managed_npm_codex"
                        .to_string(),
                ),
                note: None,
            }],
        }],
    };
    let rustup = TaskResult {
        label: "Rustup".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "rustup_channels".to_string(),
            title: "Rustup Channel Results".to_string(),
            rows: vec![TaskReportRow {
                name: "stable".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("1.93.1".to_string()),
                after: Some("1.94.0".to_string()),
                note: None,
            }],
        }],
    };

    let summary = vec![
        ("completions".to_string(), completions),
        ("rustup".to_string(), rustup),
    ];
    let render_summary = || summary.iter().map(|(id, result)| (id.as_str(), result));
    let color_lines =
        render_update_details(render_summary(), true, crate::config::NoteVerbosity::All);
    let plain_lines =
        render_update_details(render_summary(), false, crate::config::NoteVerbosity::All);
    let color_stripped: Vec<String> = color_lines
        .iter()
        .map(|line| strip_ansi(&line.text))
        .collect();
    let plain_text: Vec<&str> = plain_lines.iter().map(|line| line.text.as_str()).collect();
    let completion_line = color_lines
        .iter()
        .find(|line| line.text.contains("codex"))
        .expect("completion row");
    let version_line = color_lines
        .iter()
        .find(|line| line.text.contains("stable"))
        .expect("version row");

    assert_eq!(color_stripped, plain_text);
    assert!(
        !completion_line.text.contains("\x1b["),
        "completion provider/artifact row should not be colorized: {}",
        completion_line.text
    );
    assert!(
        version_line.text.contains("\x1b[1;31m1.93.1"),
        "version before value should be red: {}",
        version_line.text
    );
    assert!(
        version_line.text.contains("\x1b[1;32m1.94.0"),
        "version after value should be green: {}",
        version_line.text
    );

    if let Some(value) = original_force_color {
        std::env::set_var("UPDATE_ALL_TEST_FORCE_COLOR", value);
    } else {
        std::env::remove_var("UPDATE_ALL_TEST_FORCE_COLOR");
    }
    if let Some(value) = original_no_color {
        std::env::set_var("NO_COLOR", value);
    } else {
        std::env::remove_var("NO_COLOR");
    }
    if let Some(value) = original_term {
        std::env::set_var("TERM", value);
    } else {
        std::env::remove_var("TERM");
    }
}

#[test]
fn report_row_value_change_is_version_only() {
    let version_row = TaskReportRow {
        name: "stable".to_string(),
        status: TaskReportStatus::Updated,
        before: Some("1.93.1".to_string()),
        after: Some("1.94.0".to_string()),
        note: None,
    };
    let completion_row = TaskReportRow {
        name: "codex".to_string(),
        status: TaskReportStatus::Updated,
        before: Some("npm".to_string()),
        after: Some(
            "/home/example-user/.shellrc.d/shell/completions/_managed_npm_codex".to_string(),
        ),
        note: None,
    };
    let recovery_row = TaskReportRow {
        name: "stale-file".to_string(),
        status: TaskReportStatus::Updated,
        before: Some("present".to_string()),
        after: Some("removed".to_string()),
        note: None,
    };

    assert!(report_row_has_value_change(&version_row));
    assert!(!report_row_has_value_change(&completion_row));
    assert!(!report_row_has_value_change(&recovery_row));
}

#[test]
fn report_rendering_fills_missing_after_for_unchanged_version_rows() {
    let result = TaskResult {
        label: "Cargo".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "cargo_packages".to_string(),
            title: "Cargo Package Results".to_string(),
            rows: vec![TaskReportRow {
                name: "trunk".to_string(),
                status: TaskReportStatus::Unchanged,
                before: Some("v0.21.14".to_string()),
                after: None,
                note: Some("already current".to_string()),
            }],
        }],
    };
    let categories = BTreeMap::from([("cargo".to_string(), "language".to_string())]);

    let per_task_lines = render_task_report_sections(
        &result.report_sections,
        false,
        crate::config::NoteVerbosity::All,
    );
    let per_task_text = per_task_lines
        .iter()
        .map(|line| strip_ansi(&line.text))
        .collect::<Vec<_>>()
        .join("\n");
    let per_task_row = per_task_text
        .lines()
        .find(|line| line.contains("trunk"))
        .expect("per-task trunk row");

    let rollup_lines = render_package_change_rollup_with_width(
        [("cargo", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
        120,
    );
    let rollup_text = rollup_lines
        .iter()
        .map(|line| strip_ansi(&line.text))
        .collect::<Vec<_>>()
        .join("\n");
    let rollup_row = rollup_text
        .lines()
        .find(|line| line.contains("trunk"))
        .expect("rollup trunk row");

    assert_eq!(
        per_task_row.matches("v0.21.14").count(),
        2,
        "per-task unchanged row should show before and after as the same version:\n{per_task_text}"
    );
    assert_eq!(
        rollup_row.matches("v0.21.14").count(),
        2,
        "rollup unchanged row should show before and after as the same version:\n{rollup_text}"
    );
}

#[test]
fn package_change_rollup_unifies_rows_across_tasks_and_sections() {
    let yay = TaskResult {
        label: "Yay".to_string(),
        status: TaskStatus::Failed,
        details: vec!["command failed".to_string()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "yay_recovery".to_string(),
            title: "Yay Recovery Actions".to_string(),
            rows: vec![
                TaskReportRow {
                    name: "/home/example-user/.cache/yay/gibo-bin".to_string(),
                    status: TaskReportStatus::Updated,
                    before: Some("present".to_string()),
                    after: Some("removed".to_string()),
                    note: Some("cleared package cache/worktree".to_string()),
                },
                TaskReportRow {
                    name: "gibo-bin".to_string(),
                    status: TaskReportStatus::Failed,
                    before: Some("source/build failure".to_string()),
                    after: Some("retry failed".to_string()),
                    note: Some("retry exited non-zero".to_string()),
                },
            ],
        }],
    };
    let npm = TaskResult {
        label: "NPM".to_string(),
        status: TaskStatus::Completed,
        details: vec!["Updated 1 npm package(s).".to_string()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "npm".to_string(),
            title: "NPM Package Results".to_string(),
            rows: vec![TaskReportRow {
                name: "skills".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("2026.3.24".to_string()),
                after: Some("2026.3.28".to_string()),
                note: None,
            }],
        }],
    };
    let categories = BTreeMap::from([
        ("yay".to_string(), "system".to_string()),
        ("npm".to_string(), "language".to_string()),
    ]);

    let lines = render_package_change_rollup(
        [("yay", &yay), ("npm", &npm)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Package Change Rollup"), "{text}");
    assert!(text.contains("Group"), "{text}");
    assert!(text.contains("Task"), "{text}");
    assert!(text.contains("Item"), "{text}");
    assert!(text.contains("Result"), "{text}");
    assert!(text.contains("Yay"), "{text}");
    assert!(text.contains("NPM"), "{text}");
    assert!(text.contains("gibo-bin"), "{text}");
    assert!(text.contains("skills"), "{text}");
    assert!(text.contains("Recovered"), "{text}");
    assert!(text.contains("Error"), "{text}");
    assert!(text.contains("Updated"), "{text}");
}

#[test]
fn box_table_width_allocator_caps_columns_to_target_width() {
    let preferred = [10, 18, 28, 16, 16, 10, 34];
    let minimums = [5, 6, 10, 8, 8, 7, 12];
    let widths = allocate_box_table_widths(&preferred, &minimums, 80);

    assert_eq!(box_table_width(&widths), 80);
    assert!(widths[2] < preferred[2]);
    assert!(widths[6] < preferred[6]);
    for (idx, width) in widths.iter().enumerate() {
        assert!(*width >= minimums[idx]);
    }
}

#[test]
fn package_change_rollup_respects_narrow_width_budget() {
    let result = TaskResult {
        label: "Yay".to_string(),
        status: TaskStatus::Failed,
        details: vec!["command failed".to_string()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "yay_recovery".to_string(),
            title: "Yay Recovery Actions".to_string(),
            rows: vec![TaskReportRow {
                name: "extremely-long-package-name-that-needs-truncation".to_string(),
                status: TaskReportStatus::Failed,
                before: Some("source/build failure".to_string()),
                after: Some("retry failed with a very long explanation".to_string()),
                note: Some(
                    "this note is intentionally long so the notes column must shrink".to_string(),
                ),
            }],
        }],
    };
    let categories = BTreeMap::from([("yay".to_string(), "system".to_string())]);

    let lines = render_package_change_rollup_with_width(
        [("yay", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
        80,
    );

    for line in lines {
        assert!(visible_width(&line.text) <= 80, "{}", line.text);
    }
}

#[test]
fn package_change_rollup_keeps_result_cells_inside_narrow_box_width() {
    let result = TaskResult {
        label: "Yay".to_string(),
        status: TaskStatus::Completed,
        details: vec!["recovered".to_string()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "package_recovery".to_string(),
            title: "Package Recovery Actions".to_string(),
            rows: vec![TaskReportRow {
                name: "package-with-wide-recovery-status".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("present".to_string()),
                after: Some("removed".to_string()),
                note: Some("cleared package cache/worktree".to_string()),
            }],
        }],
    };
    let categories = BTreeMap::from([("yay".to_string(), "system".to_string())]);

    let lines = render_package_change_rollup_with_width(
        [("yay", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
        80,
    );
    let table_lines = lines
        .iter()
        .map(|line| strip_ansi(&line.text))
        .filter(|line| matches!(line.chars().next(), Some('┌' | '├' | '│' | '└')))
        .collect::<Vec<_>>();
    let widths = table_lines
        .iter()
        .map(|line| UnicodeWidthStr::width(line.as_str()))
        .collect::<Vec<_>>();

    assert!(
        widths.windows(2).all(|pair| pair[0] == pair[1]),
        "expected aligned box widths:\n{}",
        table_lines.join("\n")
    );
    assert!(
        table_lines.iter().all(|line| visible_width(line) <= 80),
        "expected all rollup rows to stay within narrow width:\n{}",
        table_lines.join("\n")
    );
}

#[test]
fn package_change_rollup_uses_uncategorized_for_missing_category() {
    let result = TaskResult {
        label: "External Tool".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "external_tools".to_string(),
            title: "External Tool Results".to_string(),
            rows: vec![TaskReportRow {
                name: "demo-tool".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("1.0.0".to_string()),
                after: Some("1.1.0".to_string()),
                note: None,
            }],
        }],
    };
    let categories = BTreeMap::new();

    let lines = render_package_change_rollup_with_width(
        [("external-tool", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::Failures,
        false,
        100,
    );
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Uncategorized"), "{text}");
    assert!(
        !text.contains("Unknown"),
        "missing task categories should not leak unknown labels:\n{text}"
    );
}

#[test]
fn package_change_rollup_sanitizes_control_characters_and_ansi_in_cells() {
    let result = TaskResult {
        label: "Yay".to_string(),
        status: TaskStatus::Failed,
        details: vec!["command failed".to_string()],
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "package_recovery".to_string(),
            title: "Package Recovery Actions".to_string(),
            rows: vec![TaskReportRow {
                name: "gibo-bin\nsource-drift-demo-bin".to_string(),
                status: TaskReportStatus::Failed,
                before: Some("\x1b[31msource/build\nfailure\x1b[0m".to_string()),
                after: Some("retry\rfailed".to_string()),
                note: Some("first line\n\x1b[32msecond\tline\x1b[0m".to_string()),
            }],
        }],
    };
    let categories = BTreeMap::from([("yay".to_string(), "system".to_string())]);

    let lines = render_package_change_rollup_with_width(
        [("yay", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        true,
        140,
    );

    for line in &lines {
        assert!(
            !line.text.contains(['\n', '\r', '\t']),
            "report lines must not contain embedded control separators: {:?}",
            line.text
        );
    }

    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("gibo-bin source-drift-demo-bin"), "{text}");
    assert!(text.contains("source/build failure"), "{text}");
    assert!(text.contains("retry failed"), "{text}");
    assert!(text.contains("first line second line"), "{text}");

    let table_lines = lines
        .iter()
        .map(|line| strip_ansi(&line.text))
        .filter(|line| matches!(line.chars().next(), Some('┌' | '├' | '│' | '└')))
        .collect::<Vec<_>>();
    let widths = table_lines
        .iter()
        .map(|line| UnicodeWidthStr::width(line.as_str()))
        .collect::<Vec<_>>();
    assert!(
        widths.windows(2).all(|pair| pair[0] == pair[1]),
        "expected aligned box widths:\n{}",
        table_lines.join("\n")
    );
}

#[test]
fn package_rollup_value_colors_follow_outcome() {
    let updated = PackageChangeRow {
        category: "system".to_string(),
        task: "Yay".to_string(),
        item: "foo".to_string(),
        before: "1.0.0".to_string(),
        after: "1.1.0".to_string(),
        result: "Updated".to_string(),
        note: String::new(),
        status: TaskReportStatus::Updated,
    };
    assert_eq!(
        package_rollup_value_colors(&updated),
        (
            Some(crossterm::style::Color::Red),
            Some(crossterm::style::Color::Green)
        )
    );

    let unchanged = PackageChangeRow {
        status: TaskReportStatus::Unchanged,
        before: "1.0.0".to_string(),
        after: "1.0.0".to_string(),
        ..updated.clone()
    };
    assert_eq!(package_rollup_value_colors(&unchanged), (None, None));

    let failed = PackageChangeRow {
        status: TaskReportStatus::Failed,
        before: "1.0.0".to_string(),
        after: "1.0.0".to_string(),
        ..updated.clone()
    };
    assert_eq!(package_rollup_value_colors(&failed), (None, None));

    let blocked = PackageChangeRow {
        status: TaskReportStatus::Blocked,
        before: "4.49.81".to_string(),
        after: "4.49.89".to_string(),
        ..updated.clone()
    };
    assert_eq!(
        package_rollup_value_colors(&blocked),
        (
            Some(crossterm::style::Color::Red),
            Some(crossterm::style::Color::Green)
        )
    );

    let removed = PackageChangeRow {
        status: TaskReportStatus::Skipped,
        before: "present".to_string(),
        after: "-".to_string(),
        ..updated
    };
    assert_eq!(package_rollup_value_colors(&removed), (None, None));
}

#[test]
fn package_rollup_value_colors_do_not_treat_recovery_states_as_versions() {
    let recovery = PackageChangeRow {
        category: "system".to_string(),
        task: "Yay".to_string(),
        item: "/home/example-user/.cache/yay/gibo-bin".to_string(),
        before: "present".to_string(),
        after: "removed".to_string(),
        result: "Removed".to_string(),
        note: "cleared package cache/worktree for gibo-bin".to_string(),
        status: TaskReportStatus::Skipped,
    };

    assert_eq!(package_rollup_value_colors(&recovery), (None, None));
}

#[test]
fn emit_task_report_logs_async_preserves_task_identity_for_changes_sections() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (raw_tx, rx) = mpsc::channel::<DashboardEvent>();
    let tx = DashboardSender::new(raw_tx, Some(run_log.clone()));
    let sections = vec![TaskReportSection {
        key: "arch_update_services".to_string(),
        title: "Arch-Update Service Results".to_string(),
        rows: vec![TaskReportRow {
            name: "sshd.service".to_string(),
            status: TaskReportStatus::Updated,
            before: Some("pending restart".to_string()),
            after: Some("restarted".to_string()),
            note: Some("selected interactively".to_string()),
        }],
    }];

    emit_task_report_logs_async(
        &tx,
        Some(&run_log),
        "arch-update-services",
        &sections,
        crate::config::NoteVerbosity::All,
    );

    let records = rx
        .try_iter()
        .map(|event| match event {
            DashboardEvent::LogLine(rec) => rec,
            other => panic!("unexpected dashboard event: {other:?}"),
        })
        .collect::<Vec<_>>();
    let task_log =
        fs::read_to_string(run_log.run_dir().join("task-arch-update-services.log")).unwrap();

    assert!(!records.is_empty(), "expected task report log events");
    assert!(records
        .iter()
        .all(|rec| rec.task_id == "arch-update-services"));
    assert!(records
        .iter()
        .any(|rec| rec.line.contains("Arch-Update Service Results")));
    assert!(records.iter().any(|rec| rec.line.contains("sshd.service")));
    assert!(
        task_log.contains("Arch-Update Service Results"),
        "missing async task section in task log:\n{task_log}"
    );
    assert!(
        task_log.contains("sshd.service"),
        "missing async task row in task log:\n{task_log}"
    );
}

#[test]
fn emit_task_outcome_log_async_records_completed_task_details() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (raw_tx, rx) = mpsc::channel::<DashboardEvent>();
    let tx = DashboardSender::new(raw_tx, Some(run_log.clone()));
    let mut result = TaskResult::completed("Completions");
    result.details.push(
        "[Completions] Audit passed: Completion Audit Summary: pass=13 warn=0 fail=0 skip=0"
            .to_string(),
    );
    result.details.push("strict=hybrid, discover=0".to_string());

    emit_task_outcome_log_async(&tx, Some(&run_log), "completions", &result);

    let records = rx
        .try_iter()
        .map(|event| match event {
            DashboardEvent::LogLine(rec) => rec,
            other => panic!("unexpected dashboard event: {other:?}"),
        })
        .collect::<Vec<_>>();
    let run_log_body = fs::read_to_string(run_log.run_dir().join("run.log")).unwrap();
    let task_log_body = fs::read_to_string(run_log.run_dir().join("task-completions.log")).unwrap();

    assert!(
        records
            .iter()
            .any(|rec| rec.line.contains("Completion Audit Summary")),
        "missing detail event records: {records:#?}"
    );
    assert!(
        run_log_body.contains("Completion Audit Summary"),
        "missing completed task detail in run log:\n{run_log_body}"
    );
    assert!(
        task_log_body.contains("Completion Audit Summary"),
        "missing completed task detail in task log:\n{task_log_body}"
    );
    assert!(
        task_log_body.contains("strict=hybrid, discover=0"),
        "missing secondary completed task detail in task log:\n{task_log_body}"
    );
}

#[test]
fn yay_recovery_sections_render_recovery_headers_and_statuses() {
    let section = TaskReportSection {
        key: "yay_recovery".to_string(),
        title: "Yay Recovery Actions".to_string(),
        rows: vec![
            TaskReportRow {
                name: "exodus".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("bulk conflict".to_string()),
                after: Some("installed individually".to_string()),
                note: None,
            },
            TaskReportRow {
                name: "pinokio-bin-debug".to_string(),
                status: TaskReportStatus::Updated,
                before: Some("installed".to_string()),
                after: Some("removed".to_string()),
                note: None,
            },
        ],
    };

    let lines = render_task_report_sections(&[section], false, crate::config::NoteVerbosity::All);
    assert!(lines
        .iter()
        .any(|l| l.text.contains("Yay Recovery Actions")));
    assert!(lines.iter().any(|l| l.text.contains("Item")));
    assert!(lines.iter().any(|l| l.text.contains("Result")));
    assert!(lines.iter().any(|l| l.text.contains("Recovered")));
}

#[test]
fn completion_sync_records_render_generation_rows() {
    let sync = CompletionSyncResult {
        generated: 1,
        unchanged: 1,
        skipped: 1,
        events: Vec::new(),
        records: vec![
            crate::completions::CompletionSyncRecord {
                provider: "npm".to_string(),
                tool: "codex".to_string(),
                status: CompletionSyncRecordStatus::Generated,
                artifact: Some(
                    "/home/example-user/.shellrc.d/shell/completions/_managed_npm_codex"
                        .to_string(),
                ),
                reason: None,
            },
            crate::completions::CompletionSyncRecord {
                provider: "npm".to_string(),
                tool: "just".to_string(),
                status: CompletionSyncRecordStatus::Unchanged,
                artifact: Some("/home/example-user/.shellrc.d/shell/completions/_just".to_string()),
                reason: Some("unchanged".to_string()),
            },
            crate::completions::CompletionSyncRecord {
                provider: "npm".to_string(),
                tool: "repomix".to_string(),
                status: CompletionSyncRecordStatus::Skipped,
                artifact: None,
                reason: Some("unsupported_generator".to_string()),
            },
        ],
        catalog_used: PathBuf::from("catalog.json"),
        effective_catalog: crate::completions::registry::Registry {
            schema_version: Some(1),
            providers: Vec::new(),
            tools: Vec::new(),
        },
    };

    let sections = completion_report_sections(&sync);
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].key, "completion_generation");
    assert_eq!(sections[0].rows.len(), 3);
    assert_eq!(sections[0].rows[0].status, TaskReportStatus::Updated);
    assert_eq!(sections[0].rows[1].status, TaskReportStatus::Unchanged);
    assert_eq!(sections[0].rows[2].status, TaskReportStatus::Skipped);
    let unchanged_row_json = serde_json::to_value(&sections[0].rows[1]).unwrap();
    assert_eq!(unchanged_row_json["status"], "unchanged");

    let lines = render_task_report_sections(&sections, false, crate::config::NoteVerbosity::All);
    let text = lines
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Completion Generation Results"), "{text}");
    assert!(text.contains("Tool"), "{text}");
    assert!(text.contains("Provider"), "{text}");
    assert!(text.contains("Artifact"), "{text}");
    assert!(text.contains("codex"), "{text}");
    assert!(text.contains("repomix"), "{text}");
    let codex_row = text.lines().find(|line| line.contains("codex")).unwrap();
    assert!(
        codex_row.contains("/home/example-user/.shellrc.d/shell/completions/_managed_npm_codex"),
        "{text}"
    );
    assert!(codex_row.contains("Generated"), "{text}");
    assert!(text.contains("unsupported_generator"), "{text}");
    let just_row = text.lines().find(|line| line.contains("just")).unwrap();
    assert!(just_row.contains("Unchanged"), "{text}");
    let repomix_row = text.lines().find(|line| line.contains("repomix")).unwrap();
    assert!(repomix_row.contains("Skipped"), "{text}");
    assert!(!repomix_row.contains("Unchanged"), "{text}");

    let result = TaskResult {
        label: "Completions".to_string(),
        status: TaskStatus::Completed,
        details: vec!["completion sync finished".to_string()],
        advisories: Vec::new(),
        report_sections: sections,
    };
    let summary = vec![("completions".to_string(), result)];
    let categories = BTreeMap::from([("completions".to_string(), "maintenance".to_string())]);

    let per_task_text = render_per_task_changes(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        true,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(per_task_text.contains("Tool"), "{per_task_text}");
    assert!(per_task_text.contains("Provider"), "{per_task_text}");
    assert!(per_task_text.contains("Artifact"), "{per_task_text}");
    assert!(per_task_text.contains("unchanged"), "{per_task_text}");
    assert!(
        !per_task_text.contains("unchanged: unchanged"),
        "{per_task_text}"
    );
    assert!(
        per_task_text.contains("skipped: unsupported_generator"),
        "{per_task_text}"
    );

    assert_eq!(
        summarize_task_items(&summary[0].1),
        "generated=1 unchanged=1 skipped=1"
    );
    let final_text = render_final_task_overview(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        true,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(
        final_text.contains("generated=1 unchanged=1 skipped=1"),
        "{final_text}"
    );

    let update_details_text = render_update_details(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        false,
        crate::config::NoteVerbosity::All,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(
        update_details_text.contains("Tool"),
        "{update_details_text}"
    );
    assert!(
        update_details_text.contains("Provider"),
        "{update_details_text}"
    );
    assert!(
        update_details_text.contains("Artifact"),
        "{update_details_text}"
    );
    assert!(
        update_details_text.contains("generated"),
        "{update_details_text}"
    );
}

#[test]
fn refreshed_report_rows_serialize_render_and_summarize() {
    let result = TaskResult {
        label: "Pipx".to_string(),
        status: TaskStatus::Completed,
        details: Vec::new(),
        advisories: Vec::new(),
        report_sections: vec![TaskReportSection {
            key: "pipx_packages".to_string(),
            title: "Pipx Package Results".to_string(),
            rows: vec![TaskReportRow {
                name: "markitdown".to_string(),
                status: TaskReportStatus::Refreshed,
                before: Some("0.1.6".to_string()),
                after: Some("0.1.6".to_string()),
                note: Some("pipx refreshed app".to_string()),
            }],
        }],
    };

    let row_json = serde_json::to_value(&result.report_sections[0].rows[0]).unwrap();
    assert_eq!(row_json["status"], "refreshed");
    assert_eq!(summarize_task_items(&result), "refreshed=1");

    let rendered = render_task_report_sections(
        &result.report_sections,
        false,
        crate::config::NoteVerbosity::All,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(rendered.contains("Refreshed"), "{rendered}");
    assert!(rendered.contains("0.1.6"), "{rendered}");
}

#[test]
fn refreshed_report_row_merge_preserves_state_probe_versions() {
    let mut section = TaskReportSection {
        key: "pipx_packages".to_string(),
        title: "Pipx Package Results".to_string(),
        rows: vec![TaskReportRow {
            name: "markitdown".to_string(),
            status: TaskReportStatus::Refreshed,
            before: None,
            after: None,
            note: Some("pipx refreshed app".to_string()),
        }],
    };

    append_report_pattern_row(
        &mut section,
        TaskReportRow {
            name: "markitdown".to_string(),
            status: TaskReportStatus::Unchanged,
            before: Some("0.1.6".to_string()),
            after: Some("0.1.6".to_string()),
            note: Some("state unchanged after update".to_string()),
        },
    );

    assert_eq!(section.rows.len(), 1);
    assert_eq!(section.rows[0].status, TaskReportStatus::Refreshed);
    assert_eq!(section.rows[0].before.as_deref(), Some("0.1.6"));
    assert_eq!(section.rows[0].after.as_deref(), Some("0.1.6"));
    assert_eq!(section.rows[0].note.as_deref(), Some("pipx refreshed app"));
}

#[test]
fn updated_report_row_merge_with_same_state_probe_becomes_refreshed() {
    let mut section = TaskReportSection {
        key: "pipx_packages".to_string(),
        title: "Pipx Package Results".to_string(),
        rows: vec![TaskReportRow {
            name: "markitdown".to_string(),
            status: TaskReportStatus::Updated,
            before: None,
            after: None,
            note: Some("pipx refreshed app".to_string()),
        }],
    };

    append_report_pattern_row(
        &mut section,
        TaskReportRow {
            name: "markitdown".to_string(),
            status: TaskReportStatus::Unchanged,
            before: Some("0.1.6".to_string()),
            after: Some("0.1.6".to_string()),
            note: Some("state unchanged after update".to_string()),
        },
    );

    assert_eq!(section.rows.len(), 1);
    assert_eq!(section.rows[0].status, TaskReportStatus::Refreshed);
    assert_eq!(section.rows[0].before.as_deref(), Some("0.1.6"));
    assert_eq!(section.rows[0].after.as_deref(), Some("0.1.6"));
    assert_eq!(section.rows[0].note.as_deref(), Some("pipx refreshed app"));
}

#[test]
fn completion_audit_output_is_reported_as_per_finding_rows() {
    let output = r#"Completion Audit Summary: pass=2 warn=1 fail=0 skip=1
PASS [codex] managed_overlay_ok: managed catalog overlay shim points at generated payload
PASS [codex] compinit_smoke_ok: completion autoload smoke check passed
WARN [privatebin] stale_flags: stale flags present: --old
SKIP [ghost] missing_command: command not installed; skipped help drift probe
"#;

    let section = completion_audit_report_section_from_output("warn", "0", output)
        .expect("expected completion audit report section");
    assert_eq!(section.key, "completion_audit");
    assert_eq!(section.rows.len(), 5);
    assert_eq!(section.rows[0].name, "completion-audit");
    assert_eq!(section.rows[0].status, TaskReportStatus::Info);
    assert_eq!(section.rows[1].name, "codex");
    assert_eq!(section.rows[1].status, TaskReportStatus::Passed);
    assert_eq!(
        section.rows[1].before.as_deref(),
        Some("managed_overlay_ok")
    );
    assert_eq!(
        section.rows[1].after.as_deref(),
        Some("managed catalog overlay shim points at generated payload")
    );
    assert_eq!(section.rows[3].status, TaskReportStatus::Blocked);
    assert_eq!(section.rows[4].status, TaskReportStatus::Skipped);

    let rendered = render_task_report_sections(
        std::slice::from_ref(&section),
        false,
        crate::config::NoteVerbosity::All,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(rendered.contains("Completion Audit Results"), "{rendered}");
    assert!(rendered.contains("Check"), "{rendered}");
    assert!(rendered.contains("Code"), "{rendered}");
    assert!(rendered.contains("Detail"), "{rendered}");
    let compinit_row = rendered
        .lines()
        .find(|line| line.contains("compinit") || line.contains("compinit_smok"))
        .unwrap();
    assert!(compinit_row.contains("compinit_smoke_ok"), "{rendered}");
    assert!(rendered.contains("Pass"), "{rendered}");
    assert!(rendered.contains("Warn"), "{rendered}");
    assert!(rendered.contains("Skip"), "{rendered}");

    let result = TaskResult {
        label: "Completions".to_string(),
        status: TaskStatus::Completed,
        details: vec!["completion audit finished".to_string()],
        advisories: Vec::new(),
        report_sections: vec![section],
    };
    let summary = vec![("completions".to_string(), result)];
    let categories = BTreeMap::from([("completions".to_string(), "maintenance".to_string())]);
    assert_eq!(
        summarize_task_items(&summary[0].1),
        "passed=2 warn=1 info=1 skipped=1"
    );

    let final_text = render_final_task_overview(
        summary.iter().map(|(id, result)| (id.as_str(), result)),
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(final_text.contains("passed=2"), "{final_text}");
    assert!(final_text.contains("warn=1"), "{final_text}");
    assert!(
        !final_text.contains("updated=2"),
        "audit passes should not be summarized as package updates:\n{final_text}"
    );
}

#[test]
fn completion_audit_unavailable_warns_without_failing_task() {
    let mut details = Vec::new();
    let mut report_sections = Vec::new();
    let mut advisories = Vec::new();
    let mut status = TaskStatus::Completed;

    record_completion_audit_unavailable(
        &mut details,
        &mut report_sections,
        &mut advisories,
        &mut status,
        "warn",
        "warn",
        "0",
        "missing script /tmp/rc-root/commands/zsh/completion_audit.zsh".to_string(),
    );

    assert_eq!(status, TaskStatus::Completed);
    assert_eq!(advisories.len(), 1);
    assert_eq!(advisories[0].severity, AdvisorySeverity::Warning);
    assert!(details[0].contains("Audit unavailable"));
    assert_eq!(report_sections.len(), 1);
    assert_eq!(report_sections[0].key, "completion_audit");
    assert_eq!(report_sections[0].rows[0].status, TaskReportStatus::Failed);
    assert_eq!(
        report_sections[0].rows[0].note.as_deref(),
        Some("missing script /tmp/rc-root/commands/zsh/completion_audit.zsh")
    );
}

#[test]
fn final_task_overview_summarizes_package_recovery_without_fake_updates() {
    let result = TaskResult {
        label: "Yay".to_string(),
        status: TaskStatus::Completed,
        details: vec![
            "upstream source/checksum drift left gibo-bin unresolved after automatic recovery"
                .to_string(),
        ],
        advisories: vec![TaskAdvisory {
            severity: AdvisorySeverity::Warning,
            code: "upstream-source-drift".to_string(),
            summary: "gibo-bin still fails source/build validation".to_string(),
            remediation: "fix the upstream package checksum, then retry".to_string(),
            blocks_dependents: false,
        }],
        report_sections: vec![TaskReportSection {
            key: "package_recovery".to_string(),
            title: "Package Recovery Actions".to_string(),
            rows: vec![
                TaskReportRow {
                    name: "/home/example-user/.cache/yay/gibo-bin".to_string(),
                    status: TaskReportStatus::Skipped,
                    before: Some("present".to_string()),
                    after: Some("removed".to_string()),
                    note: Some("cleared package cache/worktree for gibo-bin".to_string()),
                },
                TaskReportRow {
                    name: "gibo-bin".to_string(),
                    status: TaskReportStatus::Failed,
                    before: Some("source/build failure".to_string()),
                    after: Some("retry failed".to_string()),
                    note: Some("retry failed after cache/worktree cleanup".to_string()),
                },
                TaskReportRow {
                    name: "Pacman Recovery".to_string(),
                    status: TaskReportStatus::Info,
                    before: None,
                    after: None,
                    note: Some("source/checksum drift for source-drift-demo-bin".to_string()),
                },
                TaskReportRow {
                    name: "Pacman Recovery".to_string(),
                    status: TaskReportStatus::Blocked,
                    before: None,
                    after: None,
                    note: Some(
                        "package dependency conflict involving jack2, pipewire-jack".to_string(),
                    ),
                },
            ],
        }],
    };
    let categories = BTreeMap::from([("yay".to_string(), "system".to_string())]);

    assert_eq!(
        summarize_task_items(&result),
        "failed=1 info=1 blocked=1 removed=1 advisories=1"
    );

    let final_text = render_final_task_overview(
        [("yay", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");

    assert!(final_text.contains("failed=1"), "{final_text}");
    assert!(final_text.contains("info=1"), "{final_text}");
    assert!(
        !final_text.contains("updated=1"),
        "recovery cleanup must not be summarized as a package update:\n{final_text}"
    );
}

#[test]
fn final_task_overview_summarizes_legacy_recovered_package_row_without_fake_updates() {
    let mut result = TaskResult::completed("Yay");
    result.report_sections.push(TaskReportSection {
        key: "package_recovery".to_string(),
        title: "Package Recovery Actions".to_string(),
        rows: vec![TaskReportRow {
            name: "/home/example-user/.cache/yay/gibo-bin".to_string(),
            status: TaskReportStatus::Updated,
            before: Some("present".to_string()),
            after: Some("removed".to_string()),
            note: Some("cleared package cache/worktree for gibo-bin".to_string()),
        }],
    });
    let categories = BTreeMap::from([("yay".to_string(), "system".to_string())]);

    assert_eq!(summarize_task_items(&result), "recovered=1");

    let final_text = render_final_task_overview(
        [("yay", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");

    assert!(final_text.contains("recovered=1"), "{final_text}");
    assert!(
        !final_text.contains("updated=1"),
        "legacy package recovery rows must not be summarized as package updates:\n{final_text}"
    );
}

#[test]
fn final_task_overview_summarizes_task_execution_failure_items() {
    let result = failed_task_error_result(
        "Svc Restart",
        "arch-update-services",
        "sudo: a password is required",
    );
    let categories = BTreeMap::from([("arch-update-services".to_string(), "system".to_string())]);

    assert_eq!(summarize_task_items(&result), "failed=1");
    assert!(result.report_sections.iter().any(|section| {
        section.key == "task_failures"
            && section.title == "Task Failure Results"
            && section.rows.iter().any(|row| {
                row.name == "arch-update-services"
                    && row.status == TaskReportStatus::Failed
                    && row.note.as_deref() == Some("sudo: a password is required")
            })
    }));

    let final_text = render_final_task_overview(
        [("arch-update-services", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");

    assert!(final_text.contains("Svc Restart"), "{final_text}");
    assert!(final_text.contains("failed=1"), "{final_text}");
    assert!(
        !final_text.contains("| Failed | -"),
        "task execution failures should render a failed item summary:\n{final_text}"
    );
}

#[test]
fn attention_required_surfaces_warning_advisory_details() {
    let mut result = TaskResult::completed("Yay");
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "package-recovery-exclusions".to_string(),
        summary:
            "gibo-bin had unresolved package-level failures and was excluded from the resumed bulk update"
                .to_string(),
        remediation: "Inspect the package failure and fix the upstream package or keep it ignored."
            .to_string(),
        blocks_dependents: false,
    });
    let categories = BTreeMap::from([("yay".to_string(), "system".to_string())]);

    let text = render_attention_required([("yay", &result)], &categories, false)
        .iter()
        .map(|line| line.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");

    assert!(text.contains("Needs Attention"), "{text}");
    assert!(text.contains("Yay"), "{text}");
    assert!(text.contains("Warning"), "{text}");
    assert!(text.contains("gibo-bin"), "{text}");
    assert!(text.contains("Inspect the package failure"), "{text}");
}

#[test]
fn arch_update_service_rows_render_as_restarts_not_package_updates() {
    let mut result = TaskResult::completed("Svc Restart");
    result.report_sections.push(TaskReportSection {
        key: "arch_update_services".to_string(),
        title: "Arch-Update Service Results".to_string(),
        rows: vec![TaskReportRow {
            name: "sshd.service".to_string(),
            status: TaskReportStatus::Updated,
            before: Some("pending".to_string()),
            after: Some("restarted".to_string()),
            note: None,
        }],
    });
    let categories = BTreeMap::from([("arch-update-services".to_string(), "system".to_string())]);

    assert_eq!(summarize_task_items(&result), "restarted=1");

    let task_text = render_task_report_sections(
        &result.report_sections,
        false,
        crate::config::NoteVerbosity::All,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(task_text.contains("Restarted"), "{task_text}");

    let detail_text = render_update_details(
        [("arch-update-services", &result)],
        false,
        crate::config::NoteVerbosity::All,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(detail_text.contains("Svc Restart"), "{detail_text}");
    assert!(detail_text.contains("sshd.service"), "{detail_text}");
    assert!(detail_text.contains("restarted"), "{detail_text}");
    assert!(
        !detail_text.contains("updated"),
        "service restart details should not read like package updates:\n{detail_text}"
    );

    let final_text = render_final_task_overview(
        [("arch-update-services", &result)],
        &categories,
        false,
        crate::config::NoteVerbosity::All,
        false,
    )
    .iter()
    .map(|line| line.text.as_str())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(final_text.contains("restarted=1"), "{final_text}");
}

#[test]
fn version_lines_report_has_fallback_row_when_no_match() {
    let sections = parse_version_lines_report("checking uv...");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert!(!sections[0].rows.is_empty());
}

#[test]
fn version_lines_report_updated_self_update_captures_versions() {
    let sections = parse_version_lines_report(
        "success: Upgraded uv from v0.8.5 to v0.8.7! https://example.invalid",
    );
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "uv");
    assert_eq!(row.status, TaskReportStatus::Updated);
    assert_eq!(row.before.as_deref(), Some("v0.8.5"));
    assert_eq!(row.after.as_deref(), Some("v0.8.7"));
    assert_eq!(row.note, None);
}

#[test]
fn version_lines_report_updated_self_update_without_old_version_captures_target() {
    let sections =
        parse_version_lines_report("success: Upgraded uv to v0.8.7! https://example.invalid");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "uv");
    assert_eq!(row.status, TaskReportStatus::Updated);
    assert_eq!(row.before.as_deref(), Some("-"));
    assert_eq!(row.after.as_deref(), Some("v0.8.7"));
    assert_eq!(row.note, None);
}

#[test]
fn version_lines_report_latest_version_captures_installed_version() {
    let sections =
        parse_version_lines_report("success: You're on the latest version of uv (v0.8.7)");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "uv");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("v0.8.7"));
    assert_eq!(row.after.as_deref(), Some("v0.8.7"));
    assert_eq!(row.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn version_lines_report_latest_available_line_captures_tool_and_version() {
    let sections = parse_version_lines_report("qwen-code v0.15.11 is the latest version available");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "qwen-code");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("v0.15.11"));
    assert_eq!(row.after.as_deref(), Some("v0.15.11"));
    assert_eq!(row.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn version_lines_report_current_version_line_captures_tool_and_version() {
    let sections = parse_version_lines_report("qwen-code current version is v0.15.11");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "qwen-code");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("v0.15.11"));
    assert_eq!(row.after.as_deref(), Some("v0.15.11"));
    assert_eq!(row.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn version_lines_report_already_installed_line_captures_tool_and_version() {
    let sections = parse_version_lines_report("qwen-code is already installed at v0.15.11");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "qwen-code");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("v0.15.11"));
    assert_eq!(row.after.as_deref(), Some("v0.15.11"));
    assert_eq!(row.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn version_lines_report_already_at_version_line_captures_tool_and_version() {
    let sections = parse_version_lines_report("qwen-code is already at version v0.15.11");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "qwen-code");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("v0.15.11"));
    assert_eq!(row.after.as_deref(), Some("v0.15.11"));
    assert_eq!(row.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn version_lines_report_simple_version_lines_capture_tool_versions() {
    let sections = parse_version_lines_report("qwen-code version 0.15.11\nprivatebin: v1.2.3");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 2);

    let qwen = &sections[0].rows[0];
    assert_eq!(qwen.name, "qwen-code");
    assert_eq!(qwen.status, TaskReportStatus::Unchanged);
    assert_eq!(qwen.before.as_deref(), Some("0.15.11"));
    assert_eq!(qwen.after.as_deref(), Some("0.15.11"));
    assert_eq!(qwen.note.as_deref(), Some("reported current version"));

    let privatebin = &sections[0].rows[1];
    assert_eq!(privatebin.name, "privatebin");
    assert_eq!(privatebin.status, TaskReportStatus::Unchanged);
    assert_eq!(privatebin.before.as_deref(), Some("v1.2.3"));
    assert_eq!(privatebin.after.as_deref(), Some("v1.2.3"));
    assert_eq!(privatebin.note.as_deref(), Some("reported current version"));
}

#[test]
fn version_lines_report_simple_up_to_date_line_keeps_tool_name() {
    let sections = parse_version_lines_report("uv up-to-date");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "uv");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("-"));
    assert_eq!(row.after.as_deref(), Some("-"));
    assert_eq!(row.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn version_lines_report_multiple_noop_lines_keeps_each_tool_name() {
    let sections = parse_version_lines_report("uv up-to-date\nqwen-code already up to date");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 2);

    let uv = &sections[0].rows[0];
    assert_eq!(uv.name, "uv");
    assert_eq!(uv.status, TaskReportStatus::Unchanged);
    assert_eq!(uv.before.as_deref(), Some("-"));
    assert_eq!(uv.after.as_deref(), Some("-"));
    assert_eq!(uv.note.as_deref(), Some("already up-to-date"));

    let qwen = &sections[0].rows[1];
    assert_eq!(qwen.name, "qwen-code");
    assert_eq!(qwen.status, TaskReportStatus::Unchanged);
    assert_eq!(qwen.before.as_deref(), Some("-"));
    assert_eq!(qwen.after.as_deref(), Some("-"));
    assert_eq!(qwen.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn version_lines_report_mixed_update_and_noop_keeps_noop_row() {
    let sections = parse_version_lines_report("demo-tool: 1.2.3 -> 1.2.4\nuv up-to-date");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 2);

    let updated = &sections[0].rows[0];
    assert_eq!(updated.name, "demo-tool");
    assert_eq!(updated.status, TaskReportStatus::Updated);
    assert_eq!(updated.before.as_deref(), Some("1.2.3"));
    assert_eq!(updated.after.as_deref(), Some("1.2.4"));

    let noop = &sections[0].rows[1];
    assert_eq!(noop.name, "uv");
    assert_eq!(noop.status, TaskReportStatus::Unchanged);
    assert_eq!(noop.before.as_deref(), Some("-"));
    assert_eq!(noop.after.as_deref(), Some("-"));
    assert_eq!(noop.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn builtin_catalog_report_patterns_convert_to_command_report_sections() {
    let detected = BuiltinTask {
        id: "demo".to_string(),
        label: "Demo".to_string(),
        os: vec!["linux".to_string()],
        detect_mode: crate::updaters::BuiltinDetectionMode::Always,
        detect_any: Vec::new(),
        detect_all: Vec::new(),
        detect_all_windows: Vec::new(),
        skip_if_any: Vec::new(),
        skip_if_any_windows: Vec::new(),
        depends_on: Vec::new(),
        after: Vec::new(),
        requires_selected_any: Vec::new(),
        depends_on_selected: false,
        depends_on_selected_exclude: Vec::new(),
        resource_locks: Vec::new(),
        include_with: Vec::new(),
        enabled_by_default: true,
        category: "language".to_string(),
        order_rank: 20,
        report_parser: None,
        kind: BuiltinTaskKind::Command {
            program: "demo".to_string(),
            args: vec!["update".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: vec![BuiltinReportPattern {
                pattern: r"^(?P<name>\S+) (?P<before>\S+) -> (?P<after>\S+)$".to_string(),
                section_key: "demo_tools".to_string(),
                section_title: "Demo Tool Results".to_string(),
                status: "updated".to_string(),
                name: Some("{name}".to_string()),
                before: Some("{before}".to_string()),
                after: Some("{after}".to_string()),
                note: Some("from {before} to {after}".to_string()),
            }],
            report_scoped_deltas: Vec::new(),
            policy_key: "tool_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
        },
    };
    let spec = builtin_to_task_spec(detected, false);
    let TaskKind::Command(cmd) = spec.kind else {
        panic!("demo should convert to a command task");
    };

    let sections = build_command_report_sections_for_command(&cmd, "demo-tool 1.2.3 -> 1.2.4");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].key, "demo_tools");
    assert_eq!(sections[0].title, "Demo Tool Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "demo-tool");
    assert_eq!(row.status, TaskReportStatus::Updated);
    assert_eq!(row.before.as_deref(), Some("1.2.3"));
    assert_eq!(row.after.as_deref(), Some("1.2.4"));
    assert_eq!(row.note.as_deref(), Some("from 1.2.3 to 1.2.4"));
}

#[test]
fn report_patterns_copy_known_version_for_unchanged_missing_after_value() {
    let pattern = CommandReportPattern {
        regex: Regex::new(r"^(?P<name>\S+)\s+(?P<before>\S+)\s+No$").unwrap(),
        section_key: "demo_tools".to_string(),
        section_title: "Demo Tool Results".to_string(),
        status: TaskReportStatus::Unchanged,
        name: Some("{name}".to_string()),
        before: Some("{before}".to_string()),
        after: None,
        note: Some("unchanged".to_string()),
    };

    let rows = report_pattern_rows(&pattern, "demo-tool 1.2.3 No");

    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.name, "demo-tool");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("1.2.3"));
    assert_eq!(row.after.as_deref(), Some("1.2.3"));
    assert_eq!(row.note.as_deref(), Some("unchanged"));
}

#[test]
fn command_state_report_sections_diff_before_after_probe_output() {
    let pattern = CommandStateReportPattern {
        regex: Regex::new(r"^(?P<name>\S+) (?P<version>\S+)$").unwrap(),
        section_key: "demo_state".to_string(),
        section_title: "Demo State Results".to_string(),
        name: None,
        version: None,
        include_unchanged: true,
    };
    let before_versions = parse_command_state_report_versions(
        &pattern,
        "demo-tool 1.2.3\nsteady-tool 9.9.9\nremoved-tool 0.1.0\n",
    );
    let after_versions = parse_command_state_report_versions(
        &pattern,
        "demo-tool 1.2.4\nsteady-tool 9.9.9\nnew-tool 0.2.0\n",
    );

    let sections = build_command_state_report_sections(vec![
        CommandStateReportSample {
            command_index: 0,
            command_label: "demo list".to_string(),
            phase: CommandReportPhase::Before,
            section_key: pattern.section_key.clone(),
            section_title: pattern.section_title.clone(),
            include_unchanged: pattern.include_unchanged,
            versions: before_versions,
        },
        CommandStateReportSample {
            command_index: 0,
            command_label: "demo list".to_string(),
            phase: CommandReportPhase::After,
            section_key: pattern.section_key,
            section_title: pattern.section_title,
            include_unchanged: pattern.include_unchanged,
            versions: after_versions,
        },
    ]);

    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].key, "demo_state");
    let rows = &sections[0].rows;
    assert!(rows.iter().any(|row| {
        row.name == "demo-tool"
            && row.status == TaskReportStatus::Updated
            && row.before.as_deref() == Some("1.2.3")
            && row.after.as_deref() == Some("1.2.4")
    }));
    assert!(rows.iter().any(|row| {
        row.name == "steady-tool"
            && row.status == TaskReportStatus::Unchanged
            && row.before.as_deref() == Some("9.9.9")
            && row.after.as_deref() == Some("9.9.9")
    }));
    assert!(rows.iter().any(|row| {
        row.name == "new-tool"
            && row.status == TaskReportStatus::Updated
            && row.before.as_deref() == Some("-")
            && row.after.as_deref() == Some("0.2.0")
    }));
    assert!(rows.iter().any(|row| {
        row.name == "removed-tool"
            && row.status == TaskReportStatus::Failed
            && row.before.as_deref() == Some("0.1.0")
            && row.after.as_deref() == Some("-")
    }));
}

#[test]
fn command_state_report_ignores_available_annotation_when_version_is_unchanged() {
    let pattern = CommandStateReportPattern {
        regex: Regex::new(r"^(?P<name>\S+) (?P<version>.+)$").unwrap(),
        section_key: "cargo_state".to_string(),
        section_title: "Cargo State Results".to_string(),
        name: None,
        version: None,
        include_unchanged: true,
    };
    let before_versions = parse_command_state_report_versions(&pattern, "trunk v0.21.14\n");
    let after_versions = parse_command_state_report_versions(
        &pattern,
        "trunk v0.21.14 (v0.22.0-beta.1 available)\n",
    );

    let sections = build_command_state_report_sections(vec![
        CommandStateReportSample {
            command_index: 0,
            command_label: "cargo install --list".to_string(),
            phase: CommandReportPhase::Before,
            section_key: pattern.section_key.clone(),
            section_title: pattern.section_title.clone(),
            include_unchanged: pattern.include_unchanged,
            versions: before_versions,
        },
        CommandStateReportSample {
            command_index: 0,
            command_label: "cargo install --list".to_string(),
            phase: CommandReportPhase::After,
            section_key: pattern.section_key,
            section_title: pattern.section_title,
            include_unchanged: pattern.include_unchanged,
            versions: after_versions,
        },
    ]);

    assert_eq!(sections.len(), 1);
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.name, "trunk");
    assert_eq!(row.status, TaskReportStatus::Unchanged);
    assert_eq!(row.before.as_deref(), Some("v0.21.14"));
    assert_eq!(row.after.as_deref(), Some("v0.21.14"));
}

#[test]
fn command_state_report_preserves_non_available_parenthetical_versions() {
    let pattern = CommandStateReportPattern {
        regex: Regex::new(r"^(?P<name>\S+) (?P<version>.+)$").unwrap(),
        section_key: "rust_state".to_string(),
        section_title: "Rust State Results".to_string(),
        name: None,
        version: None,
        include_unchanged: true,
    };
    let versions = parse_command_state_report_versions(
        &pattern,
        "rustc rustc 1.95.0 (59807616e 2026-04-14)\n",
    );

    assert_eq!(
        versions.get("rustc").map(String::as_str),
        Some("rustc 1.95.0 (59807616e 2026-04-14)")
    );
}

#[test]
fn builtin_command_tasks_limit_report_parsers_to_foundation_managers() {
    let allowed_parser_tasks = BTreeMap::from([
        (
            "builtin/arch-update-services",
            BuiltinReportParser::ArchUpdateServices,
        ),
        ("builtin/scoop-all", BuiltinReportParser::Scoop),
        ("builtin/uv", BuiltinReportParser::VersionLines),
        ("builtin/winget-machine", BuiltinReportParser::Winget),
        ("builtin/winget-user", BuiltinReportParser::Winget),
        ("builtin/yay", BuiltinReportParser::Yay),
    ]);

    for task in crate::updaters::builtin_catalog().expect("builtin catalog") {
        let Some(parser) = task.report_parser else {
            continue;
        };

        assert_eq!(
            allowed_parser_tasks.get(task.id.as_str()).copied(),
            Some(parser),
            "built-in task {} should use generic report_patterns/report_commands instead of a bespoke parser",
            task.id
        );
    }
}

#[test]
fn rustup_builtin_uses_catalog_patterns_for_channel_report() {
    let rustup_task = crate::updaters::builtin_catalog()
        .expect("builtin catalog")
        .into_iter()
        .find(|task| task.id == "builtin/rustup")
        .expect("rustup task");
    let spec = builtin_to_task_spec(rustup_task, false);
    let TaskKind::Command(cmd) = spec.kind else {
        panic!("rustup should be a command task");
    };

    assert!(
        cmd.report_parser.is_none(),
        "rustup should use generic catalog report patterns, not a bespoke parser"
    );

    let sections = build_command_report_sections_for_command(
        &cmd,
        r#"
stable-x86_64-unknown-linux-gnu updated - rustc 1.94.0 (4a4ef493e 2026-03-02) (from rustc 1.93.1 (01f6ddf75 2026-02-11))
nightly-x86_64-unknown-linux-gnu unchanged - rustc 1.95.0-nightly (59807616e 2026-04-14)
"#,
    );

    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].key, "rustup_channels");
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 2, "{rows:?}");

    let stable = rows
        .iter()
        .find(|row| row.name == "stable-x86_64-unknown-linux-gnu")
        .expect("stable row");
    assert_eq!(stable.status, TaskReportStatus::Updated);
    assert_eq!(stable.before.as_deref(), Some("rustc 1.93.1"));
    assert_eq!(stable.after.as_deref(), Some("rustc 1.94.0"));
    assert_eq!(stable.note, None);

    let nightly = rows
        .iter()
        .find(|row| row.name == "nightly-x86_64-unknown-linux-gnu")
        .expect("nightly row");
    assert_eq!(nightly.status, TaskReportStatus::Unchanged);
    assert_eq!(
        nightly.before.as_deref(),
        Some("rustc 1.95.0-nightly (59807616e 2026-04-14)")
    );
    assert_eq!(
        nightly.after.as_deref(),
        Some("rustc 1.95.0-nightly (59807616e 2026-04-14)")
    );
    assert_eq!(nightly.note.as_deref(), Some("unchanged"));
}

#[test]
fn cargo_builtin_uses_catalog_patterns_for_install_update_report() {
    let cargo_task = crate::updaters::builtin_catalog()
        .expect("builtin catalog")
        .into_iter()
        .find(|task| task.id == "builtin/cargo")
        .expect("cargo task");
    let spec = builtin_to_task_spec(cargo_task, false);
    let TaskKind::Command(cmd) = spec.kind else {
        panic!("cargo should be a command task");
    };

    assert!(
        cmd.report_parser.is_none(),
        "cargo should use generic catalog report patterns, not a bespoke parser"
    );

    let sections = build_command_report_sections_for_command(
        &cmd,
        r#"
Package           Installed  Latest                               Needs update
cargo-deny        v0.19.6    v0.19.6                              No
trunk             v0.21.14   v0.21.14 (v0.22.0-beta.1 available)  No
wasm-pack         v0.15.0    v0.16.0                              Yes
Updating wasm-pack
    Updating crates.io index
     Locking 169 packages to latest compatible versions
      Adding generic-array v0.14.7 (available: v0.14.9)
warning: profile package spec `insta` in profile `dev` did not match any packages
help: a package with a similar name exists: `bstr`
    Finished `release` profile [optimized] target(s) in 1m 44s
   Replaced package `wasm-pack v0.15.0` with `wasm-pack v0.16.0` (executable `wasm-pack`)
No packages need updating.
Overall updated 1 packages.
"#,
    );

    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].key, "cargo_packages");
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 3, "{rows:?}");

    let cargo_deny = rows
        .iter()
        .find(|row| row.name == "cargo-deny")
        .expect("cargo-deny row");
    assert_eq!(cargo_deny.status, TaskReportStatus::Unchanged);
    assert_eq!(cargo_deny.before.as_deref(), Some("v0.19.6"));
    assert_eq!(cargo_deny.after.as_deref(), Some("v0.19.6"));

    let trunk = rows
        .iter()
        .find(|row| row.name == "trunk")
        .expect("trunk row");
    assert_eq!(trunk.status, TaskReportStatus::Unchanged);
    assert_eq!(trunk.before.as_deref(), Some("v0.21.14"));
    assert_eq!(trunk.after.as_deref(), Some("v0.21.14"));
    assert_eq!(trunk.note.as_deref(), Some("v0.22.0-beta.1 available"));

    let wasm_pack = rows
        .iter()
        .find(|row| row.name == "wasm-pack")
        .expect("wasm-pack row");
    assert_eq!(wasm_pack.status, TaskReportStatus::Updated);
    assert_eq!(wasm_pack.before.as_deref(), Some("v0.15.0"));
    assert_eq!(wasm_pack.after.as_deref(), Some("v0.16.0"));
}

#[test]
fn builtin_package_manager_catalog_patterns_extract_versions() {
    let tasks = crate::updaters::builtin_catalog().expect("builtin catalog");

    let command_for = |id: &str| {
        let qualified = format!("builtin/{id}");
        let task = tasks
            .iter()
            .find(|task| task.id == qualified)
            .unwrap_or_else(|| panic!("missing built-in task {id}"))
            .clone();
        let spec = builtin_to_task_spec(task, false);
        let TaskKind::Command(cmd) = spec.kind else {
            panic!("{id} should convert to a command task");
        };
        cmd
    };

    let sections_for = |id: &str, output: &str| {
        let cmd = command_for(id);
        build_command_report_sections_for_command(&cmd, output)
    };

    let cases = [
        (
            "apt",
            "Unpacking curl (8.5.0-2ubuntu10.6) over (8.5.0-2ubuntu10.4) ...",
            "apt_packages",
            "curl",
            Some("8.5.0-2ubuntu10.4"),
            Some("8.5.0-2ubuntu10.6"),
        ),
        (
            "dnf",
            "Upgrading        ripgrep        14.1.1-1.fc40        updates",
            "dnf_packages",
            "ripgrep",
            Some("-"),
            Some("14.1.1-1.fc40"),
        ),
        (
            "pacman",
            "upgrading ripgrep (14.1.0-1 -> 14.1.1-1)",
            "pacman_packages",
            "ripgrep",
            Some("14.1.0-1"),
            Some("14.1.1-1"),
        ),
        (
            "brew-formula",
            "ripgrep 14.1.0 -> 14.1.1",
            "brew_packages",
            "ripgrep",
            Some("14.1.0"),
            Some("14.1.1"),
        ),
        (
            "brew-cask",
            "==> Upgrading firefox from 125.0 to 126.0",
            "brew_packages",
            "firefox",
            Some("125.0"),
            Some("126.0"),
        ),
        (
            "choco",
            " - ripgrep v14.1.1",
            "choco_packages",
            "ripgrep",
            Some("-"),
            Some("14.1.1"),
        ),
    ];

    for (id, output, section_key, name, before, after) in cases {
        let sections = sections_for(id, output);
        assert_eq!(sections.len(), 1, "{id} sections: {sections:?}");
        assert_eq!(sections[0].key, section_key, "{id} section key");
        assert_eq!(sections[0].rows.len(), 1, "{id} rows: {sections:?}");
        let row = &sections[0].rows[0];
        assert_eq!(row.name, name, "{id} row name");
        assert_eq!(row.status, TaskReportStatus::Updated, "{id} row status");
        assert_eq!(row.before.as_deref(), before, "{id} before");
        assert_eq!(row.after.as_deref(), after, "{id} after");
    }

    let yay = command_for("yay");
    assert!(
        yay.pre_commands.iter().any(|cmd| {
            cmd.program == "/bin/sh"
                && cmd
                    .args
                    .iter()
                    .any(|arg| arg.contains("/var/lib/pacman/db.lck"))
        }),
        "yay should preflight the pacman database lock before invoking yay"
    );
    let sections = build_command_report_sections_for_command(
        &yay,
        "pacman database lock /var/lib/pacman/db.lck is present\n",
    );
    let section = sections
        .iter()
        .find(|section| section.key == "package_recovery")
        .unwrap_or_else(|| panic!("missing package recovery section: {sections:?}"));
    assert_eq!(section.rows.len(), 1, "yay lock rows: {sections:?}");
    let row = &section.rows[0];
    assert_eq!(row.name, "/var/lib/pacman/db.lck");
    assert_eq!(row.status, TaskReportStatus::Blocked);
    assert_eq!(
        row.note.as_deref(),
        Some("pacman database lock is present; verify no package manager is running before clearing stale locks")
    );
}

#[test]
fn version_lines_report_external_manager_skip_keeps_tool_name() {
    let sections = parse_version_lines_report(
        "error: qwen-code was installed through an external package manager and cannot update itself",
    );
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "qwen-code");
    assert_eq!(row.status, TaskReportStatus::Skipped);
    assert_eq!(row.before.as_deref(), Some("-"));
    assert_eq!(row.after.as_deref(), Some("-"));
    assert_eq!(
        row.note.as_deref(),
        Some("managed by external package manager")
    );

    let sections = parse_version_lines_report(
        "Self-update is only available for qwen-code binaries installed via the standalone installation scripts",
    );
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "qwen-code");
    assert_eq!(row.status, TaskReportStatus::Skipped);
    assert_eq!(
        row.note.as_deref(),
        Some("managed by external package manager")
    );
}

#[test]
fn version_lines_report_arrow_row_captures_tool_and_versions() {
    let sections = parse_version_lines_report("demo-tool: 1.2.3 -> 1.2.4");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "demo-tool");
    assert_eq!(row.status, TaskReportStatus::Updated);
    assert_eq!(row.before.as_deref(), Some("1.2.3"));
    assert_eq!(row.after.as_deref(), Some("1.2.4"));
    assert_eq!(row.note, None);
}

#[test]
fn version_lines_report_ignores_non_version_arrows() {
    let sections = parse_version_lines_report("path rewrite: /tmp/a -> /tmp/b");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Version Line Results");
    assert_eq!(sections[0].rows.len(), 1);
    let row = &sections[0].rows[0];
    assert_eq!(row.name, "version_lines");
    assert_eq!(row.status, TaskReportStatus::Info);
}

#[test]
fn yay_report_marks_noop_when_nothing_to_do() {
    let sections = parse_yay_report("there is nothing to do");
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Yay Package Results");
    assert_eq!(sections[0].rows.len(), 1);
    assert_eq!(sections[0].rows[0].status, TaskReportStatus::Unchanged);
}

#[test]
fn failed_yay_report_keeps_confirmed_transactions_updated() {
    let cmd = CommandTask {
        program: "yay".to_string(),
        args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "aur_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: false,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: Some(BuiltinReportParser::Yay),
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };
    let sections = build_failed_command_report_sections_for_command(
        &cmd,
        "1  extra/firefox  150.0-1 -> 151.0-1\n\
         2  aur/gibo-bin  3.0.16-2 -> 3.0.22-1\n\
         upgrading firefox...\n\
         ==> ERROR: One or more files did not pass the validity check!\n\
          -> error downloading sources: /home/me/.cache/yay/gibo-bin\n\
          -> error making: gibo-bin-exit status 1\n",
    );
    let rows = &sections
        .iter()
        .find(|section| section.key == "yay_packages")
        .expect("yay package report")
        .rows;

    let firefox = rows
        .iter()
        .find(|row| row.name == "extra/firefox")
        .expect("firefox row");
    assert_eq!(firefox.status, TaskReportStatus::Updated);
    assert_eq!(firefox.note, None);

    let gibo = rows
        .iter()
        .find(|row| row.name == "aur/gibo-bin")
        .expect("gibo row");
    assert_eq!(gibo.status, TaskReportStatus::Blocked);
    assert_eq!(
        gibo.note.as_deref(),
        Some("listed before failed transaction; update not confirmed")
    );
}

#[test]
fn yay_dependency_ignore_expansion_groups_failed_dependencies_with_dependents() {
    let expanded = expand_yay_dependency_ignore_targets(
        "    (make dependency of lib32-gst-plugins-base-libs, lib32-gstreamer)\n",
        &["lib32-gstreamer".to_string()],
    );

    assert_eq!(
        expanded,
        vec![
            "lib32-gst-plugins-base-libs".to_string(),
            "lib32-gstreamer".to_string()
        ]
    );
}

#[test]
fn yay_dependency_ignore_expansion_groups_failed_dependents_from_summary_rows() {
    let expanded = expand_yay_dependency_ignore_targets(
        r#"
1  aur/lib32-gst-plugins-base-libs  1.28.1-3 -> 1.28.3-1
2  aur/lib32-gstreamer              1.28.1-3 -> 1.28.3-1
3  aur/unrelated-bin                 9.9.8-1  -> 9.9.9-1
AUR Explicit (2): lib32-gst-plugins-base-libs-1.28.3-1, unrelated-bin-9.9.9-1
AUR Dependency (1): lib32-gstreamer-1.28.3-1
lib32-gstreamer - exit status 4
"#,
        &["lib32-gstreamer".to_string()],
    );

    assert_eq!(
        expanded,
        vec![
            "lib32-gst-plugins-base-libs".to_string(),
            "lib32-gstreamer".to_string()
        ]
    );
}

#[test]
fn go_builtin_uses_catalog_patterns_for_update_and_list_report() {
    let go_task = crate::updaters::builtin_catalog()
        .expect("builtin catalog")
        .into_iter()
        .find(|task| task.id == "builtin/go")
        .expect("go task");
    let spec = builtin_to_task_spec(go_task, false);
    let TaskKind::Command(cmd) = spec.kind else {
        panic!("go should be a command task");
    };

    assert!(
        cmd.report_parser.is_none(),
        "go should use generic catalog report patterns, not a bespoke parser"
    );

    let sections = build_command_report_sections_for_command(
        &cmd,
        r#"
[7/8] golang.org/x/tools/gopls (v0.21.1 to v0.22.0)
[8/8] github.com/example/tool (v1.2.3 -> v1.2.4)
gopls: golang.org/x/tools/gopls@v0.22.0
staticcheck: honnef.co/go/tools/cmd/staticcheck@v0.7.0
"#,
    );

    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].key, "go_tools");
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 3, "{rows:?}");

    let gopls = rows
        .iter()
        .find(|row| row.name == "golang.org/x/tools/gopls")
        .expect("gopls row");
    assert_eq!(gopls.status, TaskReportStatus::Updated);
    assert_eq!(gopls.before.as_deref(), Some("v0.21.1"));
    assert_eq!(gopls.after.as_deref(), Some("v0.22.0"));
    assert_eq!(gopls.note, None);

    let example = rows
        .iter()
        .find(|row| row.name == "github.com/example/tool")
        .expect("example tool row");
    assert_eq!(example.status, TaskReportStatus::Updated);
    assert_eq!(example.before.as_deref(), Some("v1.2.3"));
    assert_eq!(example.after.as_deref(), Some("v1.2.4"));

    let staticcheck = rows
        .iter()
        .find(|row| row.name == "honnef.co/go/tools/cmd/staticcheck")
        .expect("staticcheck row");
    assert_eq!(staticcheck.status, TaskReportStatus::Unchanged);
    assert_eq!(staticcheck.before.as_deref(), Some("v0.7.0"));
    assert_eq!(staticcheck.after.as_deref(), Some("v0.7.0"));
    assert_eq!(staticcheck.note.as_deref(), Some("already up-to-date"));
}

#[test]
fn builtin_go_report_patterns_capture_gup_check_failures() {
    let go_task = crate::updaters::builtin_catalog()
        .expect("builtin catalog")
        .into_iter()
        .find(|task| task.id == "builtin/go")
        .expect("go task");
    let spec = builtin_to_task_spec(go_task, false);
    let TaskKind::Command(cmd) = spec.kind else {
        panic!("go should be a command task");
    };

    let sections = build_command_report_sections_for_command(
        &cmd,
        r#"
update binary under $GOPATH/bin or $GOBIN
gup:ERROR: [1/2] staticcheck: can't check honnef.co/go/tools:
go: module honnef.co/go/tools: Get "https://proxy.golang.org/honnef.co/go/tools/@v/list": dial tcp: lookup proxy.golang.org: i/o timeout
gup:ERROR: [2/2] gopls: can't check golang.org/x/tools/gopls:
go: module golang.org/x/tools/gopls: Get "https://proxy.golang.org/golang.org/x/tools/gopls/@v/list": dial tcp: lookup proxy.golang.org: i/o timeout
"#,
    );

    let section = sections
        .iter()
        .find(|section| section.key == "go_tools")
        .expect("go failure rows should be reported");
    assert_eq!(section.title, "Go Tool Results");
    assert_eq!(section.rows.len(), 2);

    let row = &section.rows[0];
    assert_eq!(row.name, "honnef.co/go/tools");
    assert_eq!(row.status, TaskReportStatus::Failed);
    assert_eq!(row.before.as_deref(), Some("-"));
    assert_eq!(row.after.as_deref(), Some("-"));
    assert_eq!(row.note.as_deref(), Some("staticcheck: check failed"));

    let row = &section.rows[1];
    assert_eq!(row.name, "golang.org/x/tools/gopls");
    assert_eq!(row.status, TaskReportStatus::Failed);
    assert_eq!(row.before.as_deref(), Some("-"));
    assert_eq!(row.after.as_deref(), Some("-"));
    assert_eq!(row.note.as_deref(), Some("gopls: check failed"));
}

#[test]
fn yay_report_ignores_non_package_arrows_from_build_logs() {
    let sections = parse_yay_report(
        r#"
17  core/linux-lts                       6.12.75-1        -> 6.18.16-1
14  aur/brave-bin                        1:1.87.191-1     -> 1:1.87.192-1
673 |     pub(crate) fn to_dart(&self) -> Cow<'_, str> {
501 | pub fn get_portal(conn: &SyncConnection) -> Proxy<'_, &SyncConnection> {
"#,
    );

    assert_eq!(sections.len(), 1);
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "core/linux-lts");
    assert_eq!(rows[1].name, "aur/brave-bin");
}

#[test]
fn arch_update_services_report_tracks_restart_outcomes() {
    let sections = parse_arch_update_services_report(
        r#"
==> Services:
1 - sshd.service
2 - docker.service
-> Select the service(s) to restart (e.g. 1 3 5), select 0 to restart them all or press "enter" to continue without restarting the service(s):
==> The sshd.service service has been successfully restarted
==> ERROR: An error has occurred during the restart of the docker.service service
"#,
    );
    assert_eq!(sections.len(), 1);
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "sshd.service");
    assert_eq!(rows[0].status, TaskReportStatus::Updated);
    assert_eq!(rows[1].name, "docker.service");
    assert_eq!(rows[1].status, TaskReportStatus::Failed);
}

#[test]
fn arch_update_services_report_accepts_variant_service_list_formatting() {
    let sections = parse_arch_update_services_report(
        r#"
Services:
1) sshd.service
2: docker.service
Select services to restart, or press "enter" to continue without restarting:
sshd.service has been restarted successfully
ERROR: Failed to restart docker.service
"#,
    );
    assert_eq!(sections.len(), 1);
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "sshd.service");
    assert_eq!(rows[0].status, TaskReportStatus::Updated);
    assert_eq!(rows[1].name, "docker.service");
    assert_eq!(rows[1].status, TaskReportStatus::Failed);
}

#[test]
fn arch_update_services_report_emits_no_services_row() {
    let sections =
        parse_arch_update_services_report("No service requiring a post upgrade restart found");
    assert_eq!(sections.len(), 1);
    let rows = &sections[0].rows;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "services");
    assert_eq!(rows[0].status, TaskReportStatus::Unchanged);
    assert_eq!(
        rows[0].note.as_deref(),
        Some("no services required restart")
    );
}

#[test]
fn build_task_specs_runs_arch_update_services_last_after_yay() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from(["system".to_string()])),
    };

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("yay"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("arch-update"), "#!/bin/sh\nexit 0\n");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());
    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let arch = specs
        .iter()
        .find(|spec| spec.id == "builtin/arch-update-services")
        .expect("arch-update-services spec");
    assert_eq!(arch.depends_on, vec!["builtin/yay".to_string()]);
    let order: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(order, vec!["builtin/yay", "builtin/arch-update-services"]);
}

#[test]
fn build_task_specs_does_not_block_arch_update_services_on_language_tasks() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: None,
    };

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("yay"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("arch-update"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("rustup"), "#!/bin/sh\nexit 0\n");
    write_executable(
        &temp.path().join("cargo-install-update"),
        "#!/bin/sh\nexit 0\n",
    );
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());
    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let arch = specs
        .iter()
        .find(|spec| spec.id == "builtin/arch-update-services")
        .expect("arch-update-services spec");
    let cargo = specs
        .iter()
        .find(|spec| spec.id == "builtin/cargo")
        .expect("cargo spec");

    assert_eq!(arch.depends_on, vec!["builtin/yay".to_string()]);
    assert_eq!(cargo.depends_on, vec!["builtin/rustup".to_string()]);
}

#[test]
fn build_task_specs_keeps_explicit_pacman_when_yay_skip_rule_matches() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from(["builtin/pacman".to_string()])),
    };

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("yay"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("pacman"), "#!/bin/sh\nexit 0\n");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());
    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["builtin/pacman"],
        "explicit pacman selection should override default yay skip rule: {ids:?}"
    );
}

#[test]
fn build_task_specs_skips_arch_update_services_without_required_selected_yay() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: None,
    };

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("arch-update"), "#!/bin/sh\nexit 0\n");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());
    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert!(
        !ids.contains(&"builtin/arch-update-services"),
        "arch-update-services should stay out of automatic runs without yay: {ids:?}"
    );
}

#[test]
fn build_task_specs_only_system_does_not_bypass_required_selected_any() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from(["system".to_string()])),
    };

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("arch-update"), "#!/bin/sh\nexit 0\n");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());
    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert!(
        !ids.contains(&"builtin/arch-update-services"),
        "category selection should not direct-select arch-update-services without yay: {ids:?}"
    );
}

#[test]
fn build_task_specs_run_all_detected_false_does_not_materialize_legacy_npm_pipx() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: false,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: None,
    };

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("npm"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("npx"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("pipx"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("skills"), "#!/bin/sh\nexit 0\n");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());
    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(
        ids,
        Vec::<&str>::new(),
        "run_all_detected=false should not schedule legacy defaults: {ids:?}"
    );
}

#[test]
fn build_task_specs_expands_selected_category_dependencies() {
    let _lock = env_guard();

    let mut custom_tasks = BTreeMap::new();
    custom_tasks.insert(
        "after-system".to_string(),
        UpdaterTaskConfig {
            id: "after-system".to_string(),
            label: "After System".to_string(),
            os: vec!["linux".to_string()],
            detect_mode: UpdaterDetectionMode::AnyPresent,
            detect_any: vec!["after-system".to_string()],
            detect_all: Vec::new(),
            detect_all_windows: Vec::new(),
            skip_if_any: Vec::new(),
            skip_if_any_windows: Vec::new(),
            depends_on: vec!["system".to_string()],
            after: Vec::new(),
            requires_selected_any: Vec::new(),
            depends_on_selected: false,
            depends_on_selected_exclude: Vec::new(),
            resource_locks: Vec::new(),
            authority: None,
            command: "after-system".to_string(),
            args: Vec::new(),
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            enabled: true,
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            policy_key: "system_update".to_string(),
            category: "custom".to_string(),
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        },
    );
    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks,
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: None,
    };

    let temp = TempDir::new().unwrap();
    write_executable(&temp.path().join("yay"), "#!/bin/sh\nexit 0\n");
    write_executable(&temp.path().join("after-system"), "#!/bin/sh\nexit 0\n");
    let original_path = std::env::var_os("PATH");
    std::env::set_var("PATH", temp.path());
    let specs = build_task_specs(&flags, &HostOs::Linux, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }

    let after_system = specs
        .iter()
        .find(|spec| spec.id == "after-system")
        .expect("after-system spec");
    assert_eq!(after_system.depends_on, vec!["builtin/yay".to_string()]);

    let order: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert!(
        order.iter().position(|id| *id == "builtin/yay").unwrap()
            < order.iter().position(|id| *id == "after-system").unwrap(),
        "category dependency should order custom task after selected system tasks: {order:?}"
    );
}

#[test]
fn build_task_specs_keeps_explicit_windows_system_ids_when_only_disables_sections() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from([
            "builtin/winget-user".to_string(),
            "builtin/scoop-self".to_string(),
            "builtin/scoop-all".to_string(),
        ])),
    };

    let temp = TempDir::new().unwrap();
    write_executable(
        &temp.path().join("winget.cmd"),
        "@echo off\r\nexit /b 0\r\n",
    );
    write_executable(&temp.path().join("scoop.cmd"), "@echo off\r\nexit /b 0\r\n");
    write_executable(&temp.path().join("choco.cmd"), "@echo off\r\nexit /b 0\r\n");
    let original_path = std::env::var_os("PATH");
    let original_pathext = std::env::var_os("PATHEXT");
    std::env::set_var("PATH", temp.path());
    std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");
    let specs = build_task_specs(&flags, &HostOs::Windows, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }
    if let Some(pathext) = original_pathext {
        std::env::set_var("PATHEXT", pathext);
    } else {
        std::env::remove_var("PATHEXT");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "builtin/scoop-self",
            "builtin/scoop-all",
            "builtin/winget-user"
        ]
    );
}

#[test]
fn bootstrap_enabled_includes_windows_foundations_task() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: false,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: true,
            windows_foundations: vec!["scoop".to_string(), "powershell".to_string()],
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: None,
    };

    let specs = build_task_specs(&flags, &HostOs::Windows, &updater_config).expect("build specs");
    let bootstrap = specs
        .iter()
        .find(|spec| spec.id == "bootstrap-windows-foundations")
        .expect("bootstrap spec");
    assert!(bootstrap.depends_on.is_empty());
    match &bootstrap.kind {
        TaskKind::Managed(ManagedTaskExecutor::WindowsFoundations { foundations }) => {
            assert_eq!(
                foundations,
                &vec!["scoop".to_string(), "powershell".to_string()]
            );
        }
        _ => panic!("expected Windows bootstrap task"),
    }
}

#[test]
fn only_winget_expands_to_both_winget_scopes() {
    let _lock = env_guard();

    let updater_config = UpdaterConfig {
        run_all_detected: true,
        include: BTreeSet::new(),
        exclude: BTreeSet::new(),
        privilege_mode: crate::updaters::PrivilegeMode::PromptTty,
        custom_tasks: BTreeMap::new(),
        bootstrap: BootstrapConfig {
            enabled: false,
            windows_foundations: Vec::new(),
        },
    };
    let flags = Sections {
        exclude: BTreeSet::new(),
        only: Some(BTreeSet::from(["winget".to_string()])),
    };
    let temp = TempDir::new().unwrap();
    write_executable(
        &temp.path().join("winget.cmd"),
        "@echo off\r\nexit /b 0\r\n",
    );
    let original_path = std::env::var_os("PATH");
    let original_pathext = std::env::var_os("PATHEXT");
    std::env::set_var("PATH", temp.path());
    std::env::set_var("PATHEXT", ".COM;.EXE;.BAT;.CMD");
    let specs = build_task_specs(&flags, &HostOs::Windows, &updater_config).expect("build specs");
    if let Some(path) = original_path {
        std::env::set_var("PATH", path);
    } else {
        std::env::remove_var("PATH");
    }
    if let Some(pathext) = original_pathext {
        std::env::set_var("PATHEXT", pathext);
    } else {
        std::env::remove_var("PATHEXT");
    }

    let ids: Vec<&str> = specs.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(ids, vec!["builtin/winget-user", "builtin/winget-machine"]);
}

#[test]
fn task_order_groups_dependency_families_before_unrelated_roots() {
    let specs = vec![
        TaskSpec {
            id: "pipx".to_string(),
            label: "Pipx".to_string(),
            depends_on: vec![],
            kind: TaskKind::Command(CommandTask {
                program: "pipx".to_string(),
                args: vec!["upgrade-all".to_string()],
                mode: None,
                command_candidates: Vec::new(),
                pre_commands: Vec::new(),
                report_commands: Vec::new(),
                report_patterns: Vec::new(),
                report_scoped_deltas: Vec::new(),
                policy_key: "pipx_upgrade".to_string(),
                requires_elevation: false,
                needs_sudo_session: false,
                interactive: false,
                external_window: false,
                shell: false,
                windows_bridge: false,
                report_parser: None,
                plain_header: None,
                plain_start: None,
                success_details: Vec::new(),
                external_manager_skip: false,
                result_protocol: None,
            }),
            category: "language".to_string(),
            resource_locks: BTreeSet::new(),
        },
        TaskSpec {
            id: "skills".to_string(),
            label: "Skills".to_string(),
            depends_on: vec!["npm".to_string()],
            kind: TaskKind::Command(CommandTask {
                program: "skills".to_string(),
                args: vec!["update".to_string()],
                mode: Some("direct".to_string()),
                command_candidates: Vec::new(),
                pre_commands: Vec::new(),
                report_commands: Vec::new(),
                report_patterns: Vec::new(),
                report_scoped_deltas: Vec::new(),
                policy_key: "tool_update".to_string(),
                requires_elevation: false,
                needs_sudo_session: false,
                interactive: false,
                external_window: false,
                shell: false,
                windows_bridge: false,
                report_parser: None,
                plain_header: None,
                plain_start: None,
                success_details: Vec::new(),
                external_manager_skip: false,
                result_protocol: None,
            }),
            category: "language".to_string(),
            resource_locks: BTreeSet::new(),
        },
        TaskSpec {
            id: "npm".to_string(),
            label: "NPM".to_string(),
            depends_on: vec![],
            kind: TaskKind::Managed(ManagedTaskExecutor::Npm),
            category: "language".to_string(),
            resource_locks: BTreeSet::new(),
        },
    ];

    let ordered = order_task_specs(specs).expect("order specs");
    let ids: Vec<&str> = ordered.iter().map(|spec| spec.id.as_str()).collect();
    assert_eq!(ids, vec!["npm", "skills", "pipx"]);
}

#[test]
fn package_manager_failure_formats_conflicting_file_owner_hint() {
    let detail = format_package_manager_failure(
        "yay exited non-zero (code=1); output: error: failed to commit transaction (conflicting files) insync-dolphin: /usr/share/icons/hicolor/scalable/emblems/emblem-insync-syncing.svg exists in filesystem (owned by insync-emblem-icons) Errors occurred, no packages were upgraded.",
    )
    .expect("expected conflict summary");

    assert!(detail.contains(
        "package install transaction hit conflicting files owned by insync-emblem-icons"
    ));
    assert!(detail.contains("remove or reconcile the conflicting package(s), then retry"));
}

#[test]
fn package_manager_conflict_owner_collection_deduplicates_matches() {
    let owners = collect_conflict_owners(
        "foo exists in filesystem (owned by pkg-a) bar exists in filesystem (owned by pkg-a) baz exists in filesystem (owned by pkg-b)",
    );

    assert_eq!(owners, vec!["pkg-a".to_string(), "pkg-b".to_string()]);
}

#[test]
fn pacman_conflict_parser_extracts_target_path_and_owner() {
    let records = parse_pacman_conflict_records(
        "error: failed to commit transaction (conflicting files)\ninsync-dolphin: /usr/share/icons/foo.svg exists in filesystem (owned by insync-emblem-icons)\nexodus-debug: /usr/lib/debug/.build-id/be/abc.debug exists in filesystem (owned by pinokio-bin-debug)",
    );

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].target, "insync-dolphin");
    assert_eq!(records[0].path, "/usr/share/icons/foo.svg");
    assert_eq!(records[0].owner, "insync-emblem-icons");
    assert_eq!(records[1].target, "exodus-debug");
    assert_eq!(records[1].owner, "pinokio-bin-debug");
    assert!(!records[1].transaction_internal);
}

#[test]
fn pacman_conflict_parser_extracts_exists_in_both_shape() {
    let records = parse_pacman_conflict_records(
        "error: failed to commit transaction (conflicting files)\nfoo-debug: /usr/lib/debug/foo.debug exists in both 'foo-debug' and 'bar-debug'",
    );

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target, "foo-debug");
    assert_eq!(records[0].path, "/usr/lib/debug/foo.debug");
    assert_eq!(records[0].owner, "bar-debug");
    assert!(!records[0].transaction_internal);
}

#[test]
fn pacman_conflict_parser_extracts_unprefixed_exists_in_both_shape() {
    let records = parse_pacman_conflict_records(
        "error: failed to commit transaction (conflicting files)\n/usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b exists in both 'mullvad-vpn-bin-debug' and 'pinokio-bin-debug'",
    );

    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target, "mullvad-vpn-bin-debug");
    assert_eq!(
        records[0].path,
        "/usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b"
    );
    assert_eq!(records[0].owner, "pinokio-bin-debug");
    assert!(records[0].transaction_internal);
}

#[test]
fn run_artifact_records_task_end_and_ui_wait_timing() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let mut task_result = TaskResult::completed("Yay");
    task_result
        .details
        .push("Updated 1 package; recovery not needed".to_string());
    task_result.report_sections.push(TaskReportSection {
        key: "yay_packages".to_string(),
        title: "Yay Package Results".to_string(),
        rows: vec![TaskReportRow {
            name: "demo-bin".to_string(),
            status: TaskReportStatus::Updated,
            before: Some("1.2.3".to_string()),
            after: Some("1.2.4".to_string()),
            note: None,
        }],
    });
    let tasks_completed_unix_ms = run_log.started_unix_ms();
    let tasks_ended_unix_ms = tasks_completed_unix_ms + 1;

    write_run_artifact(
        Some(&run_log),
        "linux",
        "dashboard",
        "async",
        vec!["yay".to_string()],
        [("yay", &task_result)],
        tasks_ended_unix_ms,
        0,
        tasks_completed_unix_ms,
    );
    let first_payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_log.run_dir().join("run.json")).unwrap())
            .unwrap();
    let first_artifact_updated = first_payload["artifact_updated_unix_ms"].as_u64().unwrap();
    std::thread::sleep(Duration::from_millis(5));

    write_run_artifact(
        Some(&run_log),
        "linux",
        "dashboard",
        "async",
        vec!["yay".to_string()],
        [("yay", &task_result)],
        tasks_ended_unix_ms,
        0,
        tasks_completed_unix_ms,
    );

    let payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_log.run_dir().join("run.json")).unwrap())
            .unwrap();
    assert_eq!(
        payload["tasks_ended_unix_ms"].as_u64(),
        Some(tasks_ended_unix_ms)
    );
    assert_eq!(
        payload["tasks_completed_unix_ms"].as_u64(),
        Some(tasks_completed_unix_ms)
    );
    assert_eq!(
        payload["ended_unix_ms"].as_u64(),
        Some(tasks_ended_unix_ms),
        "ended_unix_ms should stop at task/report completion, not dashboard linger: {payload}"
    );
    let artifact_updated = payload["artifact_updated_unix_ms"].as_u64().unwrap();
    assert!(artifact_updated >= first_artifact_updated);
    assert!(artifact_updated >= tasks_ended_unix_ms);
    assert_eq!(
        payload["tasks_elapsed_ms"].as_u64(),
        Some(tasks_completed_unix_ms - run_log.started_unix_ms())
    );
    assert_eq!(
        payload["ui_wait_ms"].as_u64(),
        Some(artifact_updated - tasks_ended_unix_ms)
    );
    assert_eq!(
        payload["tasks"][0]["report_sections"][0]["key"],
        "yay_packages"
    );
    assert_eq!(
        payload["tasks"][0]["report_sections"][0]["rows"][0]["name"],
        "demo-bin"
    );
    assert_eq!(
        payload["tasks"][0]["report_sections"][0]["rows"][0]["status"],
        "updated"
    );
    assert_eq!(
        payload["tasks"][0]["details"][0],
        "Updated 1 package; recovery not needed"
    );
    assert!(payload["run_id"].as_str().is_some_and(|id| id.len() == 36));
    assert_eq!(payload["display_name"], payload["run_id"]);
    let meta_payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_log.run_dir().join("run-meta.json")).unwrap())
            .unwrap();
    assert_eq!(meta_payload["run_id"], payload["run_id"]);
    assert_eq!(meta_payload["display_name"], payload["display_name"]);
    assert_eq!(meta_payload["status"], "completed");
}

#[test]
fn run_artifact_records_runtime_log_viewer_failure_advisory() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    run_log
        .write_raw(&LogRecord {
            ts_unix_ms: 1,
            task_id: "runtime".to_string(),
            level: LogLevel::Warn,
            stream: LogStream::Meta,
            line: "log viewer failed: less exited with status 2".to_string(),
        })
        .unwrap();
    let task_result = TaskResult::completed("Yay");
    let tasks_completed_unix_ms = run_log.started_unix_ms();
    let tasks_ended_unix_ms = tasks_completed_unix_ms + 1;

    write_run_artifact(
        Some(&run_log),
        "linux",
        "dashboard",
        "async",
        vec!["yay".to_string()],
        [("yay", &task_result)],
        tasks_ended_unix_ms,
        0,
        tasks_completed_unix_ms,
    );

    let payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_log.run_dir().join("run.json")).unwrap())
            .unwrap();
    let advisories = payload["runtime_advisories"].as_array().unwrap();
    assert_eq!(advisories.len(), 1);
    assert_eq!(advisories[0]["code"], "runtime-log-viewer-failed");
    assert_eq!(advisories[0]["severity"], "warning");
    assert!(advisories[0]["remediation"]
        .as_str()
        .is_some_and(|text| text.contains("less exited with status 2")));
}

#[test]
fn run_artifact_records_top_level_issue_summary() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let mut completion_result = TaskResult::completed("Completions");
    completion_result.report_sections.push(TaskReportSection {
        key: "completion_audit".to_string(),
        title: "Completion Audit".to_string(),
        rows: vec![TaskReportRow {
            name: "repomix".to_string(),
            status: TaskReportStatus::Failed,
            before: None,
            after: None,
            note: Some("managed overlay missing".to_string()),
        }],
    });
    let mut npm_result = TaskResult::completed("NPM");
    npm_result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Info,
        code: "npm-deprecated-package".to_string(),
        summary: "npm warn deprecated uuid@10.0.0".to_string(),
        remediation: "Review the deprecated dependency chain.".to_string(),
        blocks_dependents: false,
    });
    let tasks_completed_unix_ms = run_log.started_unix_ms();
    let tasks_ended_unix_ms = tasks_completed_unix_ms + 1;

    write_run_artifact(
        Some(&run_log),
        "linux",
        "dashboard",
        "async",
        vec!["completions".to_string(), "npm".to_string()],
        [("completions", &completion_result), ("npm", &npm_result)],
        tasks_ended_unix_ms,
        0,
        tasks_completed_unix_ms,
    );

    let payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_log.run_dir().join("run.json")).unwrap())
            .unwrap();
    assert_eq!(payload["schema_version"], 1);
    assert_eq!(payload["completed_with_issues"], true);
    assert_eq!(payload["issue_count"], 1);
    assert_eq!(payload["failed_task_count"], 0);
    assert_eq!(payload["canceled_task_count"], 0);
    assert_eq!(
        payload["tasks"][0]["completed_with_issues"], true,
        "task-level issue marker should remain available"
    );
    assert_eq!(
        payload["tasks"][1]["completed_with_issues"], false,
        "info advisories should not become run issues"
    );
}

#[test]
fn external_manager_version_parser_prefers_labeled_command_version() {
    let output = "build date 2026-07-08\nuv version 0.11.11 (stub linux)\n";

    let parsed = parse_external_manager_version_output("uv", output);

    assert_eq!(parsed.as_deref(), Some("0.11.11"));
}

#[test]
fn external_manager_version_parser_rejects_date_like_banner_tokens() {
    let output = "Build Date: 2026-07-08\ncommit 20260708\nrelease date 2026.07.08\n";

    let parsed = parse_external_manager_version_output("uv", output);

    assert_eq!(parsed, None);
}

#[test]
fn color_policy_disables_ansi_for_no_color_non_tty_and_dumb_term() {
    assert!(!terminal_supports_color(
        true,
        true,
        Some("xterm-256color"),
        true
    ));
    assert!(!terminal_supports_color(
        false,
        false,
        Some("xterm-256color"),
        true
    ));
    assert!(!terminal_supports_color(true, false, Some("dumb"), true));
    assert!(terminal_supports_color(
        true,
        false,
        Some("xterm-256color"),
        true
    ));
}

#[test]
fn run_artifact_detail_falls_back_to_report_row_summary() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let mut task_result = TaskResult::completed("Cargo");
    task_result.report_sections.push(TaskReportSection {
        key: "cargo_packages".to_string(),
        title: "Cargo Package Results".to_string(),
        rows: vec![
            TaskReportRow {
                name: "cargo-deny".to_string(),
                status: TaskReportStatus::Skipped,
                before: Some("v0.19.6".to_string()),
                after: Some("v0.19.6".to_string()),
                note: None,
            },
            TaskReportRow {
                name: "trunk".to_string(),
                status: TaskReportStatus::Skipped,
                before: Some("v0.21.14".to_string()),
                after: Some("v0.21.14".to_string()),
                note: Some("v0.22.0-beta.1 available".to_string()),
            },
        ],
    });
    let tasks_completed_unix_ms = run_log.started_unix_ms();

    write_run_artifact(
        Some(&run_log),
        "linux",
        "plain",
        "sync",
        vec!["cargo".to_string()],
        [("cargo", &task_result)],
        tasks_completed_unix_ms,
        0,
        tasks_completed_unix_ms,
    );

    let payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_log.run_dir().join("run.json")).unwrap())
            .unwrap();
    assert_eq!(payload["tasks"][0]["detail"], "skipped=2", "{payload}");
}

#[test]
fn task_artifact_detail_falls_back_to_report_row_summary() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let mut task_result = TaskResult::completed("Cargo");
    task_result.report_sections.push(TaskReportSection {
        key: "cargo_packages".to_string(),
        title: "Cargo Package Results".to_string(),
        rows: vec![
            TaskReportRow {
                name: "cargo-deny".to_string(),
                status: TaskReportStatus::Skipped,
                before: Some("v0.19.6".to_string()),
                after: Some("v0.19.6".to_string()),
                note: None,
            },
            TaskReportRow {
                name: "trunk".to_string(),
                status: TaskReportStatus::Skipped,
                before: Some("v0.21.14".to_string()),
                after: Some("v0.21.14".to_string()),
                note: Some("v0.22.0-beta.1 available".to_string()),
            },
        ],
    });

    write_task_result_artifact(Some(&run_log), "cargo", &task_result);

    let payload: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(run_log.run_dir().join("task-cargo.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(payload["detail"], "skipped=2", "{payload}");
}

#[test]
fn structured_failure_evidence_is_bounded_while_task_log_retains_full_output() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let full_output = format!("classified failure: {}", "x".repeat(4_096));
    run_log
        .write_record(&LogRecord {
            ts_unix_ms: 1,
            task_id: "fixture".to_string(),
            level: LogLevel::Error,
            stream: LogStream::Stderr,
            line: full_output.clone(),
        })
        .unwrap();
    let task_result = TaskResult::failed("Fixture", full_output.clone());

    write_task_result_artifact(Some(&run_log), "fixture", &task_result);
    let completed_unix_ms = run_log.started_unix_ms();
    write_run_artifact(
        Some(&run_log),
        "linux",
        "plain",
        "sync",
        vec!["fixture".to_string()],
        [("fixture", &task_result)],
        completed_unix_ms,
        1,
        completed_unix_ms,
    );

    let payload: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(run_log.run_dir().join("task-fixture.json")).unwrap(),
    )
    .unwrap();
    assert!(payload["detail"].as_str().unwrap().len() <= STRUCTURED_TEXT_LIMIT_BYTES);
    assert!(payload["details"][0].as_str().unwrap().len() <= STRUCTURED_TEXT_LIMIT_BYTES);
    assert_eq!(payload["log_file"], "task-fixture.log");
    let run_payload: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(run_log.run_dir().join("run.json")).unwrap())
            .unwrap();
    assert!(
        run_payload["tasks"][0]["detail"].as_str().unwrap().len() <= STRUCTURED_TEXT_LIMIT_BYTES
    );
    assert_eq!(run_payload["tasks"][0]["log_file"], "task-fixture.log");
    let task_log = fs::read_to_string(run_log.run_dir().join("task-fixture.log")).unwrap();
    assert!(task_log.contains(&full_output), "{task_log}");
}

#[test]
fn completed_task_outcome_summarizes_report_rows_when_details_are_empty() {
    let mut task_result = TaskResult::completed("Cargo");
    task_result.report_sections.push(TaskReportSection {
        key: "cargo_packages".to_string(),
        title: "Cargo Package Results".to_string(),
        rows: vec![
            TaskReportRow {
                name: "cargo-deny".to_string(),
                status: TaskReportStatus::Skipped,
                before: Some("v0.19.6".to_string()),
                after: Some("v0.19.6".to_string()),
                note: None,
            },
            TaskReportRow {
                name: "trunk".to_string(),
                status: TaskReportStatus::Skipped,
                before: Some("v0.21.14".to_string()),
                after: Some("v0.21.14".to_string()),
                note: Some("v0.22.0-beta.1 available".to_string()),
            },
        ],
    });

    assert_eq!(
        task_outcome_message(&task_result),
        "task outcome: completed - skipped=2"
    );
}

#[test]
fn task_run_lock_uses_shared_run_root_and_releases_on_drop() {
    let temp = TempDir::new().unwrap();
    let first_run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let second_run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let lock_path = temp.path().join(".update-all-task-run.lock");

    let first_lock = acquire_task_run_lock(Some(&first_run_log))
        .unwrap()
        .unwrap();
    assert!(lock_path.is_file());

    let err = acquire_task_run_lock(Some(&second_run_log))
        .unwrap_err()
        .to_string();
    assert!(err.contains("update-all task lock is held"), "{err}");

    drop(first_lock);
    assert!(!lock_path.exists());

    let second_lock = acquire_task_run_lock(Some(&second_run_log))
        .unwrap()
        .unwrap();
    assert!(lock_path.is_file());
    drop(second_lock);
    assert!(!lock_path.exists());
}

#[test]
fn task_run_lock_is_optional_without_run_log() {
    assert!(acquire_task_run_lock(None).unwrap().is_none());
}

#[test]
fn namespaced_task_ids_write_flat_owner_only_artifact_names() {
    let temp = TempDir::new().unwrap();
    let run_log = RunLogSink::new(temp.path(), false).unwrap();
    let record = LogRecord {
        ts_unix_ms: 1,
        task_id: "syscfg/example-tool".to_string(),
        level: LogLevel::Info,
        stream: LogStream::Meta,
        line: "checked".to_string(),
    };

    run_log.write_raw(&record).unwrap();
    run_log.write_record(&record).unwrap();

    assert!(run_log
        .run_dir()
        .join("task-syscfg%2Fexample-tool.raw.log")
        .is_file());
    assert!(run_log
        .run_dir()
        .join("task-syscfg%2Fexample-tool.log")
        .is_file());
    assert!(!run_log.run_dir().join("task-syscfg").exists());
}

#[test]
fn structured_command_result_marks_a_successful_process_as_deferred() {
    let mut result = TaskResult::completed("Example Tool");
    assert!(apply_structured_command_result(
        &mut result,
        "deferred: still running\nUPDATE_ALL_RESULT {\"outcome\":\"deferred\",\"detail\":\"quit the background process\",\"current\":\"3.0.2\",\"latest\":\"3.0.3\"}\n",
    ));

    assert_eq!(result.status, TaskStatus::Completed);
    assert!(result.is_deferred());
    assert_eq!(result.details[0], "quit the background process");
    assert!(result
        .details
        .contains(&"version: 3.0.2 -> 3.0.3".to_string()));
}

#[test]
fn structured_command_result_rejects_missing_or_malformed_payloads() {
    let mut missing = TaskResult::completed("Missing");
    assert!(!apply_structured_command_result(
        &mut missing,
        "ordinary output\n"
    ));

    let mut malformed = TaskResult::completed("Malformed");
    assert!(!apply_structured_command_result(
        &mut malformed,
        "UPDATE_ALL_RESULT {not-json}\n",
    ));
}

#[test]
fn async_completion_boundary_precedes_end_report_logs() {
    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    let event_tx = DashboardSender::new(raw_event_tx, None);
    let mut categories = BTreeMap::new();
    categories.insert("demo".to_string(), "language".to_string());
    let mut result = TaskResult::completed("Demo");
    result.report_sections.push(TaskReportSection {
        key: "demo_packages".to_string(),
        title: "Demo Package Results".to_string(),
        rows: vec![TaskReportRow {
            name: "demo-tool".to_string(),
            status: TaskReportStatus::Updated,
            before: Some("1.0.0".to_string()),
            after: Some("1.1.0".to_string()),
            note: None,
        }],
    });

    emit_async_completion_boundary_and_reports(
        &event_tx,
        None,
        [("demo", &result)],
        &categories,
        crate::config::NoteVerbosity::All,
        false,
        AsyncRunOutcome::Success,
        Instant::now(),
    );
    drop(event_tx);

    let events: Vec<DashboardEvent> = event_rx.try_iter().collect();
    let run_complete_idx = events
        .iter()
        .position(|event| matches!(event, DashboardEvent::RunComplete { .. }))
        .expect("run-complete event");
    let first_report_idx = events
        .iter()
        .position(|event| {
            matches!(
                event,
                DashboardEvent::LogLine(rec)
                    if rec.line.contains("Package Change Rollup")
                        || rec.line.contains("Final Task Overview")
            )
        })
        .expect("end report log event");

    assert!(
        run_complete_idx < first_report_idx,
        "dashboard elapsed should freeze at task completion before report logs stream: {events:#?}"
    );
}

#[test]
fn dashboard_sender_records_detachment_once_and_stays_in_plain_fallback() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    drop(event_rx);
    let event_tx = DashboardSender::new(raw_event_tx, Some(run_log.clone()));

    assert!(event_tx
        .send(DashboardEvent::TaskStateChanged {
            id: "builtin/demo".to_string(),
            state: TaskState::Running,
            detail: None,
        })
        .is_err());
    assert!(event_tx.is_detached());
    assert!(event_tx
        .send(DashboardEvent::TaskStateChanged {
            id: "builtin/demo".to_string(),
            state: TaskState::Completed,
            detail: Some("updated".to_string()),
        })
        .is_err());

    let run_text = fs::read_to_string(run_log.run_dir().join("run.log")).unwrap();
    let events = fs::read_to_string(run_log.run_dir().join("events.jsonl")).unwrap();
    assert_eq!(
        run_text.matches("frontend_detached:").count(),
        1,
        "{run_text}"
    );
    assert!(run_text.contains("switched to plain output"), "{run_text}");
    assert_eq!(events.matches("frontend_detached").count(), 1, "{events}");
}

#[test]
fn prompt_events_are_journaled_without_answer_content() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    let event_tx = DashboardSender::new(raw_event_tx, Some(run_log.clone()));

    event_tx
        .send(DashboardEvent::TaskInputStateChanged {
            id: "builtin/yay".to_string(),
            enabled: true,
        })
        .unwrap();
    event_rx.recv().unwrap();
    assert!(journal_ui_control(
        &event_tx,
        &UiControlEvent::SendStdin {
            id: "builtin/yay".to_string(),
            line: "private answer".to_string(),
        },
    ));

    let events = fs::read_to_string(run_log.run_dir().join("events.jsonl")).unwrap();
    assert!(events.contains("prompt_requested"), "{events}");
    assert!(events.contains("prompt_answered"), "{events}");
    assert!(events.contains("character_count"), "{events}");
    assert!(!events.contains("private answer"), "{events}");
}

#[test]
fn journal_failure_blocks_dashboard_delivery_without_faking_detachment() {
    let temp = TempDir::new().unwrap();
    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    let event_tx = DashboardSender::new(raw_event_tx, Some(run_log.clone()));
    run_log.inject_journal_fault_for_test();

    assert!(event_tx
        .send(DashboardEvent::TaskStateChanged {
            id: "builtin/demo".to_string(),
            state: TaskState::Running,
            detail: None,
        })
        .is_err());
    assert!(event_rx.try_recv().is_err());
    assert!(!event_tx.is_detached());
    assert!(event_tx.journal_error().is_some());
}

#[test]
fn forced_cancel_join_waits_for_running_task_thread() {
    let (task_started_tx, task_started_rx) = mpsc::channel();
    let (release_task_tx, release_task_rx) = mpsc::channel();
    let (helper_done_tx, helper_done_rx) = mpsc::channel();
    let task_finished = Arc::new(AtomicBool::new(false));
    let task_finished_thread = Arc::clone(&task_finished);

    let handle = std::thread::spawn(move || {
        task_started_tx.send(()).unwrap();
        release_task_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        task_finished_thread.store(true, Ordering::SeqCst);
        TaskResult::completed("Slow Task")
    });
    task_started_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap();

    let helper_thread = std::thread::spawn(move || {
        let result = join_forced_canceled_task("slow".to_string(), handle);
        helper_done_tx.send(result).unwrap();
    });

    assert!(
        helper_done_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "forced cancel helper returned before the running task thread exited"
    );
    release_task_tx.send(()).unwrap();
    let result = helper_done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    helper_thread.join().unwrap();

    assert!(task_finished.load(Ordering::SeqCst));
    assert_eq!(result.label, "Slow Task");
    assert_eq!(result.status, TaskStatus::Canceled);
    assert_eq!(
        result.details,
        vec!["forced shutdown after cancel-all grace timeout".to_string()]
    );
}

#[cfg(unix)]
#[test]
fn completed_dashboard_open_log_control_runs_pager_and_resumes_dashboard() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let marker = temp.path().join("pager-args");
    fs::create_dir_all(&bin_dir).unwrap();
    write_executable(
        &bin_dir.join("less"),
        r#"#!/bin/sh
printf '%s\n' "$*" > "${PAGER_MARKER:?missing marker}"
exit 0
"#,
    );

    let original_path = std::env::var_os("PATH");
    let original_marker = std::env::var_os("PAGER_MARKER");
    std::env::set_var("PATH", &bin_dir);
    std::env::set_var("PAGER_MARKER", &marker);

    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    fs::write(run_log.run_dir().join("task-npm.log"), "npm log\n").unwrap();
    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    let event_tx = DashboardSender::new(raw_event_tx, Some(run_log.clone()));
    let ack_thread = std::thread::spawn(move || {
        let mut saw_suspend = false;
        let mut saw_resume = false;
        while !(saw_suspend && saw_resume) {
            match event_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(DashboardEvent::UiSuspendRequested { ack, .. }) => {
                    saw_suspend = true;
                    if let Some(ack) = ack {
                        let _ = ack.send(());
                    }
                }
                Ok(DashboardEvent::UiResumeRequested { ack }) => {
                    saw_resume = true;
                    if let Some(ack) = ack {
                        let _ = ack.send(());
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        (saw_suspend, saw_resume)
    });

    handle_completed_run_ui_control(
        UiControlEvent::OpenLog {
            target: LogViewTarget::Task {
                id: "npm".to_string(),
            },
        },
        &event_tx,
        Some(&run_log),
    );
    drop(event_tx);
    let (saw_suspend, saw_resume) = ack_thread.join().unwrap();

    match original_path {
        Some(path) => std::env::set_var("PATH", path),
        None => std::env::remove_var("PATH"),
    }
    match original_marker {
        Some(marker) => std::env::set_var("PAGER_MARKER", marker),
        None => std::env::remove_var("PAGER_MARKER"),
    }

    assert!(saw_suspend, "dashboard was not suspended before pager");
    assert!(saw_resume, "dashboard was not resumed after pager");
    let pager_args = fs::read_to_string(marker).unwrap();
    assert!(pager_args.contains("+F"), "{pager_args}");
    assert!(pager_args.contains("-K"), "{pager_args}");
    assert!(pager_args.contains("task-npm.log"), "{pager_args}");
}

#[cfg(unix)]
#[test]
fn active_log_viewer_join_waits_for_foreground_pager_to_exit() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let marker = temp.path().join("pager-args");
    let release = temp.path().join("pager-release");
    fs::create_dir_all(&bin_dir).unwrap();
    write_executable(
        &bin_dir.join("less"),
        r#"#!/bin/sh
printf '%s\n' "$*" > "${PAGER_MARKER:?missing marker}"
while [ ! -f "${PAGER_RELEASE:?missing release}" ]; do
  /usr/bin/sleep 0.05
done
exit 0
"#,
    );

    let original_path = std::env::var_os("PATH");
    let original_marker = std::env::var_os("PAGER_MARKER");
    let original_release = std::env::var_os("PAGER_RELEASE");
    std::env::set_var("PATH", &bin_dir);
    std::env::set_var("PAGER_MARKER", &marker);
    std::env::set_var("PAGER_RELEASE", &release);

    let run_log = Arc::new(RunLogSink::new(temp.path(), false).unwrap());
    fs::write(run_log.run_dir().join("task-npm.log"), "npm log\n").unwrap();
    let (raw_event_tx, event_rx) = mpsc::channel::<DashboardEvent>();
    let event_tx = DashboardSender::new(raw_event_tx, Some(run_log.clone()));
    let ack_thread = std::thread::spawn(move || {
        let mut saw_suspend = false;
        let mut saw_resume = false;
        while !(saw_suspend && saw_resume) {
            match event_rx.recv_timeout(Duration::from_secs(2)) {
                Ok(DashboardEvent::UiSuspendRequested { ack, .. }) => {
                    saw_suspend = true;
                    if let Some(ack) = ack {
                        let _ = ack.send(());
                    }
                }
                Ok(DashboardEvent::UiResumeRequested { ack }) => {
                    saw_resume = true;
                    if let Some(ack) = ack {
                        let _ = ack.send(());
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        (saw_suspend, saw_resume)
    });

    let mut active_log_viewer = None;
    handle_active_open_log_control(
        &event_tx,
        Some(&run_log),
        LogViewTarget::Task {
            id: "npm".to_string(),
        },
        &mut active_log_viewer,
    );
    wait_for_file(&marker);
    assert!(
        active_log_viewer
            .as_ref()
            .is_some_and(|handle| !handle.is_finished()),
        "pager thread exited before release marker was written"
    );

    fs::write(&release, "").unwrap();
    join_active_log_viewer(&mut active_log_viewer);
    assert!(active_log_viewer.is_none());
    drop(event_tx);
    let (saw_suspend, saw_resume) = ack_thread.join().unwrap();

    match original_path {
        Some(path) => std::env::set_var("PATH", path),
        None => std::env::remove_var("PATH"),
    }
    match original_marker {
        Some(marker) => std::env::set_var("PAGER_MARKER", marker),
        None => std::env::remove_var("PAGER_MARKER"),
    }
    match original_release {
        Some(release) => std::env::set_var("PAGER_RELEASE", release),
        None => std::env::remove_var("PAGER_RELEASE"),
    }

    assert!(saw_suspend, "dashboard was not suspended before pager");
    assert!(saw_resume, "dashboard was not resumed after pager");
    let pager_args = fs::read_to_string(marker).unwrap();
    assert!(pager_args.contains("+F"), "{pager_args}");
    assert!(pager_args.contains("-K"), "{pager_args}");
    assert!(pager_args.contains("task-npm.log"), "{pager_args}");
}

#[test]
fn log_pager_less_args_follow_and_exit_on_interrupt() {
    let args = log_pager_args(LogPagerKind::Less, Path::new("task-yay.log"))
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(args, vec!["+F", "-K", "-R", "-S", "task-yay.log"]);
}

#[test]
fn log_pager_tail_args_follow_from_start() {
    let args = log_pager_args(LogPagerKind::Tail, Path::new("run.log"))
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    assert_eq!(args, vec!["-n", "+1", "-f", "run.log"]);
}

#[cfg(unix)]
#[test]
fn log_pager_prefers_live_tail_fallback_before_static_bat() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let bin_dir = temp.path().join("bin");
    let marker = temp.path().join("pager-choice");
    let log_file = temp.path().join("task-demo.log");
    fs::create_dir_all(&bin_dir).unwrap();
    fs::write(&log_file, "demo log\n").unwrap();
    write_executable(
        &bin_dir.join("tail"),
        r#"#!/bin/sh
printf 'tail %s\n' "$*" > "${PAGER_MARKER:?missing marker}"
exit 0
"#,
    );
    write_executable(
        &bin_dir.join("bat"),
        r#"#!/bin/sh
printf 'bat %s\n' "$*" > "${PAGER_MARKER:?missing marker}"
exit 0
"#,
    );

    let original_path = std::env::var_os("PATH");
    let original_marker = std::env::var_os("PAGER_MARKER");
    std::env::set_var("PATH", &bin_dir);
    std::env::set_var("PAGER_MARKER", &marker);

    run_log_pager(&log_file).expect("pager should launch");

    match original_path {
        Some(path) => std::env::set_var("PATH", path),
        None => std::env::remove_var("PATH"),
    }
    match original_marker {
        Some(marker) => std::env::set_var("PAGER_MARKER", marker),
        None => std::env::remove_var("PAGER_MARKER"),
    }

    let choice = fs::read_to_string(marker).unwrap();
    assert!(choice.starts_with("tail "), "{choice}");
    assert!(choice.contains("-f"), "{choice}");
    assert!(
        choice.contains(log_file.to_string_lossy().as_ref()),
        "{choice}"
    );
}

#[test]
fn unprefixed_debug_conflicts_do_not_build_owner_removal_plan() {
    let plan = build_yay_recovery_plan(
        "error: failed to commit transaction (conflicting files)\n/usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b exists in both 'mullvad-vpn-bin-debug' and 'pinokio-bin-debug'\n/usr/lib/debug/.build-id/be/ffc50b8076e4eac5a913fca05e8f10eb93fa0b.debug exists in both 'mullvad-vpn-bin-debug' and 'pinokio-bin-debug'",
    );

    assert_eq!(plan, None);
}

#[test]
fn package_recovery_classifier_covers_common_manager_failures() {
    let pacman = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        "error: failed to commit transaction (conflicting files)\nfoo: /x exists in filesystem (owned by bar)",
    )
    .expect("pacman classification");
    assert!(matches!(
        pacman.causes[0],
        recovery::RecoveryCause::FileConflict { .. }
    ));

    let pacman_dependency_conflict = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        "error: unresolvable package conflicts detected\n:: jack2-1.9.22-2 and pipewire-jack-1:1.6.5-1 are in conflict\nerror: failed to prepare transaction (conflicting dependencies)",
    )
    .expect("pacman package conflict classification");
    assert!(matches!(
        &pacman_dependency_conflict.causes[0],
        recovery::RecoveryCause::PackageConflict { packages, pairs }
            if packages == &vec!["jack2".to_string(), "pipewire-jack".to_string()]
                && pairs.is_empty()
    ));

    let repository_retirement = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        ":: replacement-core-2.0-1 and retired-addon-1.0-1 are in conflict. Remove retired-addon? [y/N]\nerror: unresolvable package conflicts detected\nerror: failed to prepare transaction (conflicting dependencies)",
    )
    .expect("repository retirement conflict classification");
    assert_eq!(
        repository_retirement.actions,
        vec![recovery::RecoveryAction::VerifiedRepositoryRetirement]
    );
    assert!(matches!(
        &repository_retirement.causes[0],
        recovery::RecoveryCause::PackageConflict { pairs, .. }
            if pairs == &vec![recovery::PackageConflictPair {
                incoming: "replacement-core".to_string(),
                remove: "retired-addon".to_string(),
            }]
    ));

    let retirement_with_unrelated_error = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        ":: replacement-core-2.0-1 and retired-addon-1.0-1 are in conflict. Remove retired-addon? [y/N]\nerror: unresolvable package conflicts detected\nerror: failed retrieving file 'unrelated.db'",
    )
    .expect("mixed repository retirement classification");
    assert_eq!(
        retirement_with_unrelated_error.actions,
        vec![recovery::RecoveryAction::DiagnoseOnly]
    );

    let retirement_with_lock = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        ":: replacement-core-2.0-1 and retired-addon-1.0-1 are in conflict. Remove retired-addon? [y/N]\nerror: unresolvable package conflicts detected\nerror: failed to prepare transaction (conflicting dependencies)\n/var/lib/pacman/db.lck is present",
    )
    .expect("locked repository retirement classification");
    assert_eq!(
        retirement_with_lock.actions,
        vec![recovery::RecoveryAction::DiagnoseOnly]
    );
    assert!(retirement_with_lock
        .causes
        .iter()
        .any(|cause| matches!(cause, recovery::RecoveryCause::LockOrBusy { .. })));

    let pacman_mixed_failure = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        "error: unresolvable package conflicts detected\n:: jack2-1.9.22-2 and pipewire-jack-1:1.6.5-1 are in conflict\n==> ERROR: One or more files did not pass the validity check!\n -> error downloading sources: /home/me/.cache/yay/gibo-bin\nerror downloading sources: /home/me/.cache/yay/source-drift-demo-bin\n -> error making: gibo-bin-exit status 1",
    )
    .expect("pacman mixed failure classification");
    assert!(pacman_mixed_failure
        .causes
        .iter()
        .any(|cause| matches!(cause, recovery::RecoveryCause::PackageConflict { .. })));
    assert!(pacman_mixed_failure.causes.iter().any(|cause| matches!(
        cause,
        recovery::RecoveryCause::SourceChecksumDrift {
            package: Some(package)
        } if package == "gibo-bin"
    )));
    assert!(pacman_mixed_failure.causes.iter().any(|cause| matches!(
        cause,
        recovery::RecoveryCause::SourceChecksumDrift {
            package: Some(package)
        } if package == "source-drift-demo-bin"
    )));

    let pacman_build_failure = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        "meson.build:26:4: ERROR: Problem encountered: PTP not supported without Rust compiler\n==> ERROR: A failure occurred in build().\n -> error making: lib32-gstreamer - exit status 4",
    )
    .expect("pacman build failure classification");
    assert!(pacman_build_failure.causes.iter().any(|cause| matches!(
        cause,
        recovery::RecoveryCause::BuildFailure {
            package: Some(package),
            summary,
        } if package == "lib32-gstreamer" && summary.contains("PTP not supported without Rust compiler")
    )));
    assert!(
        !pacman_build_failure
            .causes
            .iter()
            .any(|cause| matches!(cause, recovery::RecoveryCause::SourceChecksumDrift { .. })),
        "plain AUR build failures should not be classified as upstream source/checksum drift"
    );

    let pacman_db_lock = recovery::classify_package_recovery(
        recovery::PackageManagerKind::PacmanLike,
        " -> /var/lib/pacman/db.lck is present.",
    )
    .expect("pacman lock classification");
    assert_eq!(
        pacman_db_lock.actions,
        vec![recovery::RecoveryAction::RetryWhole]
    );
    assert!(matches!(
        pacman_db_lock.causes[0],
        recovery::RecoveryCause::LockOrBusy { .. }
    ));

    let npm = recovery::classify_package_recovery(
        recovery::PackageManagerKind::Npm,
        "npm install failed",
    )
    .expect("npm classification");
    assert_eq!(
        npm.actions,
        vec![recovery::RecoveryAction::RetryIndividually]
    );

    let winget = recovery::classify_package_recovery(
        recovery::PackageManagerKind::Winget,
        "Installer hash does not match.",
    )
    .expect("winget classification");
    assert!(matches!(
        winget.causes[0],
        recovery::RecoveryCause::InstallerHashMismatch
    ));

    let scoop = recovery::classify_package_recovery(
        recovery::PackageManagerKind::Scoop,
        "ERROR The following instances of \"pwsh\" are still running. Close them and try again.",
    )
    .expect("scoop classification");
    assert!(matches!(
        &scoop.causes[0],
        recovery::RecoveryCause::RunningProcess { packages } if packages == &vec!["pwsh".to_string()]
    ));

    let apt = recovery::classify_package_recovery(
        recovery::PackageManagerKind::Apt,
        "Could not get lock /var/lib/dpkg/lock-frontend",
    )
    .expect("apt classification");
    assert_eq!(apt.actions, vec![recovery::RecoveryAction::RetryWhole]);
}

#[test]
fn repository_retirement_retry_removes_refresh_and_adds_only_conflict_answer() {
    let args = vec![
        "-Syyu".to_string(),
        "--noconfirm".to_string(),
        "--color".to_string(),
        "never".to_string(),
    ];
    assert_eq!(
        normalize_repository_retirement_retry_args(&args),
        Some(vec![
            "-Su".to_string(),
            "--noconfirm".to_string(),
            "--color".to_string(),
            "never".to_string(),
            "--ask=4".to_string(),
        ])
    );
    assert!(normalize_repository_retirement_retry_args(&[
        "-Syu".to_string(),
        "--ask=8".to_string(),
    ])
    .is_none());
}

#[test]
fn original_recovery_diagnostics_keep_non_source_blockers_visible() {
    let plan = recovery::RecoveryPlan::diagnose(
        recovery::PackageManagerKind::PacmanLike,
        vec![
            recovery::RecoveryCause::SourceChecksumDrift {
                package: Some("gibo-bin".to_string()),
            },
            recovery::RecoveryCause::SourceChecksumDrift {
                package: Some("source-drift-demo-bin".to_string()),
            },
            recovery::RecoveryCause::PackageConflict {
                packages: vec!["jack2".to_string(), "pipewire-jack".to_string()],
                pairs: Vec::new(),
            },
        ],
    );
    let mut rows = vec![TaskReportRow {
        name: "gibo-bin".to_string(),
        status: TaskReportStatus::Failed,
        before: Some("source/build failure".to_string()),
        after: Some("retry failed".to_string()),
        note: Some("retry failed".to_string()),
    }];

    let summaries =
        append_original_recovery_diagnostics(&mut rows, Some(&plan), &["gibo-bin".to_string()]);
    assert_eq!(
        summaries,
        vec![
            "source/checksum drift for source-drift-demo-bin".to_string(),
            "package dependency conflict involving jack2, pipewire-jack".to_string(),
        ]
    );
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[1].name, "source-drift-demo-bin");
    assert_eq!(rows[1].status, TaskReportStatus::Info);
    assert_eq!(
        rows[1].note.as_deref(),
        Some("source/checksum drift for source-drift-demo-bin")
    );
    assert_eq!(rows[2].name, "jack2, pipewire-jack");
    assert_eq!(rows[2].status, TaskReportStatus::Blocked);
    assert_eq!(
        rows[2].note.as_deref(),
        Some("package dependency conflict involving jack2, pipewire-jack")
    );

    let mut result = TaskResult::completed_with_advisory(
        "Yay",
        "upstream source/checksum drift left gibo-bin unresolved after automatic recovery",
        TaskAdvisory {
            severity: AdvisorySeverity::Warning,
            code: "upstream-source-drift".to_string(),
            summary: "gibo-bin still fails source/build validation after cache/worktree cleanup and one focused retry".to_string(),
            remediation: "retry after the upstream package is fixed".to_string(),
            blocks_dependents: false,
        },
    );
    annotate_unresolved_recovery_diagnostics(&mut result, &summaries);

    assert_eq!(result.status, TaskStatus::Failed);
    assert!(result
        .details
        .iter()
        .any(|detail| detail.contains("source-drift-demo-bin")));
    assert!(result
        .advisories
        .first()
        .unwrap()
        .summary
        .contains("package dependency conflict involving jack2, pipewire-jack"));
}

#[test]
fn original_recovery_diagnostics_do_not_duplicate_handled_build_failures() {
    let plan = recovery::RecoveryPlan::diagnose(
        recovery::PackageManagerKind::PacmanLike,
        vec![recovery::RecoveryCause::BuildFailure {
            package: Some("demo-bin".to_string()),
            summary: "AUR build() failed".to_string(),
        }],
    );
    let mut rows = Vec::new();

    let summaries =
        append_original_recovery_diagnostics(&mut rows, Some(&plan), &["demo-bin".to_string()]);

    assert!(summaries.is_empty());
    assert!(rows.is_empty());
}

#[test]
fn yay_source_recovery_plan_ignores_mismatched_source_path_for_target_package() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let home_dir = temp.path().join("home");
    let original_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home_dir.as_os_str());
    let gibo_cache = home_dir.join(".cache").join("yay").join("gibo-bin");
    let drift_demo_cache = home_dir
        .join(".cache")
        .join("yay")
        .join("source-drift-demo-bin");

    let plan = build_yay_package_recovery_plan(
        &format!(
            "==> ERROR: One or more files did not pass the validity check!\n\
              -> error downloading sources: {}\n\
              -> error making: gibo-bin-exit status 1",
            drift_demo_cache.display()
        ),
        None,
    )
    .expect("source recovery plan");

    let package_names = plan
        .packages
        .iter()
        .map(|package_plan| package_plan.package.as_str())
        .collect::<Vec<_>>();
    assert_eq!(package_names, vec!["gibo-bin", "source-drift-demo-bin"]);
    let gibo_plan = plan
        .packages
        .iter()
        .find(|package_plan| package_plan.package == "gibo-bin")
        .expect("gibo package plan");
    let drift_demo_plan = plan
        .packages
        .iter()
        .find(|package_plan| package_plan.package == "source-drift-demo-bin")
        .expect("drift demo package plan");
    assert!(
        gibo_plan
            .cleanup_paths
            .contains(&gibo_cache.to_string_lossy().to_string()),
        "{:?}",
        gibo_plan.cleanup_paths
    );
    assert!(
        !gibo_plan
            .cleanup_paths
            .contains(&drift_demo_cache.to_string_lossy().to_string()),
        "source recovery must keep cleanup paths scoped per package: {:?}",
        gibo_plan.cleanup_paths
    );
    assert!(
        drift_demo_plan
            .cleanup_paths
            .contains(&drift_demo_cache.to_string_lossy().to_string()),
        "{:?}",
        drift_demo_plan.cleanup_paths
    );

    match original_home {
        Some(home) => std::env::set_var("HOME", home),
        None => std::env::remove_var("HOME"),
    }
}

#[test]
fn yay_source_recovery_plan_does_not_treat_mixed_build_failures_as_source_drift() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let home_dir = temp.path().join("home");
    let original_home = std::env::var_os("HOME");
    std::env::set_var("HOME", home_dir.as_os_str());

    let plan = build_yay_package_recovery_plan(
        &format!(
            "==> ERROR: One or more files did not pass the validity check!\n\
              -> error downloading sources: {}/.cache/yay/gibo-bin\n\
              -> error making: gibo-bin-exit status 1\n\
             gstreamer/subprojects/gstreamer/libs/gst/helpers/ptp/meson.build:26:4: ERROR: Problem encountered: PTP not supported without Rust compiler\n\
             ==> ERROR: A failure occurred in build().\n\
              -> error making: lib32-gstreamer - exit status 4\n",
            home_dir.display()
        ),
        None,
    )
    .expect("source recovery plan");

    let package_names = plan
        .packages
        .iter()
        .map(|package_plan| package_plan.package.as_str())
        .collect::<Vec<_>>();
    assert_eq!(package_names, vec!["gibo-bin"]);

    match original_home {
        Some(home) => std::env::set_var("HOME", home),
        None => std::env::remove_var("HOME"),
    }
}

#[test]
fn command_recovery_kind_prefers_report_parser_metadata() {
    let cmd = CommandTask {
        program: "powershell".to_string(),
        args: vec!["-Command".to_string(), "winget upgrade --all".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: false,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: Some(BuiltinReportParser::Winget),
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };
    let spec = TaskSpec {
        id: "custom-package-manager".to_string(),
        label: "Custom Package Manager".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(cmd.clone()),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };

    assert_eq!(
        package_manager_kind_for_command(&spec, &cmd, "powershell"),
        recovery::PackageManagerKind::Winget
    );
}

#[test]
fn command_recovery_kind_falls_back_to_task_and_program_names() {
    let cmd = CommandTask {
        program: "/usr/bin/apt-get".to_string(),
        args: vec!["upgrade".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: false,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };
    let spec = TaskSpec {
        id: "custom-apt".to_string(),
        label: "Custom Apt".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(cmd.clone()),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };

    assert_eq!(
        package_manager_kind_for_command(&spec, &cmd, "/usr/bin/apt-get"),
        recovery::PackageManagerKind::Apt
    );
}

#[test]
fn recoverable_conflict_targets_only_include_debug_owned_targets() {
    let records = vec![
        PacmanConflictRecord {
            target: "exodus-debug".to_string(),
            path: "/usr/lib/debug/a".to_string(),
            owner: "pinokio-bin-debug".to_string(),
            transaction_internal: false,
        },
        PacmanConflictRecord {
            target: "insync-dolphin".to_string(),
            path: "/usr/share/icons/foo.svg".to_string(),
            owner: "insync-emblem-icons".to_string(),
            transaction_internal: false,
        },
        PacmanConflictRecord {
            target: "foo".to_string(),
            path: "/usr/lib/debug/b".to_string(),
            owner: "alpha-debug".to_string(),
            transaction_internal: false,
        },
        PacmanConflictRecord {
            target: "foo".to_string(),
            path: "/usr/lib/debug/c".to_string(),
            owner: "beta-debug".to_string(),
            transaction_internal: true,
        },
    ];

    let recoverable = collect_recoverable_conflict_targets(&records);
    assert_eq!(recoverable.len(), 1);
    assert_eq!(recoverable[0].target, "exodus-debug");
}

#[test]
fn yay_failed_package_archives_are_parsed_from_error_trailer() {
    let archives = parse_yay_failed_package_archives(
        "error: failed to commit transaction (conflicting files)\nErrors occurred, no packages were upgraded.\n -> error installing: [/home/example-user/.cache/yay/exodus/exodus-26.3.11-1-x86_64.pkg.tar.zst /home/example-user/.cache/yay/exodus/exodus-debug-26.3.11-1-x86_64.pkg.tar.zst /home/example-user/.cache/yay/rustdesk/rustdesk-1.4.6-1-x86_64.pkg.tar.zst] - exit status 1",
    );

    assert_eq!(
        archives,
        vec![
            "/home/example-user/.cache/yay/exodus/exodus-26.3.11-1-x86_64.pkg.tar.zst".to_string(),
            "/home/example-user/.cache/yay/exodus/exodus-debug-26.3.11-1-x86_64.pkg.tar.zst"
                .to_string(),
            "/home/example-user/.cache/yay/rustdesk/rustdesk-1.4.6-1-x86_64.pkg.tar.zst"
                .to_string(),
        ]
    );
}

#[test]
fn cached_archives_are_matched_to_recoverable_targets() {
    let targets = vec![
        RecoverableConflictTarget {
            target: "exodus-debug".to_string(),
            owners: vec!["pinokio-bin-debug".to_string()],
            paths: vec!["/usr/lib/debug/.build-id/be/abc.debug".to_string()],
        },
        RecoverableConflictTarget {
            target: "foo".to_string(),
            owners: vec!["alpha-debug".to_string()],
            paths: vec!["/usr/lib/debug/foo".to_string()],
        },
    ];

    let archives = vec![
        "/home/example-user/.cache/yay/exodus/exodus-debug-26.3.11-1-x86_64.pkg.tar.zst"
            .to_string(),
        "/tmp/build/foo-1.2.3-1-x86_64.pkg.tar.zst".to_string(),
    ];

    let matched = collect_cached_archives_by_target(&archives, &targets);
    assert_eq!(
        matched.get("exodus-debug"),
        Some(
            &"/home/example-user/.cache/yay/exodus/exodus-debug-26.3.11-1-x86_64.pkg.tar.zst"
                .to_string()
        )
    );
    assert_eq!(
        matched.get("foo"),
        Some(&"/tmp/build/foo-1.2.3-1-x86_64.pkg.tar.zst".to_string())
    );
}

#[test]
fn yay_recovery_plan_collects_union_debug_owners_and_cached_archives() {
    let plan = build_yay_recovery_plan(
        "error: failed to commit transaction (conflicting files)\nfoo-debug: /usr/lib/debug/foo exists in filesystem (owned by alpha-debug)\nfoo-debug: /usr/lib/debug/foo-2 exists in filesystem (owned by beta-debug)\nbar-debug: /usr/lib/debug/bar exists in filesystem (owned by beta-debug)\n -> error installing: [/tmp/build/foo-debug-1.2.3-1-x86_64.pkg.tar.zst /home/example-user/.cache/yay/bar/bar-debug-2.0.0-1-x86_64.pkg.tar.zst] - exit status 1",
    )
    .expect("recovery plan");

    assert_eq!(plan.targets.len(), 2);
    assert_eq!(plan.targets[0].target, "bar-debug");
    assert_eq!(
        plan.targets[0].cached_archive.as_deref(),
        Some("/home/example-user/.cache/yay/bar/bar-debug-2.0.0-1-x86_64.pkg.tar.zst")
    );
    assert_eq!(plan.targets[1].target, "foo-debug");
    assert_eq!(
        plan.targets[1].cached_archive.as_deref(),
        Some("/tmp/build/foo-debug-1.2.3-1-x86_64.pkg.tar.zst")
    );

    assert_eq!(plan.owners_to_remove.len(), 2);
    assert_eq!(plan.owners_to_remove[0].owner, "alpha-debug");
    assert_eq!(plan.owners_to_remove[0].cached_archive, None);
    assert_eq!(
        plan.owners_to_remove[0].targets,
        vec!["foo-debug".to_string()]
    );
    assert_eq!(plan.owners_to_remove[1].owner, "beta-debug");
    assert_eq!(plan.owners_to_remove[1].cached_archive, None);
    assert_eq!(
        plan.owners_to_remove[1].targets,
        vec!["bar-debug".to_string(), "foo-debug".to_string()]
    );
}

#[test]
fn destructive_recovery_without_rollback_proof_is_refused() {
    let owner = YayRecoveryOwnerPlan {
        owner: "pinokio-bin-debug".to_string(),
        targets: vec!["exodus-debug".to_string()],
        cached_archive: None,
    };

    let decision = destructive_recovery_rollback_decision(&[owner]);

    assert_eq!(
        decision,
        DestructiveRecoveryRollbackDecision::Blocked {
            packages: vec!["pinokio-bin-debug".to_string()]
        }
    );
}

#[test]
fn destructive_recovery_with_valid_local_archive_has_rollback_proof() {
    let temp = TempDir::new().unwrap();
    let archive = temp
        .path()
        .join("pinokio-bin-debug-1.2.3-1-x86_64.pkg.tar.zst");
    fs::write(&archive, b"archive").unwrap();
    let owner = YayRecoveryOwnerPlan {
        owner: "pinokio-bin-debug".to_string(),
        targets: vec!["exodus-debug".to_string()],
        cached_archive: Some(archive.display().to_string()),
    };

    let decision = destructive_recovery_rollback_decision(&[owner]);

    assert_eq!(
        decision,
        DestructiveRecoveryRollbackDecision::Allowed {
            proofs: vec![PackageRollbackProof::LocalArchive {
                package: "pinokio-bin-debug".to_string(),
                archive: archive.display().to_string()
            }]
        }
    );
}

#[test]
fn append_ignore_args_merges_existing_and_new_targets() {
    let args = vec![
        "-Syu".to_string(),
        "--noconfirm".to_string(),
        "--ignore".to_string(),
        "foo".to_string(),
    ];

    let merged = append_ignore_args(&args, &["bar".to_string(), "foo".to_string()]);
    assert_eq!(
        merged,
        vec![
            "-Syu".to_string(),
            "--noconfirm".to_string(),
            "--ignore".to_string(),
            "bar,foo".to_string(),
        ]
    );
}

#[test]
fn package_manager_failure_ignores_non_conflict_errors() {
    assert!(
        format_package_manager_failure("yay exited non-zero (code=1); output: random failure")
            .is_none()
    );
}

#[test]
fn package_manager_timeout_formats_yay_aur_policy_detail() {
    let tmp = TempDir::new().unwrap();
    let run_log = RunLogSink::new(tmp.path(), true).unwrap();
    let spec = TaskSpec {
        id: "yay".to_string(),
        label: "Yay".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "yay".to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "aur_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: true,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let cmd = match &spec.kind {
        TaskKind::Command(cmd) => cmd,
        _ => unreachable!("test spec is command"),
    };
    let policy = TaskPolicy::new(10800, 0, 0);

    let detail = format_package_manager_timeout_failure(
        &spec,
        cmd,
        &policy,
        Some(&run_log),
        "timeout running /usr/bin/yay",
    )
    .expect("expected yay timeout detail");

    assert!(detail.contains("AUR update timed out after 10800s"));
    assert!(detail.contains("task policy `aur_update`"));
    assert!(detail.contains("task-yay.log"));
    assert!(detail.contains("package-level cause"));
    assert!(detail.contains("timeout running /usr/bin/yay"));
}

#[test]
fn package_manager_timeout_detail_uses_yay_metadata_without_yay_task_id() {
    let spec = TaskSpec {
        id: "aur-helper".to_string(),
        label: "AUR Helper".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "yay".to_string(),
            args: vec!["-Syu".to_string(), "--noconfirm".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "aur_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: true,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Yay),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let cmd = match &spec.kind {
        TaskKind::Command(cmd) => cmd,
        _ => unreachable!("test spec is command"),
    };
    let policy = TaskPolicy::new(10800, 0, 0);

    let detail = format_package_manager_timeout_failure(
        &spec,
        cmd,
        &policy,
        None,
        "timeout running /usr/bin/yay",
    )
    .expect("expected metadata-driven AUR timeout detail");

    assert!(detail.contains("AUR update timed out after 10800s"));
    assert!(detail.contains("task policy `aur_update`"));
    assert!(detail.contains("the per-task log"));
}

#[test]
fn package_manager_failure_formats_yay_source_validity_failure() {
    let detail = format_package_manager_failure(
        "yay exited non-zero (code=1); output: ==> ERROR: One or more files did not pass the validity check!\n -> error downloading sources: /home/me/.cache/yay/gibo-bin\n -> error making: gibo-bin-exit status 1",
    )
    .expect("expected source/build failure summary");

    assert!(detail.contains("source/build validation failed for gibo-bin"));
    assert!(detail.contains("/home/me/.cache/yay/gibo-bin"));
}

#[test]
fn yay_source_retry_failure_note_summarizes_checksum_drift_without_raw_transcript() {
    let note = build_yay_package_retry_failure_note(&YayPackageRetryFailure {
        package: "gibo-bin".to_string(),
        kind: YayPackageRecoveryKind::SourceDrift,
        cause_summary: None,
        error_text: "yay exited non-zero (code=1); output: AUR Explicit (1): gibo-bin-3.0.21-1 ==> Packages to cleanBuild? ==> All ==> ERROR: One or more files did not pass the validity check! -> error making: gibo-bin-exit status 1".to_string(),
    });

    assert!(note.contains("gibo-bin still fails source validation"));
    assert!(note.contains("upstream source/checksum drift"));
    assert!(note.contains("task-yay.log"));
    assert!(!note.contains("Packages to cleanBuild"));
    assert!(!note.contains("AUR Explicit"));
}

#[test]
fn yay_source_retry_failure_detail_summarizes_checksum_drift_without_raw_transcript() {
    let detail = build_yay_package_retry_failure_detail(&YayPackageRetryFailure {
        package: "gibo-bin".to_string(),
        kind: YayPackageRecoveryKind::SourceDrift,
        cause_summary: None,
        error_text: "yay exited non-zero (code=1); output: AUR Explicit (1): gibo-bin-3.0.21-1 ==> Packages to cleanBuild? ==> All ==> ERROR: One or more files did not pass the validity check! -> error making: gibo-bin-exit status 1".to_string(),
    });

    assert!(detail.contains("gibo-bin"));
    assert!(detail.contains("source validation still failed"));
    assert!(detail.contains("upstream source or checksum drift"));
    assert!(detail.contains("task-yay.log"));
    assert!(!detail.contains("Packages to cleanBuild"));
    assert!(!detail.contains("AUR Explicit"));
}

#[test]
fn yay_build_retry_failure_detail_does_not_claim_cache_cleanup() {
    let failure = YayPackageRetryFailure {
        package: "demo-bin".to_string(),
        kind: YayPackageRecoveryKind::BuildFailure,
        cause_summary: None,
        error_text: "==> ERROR: A failure occurred in build().".to_string(),
    };

    let detail = build_yay_package_retry_failure_detail(&failure);

    assert!(detail.contains("isolated retry for demo-bin failed"));
    assert!(detail.contains("cache/worktree was preserved"));
    assert!(!detail.contains("after clearing"));
}

#[test]
fn info_advisories_do_not_mark_completed_task_as_completed_with_issues() {
    let mut result = TaskResult::completed("NPM");
    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Info,
        code: "npm-deprecated-package".to_string(),
        summary: "npm warned about a deprecated transitive package".to_string(),
        remediation: "Review the dependency chain when practical.".to_string(),
        blocks_dependents: false,
    });

    assert!(!result.has_issues());

    result.advisories.push(TaskAdvisory {
        severity: AdvisorySeverity::Warning,
        code: "upstream-source-drift".to_string(),
        summary: "source validation failed".to_string(),
        remediation: "Review the package manually.".to_string(),
        blocks_dependents: false,
    });

    assert!(result.has_issues());
}

#[test]
fn failed_report_rows_mark_completed_task_as_completed_with_issues() {
    let mut result = TaskResult::completed("Completions");
    result.report_sections.push(TaskReportSection {
        key: "completion_generation".to_string(),
        title: "Completion Generation Results".to_string(),
        rows: vec![TaskReportRow {
            name: "slowcomp".to_string(),
            status: TaskReportStatus::Failed,
            before: Some("npm".to_string()),
            after: Some("-".to_string()),
            note: Some("generator_probe_timeout".to_string()),
        }],
    });

    assert!(result.has_issues());
}

#[test]
fn windows_elevated_commands_disable_interactive_capture_mode() {
    let cmd = CommandTask {
        program: "winget".to_string(),
        args: vec!["upgrade".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: true,
        needs_sudo_session: false,
        interactive: true,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };

    assert!(!command_interactive_mode(HostOs::Windows, &cmd));
    assert!(command_interactive_mode(HostOs::Linux, &cmd));
}

#[test]
fn windows_non_elevated_commands_keep_interactive_mode() {
    let cmd = CommandTask {
        program: "winget".to_string(),
        args: vec!["upgrade".to_string()],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: true,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };

    assert!(command_interactive_mode(HostOs::Windows, &cmd));
}

#[test]
fn classify_runtime_failure_detects_user_canceled_elevation() {
    let class = classify_runtime_failure(
        "Start-Process : This command cannot be run due to the error: The operation was canceled by the user.",
        true,
    );
    assert_eq!(class, RuntimeFailureClass::UserCanceledElevation);
}

#[test]
fn classify_runtime_failure_detects_user_canceled_elevation_from_exit_code() {
    let class = classify_runtime_failure("powershell exited non-zero (code=1223)", true);
    assert_eq!(class, RuntimeFailureClass::UserCanceledElevation);
}

#[test]
fn user_canceled_elevation_result_is_warning_only_with_advisory() {
    let result = user_canceled_elevation_result("Winget (Machine)");

    assert_eq!(result.status, TaskStatus::Canceled);
    assert!(result
        .details
        .iter()
        .any(|detail| detail.contains("elevation prompt canceled")));
    assert_eq!(result.advisories.len(), 1);
    assert_eq!(result.advisories[0].severity, AdvisorySeverity::Warning);
    assert_eq!(result.advisories[0].code, "elevation-canceled");
    assert!(!result.advisories[0].blocks_dependents);
    assert!(result.advisories[0].remediation.contains("Administrator"));
}

#[test]
fn classify_runtime_failure_detects_elevation_denied() {
    let class = classify_runtime_failure(
        "Start-Process : This command cannot be run due to the error: Access is denied.",
        true,
    );
    assert_eq!(class, RuntimeFailureClass::ElevationDenied);
}

#[test]
fn classify_runtime_failure_detects_wrapper_launch_failures() {
    let class = classify_runtime_failure(
        "The term 'winget' is not recognized as the name of a cmdlet, function, script file, or operable program.",
        false,
    );
    assert_eq!(class, RuntimeFailureClass::CommandLaunchFailed);
}

#[test]
fn classify_runtime_failure_detects_transient_lock_or_busy() {
    for msg in [
        "npm error code EBUSY: Access is denied",
        " -> /var/lib/pacman/db.lck is present.",
    ] {
        let class = classify_runtime_failure(msg, false);
        assert_eq!(class, RuntimeFailureClass::TransientLockOrBusy, "{msg}");
    }
}

#[test]
fn classify_runtime_failure_detects_transient_network_failures() {
    for msg in [
        "npm error code ETIMEDOUT",
        "error: RPC failed; curl 56 Recv failure: Connection reset by peer",
        "fatal: early EOF",
        "fetch-pack: unexpected disconnect while reading sideband packet",
        "Operation too slow. Less than 1 bytes/sec transferred the last 10 seconds",
        "timeout running pipx",
    ] {
        let class = classify_runtime_failure(msg, false);
        assert_eq!(class, RuntimeFailureClass::TransientNetwork, "{msg}");
    }
}

#[test]
fn classify_runtime_failure_keeps_deterministic_package_errors_non_transient() {
    for msg in [
        "==> ERROR: One or more files did not pass the validity check!",
        "error: failed to commit transaction (conflicting files)",
        "The term 'winget' is not recognized as the name of a cmdlet",
        "sudo: a password is required",
    ] {
        let class = classify_runtime_failure(msg, false);
        assert_ne!(class, RuntimeFailureClass::TransientNetwork, "{msg}");
    }
}

#[test]
fn classify_runtime_failure_detects_sudo_session_unavailable() {
    let class = classify_runtime_failure("sudo: a password is required", true);
    assert_eq!(class, RuntimeFailureClass::SudoSessionUnavailable);
}

#[test]
fn build_command_failure_detail_distinguishes_winget_launch_failure() {
    let spec = TaskSpec {
        id: "winget-user".to_string(),
        label: "Winget (User)".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "winget".to_string(),
            args: vec!["upgrade".to_string(), "--all".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: true,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let cmd = match &spec.kind {
        TaskKind::Command(cmd) => cmd,
        _ => panic!("expected command task"),
    };

    let detail = build_command_failure_detail(
        &spec,
        cmd,
        "powershell",
        "The term 'winget' is not recognized as the name of a cmdlet.",
    );
    assert!(detail.contains("before winget started"), "{detail}");
    assert!(detail.contains("winget --info"), "{detail}");
}

#[test]
fn build_command_failure_detail_surfaces_winget_package_failure_marker() {
    let spec = TaskSpec {
        id: "winget-user".to_string(),
        label: "Winget (User)".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "winget".to_string(),
            args: vec!["upgrade".to_string(), "--all".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: false,
            needs_sudo_session: false,
            interactive: true,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: None,
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let cmd = match &spec.kind {
        TaskKind::Command(cmd) => cmd,
        _ => panic!("expected command task"),
    };

    let detail = build_command_failure_detail(
        &spec,
        cmd,
        "powershell",
        r#"Name Id Version Available Source
uv astral-sh.uv 0.11.7 0.11.8 winget
An unexpected error occurred while executing the command:
remove: Access is denied.: "C:\Users\E135328\AppData\Local\Microsoft\WinGet\Packages\astral-sh.uv_Microsoft.Winget.Source_8wekyb3d8bbwe\uv.exe"
Installer failed with exit code: 0x8a150003 : Executing command failed"#,
    );

    assert!(detail.starts_with("remove: Access is denied."), "{detail}");
    assert!(!detail.contains("powershell exited non-zero"), "{detail}");
    assert!(
        detail.contains("winget user-scope update failed"),
        "{detail}"
    );
}

#[test]
fn build_command_failure_detail_uses_winget_command_metadata_without_winget_task_id() {
    let spec = TaskSpec {
        id: "configured-system-manager".to_string(),
        label: "Configured System Manager".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "winget".to_string(),
            args: vec![
                "upgrade".to_string(),
                "--all".to_string(),
                "--scope".to_string(),
                "machine".to_string(),
            ],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Winget),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };
    let cmd = match &spec.kind {
        TaskKind::Command(cmd) => cmd,
        _ => panic!("expected command task"),
    };

    let detail = build_command_failure_detail(
        &spec,
        cmd,
        "powershell",
        "Installer failed with exit code: 2",
    );

    assert!(
        detail.contains("winget machine-scope update failed"),
        "{detail}"
    );
    assert!(
        detail.contains("winget upgrade --all --scope machine"),
        "{detail}"
    );
}

#[test]
fn build_elevation_required_detail_calls_out_machine_scope_winget() {
    let spec = TaskSpec {
        id: "configured-system-manager".to_string(),
        label: "Configured System Manager".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(CommandTask {
            program: "winget".to_string(),
            args: vec![
                "upgrade".to_string(),
                "--all".to_string(),
                "--scope".to_string(),
                "machine".to_string(),
            ],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation: true,
            needs_sudo_session: false,
            interactive: false,
            external_window: false,
            shell: false,
            windows_bridge: false,
            report_parser: Some(BuiltinReportParser::Winget),
            plain_header: None,
            plain_start: None,
            success_details: Vec::new(),
            external_manager_skip: false,
            result_protocol: None,
        }),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
    };

    let detail = build_elevation_required_detail(&spec);
    assert!(detail.contains("Administrator privileges"), "{detail}");
    assert!(detail.contains("did not receive elevation"), "{detail}");
}

#[test]
fn detect_command_output_failure_flags_winget_dependency_error_markers() {
    let cmd = CommandTask {
        program: "winget".to_string(),
        args: vec![
            "upgrade".to_string(),
            "--all".to_string(),
            "--scope".to_string(),
            "user".to_string(),
        ],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        report_scoped_deltas: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: true,
        external_window: false,
        shell: false,
        windows_bridge: false,
        report_parser: Some(BuiltinReportParser::Winget),
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
        result_protocol: None,
    };
    let output = r#"
No suitable installer found for manifest: Microsoft.WindowsAppRuntime.1.8 version 1.8.5
Error processing package dependencies. Exiting...
"#;
    let failure = detect_command_output_failure(&cmd, output);
    assert!(
        failure.is_some(),
        "expected winget output failure to be detected"
    );
}

#[test]
fn winget_report_marks_failed_package_from_dependency_error_marker() {
    let output = r#"
Name          Id                      Version    Available  Source
------------------------------------------------------------------
App Installer Microsoft.AppInstaller  1.27.460.0 1.27.470.0 winget
1 upgrades available.
(1/1) Found App Installer [Microsoft.AppInstaller] Version 1.27.470.0
No suitable installer found for manifest: Microsoft.WindowsAppRuntime.1.8 version 1.8.5
Error processing package dependencies. Exiting...
"#;
    let sections = build_command_report_sections(Some(BuiltinReportParser::Winget), output);
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Winget Package Results");
    assert!(sections[0]
        .rows
        .iter()
        .any(|r| r.name == "App Installer" && r.status == TaskReportStatus::Failed));
}

#[test]
fn scoop_report_marks_running_process_packages_as_blocked() {
    let output = r#"
nodejs-lts: 24.13.1 -> 24.14.0
ERROR The following instances of "nodejs-lts" are still running. Close them and try again.
Running process detected, skip updating.
"#;
    let sections = build_command_report_sections(Some(BuiltinReportParser::Scoop), output);
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Scoop Package Results");
    assert!(sections[0]
        .rows
        .iter()
        .any(|r| r.name == "nodejs-lts" && r.status == TaskReportStatus::Blocked));
}

#[test]
fn scoop_report_marks_version_pairs_as_updated_rows() {
    let output = r#"
git: 2.50.1 -> 2.50.2
nodejs-lts: 24.13.1 -> 24.14.0
Scoop was updated successfully!
"#;
    let sections = build_command_report_sections(Some(BuiltinReportParser::Scoop), output);
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].title, "Scoop Package Results");
    assert!(sections[0].rows.iter().any(|row| {
        row.name == "git"
            && row.status == TaskReportStatus::Updated
            && row.before.as_deref() == Some("2.50.1")
            && row.after.as_deref() == Some("2.50.2")
    }));
    assert!(sections[0].rows.iter().any(|row| {
        row.name == "nodejs-lts"
            && row.status == TaskReportStatus::Updated
            && row.before.as_deref() == Some("24.13.1")
            && row.after.as_deref() == Some("24.14.0")
    }));
}

#[test]
fn compute_retry_backoff_uses_base_for_first_retry() {
    let delay = compute_retry_backoff(Duration::from_secs(8), 0);
    assert_eq!(delay, Duration::from_secs(8));
}

#[test]
fn compute_retry_backoff_doubles_each_retry() {
    assert_eq!(
        compute_retry_backoff(Duration::from_secs(8), 1),
        Duration::from_secs(16)
    );
    assert_eq!(
        compute_retry_backoff(Duration::from_secs(8), 2),
        Duration::from_secs(32)
    );
}

#[test]
fn compute_retry_backoff_caps_at_sixty_seconds() {
    let delay = compute_retry_backoff(Duration::from_secs(20), 2);
    assert_eq!(delay, Duration::from_secs(60));
}

#[test]
fn transient_retry_backoff_uses_default_when_base_is_zero() {
    let delay = transient_retry_backoff(Duration::ZERO, 0);
    assert_eq!(delay, Duration::from_secs(8));
}

#[test]
fn effective_retry_budget_adds_one_retry_for_transient_network_failures() {
    let policy = TaskPolicy::new(60, 0, 0);
    assert_eq!(
        effective_retry_budget(&policy, "npm error code ETIMEDOUT"),
        1
    );
    assert_eq!(
        effective_retry_budget(
            &policy,
            "==> ERROR: One or more files did not pass the validity check!"
        ),
        0
    );
}
