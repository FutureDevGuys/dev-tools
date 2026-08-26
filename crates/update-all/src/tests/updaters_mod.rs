use super::*;

#[test]
fn builtin_catalog_loads_from_embedded_data_file() {
    let tasks = builtin_catalog().expect("builtin catalog");
    let ids = tasks
        .iter()
        .map(|task| task.id.as_str())
        .collect::<Vec<_>>();

    assert!(ids.contains(&"builtin/npm"));
    assert!(ids.contains(&"builtin/yay"));
    assert!(ids.contains(&"builtin/winget-user"));
    assert!(ids.iter().all(|id| id.starts_with("builtin/")));
}

#[test]
fn windows_foundation_catalog_loads_from_embedded_data_file() {
    let foundations = builtin_windows_foundations().expect("Windows foundation catalog");
    let find = |id: &str| {
        foundations
            .iter()
            .find(|foundation| foundation.id == id)
            .expect("foundation exists")
    };

    assert_eq!(find("scoop").probe, "scoop");
    assert_eq!(
        find("scoop")
            .missing_command
            .as_ref()
            .expect("scoop install command")
            .program,
        "powershell"
    );
    assert_eq!(find("powershell").probe, "pwsh");
    assert_eq!(find("powershell").requires_probe, vec!["scoop".to_string()]);
    assert_eq!(
        find("powershell")
            .present_command
            .as_ref()
            .expect("pwsh update command")
            .args,
        vec!["update".to_string(), "pwsh".to_string()]
    );
    assert_eq!(
        find("winget").present_note.as_deref(),
        Some("handled by normal update tasks")
    );
}

#[test]
fn builtin_catalog_carries_declarative_detection_rules() {
    let tasks = builtin_catalog().expect("builtin catalog");
    let find = |id: &str| {
        let qualified = format!("builtin/{id}");
        tasks
            .iter()
            .find(|t| t.id == qualified)
            .expect("task exists")
    };

    match &find("npm").kind {
        BuiltinTaskKind::Managed { executor } => {
            assert_eq!(*executor, BuiltinManagedExecutor::Npm);
        }
        _ => panic!("npm should be a managed executor task"),
    }
    match &find("pipx").kind {
        BuiltinTaskKind::Command {
            program,
            args,
            report_commands,
            ..
        } => {
            assert_eq!(program, "pipx");
            assert_eq!(args, &vec!["upgrade-all".to_string()]);
            assert_eq!(report_commands.len(), 1);
            assert_eq!(report_commands[0].program, "pipx");
            assert_eq!(report_commands[0].args, vec!["list".to_string()]);
            assert_eq!(
                report_commands[0].when,
                BuiltinReportCommandWhen::BeforeAfter
            );
            let state_pattern = report_commands[0]
                .state_pattern
                .as_ref()
                .expect("pipx state pattern");
            assert_eq!(state_pattern.section_key, "pipx_packages");
            assert_eq!(state_pattern.section_title, "Pipx Package Results");
            assert!(state_pattern.include_unchanged);
        }
        _ => panic!("pipx should be a command task"),
    }
    assert_eq!(find("go").detect_all, vec!["go".to_string()]);
    assert!(find("go").detect_all_windows.is_empty());
    match &find("go").kind {
        BuiltinTaskKind::Command {
            report_commands, ..
        } => {
            assert_eq!(report_commands.len(), 1);
            assert_eq!(report_commands[0].program, "gup");
            assert_eq!(report_commands[0].args, vec!["list".to_string()]);
        }
        _ => panic!("go should be a command task"),
    }
    assert_eq!(
        find("uv").skip_if_any_windows,
        vec![
            "winget".to_string(),
            "scoop".to_string(),
            "choco".to_string()
        ]
    );
    match &find("uv").kind {
        BuiltinTaskKind::Command {
            external_manager_skip,
            ..
        } => assert!(*external_manager_skip),
        _ => panic!("uv should be a command task"),
    }
    assert_eq!(find("uv-tools").after, vec!["builtin/uv".to_string()]);
    match &find("uv-tools").kind {
        BuiltinTaskKind::Command {
            program,
            args,
            report_commands,
            report_scoped_deltas,
            ..
        } => {
            assert_eq!(program, "uv");
            assert_eq!(
                args,
                &vec![
                    "tool".to_string(),
                    "upgrade".to_string(),
                    "--all".to_string()
                ]
            );
            assert_eq!(report_commands.len(), 1);
            assert_eq!(report_commands[0].program, "uv");
            assert_eq!(
                report_commands[0].args,
                vec!["tool".to_string(), "list".to_string()]
            );
            let state_pattern = report_commands[0]
                .state_pattern
                .as_ref()
                .expect("uv tool state pattern");
            assert_eq!(state_pattern.section_key, "uv_tools");
            assert_eq!(state_pattern.section_title, "UV Tool Results");
            assert!(state_pattern.include_unchanged);
            assert_eq!(report_scoped_deltas.len(), 1);
            assert_eq!(report_scoped_deltas[0].section_key, "uv_tool_dependencies");
            assert_eq!(
                report_scoped_deltas[0].scope_section_key.as_deref(),
                Some("uv_tools")
            );
        }
        _ => panic!("uv-tools should be a command task"),
    }
    assert_eq!(find("pacman").skip_if_any, vec!["yay".to_string()]);
    assert_eq!(find("go").report_parser, None);
    match &find("go").kind {
        BuiltinTaskKind::Command {
            report_patterns, ..
        } => assert!(
            !report_patterns.is_empty(),
            "go should use catalog report patterns"
        ),
        _ => panic!("go should be a command task"),
    }
    assert_eq!(
        find("arch-update-services").report_parser,
        Some(BuiltinReportParser::ArchUpdateServices)
    );
    assert!(!find("arch-update-services").depends_on_selected);
    assert_eq!(
        find("arch-update-services").requires_selected_any,
        vec!["builtin/yay".to_string()]
    );
    assert!(find("arch-update-services")
        .depends_on_selected_exclude
        .is_empty());
    match &find("apt").kind {
        BuiltinTaskKind::Command {
            program,
            args,
            pre_commands,
            shell,
            ..
        } => {
            assert_eq!(program, "apt-get");
            assert_eq!(args, &vec!["-y".to_string(), "dist-upgrade".to_string()]);
            assert!(!shell);
            assert_eq!(pre_commands.len(), 1);
            assert_eq!(pre_commands[0].program, "apt-get");
            assert_eq!(pre_commands[0].args, vec!["update".to_string()]);
        }
        _ => panic!("apt should be a command task"),
    }
    match &find("brew-formula").kind {
        BuiltinTaskKind::Command {
            program,
            args,
            pre_commands,
            shell,
            ..
        } => {
            assert_eq!(program, "brew");
            assert_eq!(args, &vec!["upgrade".to_string()]);
            assert!(!shell);
            assert_eq!(pre_commands.len(), 1);
            assert_eq!(pre_commands[0].program, "brew");
            assert_eq!(pre_commands[0].args, vec!["update".to_string()]);
        }
        _ => panic!("brew-formula should be a command task"),
    }
}

#[test]
fn builtin_catalog_rejects_unknown_toml_fields() {
    let err = match toml::from_str::<BuiltinCatalog>(
        r#"
[[tasks]]
id = "demo"
label = "Demo"
os = ["linux"]
detect_any = []
depends_on = []
enabled_by_default = true
category = "maintenance"
kind = "managed"
executor = "completions"
unexpected = true
"#,
    ) {
        Ok(_) => panic!("unexpected catalog parse success"),
        Err(err) => err.to_string(),
    };

    assert!(err.contains("unknown field"), "{err}");
    assert!(err.contains("unexpected"), "{err}");
}

#[test]
fn command_catalog_entries_accept_report_patterns() {
    let catalog: BuiltinCatalog = toml::from_str(
        r#"
[[tasks]]
id = "demo"
label = "Demo"
os = ["linux"]
detect_any = ["demo"]
depends_on = []
enabled_by_default = true
category = "language"
kind = "command"
program = "demo"
args = ["update"]
policy_key = "tool_update"
requires_elevation = false
needs_sudo_session = false
interactive = false
external_window = false
shell = false

[[tasks.report_patterns]]
pattern = '^(?P<name>\S+) (?P<before>\S+) -> (?P<after>\S+)$'
section_key = "demo_tools"
section_title = "Demo Tool Results"
status = "passed"
name = "{name}"
before = "{before}"
after = "{after}"
"#,
    )
    .expect("catalog with report patterns should parse");

    let task = catalog
        .tasks
        .into_iter()
        .next()
        .expect("task")
        .into_builtin_task()
        .expect("builtin task");
    match task.kind {
        BuiltinTaskKind::Command {
            report_patterns, ..
        } => {
            assert_eq!(report_patterns.len(), 1);
            assert_eq!(
                report_patterns[0].pattern,
                r"^(?P<name>\S+) (?P<before>\S+) -> (?P<after>\S+)$"
            );
            assert_eq!(report_patterns[0].section_key, "demo_tools");
            assert_eq!(report_patterns[0].section_title, "Demo Tool Results");
            assert_eq!(report_patterns[0].status, "passed");
            assert_eq!(report_patterns[0].name.as_deref(), Some("{name}"));
            assert_eq!(report_patterns[0].before.as_deref(), Some("{before}"));
            assert_eq!(report_patterns[0].after.as_deref(), Some("{after}"));
        }
        _ => panic!("demo should be a command task"),
    }
}

#[test]
fn managed_catalog_entries_require_supported_executor() {
    let parse_err = |executor_line: &str| {
        let raw = format!(
            r#"
[[tasks]]
id = "demo"
label = "Demo"
os = ["linux"]
detect_any = ["demo"]
depends_on = []
enabled_by_default = true
category = "language"
kind = "managed"
{executor_line}
"#
        );
        let catalog: BuiltinCatalog = toml::from_str(&raw).expect("valid TOML shape");
        catalog
            .tasks
            .into_iter()
            .next()
            .expect("task")
            .into_builtin_task()
            .unwrap_err()
            .to_string()
    };

    let missing = parse_err("");
    assert!(missing.contains("missing executor"), "{missing}");

    let unsupported = parse_err(r#"executor = "demo""#);
    assert!(
        unsupported.contains("unsupported executor 'demo'"),
        "{unsupported}"
    );
    assert!(
        unsupported.contains("npm|completions|windows_foundations"),
        "{unsupported}"
    );
}

#[test]
fn non_command_catalog_entries_reject_command_fields() {
    let entry = BuiltinTaskEntry {
        id: "npm".to_string(),
        label: "NPM".to_string(),
        os: vec!["linux".to_string()],
        detect_mode: None,
        detect_any: vec!["npm".to_string()],
        detect_all: None,
        detect_all_windows: None,
        skip_if_any: None,
        skip_if_any_windows: None,
        depends_on: Vec::new(),
        after: None,
        requires_selected_any: None,
        depends_on_selected: None,
        depends_on_selected_exclude: None,
        resource_locks: None,
        enabled_by_default: true,
        category: "language".to_string(),
        order_rank: None,
        report_parser: Some("go".to_string()),
        kind: "managed".to_string(),
        executor: Some("npm".to_string()),
        program: Some("npm".to_string()),
        args: None,
        mode: None,
        command_candidates: None,
        pre_commands: None,
        report_commands: None,
        report_patterns: None,
        report_scoped_deltas: None,
        policy_key: None,
        requires_elevation: None,
        needs_sudo_session: None,
        interactive: None,
        external_window: None,
        shell: None,
        plain_header: None,
        plain_start: None,
        success_details: None,
        external_manager_skip: None,
    };

    let err = entry.into_builtin_task().unwrap_err().to_string();
    assert!(err.contains("command-only fields"), "{err}");
    assert!(err.contains("managed"), "{err}");
}

#[test]
fn catalog_entries_reject_unknown_report_parser() {
    for parser in ["bespoke-demo", "cargo", "go", "rustup"] {
        let entry = BuiltinTaskEntry {
            id: "demo".to_string(),
            label: "Demo".to_string(),
            os: vec!["linux".to_string()],
            detect_mode: None,
            detect_any: vec!["demo".to_string()],
            detect_all: None,
            detect_all_windows: None,
            skip_if_any: None,
            skip_if_any_windows: None,
            depends_on: Vec::new(),
            after: None,
            requires_selected_any: None,
            depends_on_selected: None,
            depends_on_selected_exclude: None,
            resource_locks: None,
            enabled_by_default: true,
            category: "maintenance".to_string(),
            order_rank: None,
            report_parser: Some(parser.to_string()),
            kind: "command".to_string(),
            executor: None,
            program: Some("demo".to_string()),
            args: None,
            mode: None,
            command_candidates: None,
            pre_commands: None,
            report_commands: None,
            report_patterns: None,
            report_scoped_deltas: None,
            policy_key: Some("system_update".to_string()),
            requires_elevation: None,
            needs_sudo_session: None,
            interactive: None,
            external_window: None,
            shell: None,
            plain_header: None,
            plain_start: None,
            success_details: None,
            external_manager_skip: None,
        };

        let err = entry.into_builtin_task().unwrap_err().to_string();
        assert!(err.contains("unsupported report_parser"), "{parser}: {err}");
        assert!(err.contains(parser), "{parser}: {err}");
    }
}

#[test]
fn builtin_scoped_delta_validation_rejects_missing_captures_and_partial_parent() {
    let valid = || BuiltinScopedDeltaEntry {
        scope_pattern: Some(r"^Modified (?P<scope>\S+) environment$".to_string()),
        before_pattern: Some(r"^- (?P<name>\S+)==(?P<version>\S+)$".to_string()),
        after_pattern: Some(r"^\+ (?P<name>\S+)==(?P<version>\S+)$".to_string()),
        section_key: Some("dependencies".to_string()),
        section_title: Some("Dependency Results".to_string()),
        row_name: Some("{scope} / {name}".to_string()),
        scope_section_key: None,
        scope_section_title: None,
        scope_row_name: None,
    };

    let mut missing_capture = valid();
    missing_capture.scope_pattern = Some(r"^Modified \S+ environment$".to_string());
    let err = missing_capture
        .into_builtin_scoped_delta("demo", 0)
        .unwrap_err()
        .to_string();
    assert!(err.contains("named 'scope' capture"), "{err}");

    let mut partial_parent = valid();
    partial_parent.scope_section_key = Some("environments".to_string());
    let err = partial_parent
        .into_builtin_scoped_delta("demo", 0)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("scope_section_key, scope_section_title, and scope_row_name together"),
        "{err}"
    );
}

#[test]
fn builtin_catalog_validation_rejects_unknown_os_names() {
    let task = BuiltinTask {
        id: "demo".to_string(),
        label: "Demo".to_string(),
        os: vec!["linx".to_string()],
        detect_mode: BuiltinDetectionMode::Always,
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
        enabled_by_default: true,
        category: "maintenance".to_string(),
        order_rank: 20,
        report_parser: None,
        kind: BuiltinTaskKind::Managed {
            executor: BuiltinManagedExecutor::Completions,
        },
    };

    let err = validate_builtin_catalog(vec![task])
        .unwrap_err()
        .to_string();
    assert!(err.contains("unsupported OS"), "{err}");
    assert!(err.contains("linx"), "{err}");
}

#[test]
fn builtin_catalog_validation_rejects_any_present_without_any_detector() {
    let task = BuiltinTask {
        id: "demo".to_string(),
        label: "Demo".to_string(),
        os: vec!["linux".to_string()],
        detect_mode: BuiltinDetectionMode::AnyPresent,
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
        enabled_by_default: true,
        category: "maintenance".to_string(),
        order_rank: 20,
        report_parser: None,
        kind: BuiltinTaskKind::Managed {
            executor: BuiltinManagedExecutor::Completions,
        },
    };

    let err = validate_builtin_catalog(vec![task])
        .unwrap_err()
        .to_string();
    assert!(err.contains("any_present detection"), "{err}");
    assert!(err.contains("detect_any"), "{err}");
}

#[test]
fn builtin_catalog_validation_rejects_unknown_relationship_selectors() {
    let base = BuiltinTask {
        id: "demo".to_string(),
        label: "Demo".to_string(),
        os: vec!["linux".to_string()],
        detect_mode: BuiltinDetectionMode::Always,
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
        enabled_by_default: true,
        category: "maintenance".to_string(),
        order_rank: 20,
        report_parser: None,
        kind: BuiltinTaskKind::Managed {
            executor: BuiltinManagedExecutor::Completions,
        },
    };

    let mut requires_unknown = base.clone();
    requires_unknown.requires_selected_any = vec!["ghost".to_string()];
    let err = validate_builtin_catalog(vec![requires_unknown])
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("requires unknown selected task selector"),
        "{err}"
    );
    assert!(err.contains("ghost"), "{err}");

    let mut excludes_unknown = base;
    excludes_unknown.depends_on_selected_exclude = vec!["ghost".to_string()];
    let err = validate_builtin_catalog(vec![excludes_unknown])
        .unwrap_err()
        .to_string();
    assert!(err.contains("excludes unknown selected task"), "{err}");
    assert!(err.contains("ghost"), "{err}");
}

#[test]
fn builtin_command_candidates_reject_empty_arg_entries() {
    let cases = [
        (
            "args",
            BuiltinCommandCandidateEntry {
                program: "fallback".to_string(),
                args: Some(vec![String::new()]),
                probe_args: Some(vec!["--help".to_string()]),
                mode: None,
            },
        ),
        (
            "probe_args",
            BuiltinCommandCandidateEntry {
                program: "fallback".to_string(),
                args: Some(vec!["update".to_string()]),
                probe_args: Some(vec![String::new()]),
                mode: None,
            },
        ),
    ];

    for (field, entry) in cases {
        let err = entry
            .into_builtin_candidate("demo")
            .unwrap_err()
            .to_string();
        assert!(err.contains(field), "{field}: {err}");
        assert!(err.contains("empty"), "{field}: {err}");
    }
}

#[test]
fn windows_manager_gates_machine_winget_after_user_scope() {
    let tasks = builtin_catalog().expect("builtin catalog");
    let find = |id: &str| {
        let qualified = format!("builtin/{id}");
        tasks
            .iter()
            .find(|t| t.id == qualified)
            .expect("task exists")
    };

    let winget_user = find("winget-user");
    let winget_machine = find("winget-machine");
    let scoop_self = find("scoop-self");
    let scoop_all = find("scoop-all");
    let choco = find("choco");

    assert!(winget_user.depends_on.is_empty());
    assert!(scoop_self.order_rank < winget_user.order_rank);
    assert_eq!(
        winget_machine.depends_on,
        vec!["builtin/winget-user".to_string()]
    );
    assert!(scoop_self.depends_on.is_empty());
    assert_eq!(scoop_all.depends_on, vec!["builtin/scoop-self".to_string()]);
    assert!(choco.depends_on.is_empty());

    let user_interactive = match &winget_user.kind {
        BuiltinTaskKind::Command { interactive, .. } => *interactive,
        _ => false,
    };
    let machine_interactive = match &winget_machine.kind {
        BuiltinTaskKind::Command { interactive, .. } => *interactive,
        _ => true,
    };
    assert!(user_interactive);
    assert!(!machine_interactive);
}

#[test]
fn arch_update_services_builtin_uses_dashboard_input_with_sudo_preflight() {
    let tasks = builtin_catalog().expect("builtin catalog");
    let yay = tasks
        .iter()
        .find(|task| task.id == "builtin/yay")
        .expect("yay task exists");
    let task = tasks
        .iter()
        .find(|task| task.id == "builtin/arch-update-services")
        .expect("arch-update-services task exists");
    let yay_policy_key = match &yay.kind {
        BuiltinTaskKind::Command { policy_key, .. } => policy_key.as_str(),
        _ => "",
    };
    assert_eq!(yay_policy_key, "aur_update");
    assert_eq!(task.depends_on, vec!["builtin/yay".to_string()]);
    let (interactive, requires_elevation, needs_sudo_session, external_window) = match &task.kind {
        BuiltinTaskKind::Command {
            interactive,
            requires_elevation,
            needs_sudo_session,
            external_window,
            ..
        } => (
            *interactive,
            *requires_elevation,
            *needs_sudo_session,
            *external_window,
        ),
        _ => (false, false, false, true),
    };
    assert!(interactive);
    assert!(requires_elevation);
    assert!(needs_sudo_session);
    assert!(!external_window);
}
