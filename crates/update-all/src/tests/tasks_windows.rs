use super::*;

fn manager_task(program: &str, args: &[&str], requires_elevation: bool) -> CommandTask {
    CommandTask {
        program: program.to_string(),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation,
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
    }
}

#[test]
fn windows_host_safe_capture_wraps_manager_commands_in_powershell() {
    let task = manager_task("winget", &["upgrade", "--all", "--scope", "user"], false);
    let (program, args) = build_command_invocation(HostOs::Windows, &task);

    assert_eq!(program, "powershell");
    assert!(args.iter().any(|arg| arg == "-ExecutionPolicy"));
    let script = args.last().expect("powershell script");
    assert!(script.contains("WindowsApps\\winget.exe") || script.contains("& 'winget'"));
    assert!(script.contains("$LASTEXITCODE"));
    assert!(script.contains("upgrade"));
    assert!(script.contains("--scope"));
    assert_eq!(
        command_log_line(HostOs::Windows, &task, &program, &args),
        "winget upgrade --all --scope user"
    );
}

#[test]
fn windows_elevated_winget_log_line_hides_powershell_wrapper() {
    let task = manager_task("winget", &["upgrade", "--all", "--scope", "machine"], true);
    let (program, args) = build_command_invocation(HostOs::Windows, &task);

    assert_eq!(program, "powershell");
    let log_line = command_log_line(HostOs::Windows, &task, &program, &args);
    assert_eq!(log_line, "winget upgrade --all --scope machine");
    assert!(!log_line.contains("$ErrorActionPreference"));
    assert!(!log_line.contains("Start-Process"));
}

#[test]
fn non_windows_command_log_line_uses_invocation() {
    let task = manager_task("winget", &["upgrade", "--all", "--scope", "user"], false);
    let (program, args) = build_command_invocation(
        HostOs::Linux,
        &manager_task("winget", &["upgrade", "--all", "--scope", "user"], false),
    );

    assert_eq!(
        command_log_line(HostOs::Linux, &task, &program, &args),
        format_command_for_log(&program, &args)
    );
}

#[test]
fn windows_host_safe_capture_invocation_still_wraps_manager_commands_in_powershell() {
    let (program, args) = build_command_invocation(
        HostOs::Windows,
        &manager_task("winget", &["upgrade", "--all", "--scope", "user"], false),
    );

    assert_eq!(program, "powershell");
    assert!(args.iter().any(|arg| arg == "-ExecutionPolicy"));
    let script = args.last().expect("powershell script");
    assert!(script.contains("WindowsApps\\winget.exe") || script.contains("& 'winget'"));
    assert!(script.contains("$LASTEXITCODE"));
    assert!(script.contains("upgrade"));
    assert!(script.contains("--scope"));
}

#[test]
fn windows_cmd_scripts_use_cmd_c() {
    let (program, args) = build_command_invocation(
        HostOs::Windows,
        &manager_task(
            r"C:\Users\me\scoop\apps\nodejs\current\bin\skills.cmd",
            &["update"],
            false,
        ),
    );

    assert_eq!(program, "cmd");
    assert_eq!(args.first().map(String::as_str), Some("/C"));
    assert_eq!(
        args.get(1).map(String::as_str),
        Some(r"C:\Users\me\scoop\apps\nodejs\current\bin\skills.cmd")
    );
    assert!(args.iter().any(|arg| arg == "update"));
}

#[test]
fn windows_elevated_invocation_uses_start_process_runas() {
    let (program, args) = build_command_invocation(
        HostOs::Windows,
        &manager_task(
            r"C:\Program Files\winget.exe",
            &["upgrade", "--all", "--scope", "machine"],
            true,
        ),
    );

    assert_eq!(program, "powershell");
    let script = args.last().expect("powershell script");
    assert!(script.contains("Start-Process"));
    assert!(script.contains("-Verb RunAs"));
    assert!(script.contains("$ErrorActionPreference='Stop'"));
    assert!(script.contains("Test-UserCanceledElevation"));
    assert!(script.contains("-2147023673"));
    assert!(!script.contains("[uint32]"));
    assert!(script.contains("operation was canceled by the user"));
    assert!(script.contains("InnerException"));
    assert!(script.contains("exit 1223"));
    assert!(
        script
            .find("exit 1223")
            .expect("user cancellation exit should be present")
            < script
                .find("Write-Error")
                .expect("unexpected elevation failures should still be logged")
    );
    assert!(script.contains("upgrade"));
    assert!(script.contains("--scope"));
    assert!(script.contains("machine"));
}

#[test]
fn windows_elevated_cmd_scripts_use_start_process_runas() {
    let (program, args) = build_command_invocation(
        HostOs::Windows,
        &manager_task(
            r"C:\Program Files\Scoop\apps\tool\current\bin\tool.cmd",
            &["upgrade", "--all"],
            true,
        ),
    );

    assert_eq!(program, "powershell");
    let script = args.last().expect("powershell script");
    assert!(script.contains("Start-Process"));
    assert!(script.contains("-Verb RunAs"));
    assert!(script.contains(r"C:\Program Files\Scoop\apps\tool\current\bin\tool.cmd"));
    assert!(script.contains("upgrade"));
}

#[test]
fn windows_shell_tasks_use_cmd_c() {
    let task = CommandTask {
        program: "echo hello".to_string(),
        args: Vec::new(),
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: false,
        external_window: false,
        shell: true,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
    };

    let (program, args) = build_command_invocation(HostOs::Windows, &task);
    assert_eq!(program, "cmd");
    assert_eq!(args, vec!["/C".to_string(), "echo hello".to_string()]);
}

#[test]
fn windows_shell_tasks_preserve_metacharacters_and_quote_spaces_only() {
    let task = CommandTask {
        program: r#""C:\Program Files\Tool\runner.cmd""#.to_string(),
        args: vec![
            "hello world".to_string(),
            "&&".to_string(),
            "echo".to_string(),
            "%TEMP%".to_string(),
        ],
        mode: None,
        command_candidates: Vec::new(),
        pre_commands: Vec::new(),
        report_commands: Vec::new(),
        report_patterns: Vec::new(),
        policy_key: "system_update".to_string(),
        requires_elevation: false,
        needs_sudo_session: false,
        interactive: false,
        external_window: false,
        shell: true,
        windows_bridge: false,
        report_parser: None,
        plain_header: None,
        plain_start: None,
        success_details: Vec::new(),
        external_manager_skip: false,
    };

    let (program, args) = build_command_invocation(HostOs::Windows, &task);
    assert_eq!(program, "cmd");
    assert_eq!(args.first().map(String::as_str), Some("/C"));
    let script = args.get(1).expect("cmd script");
    assert_eq!(
        script,
        r#""C:\Program Files\Tool\runner.cmd" hello world && echo %TEMP%"#
    );
}

fn winget_spec(id: &str) -> TaskSpec {
    winget_spec_with_args(id, &["upgrade", "--all", "--scope", "user"])
}

fn winget_spec_with_args(id: &str, args: &[&str]) -> TaskSpec {
    TaskSpec {
        id: id.to_string(),
        label: "Winget".to_string(),
        depends_on: Vec::new(),
        kind: TaskKind::Command(manager_task("winget", args, false)),
        category: "system".to_string(),
    }
}

#[test]
fn winget_mixed_success_failure_is_completed_with_warning() {
    let output = r#"
Name             Id               Version Available Source
----------------------------------------------------------
PowerShell       Microsoft.PS      7.4.0   7.5.0     winget
Cherry Studio    Cherry.Studio     1.0.0   1.1.0     winget
Found PowerShell [Microsoft.PS]
Successfully installed
Found Cherry Studio [Cherry.Studio]
Installer failed with exit code: 2
"#;

    let result = classify_partial_winget_result(&winget_spec("winget-user"), output)
        .expect("partial result");
    assert_eq!(result.status, TaskStatus::Completed);
    assert_eq!(result.advisories.len(), 1);
    assert!(result.details[0].contains("1 updated, 1 failed"));
    let rows = &result.report_sections[0].rows;
    assert_eq!(rows[0].status, TaskReportStatus::Updated);
    assert_eq!(rows[1].status, TaskReportStatus::Failed);
}

#[test]
fn winget_partial_success_uses_configured_scope_without_winget_task_id() {
    let output = r#"
Name             Id               Version Available Source
----------------------------------------------------------
PowerShell       Microsoft.PS      7.4.0   7.5.0     winget
Cherry Studio    Cherry.Studio     1.0.0   1.1.0     winget
Found PowerShell [Microsoft.PS]
Successfully installed
Found Cherry Studio [Cherry.Studio]
Installer failed with exit code: 2
"#;

    let result = classify_partial_winget_result(
        &winget_spec_with_args(
            "configured-winget-admin",
            &["upgrade", "--all", "--scope", "machine"],
        ),
        output,
    )
    .expect("partial result for configured winget command");
    assert_eq!(result.status, TaskStatus::Completed);
    assert!(
        result.details[0].contains("winget machine-scope update"),
        "{result:?}"
    );
    assert!(
        result.advisories[0]
            .summary
            .contains("winget machine-scope update"),
        "{result:?}"
    );
}

#[test]
fn winget_zero_success_failure_stays_failed_path() {
    let output = r#"
Name             Id               Version Available Source
----------------------------------------------------------
Cherry Studio    Cherry.Studio     1.0.0   1.1.0     winget
Found Cherry Studio [Cherry.Studio]
Installer failed with exit code: 2
"#;

    assert!(classify_partial_winget_result(&winget_spec("winget-user"), output).is_none());
}

#[test]
fn winget_progress_heavy_output_produces_concise_rows() {
    let output = "\u{1b}[?25l████████████  50%\r\nFound PowerShell [Microsoft.PS]\r\nSuccessfully installed\r\n";
    let sections = parse_winget_report(&strip_progress_output(output));
    assert_eq!(sections[0].rows[0].name, "PowerShell");
    assert_eq!(sections[0].rows[0].status, TaskReportStatus::Updated);
    assert!(!sections[0].rows[0].name.contains('█'));
}

#[test]
fn winget_report_updates_found_packages_without_unknown_observed_rows() {
    let output = r#"
Name            Id                      Version             Available           Source
--------------------------------------------------------------------------------------
Cherry Studio   kangfenmao.CherryStudio 1.9.3               1.9.4               winget
Claude Code     Anthropic.ClaudeCode    2.1.123             2.1.126             winget
2 upgrades available.

(1/2) Found Cherry Studio [kangfenmao.CherryStudio] Version 1.9.4
Successfully installed
(2/2) Found Claude Code [Anthropic.ClaudeCode] Version 2.1.126
Successfully installed
"#;

    let sections = parse_winget_report(&strip_progress_output(output));
    let rows = &sections[0].rows;

    let cherry = rows.iter().find(|row| row.name == "Cherry Studio").unwrap();
    assert_eq!(cherry.status, TaskReportStatus::Updated);
    assert_eq!(cherry.before.as_deref(), Some("1.9.3"));
    assert_eq!(cherry.after.as_deref(), Some("1.9.4"));
    assert_ne!(cherry.status, TaskReportStatus::Info);
    assert_ne!(cherry.note.as_deref(), Some("observed in install output"));

    let claude = rows.iter().find(|row| row.name == "Claude Code").unwrap();
    assert_eq!(claude.status, TaskReportStatus::Updated);
    assert_eq!(claude.before.as_deref(), Some("2.1.123"));
    assert_eq!(claude.after.as_deref(), Some("2.1.126"));
}

#[test]
fn winget_report_ignores_prose_and_marks_uninstalled_available_versions_blocked() {
    let output = r#"
Name               Id                         Version         Available        Source
------------------------------------------------------------------------------------
Claude Code        Anthropic.ClaudeCode       2.1.120         2.1.123          winget
Claude             Anthropic.Claude           1.4758.0        1.5354.0         winget
Comet              Perplexity.Comet           145.1.7632.3200 145.2.7632.5936 winget
uv                 astral-sh.uv               0.11.7          0.11.8          winget
4 upgrades available.

The following packages have an upgrade available, but require explicit targeting for upgrade:
Name  Id              Version Available Source
----------------------------------------------
Slack SlackTechnologies.Slack 4.49.81 4.49.89 winget

(1/3) Found Claude Code [Anthropic.ClaudeCode] Version 2.1.123
This package is provided through Microsoft Store.
Successfully installed
(2/3) Found Claude [Anthropic.Claude] Version 1.5354.0
This application is licensed to you by its owner.
Successfully installed
(3/3) Found uv [astral-sh.uv] Version 0.11.8
remove: Access is denied.: "C:\\Users\\E135328\\.local\\bin\\uv.exe"
Installer failed with exit code: 0x8a150003
An unexpected error occurred while executing the command:
"#;

    let sections = parse_winget_report(&strip_progress_output(output));
    let rows = &sections[0].rows;
    assert!(!rows.iter().any(|row| row.name == "This package"));
    assert!(!rows
        .iter()
        .any(|row| row.name == "An unexpected error occurred"));

    let slack = rows.iter().find(|row| row.name == "Slack").unwrap();
    assert_eq!(slack.status, TaskReportStatus::Blocked);
    assert_eq!(slack.before.as_deref(), Some("4.49.81"));
    assert_eq!(slack.after.as_deref(), Some("4.49.89"));

    let comet = rows.iter().find(|row| row.name == "Comet").unwrap();
    assert_eq!(comet.status, TaskReportStatus::Blocked);
    assert_eq!(comet.before.as_deref(), Some("145.1.7632.3200"));
    assert_eq!(comet.after.as_deref(), Some("145.2.7632.5936"));

    let claude_code = rows.iter().find(|row| row.name == "Claude Code").unwrap();
    assert_eq!(claude_code.status, TaskReportStatus::Updated);

    let claude = rows.iter().find(|row| row.name == "Claude").unwrap();
    assert_eq!(claude.status, TaskReportStatus::Updated);

    let uv = rows.iter().find(|row| row.name == "uv").unwrap();
    assert_eq!(uv.status, TaskReportStatus::Failed);
    assert_eq!(uv.before.as_deref(), Some("0.11.7"));
    assert_eq!(uv.after.as_deref(), Some("0.11.8"));
    assert!(uv
        .note
        .as_deref()
        .is_some_and(|note| note.contains("0x8a150003")));
}
