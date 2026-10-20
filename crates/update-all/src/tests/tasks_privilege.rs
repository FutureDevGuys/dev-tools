use super::*;
use crate::updaters::PrivilegeMode;

fn privilege_fixture_spec(
    program: &Path,
    requires_elevation: bool,
    needs_sudo_session: bool,
) -> TaskSpec {
    TaskSpec {
        id: "privilege-fixture".to_string(),
        label: "Privilege fixture".to_string(),
        depends_on: Vec::new(),
        category: "system".to_string(),
        resource_locks: BTreeSet::new(),
        kind: TaskKind::Command(CommandTask {
            program: program.to_string_lossy().into_owned(),
            args: vec!["one argument; $HOME".to_string()],
            mode: None,
            command_candidates: Vec::new(),
            pre_commands: Vec::new(),
            report_commands: Vec::new(),
            report_patterns: Vec::new(),
            report_scoped_deltas: Vec::new(),
            policy_key: "system_update".to_string(),
            requires_elevation,
            needs_sudo_session,
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
    }
}

fn run_privilege_fixture(ctx: &SyncContext, spec: &TaskSpec) -> TaskResult {
    let TaskKind::Command(cmd) = &spec.kind else {
        panic!("command fixture")
    };
    run_command_task(ctx, spec, cmd).unwrap()
}

#[test]
fn privilege_modes_preserve_legacy_aliases_and_add_explicit_fallback_modes() {
    for (name, expected) in [
        ("skip", "skip"),
        ("best_effort_skip", "skip"),
        ("never", "skip"),
        ("prompt_tty", "prompt_tty"),
        ("prompt", "prompt_tty"),
        ("fail", "fail"),
        ("fail_run", "fail"),
        ("auto", "auto"),
        ("required", "required"),
    ] {
        let parsed = PrivilegeMode::parse(name);
        assert!(parsed.is_some(), "mode {name} must parse");
        assert_eq!(parsed, PrivilegeMode::parse(expected), "{name}");
    }
    assert_ne!(
        PrivilegeMode::parse("fail"),
        PrivilegeMode::parse("required")
    );
    assert!(PrivilegeMode::parse("automatic").is_none());
}

#[test]
fn auto_privilege_defers_missing_sudo_without_starting_the_command() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let marker = temp.path().join("effect");
    let program = temp.path().join("protected");
    write_executable(
        &program,
        &format!("#!/bin/sh\nprintf effect >> '{}'\n", marker.display()),
    );
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::parse("auto").expect("auto mode");
    let result = run_privilege_fixture(&ctx, &privilege_fixture_spec(&program, true, false));
    assert_eq!(result.status, TaskStatus::Skipped, "{result:?}");
    assert!(result.is_deferred(), "{result:?}");
    assert!(result.has_blocking_advisory(), "{result:?}");
    assert!(result
        .advisories
        .iter()
        .any(|a| a.code == "privilege-missing-executable"));
    assert!(!marker.exists());
}

#[test]
fn never_privilege_skips_without_sudo_or_command_invocation() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let marker = temp.path().join("effect");
    let program = temp.path().join("protected");
    let command = format!("#!/bin/sh\nprintf effect >> '{}'\n", marker.display());
    write_executable(&program, &command);
    write_executable(&temp.path().join("sudo"), &command);
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::parse("never").expect("never mode");
    let result = run_privilege_fixture(&ctx, &privilege_fixture_spec(&program, true, false));
    assert_eq!(result.status, TaskStatus::Skipped, "{result:?}");
    assert!(!result.is_deferred());
    assert!(
        result.has_blocking_advisory(),
        "unestablished capability must block health dependents"
    );
    assert!(!marker.exists());
}

fn write_noninteractive_sudo_fixture(bin: &Path) {
    write_executable(
        &bin.join("sudo"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$PRIVILEGE_SUDO_LOG"
if [ "${1:-}" = -n ] && [ "${2:-}" = -v ]; then
  count=0
  if [ -f "$PRIVILEGE_ADMISSION_COUNT" ]; then read count < "$PRIVILEGE_ADMISSION_COUNT"; fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$PRIVILEGE_ADMISSION_COUNT"
  if [ "${PRIVILEGE_DENY:-0}" = 1 ] || { [ "${PRIVILEGE_EXPIRE:-0}" = 1 ] && [ "$count" -gt 1 ]; }; then
    printf 'sudo: noninteractive authority unavailable\n' >&2
    exit 1
  fi
  if [ "${PRIVILEGE_ADMISSION_STALL:-0}" = 1 ]; then /bin/sleep 5; fi
  exit 0
fi
[ "${1:-}" = -n ] && [ "${2:-}" = -- ] || { printf 'unexpected prompt-capable invocation\n' >&2; exit 90; }
shift 2
exec "$@"
"#,
    );
}

#[test]
fn auto_privilege_uses_exact_noninteractive_argv_and_never_replays_started_work() {
    let _lock = env_guard();
    for (scenario, expected) in [
        ("success", TaskStatus::Completed),
        ("auth-failure", TaskStatus::Failed),
        ("lock-failure", TaskStatus::Failed),
        ("timeout", TaskStatus::Failed),
    ] {
        let temp = TempDir::new().unwrap();
        write_noninteractive_sudo_fixture(temp.path());
        let program = temp.path().join("protected");
        write_executable(
            &program,
            r#"#!/bin/sh
set -eu
[ "$#" = 1 ] && [ "$1" = 'one argument; $HOME' ] || exit 91
printf 'effect\n' >> "$PRIVILEGE_EFFECT"
case "$PRIVILEGE_SCENARIO" in
  auth-failure) printf 'sudo: a password is required\n' >&2; exit 1 ;;
  lock-failure) printf 'unable to lock database\n' >&2; exit 1 ;;
  timeout) /bin/sleep 5 ;;
esac
"#,
        );
        let log = temp.path().join("sudo.log");
        let effect = temp.path().join("effect");
        let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
        let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
        let _count = EnvVarGuard::set(
            "PRIVILEGE_ADMISSION_COUNT",
            temp.path().join("admissions").into_os_string(),
        );
        let _effect = EnvVarGuard::set("PRIVILEGE_EFFECT", effect.as_os_str());
        let _scenario = EnvVarGuard::set("PRIVILEGE_SCENARIO", scenario);
        let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
        ctx.updater_config.privilege_mode = PrivilegeMode::Auto;
        ctx.task_policies.system_update.timeout = Duration::from_millis(150);
        ctx.task_policies.system_update.retries = 3;
        let result = run_privilege_fixture(&ctx, &privilege_fixture_spec(&program, true, false));
        assert_eq!(result.status, expected, "{scenario}: {result:?}");
        assert!(
            !result.is_deferred(),
            "begun invocation must never become a deferral"
        );
        assert_eq!(
            fs::read_to_string(effect).unwrap().lines().count(),
            1,
            "{scenario}"
        );
        let invocations = fs::read_to_string(log).unwrap();
        assert_eq!(invocations.lines().count(), 2, "{scenario}: {invocations}");
        assert_eq!(invocations.lines().next(), Some("-n -v"));
        assert!(
            invocations.lines().nth(1).unwrap().starts_with("-n -- "),
            "{invocations}"
        );
    }
}

#[test]
fn auto_privilege_denial_is_latched_and_independent_work_continues() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    write_noninteractive_sudo_fixture(temp.path());
    let program = temp.path().join("protected");
    let effect = temp.path().join("effect");
    write_executable(
        &program,
        &format!("#!/bin/sh\nprintf 'effect\\n' >> '{}'\n", effect.display()),
    );
    let log = temp.path().join("sudo.log");
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
    let _count = EnvVarGuard::set(
        "PRIVILEGE_ADMISSION_COUNT",
        temp.path().join("admissions").into_os_string(),
    );
    let _deny = EnvVarGuard::set("PRIVILEGE_DENY", "1");
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::Auto;
    for _ in 0..2 {
        let result = run_privilege_fixture(&ctx, &privilege_fixture_spec(&program, true, false));
        assert!(result.is_deferred(), "{result:?}");
        assert!(result
            .advisories
            .iter()
            .any(|a| a.code == "privilege-noninteractive-unavailable"));
    }
    assert!(!effect.exists());
    let result = run_privilege_fixture(&ctx, &privilege_fixture_spec(&program, false, false));
    assert_eq!(result.status, TaskStatus::Completed, "{result:?}");
    assert_eq!(fs::read_to_string(log).unwrap(), "-n -v\n");
    assert_eq!(fs::read_to_string(effect).unwrap(), "effect\n");
}

#[test]
fn auto_privilege_expiry_defers_new_work_without_refresh_or_replay() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    write_noninteractive_sudo_fixture(temp.path());
    let program = temp.path().join("protected");
    let effect = temp.path().join("effect");
    write_executable(
        &program,
        &format!("#!/bin/sh\nprintf 'effect\\n' >> '{}'\n", effect.display()),
    );
    let log = temp.path().join("sudo.log");
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
    let _count = EnvVarGuard::set(
        "PRIVILEGE_ADMISSION_COUNT",
        temp.path().join("admissions").into_os_string(),
    );
    let _expire = EnvVarGuard::set("PRIVILEGE_EXPIRE", "1");
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::Auto;
    let spec = privilege_fixture_spec(&program, true, false);
    assert_eq!(
        run_privilege_fixture(&ctx, &spec).status,
        TaskStatus::Completed
    );
    for _ in 0..2 {
        let result = run_privilege_fixture(&ctx, &spec);
        assert!(result.is_deferred());
        assert!(result
            .advisories
            .iter()
            .any(|a| a.code == "privilege-expired-session"));
    }
    assert_eq!(fs::read_to_string(log).unwrap().lines().count(), 3);
    assert_eq!(fs::read_to_string(effect).unwrap(), "effect\n");
}

#[test]
fn auto_privilege_defers_nested_and_unsupported_platforms_without_sudo() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    let marker = temp.path().join("effect");
    let program = temp.path().join("protected");
    let command = format!("#!/bin/sh\nprintf effect >> '{}'\n", marker.display());
    write_executable(&program, &command);
    write_executable(&temp.path().join("sudo"), &command);
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    for (host, elevated, nested, reason) in [
        (
            HostOs::Linux,
            false,
            true,
            "privilege-unsupported-nested-session",
        ),
        (
            HostOs::Linux,
            true,
            true,
            "privilege-unsupported-nested-session",
        ),
        (
            HostOs::Windows,
            true,
            false,
            "privilege-unsupported-platform",
        ),
        (HostOs::Macos, true, false, "privilege-unsupported-platform"),
        (
            HostOs::Unknown,
            true,
            false,
            "privilege-unsupported-platform",
        ),
    ] {
        let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
        ctx.host_os = host;
        ctx.updater_config.privilege_mode = PrivilegeMode::Auto;
        let result =
            run_privilege_fixture(&ctx, &privilege_fixture_spec(&program, elevated, nested));
        assert!(result.is_deferred(), "{result:?}");
        assert!(
            result.advisories.iter().any(|a| a.code == reason),
            "{result:?}"
        );
    }
    assert!(!marker.exists());
}

#[test]
fn auto_privilege_interactive_task_invocation_still_forbids_password_prompts() {
    let mut spec = privilege_fixture_spec(Path::new("/bin/true"), true, false);
    let TaskKind::Command(ref mut cmd) = spec.kind else {
        panic!("command fixture")
    };
    cmd.interactive = true;
    let (_, auto) =
        build_command_invocation_with_privilege(HostOs::Linux, cmd, PrivilegeMode::Auto);
    assert_eq!(&auto[..2], ["-n", "--"]);
    let (_, prompt) =
        build_command_invocation_with_privilege(HostOs::Linux, cmd, PrivilegeMode::PromptTty);
    assert_eq!(prompt[0], "--");
}

#[test]
fn auto_privilege_admission_timeout_is_bounded_and_latched() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    write_noninteractive_sudo_fixture(temp.path());
    let log = temp.path().join("sudo.log");
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
    let _count = EnvVarGuard::set(
        "PRIVILEGE_ADMISSION_COUNT",
        temp.path().join("admissions").into_os_string(),
    );
    let _stall = EnvVarGuard::set("PRIVILEGE_ADMISSION_STALL", "1");
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::Auto;
    ctx.task_policies.system_update.timeout = Duration::from_millis(100);
    let started = std::time::Instant::now();
    let spec = privilege_fixture_spec(Path::new("/bin/true"), true, false);
    for _ in 0..2 {
        assert!(run_privilege_fixture(&ctx, &spec).is_deferred());
    }
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(fs::read_to_string(log).unwrap(), "-n -v\n");
}

#[test]
fn required_privilege_noninteractive_preflight_never_falls_back_to_prompting() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    write_noninteractive_sudo_fixture(temp.path());
    let log = temp.path().join("sudo.log");
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
    let _count = EnvVarGuard::set(
        "PRIVILEGE_ADMISSION_COUNT",
        temp.path().join("admissions").into_os_string(),
    );
    let _deny = EnvVarGuard::set("PRIVILEGE_DENY", "1");
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::Required;
    let spec = privilege_fixture_spec(Path::new("/bin/true"), true, false);
    assert!(ensure_sudo_preflight_once(&ctx, &spec).is_err());
    assert!(ensure_sudo_preflight_once(&ctx, &spec).is_err());
    assert_eq!(fs::read_to_string(log).unwrap(), "-n -v\n");
}

#[test]
fn auto_privilege_cancellation_preserves_execution_ownership_and_one_effect() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    write_noninteractive_sudo_fixture(temp.path());
    let program = temp.path().join("protected");
    let effect = temp.path().join("effect");
    write_executable(&program, &format!("#!/bin/sh\nprintf 'effect\\n' >> '{}'\nprintf 'PRIVILEGE_EFFECT_READY\\n'\n/bin/sleep 5\n", effect.display()));
    let log = temp.path().join("sudo.log");
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
    let _count = EnvVarGuard::set(
        "PRIVILEGE_ADMISSION_COUNT",
        temp.path().join("admissions").into_os_string(),
    );
    let runtime = Arc::new(RuntimeControl::default());
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::Auto;
    ctx.runtime_control = Some(runtime.clone());
    ctx.task_policies.system_update.retries = 3;
    let (tx, rx) = mpsc::channel();
    ctx.event_tx = Some(DashboardSender::new(tx, None));
    let spec = privilege_fixture_spec(&program, true, false);
    let (result_tx, result_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let TaskKind::Command(cmd) = &spec.kind else {
            panic!("command fixture")
        };
        result_tx.send(run_command_task(&ctx, &spec, cmd)).unwrap();
    });
    loop {
        if let DashboardEvent::LogLine(record) = rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            if record.line == "PRIVILEGE_EFFECT_READY" {
                runtime.request_cancel_all();
                break;
            }
        }
    }
    let error = result_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap_err();
    worker.join().unwrap();
    assert!(
        error.downcast_ref::<crate::Cancelled>().is_some(),
        "{error:#}"
    );
    assert!(runtime.running_pids.lock().unwrap().is_empty());
    assert_eq!(fs::read_to_string(effect).unwrap(), "effect\n");
    assert_eq!(fs::read_to_string(log).unwrap().lines().count(), 2);
}

#[test]
fn auto_privilege_precommand_failure_is_not_replayed_or_reclassified() {
    let _lock = env_guard();
    let temp = TempDir::new().unwrap();
    write_noninteractive_sudo_fixture(temp.path());
    let program = temp.path().join("protected");
    let effect = temp.path().join("effect");
    write_executable(&program, &format!("#!/bin/sh\nprintf 'effect\\n' >> '{}'\nprintf 'sudo: a password is required\\n' >&2\nexit 1\n", effect.display()));
    let log = temp.path().join("sudo.log");
    let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
    let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
    let _count = EnvVarGuard::set(
        "PRIVILEGE_ADMISSION_COUNT",
        temp.path().join("admissions").into_os_string(),
    );
    let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
    ctx.updater_config.privilege_mode = PrivilegeMode::Auto;
    ctx.task_policies.system_update.retries = 3;
    let mut spec = privilege_fixture_spec(&program, true, false);
    let TaskKind::Command(ref mut cmd) = spec.kind else {
        panic!("command fixture")
    };
    cmd.pre_commands.push(CommandPreCommand {
        program: program.to_string_lossy().into_owned(),
        args: Vec::new(),
    });
    let result = run_privilege_fixture(&ctx, &spec);
    assert_eq!(result.status, TaskStatus::Failed, "{result:?}");
    assert!(!result.is_deferred());
    assert_eq!(fs::read_to_string(effect).unwrap(), "effect\n");
    let log = fs::read_to_string(log).unwrap();
    assert_eq!(log.lines().count(), 2, "{log}");
    assert!(log.lines().nth(1).unwrap().starts_with("-n -- "), "{log}");
}

#[test]
fn required_privilege_launch_failure_never_prompts_or_replays() {
    let _lock = env_guard();
    for (scenario, interactive) in [
        ("launch-denied", false),
        ("partial-auth-failure", false),
        ("partial-lock-failure", false),
        ("launch-denied", true),
        ("partial-auth-failure", true),
        ("partial-lock-failure", true),
    ] {
        let temp = TempDir::new().unwrap();
        write_executable(
            &temp.path().join("sudo"),
            r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$PRIVILEGE_SUDO_LOG"
if [ "${1:-}" = -n ] && [ "${2:-}" = -v ]; then exit 0; fi
if [ "${1:-}" = -v ]; then exit 0; fi
[ "${1:-}" = -n ] && [ "${2:-}" = -- ] || exit 90
if [ "$PRIVILEGE_SCENARIO" = launch-denied ]; then
  printf 'sudo: a password is required\n' >&2
  exit 1
fi
shift 2
exec "$@"
"#,
        );
        let program = temp.path().join("protected");
        write_executable(
            &program,
            r#"#!/bin/sh
set -eu
printf 'effect\n' >> "$PRIVILEGE_EFFECT"
if [ "$PRIVILEGE_SCENARIO" = partial-auth-failure ]; then
  printf 'sudo: a password is required\n' >&2
else
  printf 'unable to lock database\n' >&2
fi
exit 1
"#,
        );
        let log = temp.path().join("sudo.log");
        let effect = temp.path().join("effect");
        let _path = EnvVarGuard::set("PATH", temp.path().as_os_str());
        let _log = EnvVarGuard::set("PRIVILEGE_SUDO_LOG", log.as_os_str());
        let _effect = EnvVarGuard::set("PRIVILEGE_EFFECT", effect.as_os_str());
        let _scenario = EnvVarGuard::set("PRIVILEGE_SCENARIO", scenario);
        let mut ctx = test_context(Arc::new(PrivilegeSession::default()));
        ctx.updater_config.privilege_mode = PrivilegeMode::Required;
        ctx.task_policies.system_update.retries = 3;
        let mut spec = privilege_fixture_spec(&program, true, false);
        let TaskKind::Command(ref mut cmd) = spec.kind else {
            panic!("command fixture")
        };
        cmd.interactive = interactive;
        let result = run_privilege_fixture(&ctx, &spec);
        assert_eq!(
            result.status,
            TaskStatus::Failed,
            "{scenario}, interactive={interactive}: {result:?}"
        );
        assert!(!result.is_deferred());
        let invocations = fs::read_to_string(log).unwrap();
        assert_eq!(invocations.lines().next(), Some("-n -v"));
        assert_eq!(
            invocations.lines().count(),
            2,
            "{scenario}, interactive={interactive}: {invocations}"
        );
        assert!(invocations.lines().nth(1).unwrap().starts_with("-n -- "));
        assert!(!invocations.lines().any(|line| line == "-v"));
        if scenario == "launch-denied" {
            assert!(!effect.exists());
        } else {
            assert_eq!(fs::read_to_string(effect).unwrap(), "effect\n");
        }
    }
}

#[test]
fn required_privilege_interactive_catalog_task_cannot_create_password_permission() {
    // The test harness has no caller TTY. A catalog's interactive flag may
    // select a task PTY, but cannot authorize privilege prompts in that PTY.
    assert!(!std::io::stdin().is_terminal() || !std::io::stdout().is_terminal());
    let mut spec = privilege_fixture_spec(Path::new("/bin/true"), true, false);
    let TaskKind::Command(ref mut cmd) = spec.kind else {
        panic!("command fixture")
    };
    cmd.interactive = true;
    let (_, required) =
        build_command_invocation_with_privilege(HostOs::Linux, cmd, PrivilegeMode::Required);
    assert_eq!(&required[..2], ["-n", "--"]);
    let (_, prompt) =
        build_command_invocation_with_privilege(HostOs::Linux, cmd, PrivilegeMode::PromptTty);
    assert_eq!(prompt[0], "--", "legacy prompt_tty invocation is unchanged");
}
