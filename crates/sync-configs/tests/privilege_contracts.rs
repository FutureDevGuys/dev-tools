#![cfg(all(unix, any(debug_assertions, feature = "test-support")))]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use sync_configs::privilege::{
    AuthenticationFailure, AuthenticationStage, PrivilegeError, PrivilegeSession,
};
use tempfile::TempDir;

static PRIVILEGE_PROCESS_TEST: Mutex<()> = Mutex::new(());

fn process_test_guard() -> MutexGuard<'static, ()> {
    PRIVILEGE_PROCESS_TEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The sudo policy a fake sudo models. `-n` invocations succeed only with a
/// valid timestamp or, for commands, a policy grant, as native sudo does.
#[derive(Clone, Copy, Default)]
struct SudoPolicy {
    cached: bool,
    granted: bool,
    prompt_fails: bool,
    prompt_reads_terminal: bool,
}

fn fake_sudo(root: &std::path::Path, policy: SudoPolicy) -> std::path::PathBuf {
    let sudo = root.join("sudo");
    let ticket = root.join("sudo.ticket");
    let grant = root.join("sudo.grant");
    if policy.cached {
        fs::write(&ticket, b"").expect("write sudo timestamp");
    }
    if policy.granted {
        fs::write(&grant, b"").expect("write sudo grant");
    }
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> '{log}'
if [ "${{1:-}} ${{2:-}}" = '-n -v' ]; then
  [ -f '{ticket}' ]
  exit
fi
if [ "${{1:-}}" = '-v' ]; then
  {read_reply}
  if [ {prompt_status} -ne 0 ]; then
    exit {prompt_status}
  fi
  : > '{ticket}'
  exit 0
fi
if [ "${{1:-}} ${{2:-}}" = '-n --' ]; then
  if [ ! -f '{ticket}' ] && [ ! -f '{grant}' ]; then
    printf 'sudo: a password is required\n' >&2
    exit 1
  fi
  shift 2
  exec "$@"
fi
exit 64
"#,
        log = root.join("sudo.log").display(),
        ticket = ticket.display(),
        grant = grant.display(),
        read_reply = if policy.prompt_reads_terminal {
            "IFS= read -r reply < /dev/tty"
        } else {
            ":"
        },
        prompt_status = if policy.prompt_fails { 1 } else { 0 },
    );
    fs::write(&sudo, script).expect("write fake sudo");
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).expect("chmod fake sudo");
    sudo
}

fn sudo_calls(root: &Path) -> Vec<String> {
    fs::read_to_string(root.join("sudo.log"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// Authentication tries a harmless system `true` through `sudo -n --` before it
/// prompts.
fn pathless_authorization_probe() -> String {
    let probe = ["/usr/bin/true", "/bin/true"]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file())
        .expect("system true");
    format!("-n -- {probe}")
}

fn environment_without_path() -> BTreeMap<OsString, OsString> {
    std::env::vars_os()
        .filter(|(name, _)| name != "PATH")
        .collect()
}

fn executable_script(path: &Path, script: &str) {
    fs::write(path, script).expect("write executable script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod executable script");
}

#[test]
fn authentication_failures_identify_stage_without_echoing_executable_authority() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = root.path().join("private-executable-sentinel");
    executable_script(&sudo, "#!/bin/sh\nexit 0\n");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo.clone()).unwrap();
    fs::remove_file(&sudo).unwrap();
    let error = session.ensure_authenticated().unwrap_err();
    let diagnostic = format!("{error}");
    assert!(diagnostic.contains("cached check"));
    assert!(diagnostic.contains("process error"));
    assert!(diagnostic.contains("NotFound"));
    assert!(!format!("{error:?}").contains("private-executable-sentinel"));
    assert!(matches!(
        error,
        PrivilegeError::Authentication {
            stage: AuthenticationStage::CachedCheck,
            failure: AuthenticationFailure::Process {
                kind: std::io::ErrorKind::NotFound,
                os_code: Some(libc::ENOENT),
            },
        }
    ));
    assert!(!session.is_authenticated());

    let diagnostic = sync_configs::engine::EngineError::Privilege(error).failure_diagnostic();
    assert_eq!(
        serde_json::to_value(diagnostic).unwrap(),
        serde_json::json!({
            "kind": "authentication_process",
            "stage": "cached_check",
            "os_code": libc::ENOENT,
        })
    );

    executable_script(&sudo, "#!/bin/sh\nexit 17\n");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo)
        .unwrap()
        .with_foreground_terminal_for_test(true);
    let error = session.ensure_authenticated().unwrap_err();
    let diagnostic = format!("{error}");
    assert!(diagnostic.contains("prompt"));
    assert!(diagnostic.contains("exit code Some(17)"));
    assert!(!format!("{error:?}").contains("private-executable-sentinel"));
    assert!(matches!(
        error,
        PrivilegeError::Authentication {
            stage: AuthenticationStage::Prompt,
            failure: AuthenticationFailure::Exit {
                code: Some(17),
                signal: None,
            },
        }
    ));
    assert!(!session.is_authenticated());
    let diagnostic = sync_configs::engine::EngineError::Privilege(error).failure_diagnostic();
    assert_eq!(
        serde_json::to_value(diagnostic).unwrap(),
        serde_json::json!({
            "kind": "authentication_exit",
            "stage": "prompt",
            "code": 17,
            "signal": null,
        })
    );
}

#[test]
fn authentication_failure_preserves_signal_termination() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = root.path().join("sudo");
    executable_script(&sudo, "#!/bin/sh\nkill -TERM \"$$\"\n");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo)
        .unwrap()
        .with_foreground_terminal_for_test(true);
    assert!(matches!(
        session.ensure_authenticated().unwrap_err(),
        PrivilegeError::Authentication {
            stage: AuthenticationStage::Prompt,
            failure: AuthenticationFailure::Exit {
                code: None,
                signal: Some(libc::SIGTERM),
            },
        }
    ));
    assert!(!session.is_authenticated());
}

#[test]
fn production_session_rejects_a_user_owned_sudo_executable() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), SudoPolicy::default());

    let error = PrivilegeSession::new(sudo).expect_err("user-owned sudo must be rejected");

    assert!(matches!(error, PrivilegeError::UnsafeSudo));
    assert!(!root.path().join("sudo.log").exists());
}

fn canonical_system_executable(name: &str) -> std::path::PathBuf {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("missing system executable {name}"))
        .canonicalize()
        .expect("canonical system executable")
}

#[test]
fn production_session_rejects_a_trusted_non_sudo_executable() {
    let _guard = process_test_guard();
    let error = PrivilegeSession::new(canonical_system_executable("true"))
        .expect_err("a non-sudo executable must not become privilege authority");

    assert!(matches!(error, PrivilegeError::UnsafeSudo));
}

#[test]
fn production_session_rejects_a_user_owned_privileged_command_before_authentication() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let command = root.path().join("user-command");
    let marker = root.path().join("must-not-run");
    fs::write(
        &command,
        format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    )
    .expect("write user command");
    fs::set_permissions(&command, fs::Permissions::from_mode(0o700)).expect("chmod user command");
    let sudo = fake_sudo(root.path(), SudoPolicy::default());
    let session = PrivilegeSession::new_injected_sudo_for_test(sudo)
        .expect("strict command authority with injected sudo");

    let error = session
        .run(&[command.into_os_string()])
        .expect_err("user-owned command must be rejected");

    assert!(matches!(error, PrivilegeError::UnsafeCommand));
    assert!(!marker.exists());
}

#[test]
fn one_visible_authentication_is_reused_for_exact_noninteractive_commands() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), SudoPolicy::default());
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo)
        .expect("session")
        .with_environment_for_test(environment_without_path())
        .with_foreground_terminal_for_test(true);

    session.ensure_authenticated().expect("authenticate");
    session.ensure_authenticated().expect("reuse");
    session
        .run(&["/usr/bin/touch".into(), marker.as_os_str().to_owned()])
        .expect("privileged command");

    assert!(marker.is_file());
    assert_eq!(
        sudo_calls(root.path()),
        [
            "-n -v".to_owned(),
            pathless_authorization_probe(),
            "-v".to_owned(),
            format!("-n -- /usr/bin/touch {}", marker.display()),
        ]
    );
}

#[test]
fn a_cached_timestamp_authenticates_without_a_probe_or_prompt() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            cached: true,
            prompt_fails: true,
            ..SudoPolicy::default()
        },
    );
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo).expect("session");

    session
        .ensure_authenticated()
        .expect("a cached timestamp authenticates");

    assert!(session.is_authenticated());
    assert_eq!(sudo_calls(root.path()), ["-n -v"]);
}

#[test]
fn a_noninteractive_sudo_policy_authenticates_without_a_prompt() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            granted: true,
            prompt_fails: true,
            ..SudoPolicy::default()
        },
    );
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo)
        .expect("session")
        .with_environment_for_test(environment_without_path());

    session
        .ensure_authenticated()
        .expect("a policy that admits sudo -n commands authenticates without a timestamp");
    session
        .run(&["/usr/bin/touch".into(), marker.as_os_str().to_owned()])
        .expect("privileged command runs under the policy");

    assert!(marker.is_file());
    assert_eq!(
        sudo_calls(root.path()),
        [
            "-n -v".to_owned(),
            pathless_authorization_probe(),
            format!("-n -- /usr/bin/touch {}", marker.display()),
        ]
    );
}

#[test]
fn the_authorization_probe_resolves_true_through_the_session_path() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            granted: true,
            prompt_fails: true,
            ..SudoPolicy::default()
        },
    );
    let bin = root.path().join("bin");
    fs::create_dir(&bin).expect("PATH directory");
    let probe = bin.join("true");
    executable_script(&probe, "#!/bin/sh\nexit 0\n");
    let mut session = PrivilegeSession::new_fully_injected_for_test(sudo)
        .expect("session")
        .with_environment_for_test(BTreeMap::from([(
            OsString::from("PATH"),
            bin.into_os_string(),
        )]))
        .with_foreground_terminal_for_test(false);

    session
        .ensure_authenticated()
        .expect("the only true on PATH detects the policy grant");

    assert!(session.is_authenticated());
    assert_eq!(
        sudo_calls(root.path()),
        ["-n -v".to_owned(), format!("-n -- {}", probe.display())]
    );
}

#[test]
fn a_session_path_without_a_usable_true_falls_through_to_the_prompt_decision() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), SudoPolicy::default());
    let empty = root.path().join("empty");
    let directory = root.path().join("directory");
    let unexecutable = root.path().join("unexecutable");
    fs::create_dir(&empty).expect("empty PATH directory");
    fs::create_dir_all(directory.join("true")).expect("directory named true");
    fs::create_dir(&unexecutable).expect("unexecutable PATH directory");
    fs::write(unexecutable.join("true"), "#!/bin/sh\nexit 0\n").expect("unexecutable true");
    fs::set_permissions(unexecutable.join("true"), fs::Permissions::from_mode(0o600))
        .expect("chmod unexecutable true");
    let path = std::env::join_paths([empty, directory, unexecutable]).expect("PATH");
    let mut session = PrivilegeSession::new_fully_injected_for_test(sudo)
        .expect("session")
        .with_environment_for_test(BTreeMap::from([(OsString::from("PATH"), path)]))
        .with_foreground_terminal_for_test(false);

    let error = session
        .ensure_authenticated()
        .expect_err("no grant, no timestamp and no foreground prompt");

    assert!(
        matches!(error, PrivilegeError::PromptUnavailable),
        "{error:?}"
    );
    assert!(!session.is_authenticated());
    let calls = sudo_calls(root.path());
    assert_eq!(calls[0], "-n -v", "{calls:?}");
    assert!(calls.len() <= 2, "{calls:?}");
    assert!(
        calls[1..]
            .iter()
            .all(|call| call.starts_with("-n -- /")
                && !call.contains(&*root.path().to_string_lossy())),
        "an unusable PATH candidate ran: {calls:?}"
    );
}

#[test]
fn failed_authentication_never_runs_the_requested_command() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            prompt_fails: true,
            ..SudoPolicy::default()
        },
    );
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo)
        .expect("session")
        .with_foreground_terminal_for_test(true);

    let error = session.ensure_authenticated().expect_err("auth must fail");
    assert!(error.to_string().contains("authenticate"));
    assert!(session
        .run(&["/usr/bin/touch".into(), marker.as_os_str().to_owned(),])
        .is_err());
    assert!(!marker.exists());
}

#[test]
fn unused_session_performs_no_probe_or_prompt() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), SudoPolicy::default());
    let _session = PrivilegeSession::new_injected_sudo_for_test(sudo).expect("session");
    assert!(!root.path().join("sudo.log").exists());
}

#[test]
fn privileged_commands_receive_the_captured_environment_and_closed_stdin() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            cached: true,
            ..SudoPolicy::default()
        },
    );
    let probe = root.path().join("probe");
    executable_script(
        &probe,
        r#"#!/bin/sh
printf '%s:' "${CAPTURED_ONLY:-missing}"
if IFS= read -r value; then
  printf 'open'
else
  printf 'closed'
fi
"#,
    );
    let environment =
        BTreeMap::from([(OsString::from("CAPTURED_ONLY"), OsString::from("planned"))]);
    let session = PrivilegeSession::new_authenticated_fully_injected_for_test(sudo)
        .expect("session")
        .with_environment_for_test(environment);

    let output = session
        .run(&[probe.into_os_string()])
        .expect("bounded privileged command");

    assert_eq!(output.stdout, b"planned:closed");
    assert!(output.stderr.is_empty());
}

#[test]
fn privileged_command_timeout_and_output_limit_are_typed_and_value_free() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            cached: true,
            ..SudoPolicy::default()
        },
    );
    let slow = root.path().join("slow");
    let noisy = root.path().join("noisy");
    executable_script(&slow, "#!/bin/sh\n/bin/sleep 30\n");
    executable_script(&noisy, "#!/bin/sh\nprintf '12345'\n");
    let session = PrivilegeSession::new_authenticated_fully_injected_for_test(sudo)
        .expect("session")
        .with_execution_limits_for_test(Duration::from_millis(50), 4);

    let timeout = session
        .run(&[slow.into_os_string()])
        .expect_err("slow command must time out");
    let output_limit = session
        .run(&[noisy.into_os_string()])
        .expect_err("noisy command must exceed its capture limit");

    let private_path = root.path().to_string_lossy();
    for rendered in [
        timeout.to_string(),
        format!("{timeout:?}"),
        output_limit.to_string(),
        format!("{output_limit:?}"),
    ] {
        assert!(!rendered.contains(private_path.as_ref()));
    }
    assert!(matches!(timeout, PrivilegeError::TimedOut));
    assert!(matches!(output_limit, PrivilegeError::OutputLimit));
}

#[test]
fn cancellation_terminalizes_the_owned_privileged_process_group_before_returning() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            cached: true,
            ..SudoPolicy::default()
        },
    );
    let command = root.path().join("command");
    let ready = root.path().join("ready");
    let release = root.path().join("release");
    let survived = root.path().join("survived");
    let descendant_pid = root.path().join("descendant-pid");
    executable_script(
        &command,
        &format!(
            "#!/bin/sh\n\
             ( trap '' HUP TERM; /usr/bin/touch '{}'; \
               while [ ! -e '{}' ]; do /bin/sleep 0.01; done; \
               /usr/bin/touch '{}' ) &\n\
             descendant=$!\n\
             printf '%s' \"$descendant\" > '{}'\n\
             while [ ! -e '{}' ]; do /bin/sleep 0.01; done\n\
             wait\n",
            ready.display(),
            release.display(),
            survived.display(),
            descendant_pid.display(),
            ready.display(),
        ),
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let session = PrivilegeSession::new_authenticated_fully_injected_for_test(sudo)
        .expect("session")
        .with_execution_limits_for_test(Duration::from_secs(30), 32)
        .with_cancellation_for_test(Arc::clone(&cancelled));
    let (sender, receiver) = mpsc::sync_channel(1);
    let runner = thread::spawn(move || {
        let result = session.run(&[command.into_os_string()]).map(|_| ());
        let _ = sender.send(result);
    });

    let ready_deadline = Instant::now() + Duration::from_secs(2);
    while !ready.exists() && Instant::now() < ready_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists(), "privileged child did not become ready");
    cancelled.store(true, Ordering::Release);
    let result = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("cancelled privileged command exceeded its cleanup bound");
    runner.join().expect("join privileged command runner");

    fs::write(&release, b"release").expect("release possible escaped descendant");
    for _ in 0..50 {
        if survived.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let escaped = survived.exists();
    if escaped {
        let raw_pid = fs::read_to_string(descendant_pid)
            .expect("read escaped descendant pid")
            .trim()
            .parse()
            .expect("parse escaped descendant pid");
        if let Some(pid) = rustix::process::Pid::from_raw(raw_pid) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
    assert!(matches!(result, Err(PrivilegeError::Interrupted)));
    assert!(!escaped, "a privileged descendant survived cancellation");
}

#[test]
fn privileged_cleanup_ignores_cancellation_but_remains_time_bounded() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            cached: true,
            ..SudoPolicy::default()
        },
    );
    let cleanup = root.path().join("cleanup");
    let started = root.path().join("cleanup-started");
    executable_script(
        &cleanup,
        &format!(
            "#!/bin/sh\n/usr/bin/touch '{}'\n/bin/sleep 30\n",
            started.display()
        ),
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let session = PrivilegeSession::new_authenticated_fully_injected_for_test(sudo)
        .expect("session")
        .with_execution_limits_for_test(Duration::from_millis(200), 32)
        .with_cancellation_for_test(Arc::clone(&cancelled));
    cancelled.store(true, Ordering::Release);
    let began = Instant::now();

    let error = session
        .run_cleanup_for_test(&[cleanup.into_os_string()])
        .expect_err("cleanup must remain time bounded");

    assert!(
        started.exists(),
        "cleanup incorrectly observed cancellation"
    );
    assert!(matches!(error, PrivilegeError::TimedOut));
    assert!(
        began.elapsed() < Duration::from_secs(3),
        "cleanup exceeded the runner's bounded termination window"
    );
}

const TERMINAL_ROLE: &str = "SYNC_CONFIGS_TEST_TERMINAL_ROLE";
const TERMINAL_FIXTURE: &str = "authentication_prompts_only_from_the_terminal_foreground";

/// The interactive `sudo -v` reads its reply from the controlling terminal, and
/// only the terminal's foreground process group can complete that read. Each
/// role runs in a fresh copy of this test binary inside the session layout it
/// names: no controlling terminal, a background process group of a terminal
/// session, or that session's foreground process group.
#[test]
fn authentication_prompts_only_from_the_terminal_foreground() {
    match std::env::var(TERMINAL_ROLE).as_deref() {
        Ok("foreground") => return foreground_terminal_role(),
        Ok("background" | "detached") => return refused_prompt_role(),
        Ok(role) => panic!("unknown terminal role {role}"),
        Err(_) => {}
    }
    let _guard = process_test_guard();
    let output = TempDir::new().expect("role output root");

    let detached_log = output.path().join("detached.log");
    let detached_status = {
        let log = fs::File::create(&detached_log).expect("detached role log");
        let mut detached = terminal_role("detached");
        detached
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("detached stdout"))
            .stderr(log);
        // SAFETY: setsid is async-signal-safe and runs only in the forked child.
        unsafe {
            detached.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        wait_for_role(
            detached.spawn().expect("spawn detached role"),
            Duration::from_secs(30),
        )
    };
    let (master, slave) = open_pty();
    let child = {
        let mut foreground = terminal_role("foreground");
        foreground
            .stdin(slave.try_clone().expect("terminal stdin"))
            .stdout(slave.try_clone().expect("terminal stdout"))
            .stderr(slave.try_clone().expect("terminal stderr"));
        // SAFETY: stdin is already the terminal; setsid and TIOCSCTTY are
        // async-signal-safe and run only in the forked child.
        unsafe {
            foreground.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        foreground.spawn().expect("spawn terminal session")
    };
    drop(slave);
    (&master)
        .write_all(b"reply\n")
        .expect("type the prompt reply");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut transcript = Vec::new();
        let _ = (&master).read_to_end(&mut transcript);
        let _ = sender.send(transcript);
    });
    let terminal_status = wait_for_role(child, Duration::from_secs(60));
    let transcript = receiver
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    assert!(
        detached_status.success() && terminal_status.success(),
        "detached role: {detached_status}\n{}\nterminal session: {terminal_status}\n{}",
        fs::read_to_string(&detached_log).unwrap_or_default(),
        String::from_utf8_lossy(&transcript)
    );
}

fn foreground_terminal_role() {
    let mut background = terminal_role("background");
    background.process_group(0);
    let status = wait_for_role(
        background.spawn().expect("spawn background role"),
        Duration::from_secs(20),
    );
    assert!(status.success(), "background role failed with {status}");

    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            prompt_reads_terminal: true,
            ..SudoPolicy::default()
        },
    );
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo).expect("session");

    session
        .ensure_authenticated()
        .expect("the foreground process group answers the prompt");
    session
        .run(&["/usr/bin/touch".into(), marker.as_os_str().to_owned()])
        .expect("privileged command after the prompt");

    assert!(marker.is_file());
    let calls = sudo_calls(root.path());
    assert_eq!(
        calls.iter().filter(|call| *call == "-v").count(),
        1,
        "{calls:?}"
    );
}

fn refused_prompt_role() {
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(
        root.path(),
        SudoPolicy {
            prompt_reads_terminal: true,
            ..SudoPolicy::default()
        },
    );
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo)
        .expect("session")
        .with_environment_for_test(environment_without_path());

    let error = session
        .ensure_authenticated()
        .expect_err("authentication outside the terminal foreground");

    assert!(
        matches!(error, PrivilegeError::PromptUnavailable),
        "{error:?}"
    );
    assert!(error.to_string().contains("sudo -n -v"), "{error}");
    assert!(!session.is_authenticated());
    assert_eq!(
        sudo_calls(root.path()),
        ["-n -v".to_owned(), pathless_authorization_probe()],
        "prompted outside the terminal foreground"
    );
    let diagnostic = sync_configs::engine::EngineError::Privilege(error).failure_diagnostic();
    assert_eq!(
        serde_json::to_value(diagnostic).unwrap(),
        serde_json::json!({"kind": "authentication_prompt_unavailable"})
    );
}

fn terminal_role(role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            TERMINAL_FIXTURE,
            "--test-threads=1",
            "--nocapture",
        ])
        .env(TERMINAL_ROLE, role);
    command
}

fn wait_for_role(mut child: Child, limit: Duration) -> ExitStatus {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("poll role") {
            return status;
        }
        if Instant::now() >= deadline {
            let group = rustix::process::Pid::from_child(&child);
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            let _ = child.wait();
            panic!("role did not finish within {limit:?}; a terminal read stopped it");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn open_pty() -> (fs::File, fs::File) {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: openpty writes two new descriptors into the outputs; the null
    // name, termios and window size select the kernel defaults.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(opened, 0, "openpty: {}", io::Error::last_os_error());
    // SAFETY: a successful openpty returned two distinct descriptors that
    // nothing else owns.
    unsafe { (fs::File::from_raw_fd(master), fs::File::from_raw_fd(slave)) }
}
