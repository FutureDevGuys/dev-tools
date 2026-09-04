#![cfg(all(unix, any(debug_assertions, feature = "test-support")))]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use sync_configs::privilege::{PrivilegeError, PrivilegeSession};
use tempfile::TempDir;

static PRIVILEGE_PROCESS_TEST: Mutex<()> = Mutex::new(());

fn process_test_guard() -> MutexGuard<'static, ()> {
    PRIVILEGE_PROCESS_TEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn fake_sudo(root: &std::path::Path, prompt_fails: bool) -> std::path::PathBuf {
    let sudo = root.join("sudo");
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> '{log}'
if [ "${{1:-}} ${{2:-}}" = '-n -v' ]; then
  exit 1
fi
if [ "${{1:-}}" = '-v' ]; then
  exit {prompt_status}
fi
if [ "${{1:-}} ${{2:-}}" = '-n --' ]; then
  shift 2
  exec "$@"
fi
exit 64
"#,
        log = root.join("sudo.log").display(),
        prompt_status = if prompt_fails { 1 } else { 0 },
    );
    fs::write(&sudo, script).expect("write fake sudo");
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).expect("chmod fake sudo");
    sudo
}

fn executable_script(path: &Path, script: &str) {
    fs::write(path, script).expect("write executable script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod executable script");
}

#[test]
fn production_session_rejects_a_user_owned_sudo_executable() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), false);

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
    let sudo = fake_sudo(root.path(), false);
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
    let sudo = fake_sudo(root.path(), false);
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo).expect("session");

    session.ensure_authenticated().expect("authenticate");
    session.ensure_authenticated().expect("reuse");
    session
        .run(&["/usr/bin/touch".into(), marker.as_os_str().to_owned()])
        .expect("privileged command");

    assert!(marker.is_file());
    let calls = fs::read_to_string(root.path().join("sudo.log")).expect("sudo log");
    assert_eq!(calls.lines().filter(|line| *line == "-n -v").count(), 1);
    assert_eq!(calls.lines().filter(|line| *line == "-v").count(), 1);
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("-n -- "))
            .count(),
        1
    );
}

#[test]
fn failed_authentication_never_runs_the_requested_command() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), true);
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new_injected_sudo_for_test(sudo).expect("session");

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
    let sudo = fake_sudo(root.path(), false);
    let _session = PrivilegeSession::new_injected_sudo_for_test(sudo).expect("session");
    assert!(!root.path().join("sudo.log").exists());
}

#[test]
fn privileged_commands_receive_the_captured_environment_and_closed_stdin() {
    let _guard = process_test_guard();
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), false);
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
    let sudo = fake_sudo(root.path(), false);
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
    let sudo = fake_sudo(root.path(), false);
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
    let sudo = fake_sudo(root.path(), false);
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
