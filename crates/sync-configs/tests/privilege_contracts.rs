#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use sync_configs::privilege::PrivilegeSession;
use tempfile::TempDir;

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

#[test]
fn one_visible_authentication_is_reused_for_exact_noninteractive_commands() {
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), false);
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new(sudo).expect("session");

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
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), true);
    let marker = root.path().join("marker");
    let mut session = PrivilegeSession::new(sudo).expect("session");

    let error = session.ensure_authenticated().expect_err("auth must fail");
    assert!(error.to_string().contains("authenticate"));
    assert!(session
        .run(&["/usr/bin/touch".into(), marker.as_os_str().to_owned(),])
        .is_err());
    assert!(!marker.exists());
}

#[test]
fn unused_session_performs_no_probe_or_prompt() {
    let root = TempDir::new().expect("temp root");
    let sudo = fake_sudo(root.path(), false);
    let _session = PrivilegeSession::new(sudo).expect("session");
    assert!(!root.path().join("sudo.log").exists());
}
