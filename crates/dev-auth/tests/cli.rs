use std::fs;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn private_runtime() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn credential_helper(operation: &str, input: &str) -> std::process::Output {
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(env!("CARGO_BIN_EXE_git-credential-dev-auth"))
        .arg(operation)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn get_failure_stops_git_from_falling_back_to_human_credentials() {
    let secret = "must-not-appear";
    let output = credential_helper(
        "get",
        &format!(
            "protocol=https\nhost=github.com\npath=FutureDevGuys/dev-tools.git\npassword={secret}\n\n"
        ),
    );
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains(secret));
}

#[test]
fn store_discards_git_supplied_secrets_without_output() {
    let output = credential_helper(
        "store",
        "protocol=https\nhost=github.com\npath=FutureDevGuys/dev-tools.git\nusername=x-access-token\npassword=must-not-appear\n\n",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn help_is_product_generic_and_lists_the_bounded_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in ["exec", "ssh-load", "status", "purge"] {
        assert!(help.contains(command));
    }
    assert!(!help.to_ascii_lowercase().contains("codex"));
    assert!(!help.to_ascii_lowercase().contains("homelab"));
}

#[test]
fn one_released_binary_serves_the_git_helper_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
        .arg("get")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=FutureDevGuys/dev-tools.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
}
