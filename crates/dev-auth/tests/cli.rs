#![cfg(unix)]

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
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
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
            "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\npassword={secret}\n\n"
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
        "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\nusername=x-access-token\npassword=must-not-appear\n\n",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn store_accepts_git_eof_without_parsing_or_retaining_the_credential() {
    let output = credential_helper(
        "store",
        "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\nusername=x-access-token\npassword=must-not-appear\n",
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
    for command in [
        "enroll",
        "validate",
        "exec",
        "agent",
        "agent-endpoint",
        "ssh-load",
        "ssh-public",
        "status",
        "purge",
    ] {
        assert!(help.contains(command));
    }
    assert!(!help.to_ascii_lowercase().contains("codex"));
    assert!(!help.to_ascii_lowercase().contains("homelab"));
}

#[test]
fn offline_validation_is_value_free_and_does_not_read_secrets() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "/usr/bin/false"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Example Vault/app/private-key"
discover_installations = true
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }
[profiles.plan]
executables = ["/usr/bin/false"]
environment = { EXAMPLE_TOKEN = "op://Example Vault/plan/token" }
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Example Vault/auth/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Example Vault/signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#;
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .arg("validate")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "config_valid=true online=false declared_exec_profiles=1 declared_ssh_profiles=1 declared_secret_references=4\n"
    );
    assert!(output.stderr.is_empty());
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
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
}

#[test]
fn one_released_binary_serves_every_declared_symlink_frontend() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    for frontend in [
        "gh-dev-auth",
        "ssh-keygen-dev-auth",
        "gh-dev-auth.exe",
        "ssh-keygen-dev-auth.exe",
    ] {
        let path = directory.path().join(frontend);
        symlink(env!("CARGO_BIN_EXE_dev-auth"), &path).unwrap();
        let output = Command::new(&path)
            .arg("--help")
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{frontend}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with(&format!("{frontend}: ")),
            "{frontend}"
        );
    }
}

#[test]
fn internal_gh_children_do_not_forward_the_installation_token_to_git() {
    let directory = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let upstream_git = directory.path().join("upstream-git");
    fs::write(
        &upstream_git,
        "#!/bin/sh\n[ -z \"${GH_TOKEN+x}\" ] || exit 90\n[ -z \"${GITHUB_TOKEN+x}\" ] || exit 91\n[ \"$GIT_TERMINAL_PROMPT\" = 0 ] || exit 92\nprintf passed > \"$1\"\n",
    )
    .unwrap();
    fs::set_permissions(&upstream_git, fs::Permissions::from_mode(0o700)).unwrap();

    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "{}"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Example Vault/app/private-key"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
"#,
        upstream_git.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let marker = home.path().join("git-child-result");
    let output = Command::new(&git_frontend)
        .arg(&marker)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", &upstream_git)
        .env("GH_TOKEN", "must-not-reach-git")
        .env("GITHUB_TOKEN", "must-not-reach-git")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), "passed");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn internal_gh_pager_copies_only_standard_input() {
    let directory = tempfile::tempdir().unwrap();
    let pager = directory.path().join("cat");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &pager).unwrap();
    let mut child = Command::new(&pager)
        .env_clear()
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("GH_TOKEN", "must-not-be-rendered")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"bounded output\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"bounded output\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn windows_credential_helper_name_preserves_fail_closed_git_output() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth.exe");
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
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
}

#[test]
fn git_verification_does_not_require_the_secret_runtime_or_ssh_agent() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("ssh-keygen-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let verifier = directory.path().join("ssh-keygen");
    fs::write(
        &verifier,
        "#!/bin/sh\n[ \"$1\" = -Y ] && [ \"$2\" = verify ]\n",
    )
    .unwrap();
    fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700)).unwrap();

    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[credential_store]
service = "test-dev-auth"
account = "service-token"
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "/usr/bin/git"
ssh_add = "/usr/bin/false"
ssh_keygen = "{}"
[github]
app_id = 42
private_key_ref = "op://Automation/app/key"
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
discover_installations = true
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Automation/auth/private key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Automation/sign/private key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        verifier.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let absent_runtime = home.path().join("absent-runtime");
    let output = Command::new(&helper)
        .args(["-Y", "verify", "-n", "git"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_RUNTIME_DIR", &absent_runtime)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!absent_runtime.exists());
}
