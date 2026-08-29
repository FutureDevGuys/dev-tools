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
fn unsafe_gh_operations_are_rejected_before_configuration_or_credentials_are_read() {
    let directory = tempfile::tempdir().unwrap();
    let frontend = directory.path().join("gh-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &frontend).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();

    for arguments in [
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--base",
            "main",
            "--title",
            "Bounded change",
            "--body",
            "Reviewed body",
            "--dry-run",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body-file=/proc/self/environ",
        ],
        vec!["pr", "comment", "42", "--body-file=private-link"],
        vec!["pr", "review", "42", "-aF/proc/self/environ"],
        vec!["pr", "merge", "42", "--admin", "--squash"],
        vec!["run", "download", "42", "--dir=/tmp"],
        vec!["repo", "view", "-RExampleOrg/sample-repo"],
        vec![
            "pr",
            "comment",
            "https://github.com/OtherOrg/other-repo/pull/42",
            "--body",
            "cross-repository",
        ],
        vec!["pr", "view", "42", "--unknown"],
    ] {
        let output = Command::new(&frontend)
            .args(&arguments)
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .output()
            .unwrap();

        assert!(!output.status.success(), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("configuration"), "{arguments:?}: {error}");
        assert!(!error.contains("credential"), "{arguments:?}: {error}");
    }
}

#[test]
fn offline_validation_is_value_free_and_pins_the_gh_protocol() {
    let home = tempfile::tempdir().unwrap();
    let gh = home.path().join("gh");
    fs::write(
        &gh,
        "#!/bin/sh\n\
         [ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 91\n\
         [ -z \"${GH_TOKEN+x}\" ] || exit 92\n\
         [ -z \"${GITHUB_TOKEN+x}\" ] || exit 93\n\
         [ -z \"${GH_REPO+x}\" ] || exit 94\n\
         [ -z \"${DEV_AUTH_GH_CHILD+x}\" ] || exit 95\n\
         [ -z \"${DEV_AUTH_GH_GIT+x}\" ] || exit 96\n\
         case \"$HOME\" in */gh-sandbox/home) ;; *) exit 97 ;; esac\n\
         case \"$GH_CONFIG_DIR\" in */gh-sandbox/config) ;; *) exit 98 ;; esac\n\
         printf 'gh version 2.98.0 (2026-08-21)\\nhttps://github.com/cli/cli/releases/tag/v2.98.0\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
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
gh = "{}"
git = "/usr/bin/false"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Example Vault/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[profiles.plan]
executables = ["/usr/bin/false"]
environment = {{ EXAMPLE_TOKEN = "op://Example Vault/plan/token" }}
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Example Vault/auth/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Example Vault/signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        gh.display()
    );
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

    fs::write(
        &gh,
        "#!/bin/sh\nprintf 'gh version 2.99.0 (2026-08-28)\\nhttps://github.com/cli/cli/releases/tag/v2.99.0\\n'\n",
    )
    .unwrap();
    let rejected = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .arg("validate")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .output()
        .unwrap();
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = String::from_utf8(rejected.stderr).unwrap();
    assert!(error.contains("supported 2.98.0 protocol"));
    assert!(!error.contains("2.99.0"));
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
    let home = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let upstream_git = directory.path().join("upstream-git");
    fs::write(
        &upstream_git,
        format!(
            "#!/bin/sh\n[ -z \"${{GH_TOKEN+x}}\" ] || exit 90\n[ -z \"${{GITHUB_TOKEN+x}}\" ] || exit 91\n[ \"$GIT_TERMINAL_PROMPT\" = 0 ] || exit 92\n[ \"$1 $2\" = 'remote -v' ] || exit 93\nprintf passed > '{}'\n",
            home.path().join("git-child-result").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&upstream_git, fs::Permissions::from_mode(0o700)).unwrap();

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
repository_selection = "all"
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
        .args(["remote", "-v"])
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
fn internal_gh_git_child_rejects_url_scoped_repository_credential_helpers() {
    let directory = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args(["init", "--quiet"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let marker = directory.path().join("credential-helper-ran");
    let helper = directory.path().join("credential-helper");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nif [ \"${{1:-}}\" = get ]; then\n  printf 'username=human\\npassword=human-secret\\n'\nfi\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            "credential.https://github.com.helper",
            &format!("!{}", helper.display()),
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(&git_frontend)
        .args(["credential", "fill"])
        .current_dir(&repository)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", "/usr/bin/git")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/repository.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    assert!(!marker.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("human-secret"));
}

#[test]
fn internal_gh_git_child_rejects_explicit_config_overrides() {
    let directory = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let marker = directory.path().join("upstream-git-ran");
    let upstream_git = directory.path().join("upstream-git");
    fs::write(
        &upstream_git,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&upstream_git, fs::Permissions::from_mode(0o700)).unwrap();
    let home = tempfile::tempdir().unwrap();

    let output = Command::new(&git_frontend)
        .args(["-ccredential.helper=!attacker", "status"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", &upstream_git)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!marker.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outside the bounded read-only surface")
    );
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
repository_selection = "all"
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
