use std::process::{Command, Output, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

fn invoke(arguments: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args(arguments)
        .env_clear()
        .env("PATH", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if child
        .wait_timeout(Duration::from_secs(10))
        .unwrap()
        .is_none()
    {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("noninteractive privilege control must return without a prompt");
    }
    child.wait_with_output().unwrap()
}

#[test]
fn privilege_help_exposes_the_grant_lifecycle() {
    let output = invoke(&["privilege", "--help"]);
    assert!(output.status.success(), "{:?}", output);
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "request", "status", "inspect", "exec", "delegate", "revoke", "leave",
    ] {
        assert!(help.contains(command), "missing {command}: {help}");
    }
}

#[test]
fn workload_launch_requires_explicit_scope_and_duration_and_never_prompts_noninteractive() {
    let output = invoke(&[
        "workload",
        "launch",
        "worker",
        "--privilege-scope",
        "workload",
        "--privilege-duration",
        "12h",
        "--non-interactive",
        "--",
    ]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("approval_required"));
    for extra in [
        vec!["--privilege-scope", "workload"],
        vec!["--privilege-duration", "12h"],
        vec![
            "--privilege-scope",
            "workload",
            "--privilege-duration",
            "invalid-private-marker",
        ],
    ] {
        let mut arguments = vec!["workload", "launch", "worker"];
        arguments.extend(extra);
        arguments.extend(["--non-interactive", "--"]);
        let output = invoke(&arguments);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("invalid-private-marker"));
    }
}

#[test]
fn an_explicit_overnight_noninteractive_request_never_prompts_or_creates_a_grant() {
    let output = invoke(&[
        "privilege",
        "request",
        "--scope",
        "user",
        "--authority",
        "administrator",
        "--duration",
        "12h",
        "--non-interactive",
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(3), "{:?}", output);
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["schema"], "dev-auth-privilege-result-v1");
    assert_eq!(result["changed"], false);
    assert_eq!(result["error_kind"], "approval_required");
    assert!(result.get("grant").is_none_or(serde_json::Value::is_null));
}

#[test]
fn invalid_duration_returns_value_free_json_before_any_approval() {
    let marker = "not-a-duration-private-marker";
    let output = invoke(&[
        "privilege",
        "request",
        "--scope",
        "user",
        "--authority",
        "administrator",
        "--duration",
        marker,
        "--non-interactive",
        "--format",
        "json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stdout).contains(marker));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["error_kind"], "invalid_request");
    assert_eq!(result["changed"], false);
}

#[test]
fn privilege_policy_template_is_standalone_readable_and_non_authorizing() {
    let output = invoke(&["setup", "template", "privilege-policy"]);
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "dev-auth-privilege-policy-v1");
    assert_eq!(value["subjects"], serde_json::json!([]));
    assert_eq!(value["sudo_program"], "/usr/bin/sudo");
    let policy: dev_auth::privilege::policy::Policy = serde_json::from_value(value).unwrap();
    policy.validate().unwrap();
}

#[cfg(unix)]
#[test]
fn privilege_only_deployment_needs_no_credential_provider_or_user_configuration() {
    let output = invoke(&["setup", "template", "privilege-deployment"]);
    assert!(output.status.success(), "{output:?}");
    let document = dev_auth::deployment::parse_deployment_document(&output.stdout).unwrap();
    let intent = dev_auth::deployment::normalize_deployment(
        Some(document),
        dev_auth::deployment::DeploymentCliInput::default(),
    )
    .unwrap();
    let value = serde_json::to_value(intent).unwrap();
    assert_eq!(value["purpose"], "privilege_only");
    assert_eq!(value["mode"], "strong");
    assert_eq!(value["activation"], "inactive");
    assert_eq!(value["users"], serde_json::json!([]));
    assert_eq!(value["credentials"], serde_json::json!([]));
}

#[cfg(target_os = "linux")]
#[test]
fn independent_setup_approval_rejects_secret_stdin_before_native_authorization() {
    let output = invoke(&[
        "setup",
        "apply",
        "--plan",
        "/run/dev-auth/missing.plan",
        "--sha256",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "--authorize",
        "polkit",
        "--credential-stdin",
        "automation",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("PolicyKit setup authorization cannot forward credential stdin"),
        "{output:?}"
    );
}

#[test]
fn approved_plan_execution_has_an_explicit_selector_and_never_accepts_extra_commands() {
    let output = invoke(&["privilege", "exec", "--operation", "fixture-pipeline"]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    for arguments in [
        vec![
            "privilege",
            "exec",
            "--operation",
            "fixture-pipeline",
            "--",
            "/usr/bin/id",
        ],
        vec![
            "privilege",
            "exec",
            "--operation",
            "fixture-pipeline",
            "--plan-sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
    ] {
        assert_eq!(invoke(&arguments).status.code(), Some(2));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn private_graph_worker_rejects_nonroot_before_descriptor_intake() {
    use std::os::unix::process::CommandExt;

    for descriptor in ["not-a-descriptor", "0", "198"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dev-auth"));
        command
            .args(["privilege-plan-worker", descriptor])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if nix::unistd::geteuid().is_root() {
            command.uid(65534).gid(65534);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(4), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn execution_failure_writes_only_the_separate_metadata_destination() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let result = directory.path().join("result.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args(["privilege", "exec", "--format", "json", "--result-file"])
        .arg(&result)
        .args(["--", "test-private-command-never-executed"])
        .env_clear()
        .env("PATH", "")
        .env(
            "DEV_AUTH_PRIVILEGE_SOCKET",
            directory.path().join("missing.sock"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(child
        .wait_timeout(Duration::from_secs(5))
        .unwrap()
        .is_some());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let bytes = std::fs::read(result).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("test-private-command"));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema"], "dev-auth-privilege-result-v1");
    assert_eq!(value["changed"], false);
    assert_eq!(value["error_kind"], "requires_setup");
}

#[cfg(target_os = "linux")]
#[test]
fn a_private_sudo_relay_never_invokes_native_sudo_when_coordination_is_absent() {
    let directory = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args([
            "privilege-sudo-relay",
            "00000000000000000000000000000000",
            "--",
            "/usr/bin/sudo",
            "--version",
        ])
        .env_clear()
        .env("PATH", "")
        .env(
            "DEV_AUTH_PRIVILEGE_SOCKET",
            directory.path().join("missing.sock"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    assert!(child
        .wait_timeout(Duration::from_secs(5))
        .unwrap()
        .is_some());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        output.stdout.is_empty(),
        "native sudo version output would reveal fallback"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Sudo version"));
}
