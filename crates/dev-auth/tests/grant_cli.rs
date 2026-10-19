//! Static and noninteractive controls never enter native administrator approval.
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use wait_timeout::ChildExt;

fn bounded_output(command: &mut Command) -> Output {
    let mut child = command.spawn().unwrap();
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

fn invoke(arguments: &[&str]) -> Output {
    let directory = tempfile::tempdir().unwrap();
    bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(arguments)
            .env_clear()
            .env("PATH", "")
            .env(
                "DEV_AUTH_GRANT_SOCKET",
                directory.path().join("missing.sock"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    )
}

#[test]
fn nested_grant_help_exposes_the_lifecycle_and_hides_private_entrypoints() {
    let output = invoke(&["privilege", "grant", "--help"]);
    assert!(output.status.success(), "{:?}", output);
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "request", "status", "inspect", "exec", "delegate", "revoke", "leave",
    ] {
        assert!(help.contains(command), "missing {command}: {help}");
        let output = invoke(&["privilege", "grant", command, "--help"]);
        assert!(output.status.success(), "{command}: {output:?}");
    }
    for private in [
        "grant-daemon",
        "grant-plan-worker",
        "grant-payload",
        "grant-sudo-relay",
    ] {
        assert!(!help.contains(private), "exposed {private}: {help}");
    }
}

#[test]
fn finite_privilege_help_keeps_its_commands_and_adds_the_grant_namespace() {
    let output = invoke(&["privilege", "--help"]);
    assert!(output.status.success(), "{output:?}");
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "plan",
        "request",
        "execute",
        "execute-plan",
        "status",
        "revoke",
        "grant",
        "inspect",
        "exec",
        "delegate",
        "leave",
    ] {
        assert!(
            help.lines()
                .any(|line| line.split_whitespace().next() == Some(command)),
            "missing {command}: {help}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn direct_grant_alias_help_uses_the_direct_public_invocation() {
    for command in ["inspect", "exec", "delegate", "leave"] {
        let output = invoke(&["privilege", command, "--help"]);
        assert!(output.status.success(), "{command}: {output:?}");
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(
            help.contains(&format!("dev-auth privilege {command}")),
            "incorrect direct usage: {help}"
        );
        assert!(!help.contains("dev-auth privilege grant"), "{help}");
    }
}

#[cfg(target_os = "linux")]
mod alias_grammar {
    use dev_auth::privilege::grants::{direct_specification, specification, DirectGrantCommand};
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};

    fn raw_arguments(matches: &clap::ArgMatches) -> BTreeMap<String, Vec<OsString>> {
        matches
            .ids()
            .filter_map(|id| {
                matches.get_raw(id.as_str()).map(|values| {
                    (
                        id.as_str().to_owned(),
                        values.map(OsStr::to_os_string).collect(),
                    )
                })
            })
            .collect()
    }

    #[test]
    fn direct_and_nested_aliases_consume_the_same_grant_arguments() {
        for arguments in [
            vec!["inspect", "selected-grant"],
            vec!["inspect", "selected-grant", "--format", "json"],
            vec!["leave", "--format", "json", "--non-interactive"],
            vec![
                "exec",
                "--grant",
                "selected-grant",
                "--",
                "/usr/bin/id",
                "-u",
            ],
            vec![
                "exec",
                "--operation",
                "selected-operation",
                "--result-file",
                "/tmp/result",
            ],
            vec![
                "exec",
                "--plan-sha256",
                "selected-digest",
                "--format",
                "json",
                "--result-file",
                "/tmp/result",
            ],
            vec![
                "delegate",
                "selected-grant",
                "--scope",
                "user",
                "--authority",
                "administrator",
                "--duration",
                "12h",
                "--uses",
                "2",
            ],
            vec![
                "delegate",
                "selected-grant",
                "--scope",
                "workload",
                "--authority",
                "typed",
                "--duration",
                "45m",
                "--operation",
                "first",
                "--operation",
                "second",
                "--idle",
                "30s",
                "--format",
                "json",
            ],
        ] {
            let nested = specification()
                .try_get_matches_from(std::iter::once("grant").chain(arguments.iter().copied()))
                .unwrap();
            let direct = direct_specification()
                .try_get_matches_from(std::iter::once("privilege").chain(arguments.iter().copied()))
                .unwrap();
            let composed = dev_auth::privilege::cli::specification()
                .try_get_matches_from(std::iter::once("privilege").chain(arguments.iter().copied()))
                .unwrap();
            let (nested_name, nested) = nested.subcommand().unwrap();
            let (direct_name, direct) = direct.subcommand().unwrap();
            let (composed_name, composed) = composed.subcommand().unwrap();
            assert_eq!(nested_name, direct_name);
            assert_eq!(nested_name, composed_name);
            assert_eq!(raw_arguments(nested), raw_arguments(direct));
            assert_eq!(raw_arguments(nested), raw_arguments(composed));
        }
    }

    #[test]
    fn direct_and_nested_aliases_reject_the_same_invalid_grant_arguments() {
        for arguments in [
            vec!["inspect"],
            vec!["inspect", "--grant", "selected-grant"],
            vec!["leave", "selected-grant"],
            vec!["exec"],
            vec!["exec", "--session", "selected-session", "--", "/usr/bin/id"],
            vec![
                "exec",
                "--operation",
                "selected-operation",
                "--",
                "/usr/bin/id",
            ],
            vec![
                "exec",
                "--operation",
                "selected-operation",
                "--plan-sha256",
                "selected-digest",
            ],
            vec![
                "delegate",
                "selected-grant",
                "--authority",
                "administrator",
                "--duration",
                "12h",
            ],
            vec![
                "delegate",
                "selected-grant",
                "--scope",
                "user",
                "--duration",
                "12h",
            ],
            vec![
                "delegate",
                "selected-grant",
                "--scope",
                "user",
                "--authority",
                "administrator",
            ],
        ] {
            let nested = specification()
                .try_get_matches_from(std::iter::once("grant").chain(arguments.iter().copied()))
                .unwrap_err();
            let direct = direct_specification()
                .try_get_matches_from(std::iter::once("privilege").chain(arguments.iter().copied()))
                .unwrap_err();
            assert_eq!(nested.kind(), direct.kind(), "{arguments:?}");
        }
    }

    #[test]
    fn direct_alias_selection_is_exact_and_excludes_maintenance_names() {
        for (name, kind) in [
            ("inspect", DirectGrantCommand::Inspect),
            ("exec", DirectGrantCommand::Exec),
            ("delegate", DirectGrantCommand::Delegate),
            ("leave", DirectGrantCommand::Leave),
        ] {
            assert_eq!(DirectGrantCommand::from_name(OsStr::new(name)), Some(kind));
            assert_eq!(kind.name(), name);
        }
        for name in [
            "plan",
            "request",
            "execute",
            "execute-plan",
            "status",
            "revoke",
            "grant",
            "EXEC",
            "exec ",
        ] {
            assert!(DirectGrantCommand::from_name(OsStr::new(name)).is_none());
        }
        use std::os::unix::ffi::OsStrExt;
        assert!(DirectGrantCommand::from_name(OsStr::from_bytes(b"exec\xff")).is_none());
    }
}

#[test]
fn an_explicit_overnight_noninteractive_request_never_prompts_or_creates_a_grant() {
    let output = invoke(&[
        "privilege",
        "grant",
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
    assert_eq!(result["schema"], "dev-auth-administrator-grant-result-v1");
    assert_eq!(result["changed"], false);
    assert_eq!(result["error_kind"], "approval_required");
    assert!(result.get("grant").is_none_or(serde_json::Value::is_null));
}

#[test]
fn a_noninteractive_grant_request_requires_scope_authority_and_duration() {
    for extra in [
        vec!["--scope", "user", "--authority", "administrator"],
        vec!["--scope", "user", "--duration", "12h"],
        vec!["--authority", "administrator", "--duration", "12h"],
    ] {
        let mut arguments = vec!["privilege", "grant", "request"];
        arguments.extend(extra);
        arguments.extend(["--non-interactive", "--format", "json"]);
        let output = invoke(&arguments);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["schema"], "dev-auth-administrator-grant-result-v1");
        assert_eq!(result["error_kind"], "invalid_request");
        assert_eq!(result["changed"], false);
        assert!(result.get("grant").is_none_or(serde_json::Value::is_null));
    }
}

#[test]
fn invalid_duration_returns_value_free_json_before_any_approval() {
    let marker = "not-a-duration-private-marker";
    let output = invoke(&[
        "privilege",
        "grant",
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
fn grant_policy_template_is_standalone_readable_and_non_authorizing() {
    let output = invoke(&["setup", "template", "administrator-grant-policy"]);
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "dev-auth-administrator-grant-policy-v1");
    assert_eq!(value["subjects"], serde_json::json!([]));
    assert_eq!(value["sudo_program"], "/usr/bin/sudo");
    let policy: dev_auth::privilege::grants::policy::Policy =
        serde_json::from_value(value).unwrap();
    policy.validate().unwrap();
    assert!(dev_auth::privilege::policy::parse_policy(&output.stdout).is_err());
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

#[cfg(unix)]
#[test]
fn combined_deployment_keeps_credential_and_grant_policy_inputs_separate() {
    let output = invoke(&["setup", "template", "credential-grant-deployment"]);
    assert!(output.status.success(), "{output:?}");
    let document = dev_auth::deployment::parse_deployment_document(&output.stdout).unwrap();
    let intent = dev_auth::deployment::normalize_deployment(
        Some(document),
        dev_auth::deployment::DeploymentCliInput::default(),
    )
    .unwrap();
    assert!(intent.has_grants());
    assert!(intent.purpose.is_credentials());
    assert_ne!(
        intent.grant_policy.as_ref().unwrap(),
        &intent.administrator_policy
    );
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
    let output = invoke(&[
        "privilege",
        "grant",
        "exec",
        "--operation",
        "fixture-pipeline",
    ]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    for arguments in [
        vec![
            "privilege",
            "grant",
            "exec",
            "--operation",
            "fixture-pipeline",
            "--",
            "/usr/bin/id",
        ],
        vec![
            "privilege",
            "grant",
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
            .args(["grant-plan-worker", descriptor])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if nix::unistd::geteuid().is_root() {
            command.uid(65534).gid(65534);
        }
        let output = bounded_output(&mut command);
        assert_eq!(output.status.code(), Some(4), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn execution_failure_writes_only_the_separate_metadata_destination() {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let result = directory.path().join("result.json");
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "privilege",
                "grant",
                "exec",
                "--format",
                "json",
                "--result-file",
            ])
            .arg(&result)
            .args(["--", "test-private-command-never-executed"])
            .env_clear()
            .env("PATH", "")
            .env(
                "DEV_AUTH_GRANT_SOCKET",
                directory.path().join("missing.sock"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let bytes = std::fs::read(result).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("test-private-command"));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema"], "dev-auth-administrator-grant-result-v1");
    assert_eq!(value["changed"], false);
    assert_eq!(value["error_kind"], "requires_setup");
}

#[cfg(target_os = "linux")]
#[test]
fn a_private_sudo_relay_never_invokes_native_sudo_when_coordination_is_absent() {
    let directory = tempfile::tempdir().unwrap();
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "grant-sudo-relay",
                "00000000000000000000000000000000",
                "--",
                "/usr/bin/sudo",
                "--version",
            ])
            .env_clear()
            .env("PATH", "")
            .env(
                "DEV_AUTH_GRANT_SOCKET",
                directory.path().join("missing.sock"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(
        output.stdout.is_empty(),
        "native sudo version output would reveal fallback"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Sudo version"));
}
