//! Static public surfaces must not perform setup or administrator admission.
#![cfg(target_os = "linux")]
use std::process::Command;

#[test]
fn reusable_administrator_surface_is_static_and_closed() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args(["privilege", "--help"])
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
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
        assert!(help.contains(command), "missing {command}");
    }
    for private in ["admit-v1", "serve-v1", "child-v1", "unrestricted"] {
        assert!(!help.contains(private), "exposed {private}");
    }
}

#[test]
fn maintenance_grammar_remains_explicit_and_accepts_its_existing_operations() {
    for arguments in [
        vec![
            "plan",
            "--request",
            "/tmp/request",
            "--output",
            "/tmp/plan",
            "--json",
        ],
        vec![
            "request",
            "--plan",
            "/tmp/plan",
            "--sha256",
            "selected-digest",
            "--authorize",
            "polkit",
            "--non-interactive",
            "--result-file",
            "/tmp/result",
            "--",
            "/usr/bin/true",
        ],
        vec![
            "execute",
            "--session",
            "selected-session",
            "--operation",
            "selected-operation",
            "--request",
            "/tmp/request",
            "--result-file",
            "/tmp/result",
        ],
        vec![
            "execute-plan",
            "--session",
            "selected-session",
            "--operation",
            "selected-operation",
            "--plan-id",
            "selected-plan",
            "--result-file",
            "/tmp/result",
        ],
        vec!["status", "--session", "selected-session", "--json"],
        vec!["revoke", "--session", "selected-session", "--json"],
    ] {
        let parsed = dev_auth::privilege::cli::specification()
            .try_get_matches_from(std::iter::once("privilege").chain(arguments.iter().copied()))
            .unwrap();
        assert_eq!(parsed.subcommand_name(), Some(arguments[0]));
    }
}

#[test]
fn administrator_request_status_and_revoke_require_the_grant_namespace() {
    for arguments in [
        vec![
            "request",
            "--scope",
            "user",
            "--authority",
            "administrator",
            "--duration",
            "12h",
            "--non-interactive",
        ],
        vec!["status", "--format", "json"],
        vec!["revoke", "selected-grant"],
        vec![
            "request",
            "--plan",
            "/tmp/plan",
            "--sha256",
            "selected-digest",
            "--format",
            "json",
            "--",
            "/usr/bin/true",
        ],
    ] {
        assert!(
            dev_auth::privilege::cli::specification()
                .try_get_matches_from(std::iter::once("privilege").chain(arguments.iter().copied()))
                .is_err(),
            "{arguments:?}"
        );
    }
    for arguments in [
        vec![
            "grant",
            "request",
            "--scope",
            "user",
            "--authority",
            "administrator",
            "--duration",
            "12h",
            "--non-interactive",
        ],
        vec!["grant", "status", "--format", "json"],
        vec!["grant", "revoke", "selected-grant", "--format", "json"],
    ] {
        let parsed = dev_auth::privilege::cli::specification()
            .try_get_matches_from(std::iter::once("privilege").chain(arguments.iter().copied()))
            .unwrap();
        assert_eq!(parsed.subcommand_name(), Some("grant"));
    }
}

#[test]
fn native_request_has_no_arbitrary_root_command_tail() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .args(["privilege", "execute-plan", "--help"])
        .env_clear()
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--operation") && help.contains("--plan-id"));
    assert!(!help.contains("COMMAND") && !help.contains("--authorize"));
}
