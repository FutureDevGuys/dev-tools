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
    ] {
        assert!(help.contains(command), "missing {command}");
    }
    for private in ["admit-v1", "serve-v1", "child-v1", "unrestricted"] {
        assert!(!help.contains(private), "exposed {private}");
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
