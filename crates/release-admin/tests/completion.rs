use assert_cmd::Command;
use std::time::Duration;

#[test]
fn completion_is_static_and_does_not_open_release_or_credential_inputs() {
    let root = tempfile::tempdir().unwrap();
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = Command::new(assert_cmd::cargo::cargo_bin!("release-admin"))
            .env_clear()
            .env("HOME", root.path())
            .current_dir(root.path())
            .args(["completion", shell])
            .timeout(Duration::from_secs(5))
            .assert()
            .success()
            .stderr("")
            .get_output()
            .stdout
            .clone();
        let script = std::str::from_utf8(&output).unwrap();
        for token in [
            "release-admin",
            "build-info",
            "completion",
            "root",
            "manifest",
            "crate-set",
            "set",
        ] {
            assert!(script.contains(token), "{shell}: missing {token}");
        }
        assert!(!script.contains("--cargo-plugin"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn completion_rejects_invalid_invocations_before_output() {
    for arguments in [
        vec!["completion"],
        vec!["completion", "unknown"],
        vec!["completion", "bash", "--json"],
    ] {
        Command::new(assert_cmd::cargo::cargo_bin!("release-admin"))
            .env_clear()
            .args(arguments)
            .timeout(Duration::from_secs(5))
            .assert()
            .code(2)
            .stdout("");
    }
}
