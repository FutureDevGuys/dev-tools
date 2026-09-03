use std::process::Command;

fn sync_configs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sync-configs"))
}

#[test]
fn help_exposes_the_full_manifest_and_log_surface() {
    let output = sync_configs().arg("--help").output().expect("run help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in [
        "--config",
        "--mode",
        "--no-source-overrides",
        "--profile",
        "--host-profile",
        "--profile-map",
        "--profile-map-field",
        "--list-profiles",
        "--print-example",
        "--init",
        "--force-init",
        "--dry-run",
        "--validate",
        "--format",
        "--managed-path-policy",
        "--verbose",
        "--no-color",
        "--log-style",
        "--log-level",
        "--log-root",
        "logs",
        "completion",
    ] {
        assert!(stdout.contains(expected), "missing {expected} in {stdout}");
    }
}

#[test]
fn dependent_arguments_fail_during_parsing() {
    for args in [
        vec!["--force-init"],
        vec!["--host-profile", "desktop"],
        vec!["--profile-map-field", "profiles"],
    ] {
        let output = sync_configs().args(args).output().expect("run parser");
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("required"));
    }
}

#[test]
fn dry_run_init_is_rejected_instead_of_writing() {
    let output = sync_configs()
        .args(["--dry-run", "--init"])
        .output()
        .expect("run parser");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used"));
}

#[test]
fn native_completion_is_available_for_every_supported_shell() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = sync_configs()
            .args(["completion", shell])
            .output()
            .expect("generate completion");
        assert!(output.status.success(), "{shell}: {:?}", output);
        assert!(!output.stdout.is_empty(), "{shell}");
        assert!(output.stderr.is_empty(), "{shell}");
    }
}
