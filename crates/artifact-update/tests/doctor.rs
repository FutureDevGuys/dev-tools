use std::fs;
use std::process::Command;

const CONFIG: &str = "schema = \"artifact-update-config-v1\"\nartifacts = []\n";

#[test]
fn doctor_preserves_human_success_output() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    fs::write(&config, CONFIG).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_artifact-update"))
        .env_clear()
        .args(["doctor", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"configuration=valid artifacts=0\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn doctor_uses_common_results_without_preparing_local_state() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    for (contents, extra, code, error) in [
        (Some(CONFIG), None, 0, None),
        (
            Some("private-sentinel = 'invalid'"),
            None,
            2,
            Some("invalid_configuration"),
        ),
        (None, None, 2, Some("invalid_configuration")),
        (
            Some(CONFIG),
            Some("--unsupported"),
            2,
            Some("invalid_invocation"),
        ),
    ] {
        match contents {
            Some(bytes) => fs::write(&config, bytes).unwrap(),
            None => fs::remove_file(&config).unwrap(),
        }
        let mut command = Command::new(env!("CARGO_BIN_EXE_artifact-update"));
        command
            .env_clear()
            .env("HOME", root.path())
            .env("USERPROFILE", root.path())
            .env("PATH", root.path().join("absent-bin"))
            .args(["doctor", "--json", "--config"])
            .arg(&config);
        if let Some(extra) = extra {
            command.arg(extra);
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(code));
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["schema"], "dev-tools-operation-result-v1");
        assert_eq!(result["product"], "artifact-update");
        assert_eq!(result["operation"], "doctor");
        assert_eq!(result["exit_code"], code);
        assert_eq!(result["changed"], false);
        assert_eq!(result["network_accessed"], false);
        assert_eq!(result["scope"], "configuration");
        assert_eq!(result["healthy"], code == 0);
        assert_eq!(
            result["outcome"],
            if code == 0 { "completed" } else { "failed" }
        );
        assert_eq!(
            result.get("error_kind").and_then(|value| value.as_str()),
            error
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-sentinel"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-sentinel"));
        if code == 0 {
            assert_eq!(result["artifact_count"], 0);
            assert!(output.stderr.is_empty());
        } else {
            assert!(result.get("artifact_count").is_none());
        }
        assert_eq!(fs::read_to_string(&config).ok().as_deref(), contents);
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            usize::from(contents.is_some())
        );
    }
}
