use std::process::Command;

#[cfg(target_os = "linux")]
fn repair_result(home: &std::path::Path, mode: &str, dry_run: bool) -> serde_json::Value {
    // A native empty-inventory fixture: printf ignores the appended list argv.
    // No package runner, network access or user skill inventory is involved.
    let mut command = Command::new(env!("CARGO_BIN_EXE_skills-sync"));
    command
        .env_clear()
        .env("HOME", home)
        .env("TMPDIR", home)
        .env("PATH", "/nonexistent")
        .current_dir(home)
        .args([
            mode,
            "--global",
            "--json",
            "--skills-cmd",
            "/usr/bin/printf '[]'",
        ]);
    if dry_run {
        command.arg("--dry-run");
    }
    let output = command.output().unwrap();
    assert!(output.status.success(), "{mode}: {:?}", output);
    assert!(output.stderr.is_empty(), "{mode}: {:?}", output.stderr);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn repair_preserves_doctor_dry_run_without_creating_state() {
    let home = tempfile::tempdir().unwrap();
    let legacy = repair_result(home.path(), "doctor", true);
    assert_eq!(legacy["command"], "doctor");
    assert_eq!(legacy["planned_lock_repairs"].as_array().unwrap().len(), 1);
    let explicit = repair_result(home.path(), "repair", true);
    assert_eq!(explicit, legacy);
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn repair_applies_existing_lock_workflow_and_repeats_without_repair() {
    let home = tempfile::tempdir().unwrap();
    let applied = repair_result(home.path(), "repair", false);
    assert_eq!(applied["planned_lock_repairs"].as_array().unwrap().len(), 1);
    let lock = home.path().join(".agents/skills-lock.json");
    let bytes = std::fs::read(&lock).unwrap();
    let repeated = repair_result(home.path(), "repair", false);
    assert!(repeated["planned_lock_repairs"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(std::fs::read(&lock).unwrap(), bytes);
    assert_eq!(repair_result(home.path(), "doctor", false), repeated);
}

#[test]
fn completion_is_static_despite_invalid_operational_environment() {
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
            .env_clear()
            .env("SKILLS_SYNC_SCOPE", "invalid")
            .env("SKILLS_SYNC_DRY_RUN", "invalid")
            .args(["completion", shell])
            .output()
            .unwrap();
        assert!(output.status.success(), "{shell}: {:?}", output.stderr);
        assert!(output.stderr.is_empty());
        let script = std::str::from_utf8(&output.stdout).unwrap();
        for token in [
            "skills-sync",
            "build-info",
            "completion",
            "doctor",
            "repair",
            "agent-link-policy",
        ] {
            assert!(script.contains(token), "{shell}: missing {token}");
        }
    }
}

#[test]
fn completion_rejects_invalid_arguments_without_emitting_script() {
    for arguments in [
        vec!["completion"],
        vec!["completion", "unknown"],
        vec!["completion", "bash", "--json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
            .env_clear()
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn completion_bash_offers_nested_options_and_policy_values() {
    if !std::path::Path::new("/usr/bin/bash").is_file() {
        return;
    }
    let generated = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
        .env_clear()
        .args(["completion", "bash"])
        .output()
        .unwrap();
    assert!(generated.status.success());
    let script = String::from_utf8(generated.stdout).unwrap();
    let probe = r#"source <(printf '%s' "$1")
read -r -a registration <<< "$(complete -p skills-sync)"
function_name=
for ((index=0; index+1<${#registration[@]}; index++)); do
    if [[ ${registration[index]} == -F ]]; then
        function_name=${registration[index+1]}
        break
    fi
done
[[ -n $function_name ]] || exit 1
COMP_WORDS=(skills-sync build-info --j)
COMP_CWORD=2
"$function_name" skills-sync --j build-info
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(skills-sync lock repair --agent-link-p)
COMP_CWORD=3
"$function_name" skills-sync --agent-link-p repair
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(skills-sync doctor --agent-link-policy rec)
COMP_CWORD=3
"$function_name" skills-sync rec --agent-link-policy
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(skills-sync rep)
COMP_CWORD=1
"$function_name" skills-sync rep skills-sync
printf '%s\n' "${COMPREPLY[@]}"
"#;
    let output = Command::new("/usr/bin/bash")
        .env_clear()
        .env("PATH", "/nonexistent")
        .args(["--noprofile", "--norc", "-c", probe, "fixture", &script])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        b"--json\n--agent-link-policy\nreconcile\nrepair\n"
    );
}

#[test]
fn standard_build_info_subcommand_uses_the_common_product_schema() {
    let output = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
        .args(["build-info", "--json"])
        .output()
        .expect("run standard build-info");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("build-info JSON");
    assert_eq!(payload["schema"], "dev-tools-build-info-v1");
    assert_eq!(payload["product"], "skills-sync");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    assert!(payload["source_commit"].as_str().is_some());
    assert!(payload["source_state"].as_str().is_some());
    assert!(payload["target"].as_str().is_some());
    assert!(payload["profile"].as_str().is_some());
    assert!(payload["built_unix"].as_u64().is_some());
}

#[test]
fn legacy_build_info_flag_remains_available_during_the_declared_window() {
    let output = Command::new(env!("CARGO_BIN_EXE_skills-sync"))
        .arg("--build-info")
        .output()
        .expect("run legacy build-info");
    assert!(output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("legacy build-info JSON");
    assert!(payload["git_commit"].as_str().is_some());
}
