use dev_tools_command::{run_bounded_command, BoundedCommand};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

fn invoke(root: &Path, arguments: &[&str]) -> dev_tools_command::BoundedCommandOutput {
    let arguments: Vec<OsString> = arguments.iter().map(OsString::from).collect();
    let environment = BTreeMap::from([
        ("HOME".into(), root.as_os_str().to_owned()),
        (
            "XDG_CONFIG_HOME".into(),
            root.join("config").into_os_string(),
        ),
        ("XDG_CACHE_HOME".into(), root.join("cache").into_os_string()),
        ("XDG_STATE_HOME".into(), root.join("state").into_os_string()),
        ("HTTPS_PROXY".into(), "http://127.0.0.1:1".into()),
    ]);
    run_bounded_command(&BoundedCommand {
        executable: Path::new(env!("CARGO_BIN_EXE_artifact-update")),
        arguments: &arguments,
        environment: &environment,
        cwd: Some(root),
        timeout: Duration::from_secs(5),
        output_limit: 256 * 1024,
    })
    .unwrap()
}

#[test]
fn completion_emits_each_shell_without_configuration_or_state_mutation() {
    let root = tempfile::tempdir().unwrap();
    let help = invoke(root.path(), &["--help"]);
    assert!(help.status.success());
    assert!(std::str::from_utf8(&help.stdout)
        .unwrap()
        .contains("completion bash|zsh|fish|elvish|powershell"));
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = invoke(root.path(), &["completion", shell]);
        assert!(
            output.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let script = std::str::from_utf8(&output.stdout).unwrap();
        for token in [
            "artifact-update",
            "check",
            "config",
            "trust",
            "rollback",
            "recover",
            "offline",
        ] {
            assert!(script.contains(token), "{shell} must include {token}");
        }
        assert_eq!(
            invoke(root.path(), &["completion", shell]).stdout,
            output.stdout
        );
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[test]
fn completion_rejects_unknown_shells_and_extra_options_without_output() {
    let root = tempfile::tempdir().unwrap();
    for arguments in [
        vec!["completion"],
        vec!["completion", "unknown"],
        vec!["completion", "bash", "--config", "/ignored"],
        vec!["completion", "bash", "--json"],
    ] {
        let output = invoke(root.path(), &arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}

#[cfg(unix)]
#[test]
fn generated_bash_and_zsh_parse_with_available_native_shells() {
    let root = tempfile::tempdir().unwrap();
    for (shell, executable, options) in [
        ("bash", "/usr/bin/bash", vec!["--noprofile", "--norc", "-n"]),
        ("zsh", "/usr/bin/zsh", vec!["-f", "-n"]),
    ] {
        if !Path::new(executable).is_file() {
            continue;
        }
        let path = root.path().join(format!("completion.{shell}"));
        std::fs::write(&path, invoke(root.path(), &["completion", shell]).stdout).unwrap();
        let mut arguments: Vec<OsString> = options.into_iter().map(OsString::from).collect();
        arguments.push(path.into_os_string());
        let output = run_bounded_command(&BoundedCommand {
            executable: Path::new(executable),
            arguments: &arguments,
            environment: &BTreeMap::new(),
            cwd: Some(root.path()),
            timeout: Duration::from_secs(5),
            output_limit: 4096,
        })
        .unwrap();
        assert!(
            output.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(unix)]
#[test]
fn bash_completion_offers_only_the_relevant_command_and_option() {
    let shell = Path::new("/usr/bin/bash");
    if !shell.is_file() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("completion.bash");
    std::fs::write(&path, invoke(root.path(), &["completion", "bash"]).stdout).unwrap();
    // Foreign-shell protocol fixture: all input remains positional data.
    let program = r#"source "$1"
shift
read -r -a registration <<< "$(complete -p artifact-update)"
function_name=
for ((index=0; index+1<${#registration[@]}; index++)); do
    if [[ ${registration[index]} == -F ]]; then
        function_name=${registration[index+1]}
        break
    fi
done
[[ -n $function_name ]] || exit 1
COMP_WORDS=(artifact-update "$@")
COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
"$function_name" artifact-update "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
printf '%s\n' "${COMPREPLY[@]}"
"#;
    for (words, expected) in [
        (vec!["ch"], "check"),
        (vec!["config", "a"], "apply"),
        (vec!["build-info", "--j"], "--json"),
        (vec!["completion", "po"], "powershell"),
        (vec!["install", "example", "--off"], "--offline"),
        (vec!["rollback", "example", "--off"], ""),
    ] {
        let mut arguments: Vec<OsString> = ["--noprofile", "--norc", "-c", program, "fixture"]
            .into_iter()
            .map(OsString::from)
            .collect();
        arguments.push(path.as_os_str().to_owned());
        arguments.extend(words.into_iter().map(OsString::from));
        let environment = BTreeMap::from([("PATH".into(), "/nonexistent".into())]);
        let output = run_bounded_command(&BoundedCommand {
            executable: shell,
            arguments: &arguments,
            environment: &environment,
            cwd: Some(root.path()),
            timeout: Duration::from_secs(5),
            output_limit: 4096,
        })
        .unwrap();
        assert!(output.status.success());
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::str::from_utf8(&output.stdout).unwrap().trim(),
            expected
        );
    }
}
