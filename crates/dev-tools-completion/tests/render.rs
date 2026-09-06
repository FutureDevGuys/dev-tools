use clap::{Arg, ArgAction, Command};
use dev_tools_completion::{render, InvalidCommandName, Shell};

fn specification() -> Command {
    Command::new("fixture")
        .subcommand(
            Command::new("build-info")
                .arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        )
        .subcommand(Command::new("config").subcommand(
            Command::new("apply").arg(Arg::new("json").long("json").action(ArgAction::SetTrue)),
        ))
}

fn deep_specification() -> Command {
    Command::new("fixture").subcommand(
        Command::new("workload").visible_alias("wl").subcommand(
            Command::new("bind")
                .visible_alias("b")
                .subcommand(
                    Command::new("plan")
                        .visible_alias("p")
                        .arg(
                            Arg::new("mode")
                                .long("mode")
                                .short('m')
                                .visible_alias("policy")
                                .value_parser(["safe", "strict"]),
                        )
                        .subcommand(
                            Command::new("detail").arg(
                                Arg::new("verbose")
                                    .long("verbose")
                                    .action(ArgAction::SetTrue),
                            ),
                        ),
                )
                .subcommand(Command::new("list")),
        ),
    )
}

#[test]
fn fish_generation_does_not_truncate_deep_command_metadata() {
    let command = deep_specification();
    command.clone().debug_assert();
    let generated =
        String::from_utf8(render(Shell::Fish, command, "sample-tool").unwrap()).unwrap();
    for fragment in [" -l mode", " -l verbose", " -a \"detail\""] {
        assert!(generated.contains(fragment), "missing {fragment}");
    }
}

#[cfg(unix)]
#[test]
#[ignore = "requires explicitly configured native Fish"]
fn native_fish_retains_deep_options_values_aliases_and_branch_scope() {
    use dev_tools_command::{run_bounded_command, BoundedCommand};
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let shell =
        PathBuf::from(std::env::var_os("DEV_TOOLS_TEST_FISH").expect("set DEV_TOOLS_TEST_FISH"));
    assert!(shell.is_absolute() && shell.is_file());
    let command = deep_specification();
    command.clone().debug_assert();
    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("completion.fish");
    std::fs::write(
        &script,
        render(Shell::Fish, command, "sample-tool").unwrap(),
    )
    .unwrap();
    for (words, candidate, present) in [
        ("workload bind plan --m", "--mode", true),
        ("wl b p --m", "--mode", true),
        ("workload bind plan --mode s", "safe", true),
        ("workload bind plan d", "detail", true),
        ("workload bind plan detail --v", "--verbose", true),
        ("workload bind list --m", "--mode", false),
        ("workload bind --m", "--mode", false),
    ] {
        let output = run_bounded_command(&BoundedCommand {
            executable: &shell,
            arguments: &[
                "--no-config".into(),
                "-c".into(),
                "source $SCRIPT; complete -C $LINE".into(),
            ],
            environment: &BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.path().as_os_str().into()),
                ("XDG_CONFIG_HOME".into(), root.path().as_os_str().into()),
                ("XDG_DATA_HOME".into(), root.path().as_os_str().into()),
                ("XDG_CACHE_HOME".into(), root.path().as_os_str().into()),
                ("SCRIPT".into(), script.as_os_str().into()),
                ("LINE".into(), format!("sample-tool {words}").into()),
            ]),
            cwd: Some(root.path()),
            timeout: Duration::from_secs(5),
            output_limit: 16384,
        })
        .unwrap();
        assert!(output.status.success());
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = std::str::from_utf8(&output.stdout).unwrap();
        assert_eq!(
            text.lines()
                .any(|line| line.split('\t').next() == Some(candidate)),
            present,
            "{words}: {text}"
        );
    }
}

#[test]
fn rejects_registration_syntax_instead_of_emitting_shell_code() {
    for name in [
        "",
        "-flag",
        "1name",
        "two words",
        "a;b",
        "$(id)",
        "a\nb",
        "é",
    ] {
        assert_eq!(
            render(Shell::Bash, specification(), name),
            Err(InvalidCommandName)
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires explicitly configured native Elvish and util-linux script"]
fn native_elvish_offers_scoped_option_values() {
    use dev_tools_command::{run_bounded_command, BoundedCommand};
    use std::{collections::BTreeMap, path::PathBuf, time::Duration};
    let runtime = PathBuf::from(std::env::var_os("DEV_TOOLS_TEST_ELVISH").expect("set Elvish"));
    let pty = PathBuf::from(std::env::var_os("DEV_TOOLS_TEST_SCRIPT").expect("set script"));
    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("completion.elv");
    std::fs::write(
        &script,
        render(Shell::Elvish, deep_specification(), "sample-tool").unwrap(),
    )
    .unwrap();
    for (words, expected) in [
        ("workload bind plan --mode s", true),
        ("wl b p --mode s", true),
        ("workload bind plan -m s", true),
        ("workload bind plan --policy s", true),
        ("workload bind plan --mode strict --mode s", true),
        ("workload bind list --mode s", false),
        ("workload bind plan -- --mode s", false),
    ] {
        let probe = root.path().join("probe.elv");
        std::fs::write(&probe, format!("try {{\n eval (slurp < $E:COMPLETION_SCRIPT)\n $edit:completion:arg-completer[sample-tool] sample-tool {words} | each {{|candidate| echo $candidate }}\n}} catch e {{ echo $e; exit 1 }}\nexit\n")).unwrap();
        let output = run_bounded_command(&BoundedCommand {
            executable: &pty,
            arguments: &[
                "-q".into(),
                "-e".into(),
                "-E".into(),
                "never".into(),
                "-O".into(),
                "/dev/null".into(),
                "--".into(),
                runtime.as_os_str().into(),
                "-rc".into(),
                probe.into_os_string(),
            ],
            environment: &BTreeMap::from([
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.path().as_os_str().into()),
                ("XDG_CONFIG_HOME".into(), root.path().as_os_str().into()),
                ("XDG_DATA_HOME".into(), root.path().as_os_str().into()),
                ("TERM".into(), "dumb".into()),
                ("COMPLETION_SCRIPT".into(), script.as_os_str().into()),
            ]),
            cwd: Some(root.path()),
            timeout: Duration::from_secs(20),
            output_limit: 16384,
        })
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(!text.contains("Exception"), "{text}");
        assert_eq!(
            text.contains("complex-candidate safe "),
            expected,
            "{words}: {text}"
        );
        if expected {
            assert!(text.contains("complex-candidate strict "), "{text}");
            assert!(!text.contains("complex-candidate --mode "), "{text}");
        }
    }
}

#[test]
fn other_shells_preserve_upstream_bytes_and_bash_cannot_mutate_the_source() {
    let command = specification();
    command.clone().debug_assert();
    render(Shell::Bash, command.clone(), "sample-tool").unwrap();
    for shell in [Shell::Zsh, Shell::Fish, Shell::PowerShell] {
        let mut expected = Vec::new();
        clap_complete::generate(shell, &mut command.clone(), "sample-tool", &mut expected);
        assert_eq!(
            render(shell, command.clone(), "sample-tool").unwrap(),
            expected
        );
    }
}

#[cfg(unix)]
#[test]
fn native_bash_resolves_root_hyphens_and_nested_command_paths() {
    use dev_tools_command::{run_bounded_command, BoundedCommand};
    use std::{collections::BTreeMap, ffi::OsString, path::Path, time::Duration};
    let shell = Path::new("/usr/bin/bash");
    if !shell.is_file() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let script = root.path().join("completion.bash");
    let probe = r#"source "$1"
binary_name=$2
shift 2
read -r -a registration <<< "$(complete -p "$binary_name")"
function_name=
for ((index=0; index+1<${#registration[@]}; index++)); do
    if [[ ${registration[index]} == -F ]]; then
        function_name=${registration[index+1]}
        break
    fi
done
[[ -n $function_name ]] || exit 1
COMP_WORDS=("$binary_name" "$@")
COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
"$function_name" "$binary_name" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
printf '%s\n' "${COMPREPLY[@]}"
"#;
    for name in ["sample", "sample-tool", "sample-tool-next", "sample_tool"] {
        std::fs::write(&script, render(Shell::Bash, specification(), name).unwrap()).unwrap();
        for (words, expected) in [
            (vec!["bu"], "build-info"),
            (vec!["build-info", "--j"], "--json"),
            (vec!["config", "a"], "apply"),
            (vec!["config", "apply", "--j"], "--json"),
        ] {
            let mut arguments: Vec<OsString> = ["--noprofile", "--norc", "-c", probe, "fixture"]
                .into_iter()
                .map(OsString::from)
                .collect();
            arguments.push(script.as_os_str().to_owned());
            arguments.push(name.into());
            arguments.extend(words.into_iter().map(OsString::from));
            let output = run_bounded_command(&BoundedCommand {
                executable: shell,
                arguments: &arguments,
                environment: &BTreeMap::from([("PATH".into(), "/nonexistent".into())]),
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
                expected,
                "{name}"
            );
        }
    }
}
