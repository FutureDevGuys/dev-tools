#![cfg(unix)]
use assert_cmd::Command;
use std::path::Path;
use std::time::Duration;

#[test]
fn self_completion_bash_resolves_hyphenated_subcommand() {
    if !Path::new("/usr/bin/bash").is_file() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let output = Command::new(assert_cmd::cargo::cargo_bin!("update-all"))
        .env_clear()
        .current_dir(root.path())
        .args(["completion", "bash"])
        .timeout(Duration::from_secs(5))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let script = root.path().join("completion.bash");
    std::fs::write(&script, output).unwrap();
    // Shell protocol fixture; script path is positional data, never interpolated.
    let probe = r#"source "$1"
read -r -a registration <<< "$(complete -p update-all)"
function_name=
for ((index=0; index+1<${#registration[@]}; index++)); do
    if [[ ${registration[index]} == -F ]]; then
        function_name=${registration[index+1]}
        break
    fi
done
[[ -n $function_name ]] || exit 1
COMP_WORDS=(update-all build-info --j)
COMP_CWORD=2
"$function_name" update-all --j build-info
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(update-all update status --j)
COMP_CWORD=3
"$function_name" update-all --j status
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(update-all update check --j)
COMP_CWORD=3
"$function_name" update-all --j check
printf '%s\n' "${COMPREPLY[@]}"
"#;
    Command::new("/usr/bin/bash")
        .env_clear()
        .env("PATH", "/nonexistent")
        .current_dir(root.path())
        .args(["--noprofile", "--norc", "-c", probe, "fixture"])
        .arg(script)
        .timeout(Duration::from_secs(5))
        .assert()
        .success()
        .stderr("")
        .stdout("--json\n--json\n--json\n");
}
