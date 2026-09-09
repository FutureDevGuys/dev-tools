#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::symlink;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use wait_timeout::ChildExt;

#[cfg(target_os = "linux")]
#[path = "support/enrolled_store.rs"]
mod enrolled_store;

const PUBLIC_SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const PUBLIC_SUBPROCESS_OUTPUT_LIMIT: u64 = 1024 * 1024;

#[test]
fn logical_secret_commands_fail_closed_without_admission_and_keep_stdout_clean() {
    for operation in ["read", "public"] {
        let root = private_runtime();
        let result = root.path().join("result.json");
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .env_clear()
                .env("HOME", root.path())
                .env("PATH", "/missing")
                .args([
                    "secret",
                    operation,
                    "build-token",
                    "--non-interactive",
                    "--result-file",
                ])
                .arg(&result),
        );
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&fs::read(result).unwrap()).unwrap();
        assert_eq!(report["schema"], "dev-auth-execution-result-v1");
        assert_eq!(report["operation"], format!("secret_{operation}"));
        assert_eq!(report["outcome"], "admission_required");
        assert_eq!(report["started"], false);
    }
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .args(["secret", "read", "op://private-sentinel/item/value"]),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-sentinel"));
}

#[test]
fn secret_exec_requires_admission_before_projecting_or_starting() {
    let root = private_runtime();
    let result = root.path().join("result.json");
    let marker = root.path().join("must-not-exist");
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", "/missing")
            .args([
                "secret",
                "exec",
                "--stdin",
                "build-token",
                "--non-interactive",
                "--result-file",
            ])
            .arg(&result)
            .args(["--", "/usr/bin/touch"])
            .arg(&marker),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!marker.exists());
    let report: serde_json::Value = serde_json::from_slice(&fs::read(result).unwrap()).unwrap();
    assert_eq!(report["operation"], "secret_exec");
    assert_eq!(report["outcome"], "admission_required");
    assert_eq!(report["started"], false);
}

#[test]
fn uninstalled_doctor_reports_external_without_loading_credentials_or_installing() {
    let root = private_runtime();
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .env("HOME", root.path())
            .env("PATH", "/path-that-does-not-exist")
            .current_dir(root.path())
            .args(["doctor", "--json"]),
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "dev-tools-operation-result-v1");
    assert_eq!(report["product"], "dev-auth");
    assert_eq!(report["operation"], "doctor");
    assert_eq!(report["outcome"], "external");
    assert_eq!(report["installation_state"], "external");
    assert_eq!(report["changed"], false);
    assert_eq!(report["invoked_version"], env!("CARGO_PKG_VERSION"));
    assert!(report.get("details").is_none());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn doctor_invalid_arguments_are_one_value_free_json_result() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .args(["doctor", "--json", "private-input-must-not-be-echoed"]),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["error_kind"], "invalid_invocation");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-input-must-not-be-echoed"));
}

#[test]
fn noninteractive_workload_launch_reports_setup_requirement_without_prompting() {
    let root = private_runtime();
    let result_file = root.path().join("result.json");
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .env("PATH", "/missing")
            .current_dir(root.path())
            .args([
                "workload",
                "launch",
                "generic-worker",
                "--non-interactive",
                "--result-file",
            ])
            .arg(&result_file)
            .arg("--")
            .arg("literal caller input"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&result_file).unwrap()).unwrap();
    assert_eq!(report["schema"], "dev-auth-execution-result-v1");
    assert_eq!(report["operation"], "workload_launch");
    assert_eq!(report["outcome"], "requires_setup");
    assert_eq!(report["started"], false);
    assert_eq!(report["exit_code"], 3);
    assert_eq!(
        fs::metadata(&result_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = fs::read_to_string(&result_file).unwrap();
    assert!(!text.contains("literal caller input"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("literal caller input"));
}

#[test]
fn workload_result_destination_cannot_overwrite_an_existing_document() {
    let root = private_runtime();
    let result_file = root.path().join("result.json");
    fs::write(&result_file, b"existing user document").unwrap();
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .args([
                "workload",
                "launch",
                "generic-worker",
                "--non-interactive",
                "--result-file",
            ])
            .arg(&result_file)
            .arg("--"),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(&result_file).unwrap(), b"existing user document");
}

#[test]
fn workload_launch_help_names_noninteractive_and_separate_result_controls() {
    let output = bounded_output(Command::new(env!("CARGO_BIN_EXE_dev-auth")).arg("--help"));
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("dev-auth doctor"));
    assert!(help.contains("--json"));
    assert!(help.contains("dev-auth workload launch"));
    assert!(help.contains("--non-interactive"));
    assert!(help.contains("--result-file"));
}

#[test]
fn workload_launch_help_is_available_without_a_workload_or_separator() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth")).args(["workload", "launch", "--help"]),
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--non-interactive"));
    assert!(help.contains("--result-file"));
}

#[test]
fn workload_launch_invalid_input_never_reserves_a_result() {
    let root = private_runtime();
    for extra in [
        vec!["--non-interactive", "--non-interactive", "--"],
        vec!["--unknown", "--"],
        vec![],
    ] {
        let result = root.path().join("result.json");
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .args(["workload", "launch", "generic-worker", "--result-file"])
                .arg(&result)
                .args(extra),
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!result.exists());
    }
}

#[test]
fn workload_launch_native_arguments_are_not_decoded_or_exposed() {
    use std::os::unix::ffi::OsStringExt;
    let root = private_runtime();
    let result = root.path().join("result.json");
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "workload",
                "launch",
                "generic-worker",
                "--non-interactive",
                "--result-file",
            ])
            .arg(&result)
            .arg("--")
            .arg(std::ffi::OsString::from_vec(
                b"caller-\xff-private".to_vec(),
            )),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("caller-"));
    let report: serde_json::Value = serde_json::from_slice(&fs::read(result).unwrap()).unwrap();
    assert_eq!(report["started"], false);
}

#[test]
fn workload_result_destination_rejects_links_and_nonprivate_parents() {
    let root = private_runtime();
    let target = root.path().join("existing");
    fs::write(&target, "preserve").unwrap();
    let linked_file = root.path().join("linked-file");
    symlink(&target, &linked_file).unwrap();
    let linked_parent = root.path().join("linked-parent");
    symlink(root.path(), &linked_parent).unwrap();
    let public = root.path().join("public");
    fs::create_dir(&public).unwrap();
    fs::set_permissions(&public, fs::Permissions::from_mode(0o755)).unwrap();
    for result in [
        linked_file,
        linked_parent.join("new.json"),
        public.join("new.json"),
    ] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .args(["workload", "launch", "generic-worker", "--result-file"])
                .arg(result)
                .arg("--"),
        );
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(fs::read_to_string(target).unwrap(), "preserve");
    assert!(!root.path().join("new.json").exists());
    assert!(!public.join("new.json").exists());
}

#[test]
fn standard_identity_is_local_and_preserves_legacy_release_build_info() {
    let root = tempfile::tempdir().unwrap();
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .env("HOME", root.path())
            .current_dir(root.path())
            .arg("--version"),
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("dev-auth {}\n", env!("CARGO_PKG_VERSION"))
    );
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .env("HOME", root.path())
            .current_dir(root.path())
            .args(["build-info", "--json"]),
    );
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["schema"], "dev-tools-build-info-v1");
    assert_eq!(info["product"], "dev-auth");
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info["source_commit"].is_string());
    assert!(info["source_state"].is_string());
    assert!(info["target"]
        .as_str()
        .is_some_and(|target| target != "unknown"));
    assert!(info["profile"]
        .as_str()
        .is_some_and(|profile| profile != "unknown"));
    assert!(info["built_unix"].is_u64());
    let legacy = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .env("HOME", root.path())
            .current_dir(root.path())
            .arg("build-info"),
    );
    assert!(legacy.status.success());
    let info: serde_json::Value = serde_json::from_slice(&legacy.stdout).unwrap();
    assert_eq!(info.as_object().unwrap().len(), 3);
    assert_eq!(info["product"], "dev-auth");
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    assert!(info.get("source_commit").is_some());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn standard_identity_rejects_extra_arguments_without_output() {
    for arguments in [
        vec!["--version", "extra"],
        vec!["build-info", "--json", "extra"],
        vec!["build-info", "--unknown"],
    ] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .env_clear()
                .args(arguments),
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn static_output_write_failure_is_operational_not_a_panic() {
    for arguments in [
        vec!["--version"],
        vec!["build-info", "--json"],
        vec!["completion", "bash"],
        vec!["doctor", "--json"],
    ] {
        let full = fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .args(arguments)
            .stdout(full)
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let Some(status) = child.wait_timeout(Duration::from_secs(5)).unwrap() else {
            let _ = child.kill();
            let _ = child.wait();
            panic!("static output operation did not stop after write failure");
        };
        assert_eq!(status.code(), Some(1));
    }
}

#[test]
fn static_completion_does_not_load_configuration_or_change_private_dispatch() {
    let root = tempfile::tempdir().unwrap();
    for shell in ["bash", "zsh", "fish", "elvish", "powershell"] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .env_clear()
                .env("HOME", root.path())
                .current_dir(root.path())
                .args(["completion", shell]),
        );
        assert!(output.status.success(), "{shell}: {:?}", output.stderr);
        assert!(output.stderr.is_empty());
        let script = std::str::from_utf8(&output.stdout).unwrap();
        for token in [
            "dev-auth",
            "completion",
            "setup",
            "doctor",
            "workload",
            "ssh-public",
            "credential-stdin",
            "restore",
            "caller-argument-index",
            "component",
        ] {
            assert!(script.contains(token), "{shell}: missing {token}");
        }
        // The retained upstream PowerShell renderer emits option names but
        // does not implement possible-value completion (ADR 0012).
        if shell != "powershell" {
            assert!(script.contains("providers"), "{shell}: missing providers");
        }
        for hidden in ["supervisor-child", "sandbox-child", "provider-exec"] {
            assert!(
                !script.contains(hidden),
                "{shell}: advertises private {hidden}"
            );
        }
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
    for private_marker in ["DEV_AUTH_GH_CHILD", "DEV_AUTH_GIT_CHILD"] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .env_clear()
                .env(private_marker, "1")
                .args(["completion", "bash"]),
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("unrecognized private child launcher identity"));
    }
}

#[test]
fn static_completion_rejects_invalid_arguments_before_output() {
    for arguments in [
        vec!["completion"],
        vec!["completion", "unknown"],
        vec!["completion", "bash", "--json"],
    ] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .env_clear()
                .args(arguments),
        );
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn static_completion_bash_resolves_public_nested_commands() {
    if !Path::new("/usr/bin/bash").is_file() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let generated = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .args(["completion", "bash"]),
    );
    assert!(generated.status.success());
    let script = root.path().join("completion.bash");
    fs::write(&script, generated.stdout).unwrap();
    let probe = r#"source "$1"
read -r -a registration <<< "$(complete -p dev-auth)"
function_name=
for ((index=0; index+1<${#registration[@]}; index++)); do
    if [[ ${registration[index]} == -F ]]; then
        function_name=${registration[index+1]}
        break
    fi
done
[[ -n $function_name ]] || exit 1
COMP_WORDS=(dev-auth build-info --j)
COMP_CWORD=2
"$function_name" dev-auth --j build-info
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth ssh-public --pu)
COMP_CWORD=2
"$function_name" dev-auth --pu ssh-public
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth setup apply --credential-s)
COMP_CWORD=3
"$function_name" dev-auth --credential-s apply
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth setup recover --credential-fd)
COMP_CWORD=3
"$function_name" dev-auth --credential-fd recover
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth setup restore --mode user-)
COMP_CWORD=4
"$function_name" dev-auth user- --mode
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth setup plan --channel st)
COMP_CWORD=4
"$function_name" dev-auth st --channel
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth workload bind plan --command-n)
COMP_CWORD=4
"$function_name" dev-auth --command-n plan
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth workload bind plan --target st)
COMP_CWORD=5
"$function_name" dev-auth st --target
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth workload bind plan --arg structured --caller-a)
COMP_CWORD=6
"$function_name" dev-auth --caller-a structured
printf '%s\n' "${COMPREPLY[@]}"
COMP_WORDS=(dev-auth validate --component pro)
COMP_CWORD=3
"$function_name" dev-auth pro --component
printf '%s\n' "${COMPREPLY[@]}"
"#;
    let output = bounded_output(
        Command::new("/usr/bin/bash")
            .env_clear()
            .env("PATH", "/nonexistent")
            .args(["--noprofile", "--norc", "-c", probe, "fixture"])
            .arg(script),
    );
    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.stdout,
        b"--json\n--purpose\n--credential-stdin\n--credential-fd\nuser-only\nstable\n--command-name\nstructured\n--caller-argument-index\nproviders\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn setup_restoration_has_closed_arguments_and_value_free_native_gates() {
    let help = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["setup", "restore", "--help"])
            .env_clear(),
    );
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("dev-auth setup restore"));
    let invalid = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["setup", "restore", "--credential-stdin", "unexpected"])
            .env_clear(),
    );
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    // Never invoke a mutating root restoration against the test host. The
    // explicit disposable-systemd fixture qualifies the native owner path.
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let blocked = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["setup", "restore", "--mode", "strong", "--format", "json"])
            .env_clear(),
    );
    assert_eq!(blocked.status.code(), Some(4));
    assert!(blocked.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(report["schema"], "dev-auth-setup-restore-v1");
    assert_eq!(report["changed"], false);
    assert_eq!(report["error_kind"], "setup_restoration_authority");
    assert_eq!(report["next_action"], "run_as_installation_owner");
}

#[cfg(target_os = "linux")]
#[test]
fn internal_provider_child_reads_only_a_sealed_fd_and_executes_the_held_provider() {
    use std::os::unix::process::CommandExt;

    let directory = tempfile::tempdir().unwrap();
    let provider = directory.path().join("op");
    fs::write(
        &provider,
        b"#!/bin/sh\n\
case \"$1\" in\n\
  read) [ \"$#\" -eq 3 ] && [ \"$2\" = --no-newline ] && [ \"$3\" = op://Automation/provider/private-key ] || exit 90 ;;\n\
  user) [ \"$#\" -eq 5 ] && [ \"$2\" = get ] && [ \"$3\" = --me ] && [ \"$4\" = --format ] && [ \"$5\" = json ] || exit 91 ;;\n\
  *) exit 92 ;;\n\
esac\n\
[ \"${OP_SERVICE_ACCOUNT_TOKEN-}\" = transport-test-token ] || exit 94\n\
for descriptor in /proc/$$/fd/*; do\n\
  case \"$(/usr/bin/readlink \"$descriptor\")\" in\n\
    *dev-auth-provider-token*) exit 95 ;;\n\
  esac\n\
done\n\
case \"$(/usr/bin/tr '\\000' '\\n' </proc/$$/cmdline)\" in\n\
  *transport-test-token*) exit 96 ;;\n\
esac\n\
printf provider-secret",
    )
    .unwrap();
    fs::set_permissions(&provider, fs::Permissions::from_mode(0o700)).unwrap();

    let mut provider_options = fs::OpenOptions::new();
    provider_options
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_CLOEXEC);
    let provider_guard = provider_options.open(&provider).unwrap();
    let mut child_options = fs::OpenOptions::new();
    child_options
        .read(true)
        .custom_flags(nix::libc::O_PATH | nix::libc::O_CLOEXEC);
    let child_guard = child_options.open(env!("CARGO_BIN_EXE_dev-auth")).unwrap();
    let token_descriptor = rustix::fs::memfd_create(
        "dev-auth-provider-token",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut token = fs::File::from(token_descriptor);
    rustix::fs::fchmod(&token, rustix::fs::Mode::from_bits_truncate(0o600)).unwrap();
    token.write_all(b"transport-test-token").unwrap();
    token.seek(SeekFrom::Start(0)).unwrap();
    rustix::fs::fcntl_add_seals(
        &token,
        rustix::fs::SealFlags::SEAL
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::WRITE,
    )
    .unwrap();

    let child_fd = child_guard.as_raw_fd();
    let provider_fd = provider_guard.as_raw_fd();
    let token_fd = token.as_raw_fd();
    for (arguments, permitted) in [
        (
            vec!["--reference", "op://Automation/provider/private-key"],
            true,
        ),
        (vec!["--current-account"], true),
        (vec!["--current-account", "--user", "other"], false),
        (
            vec![
                "--current-account",
                "--reference",
                "op://Automation/provider/private-key",
            ],
            false,
        ),
        (vec!["--operation", "arbitrary"], false),
    ] {
        token.seek(SeekFrom::Start(0)).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_dev-auth"));
        command
            .arg0("dev-auth-provider-exec")
            .args([
                "--child-fd".into(),
                child_fd.to_string(),
                "--provider-fd".into(),
                provider_fd.to_string(),
                "--token-fd".into(),
                token_fd.to_string(),
                "--provider-argv0".into(),
                provider.to_string_lossy().into_owned(),
            ])
            .args(arguments)
            .env_clear();
        // SAFETY: all three File owners remain live until bounded_output completes.
        // Clearing FD_CLOEXEC is async-signal-safe and occurs only in the child.
        unsafe {
            command.pre_exec(move || {
                for descriptor in [child_fd, provider_fd, token_fd] {
                    // SAFETY: the File owners above retain these exact descriptors
                    // through the pre-exec callback.
                    let descriptor = BorrowedFd::borrow_raw(descriptor);
                    rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty())?;
                }
                Ok(())
            });
        }
        let output = bounded_output(&mut command);
        assert_eq!(
            output.status.success(),
            permitted,
            "provider child failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        if permitted {
            assert_eq!(output.stdout, b"provider-secret");
        } else {
            assert!(output.stdout.is_empty());
        }
        assert!(!output
            .stderr
            .windows(b"transport-test-token".len())
            .any(|window| { window == b"transport-test-token" }));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn internal_provider_child_argv0_rejects_missing_descriptor_authority() {
    use std::os::unix::process::CommandExt;

    let mut command = Command::new(env!("CARGO_BIN_EXE_dev-auth"));
    command
        .arg0("dev-auth-provider-exec")
        .args(["--child-fd", "9"])
        .env_clear();
    let output = bounded_output(&mut command);
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.starts_with("dev-auth-provider-exec:"), "{error}");
    assert!(error.contains("internal provider child protocol is malformed"));
}

#[cfg(target_os = "linux")]
#[test]
fn signed_release_asset_name_enters_the_setup_cli_without_renaming() {
    const CHILD: &str = "DEV_AUTH_TEST_RELEASE_ASSET_CHILD";
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new("1")) {
        run_signed_release_asset_name_child();
        return;
    }
    // A concurrent pre-exec child can inherit fs::copy's writable descriptor,
    // even with CLOEXEC, and retain it after this thread closes its copy. Linux
    // then rejects execution with ETXTBSY until that other child execs. Create
    // and exercise the fixture in an isolated test process instead of retrying.
    let output = bounded_output_with_timeout(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "signed_release_asset_name_enters_the_setup_cli_without_renaming",
                "--test-threads=1",
                "--nocapture",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env(CHILD, "1"),
        Duration::from_secs(150),
        "release asset filename acceptance subprocess",
    );
    assert!(
        output.status.success(),
        "isolated release asset test failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
fn run_signed_release_asset_name_child() {
    let directory = tempfile::tempdir().unwrap();
    let asset = directory.path().join(format!(
        "dev-auth-{}-linux-{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    ));
    fs::copy(env!("CARGO_BIN_EXE_dev-auth"), &asset).unwrap();
    fs::set_permissions(&asset, fs::Permissions::from_mode(0o700)).unwrap();

    let output = bounded_output(
        Command::new(&asset)
            .arg("build-info")
            .env_clear()
            .env("PATH", "/usr/bin:/bin"),
    );
    assert!(
        output.status.success(),
        "downloaded release asset did not enter the core CLI: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(info["product"], "dev-auth");
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let output = bounded_output(
        Command::new(&asset)
            .args([
                "setup",
                "plan",
                "--mode",
                "strong",
                "--channel",
                "stable",
                "--offline",
                "--activation",
                "inactive",
                "--administrator-policy",
                directory.path().join("policy.toml").to_str().unwrap(),
                "--user-config",
                &format!(
                    "{}={}",
                    user.name,
                    directory.path().join("config.toml").display()
                ),
                "--release-root",
                directory.path().join("missing-root.json").to_str().unwrap(),
                "--release-manifest",
                directory
                    .path()
                    .join("missing-manifest.json")
                    .to_str()
                    .unwrap(),
                "--release-artifact",
                directory.path().join("missing-artifact").to_str().unwrap(),
                "--output",
                directory.path().join("plan.json").to_str().unwrap(),
                "--format",
                "json",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin"),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("open root document"),
        "downloaded release asset did not parse the local setup plan: {error}"
    );
}

fn bounded_reader<T>(mut reader: T) -> thread::JoinHandle<Vec<u8>>
where
    T: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut output = Vec::new();
        reader
            .by_ref()
            .take(PUBLIC_SUBPROCESS_OUTPUT_LIMIT + 1)
            .read_to_end(&mut output)
            .unwrap();
        output
    })
}

fn bounded_output(command: &mut Command) -> Output {
    bounded_output_with_timeout(
        command,
        PUBLIC_SUBPROCESS_TIMEOUT,
        "public dev-auth subprocess",
    )
}

fn bounded_output_with_timeout(
    command: &mut Command,
    timeout: Duration,
    description: &str,
) -> Output {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = bounded_reader(child.stdout.take().unwrap());
    let stderr = bounded_reader(child.stderr.take().unwrap());
    let (status, timed_out) = match child.wait_timeout(timeout).unwrap() {
        Some(status) => (status, false),
        None => {
            child.kill().unwrap();
            (child.wait().unwrap(), true)
        }
    };
    let stdout = stdout.join().unwrap();
    let stderr = stderr.join().unwrap();
    if timed_out {
        panic!(
            "{description} exceeded its {} second bound: stdout={} stderr={}",
            timeout.as_secs(),
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
    }
    assert!(stdout.len() <= PUBLIC_SUBPROCESS_OUTPUT_LIMIT as usize);
    assert!(stderr.len() <= PUBLIC_SUBPROCESS_OUTPUT_LIMIT as usize);
    Output {
        status,
        stdout,
        stderr,
    }
}

fn private_runtime() -> TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn private_program_root() -> TempDir {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let directory = tempfile::Builder::new()
        .prefix("dev-auth-cli-programs-")
        .tempdir_in(user.dir)
        .unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn standalone_binary_embeds_every_setup_source_template() {
    for name in [
        "deployment",
        "administrator-policy",
        "user-only-policy",
        "user-config",
    ] {
        let output = bounded_output(
            Command::new(env!("CARGO_BIN_EXE_dev-auth"))
                .args(["setup", "template", name])
                .env_clear(),
        );
        assert!(output.status.success(), "{name}: {:?}", output);
        assert!(output.stderr.is_empty(), "{name}");
        match name {
            "deployment" => {
                dev_auth::deployment::parse_deployment_document(&output.stdout).unwrap();
            }
            "administrator-policy" | "user-only-policy" => {
                dev_auth::policy_v2::parse_system_policy_v2(&output.stdout).unwrap();
            }
            "user-config" => {
                dev_auth::policy_v2::parse_user_config_v2(&output.stdout).unwrap();
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn full_setup_apply_never_falls_back_to_a_binary_only_v2_plan() {
    let root = private_runtime();
    let plan = root.path().join("setup-plan.json");
    fs::write(
        &plan,
        br#"{"schema":"dev-auth-setup-plan-v2","actions":[]}"#,
    )
    .unwrap();
    fs::set_permissions(&plan, fs::Permissions::from_mode(0o600)).unwrap();

    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "setup",
                "apply",
                "--plan",
                plan.to_str().unwrap(),
                "--sha256",
                &"0".repeat(64),
                "--format",
                "json",
            ])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("accepts only a full setup plan v3"));
}

#[cfg(target_os = "linux")]
#[test]
fn setup_helper_identity_accepts_only_its_narrow_apply_protocol() {
    use std::os::unix::process::CommandExt;

    for arguments in [
        vec!["build-info"],
        vec!["setup", "readiness"],
        vec!["apply-v3", "--help"],
        vec!["apply-v3", "--plan", "/tmp/plan", "--sha256"],
        vec![
            "apply-v3",
            "--plan",
            "/tmp/plan",
            "--sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--format",
            "json",
        ],
        vec![
            "apply-v3",
            "--plan",
            "/tmp/plan",
            "--sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--credential-fd",
            "automation=7",
        ],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dev-auth"));
        command
            .arg0("dev-auth-setup-helper")
            .args(arguments)
            .env_clear();
        let output = bounded_output(&mut command);
        assert!(
            !output.status.success(),
            "helper grammar unexpectedly succeeded"
        );
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.starts_with("dev-auth-setup-helper:"),
            "helper identity fell through to another frontend: {error}"
        );
        assert!(!error.contains("workload alias"), "{error}");
    }

    for arguments in [
        vec![
            "apply-v3",
            "--plan",
            "/tmp/plan",
            "--sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ],
        vec![
            "apply-v3",
            "--sha256",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "--plan",
            "/tmp/plan",
            "--format",
            "json",
        ],
    ] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dev-auth"));
        command
            .arg0("dev-auth-setup-helper")
            .args(arguments)
            .env_clear();
        let output = bounded_output(&mut command);
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("requires --format") || error.contains("canonical protocol form"),
            "noncanonical helper grammar reached plan processing: {error}"
        );
        assert!(!error.contains("inspect root-owned setup plan"), "{error}");
    }
}

#[test]
fn setup_plan_requires_one_complete_offline_release_bundle() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let user_config = format!("{}=/tmp/dev-auth-config.toml", user.name);
    let common = [
        "setup",
        "plan",
        "--mode",
        "user-only",
        "--channel",
        "stable",
        "--activation",
        "inactive",
        "--administrator-policy",
        "/tmp/dev-auth-policy.toml",
        "--user-config",
        &user_config,
        "--output",
        "/tmp/dev-auth-plan.json",
        "--format",
        "json",
    ];
    let incomplete = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(common)
            .args(["--offline", "--release-root", "/tmp/root.json"])
            .env_clear(),
    );
    assert!(!incomplete.status.success());
    assert!(String::from_utf8(incomplete.stderr)
        .unwrap()
        .contains("must be provided together"));

    let online = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(common)
            .args([
                "--release-root",
                "/tmp/root.json",
                "--release-manifest",
                "/tmp/manifest.json",
                "--release-artifact",
                "/tmp/artifact",
            ])
            .env_clear(),
    );
    assert!(!online.status.success());
    assert!(String::from_utf8(online.stderr)
        .unwrap()
        .contains("requires --offline"));
}

#[test]
fn setup_v3_does_not_expose_a_global_launcher_activation_command() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["setup", "activate", "--mode", "user-only"])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("unknown setup operation"));
}

#[test]
fn typed_reconcile_cli_reserves_only_the_fixed_protocol_grammar() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "reconcile",
                "plan",
                "--source",
                "relative.toml",
                "--output",
                "/tmp/plan.json",
                "--format",
                "json",
            ])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("source and output paths must be absolute"));
    assert!(!error.contains("unknown command"));
}

#[test]
fn typed_reconcile_defers_when_standalone_system_is_absent() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("config-v2.toml");
    let plan = root.path().join("plan.json");
    fs::write(&source, b"version = 2\n").unwrap();
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args([
                "reconcile",
                "plan",
                "--source",
                source.to_str().unwrap(),
                "--output",
                plan.to_str().unwrap(),
                "--format",
                "json",
            ])
            .env_clear(),
    );

    assert!(output.status.success(), "{:?}", output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["deferred"], true);
    assert_eq!(report["next_action"], "setup");
    assert_eq!(report["diagnostics"][0], "system_installation_absent");
    assert!(!plan.exists());
}

#[test]
fn release_manifest_signing_rejects_an_empty_payload_before_broker_access() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .args(["sign-release-manifest", "--profile", "release"])
            .env_clear(),
    );
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("release manifest must not be empty"),
        "{error}"
    );
    assert!(!error.contains("unknown command"), "{error}");
}

#[cfg(target_os = "linux")]
struct NativeUserSandbox {
    _root: TempDir,
    root: PathBuf,
    home: PathBuf,
    runtime: PathBuf,
    passwd: PathBuf,
}

#[cfg(target_os = "linux")]
impl NativeUserSandbox {
    fn new() -> Self {
        assert!(Path::new("/usr/bin/bwrap").is_file());
        let root = private_program_root();
        let root_path = root.path().to_path_buf();
        let home = root_path.join("native-home");
        let runtime = root_path.join("run-user");
        let passwd = root_path.join("passwd");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&root_path).unwrap();
        fs::write(
            &passwd,
            format!(
                "dev-auth-test:x:{}:{}::{}:/bin/sh\n",
                metadata.uid(),
                metadata.gid(),
                home.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&passwd, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            _root: root,
            root: root_path,
            home,
            runtime,
            passwd,
        }
    }

    fn command(&self, program: &Path, cwd: &Path) -> Command {
        let uid = fs::metadata(&self.root).unwrap().uid();
        let program_name = program.file_name().unwrap();
        let sandbox_program = Path::new("/test-bin").join(program_name);
        let attacker_home = self.root.join("attacker-home");
        let attacker_config = self.root.join("attacker-config");
        fs::create_dir_all(&attacker_home).unwrap();
        fs::create_dir_all(&attacker_config).unwrap();
        let mut command = Command::new("/usr/bin/bwrap");
        command
            .arg("--die-with-parent")
            .args(["--tmpfs", "/"])
            .args(["--dir", "/usr"])
            .args(["--ro-bind", "/usr", "/usr"])
            .args(["--symlink", "usr/bin", "/bin"])
            .args(["--symlink", "usr/lib", "/lib"])
            .args(["--symlink", "usr/lib", "/lib64"])
            .args(["--dev", "/dev"])
            .args(["--proc", "/proc"])
            .args(["--dir", "/etc"])
            .args(["--dir", "/run"])
            .args(["--dir", "/run/user"])
            .args(["--dir", "/tmp"])
            .args(["--dir", "/test-bin"])
            .arg("--ro-bind")
            .arg(program)
            .arg(&sandbox_program);
        let mut ancestor = PathBuf::new();
        for component in self
            .root
            .components()
            .take(self.root.components().count() - 1)
        {
            ancestor.push(component.as_os_str());
            if ancestor != Path::new("/") {
                command.arg("--dir").arg(&ancestor);
            }
        }
        command
            .arg("--bind")
            .arg(&self.root)
            .arg(&self.root)
            .arg("--bind")
            .arg(&self.passwd)
            .arg("/etc/passwd")
            .arg("--bind")
            .arg(&self.runtime)
            .arg(format!("/run/user/{uid}"))
            .arg("--clearenv")
            .arg("--setenv")
            .arg("HOME")
            .arg(&attacker_home)
            .arg("--setenv")
            .arg("XDG_CONFIG_HOME")
            .arg(&attacker_config)
            .arg("--setenv")
            .arg("PATH")
            .arg("/usr/bin")
            .arg("--chdir")
            .arg(cwd)
            .arg("--")
            .arg(sandbox_program);
        command
    }

    fn install_binary(&self, destination: &Path) {
        fs::copy(env!("CARGO_BIN_EXE_dev-auth"), destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[cfg(target_os = "linux")]
fn run_standalone_user_only_setup_child(trace_doctor: bool) {
    use dev_auth::deployment::{
        normalize_deployment, parse_deployment_document, DeploymentCliInput,
    };
    use dev_auth::setup::{
        build_plan, deactivate_transparent_launchers_at, InstallMode, InstallRequest, SetupPaths,
    };
    use dev_auth::setup_v3::{build_setup_plan_v3_at, write_setup_plan_v3_at};
    use std::os::unix::process::CommandExt;

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let root = tempfile::Builder::new()
        .prefix("dev-auth-clean-home-")
        .tempdir_in(&user.dir)
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let candidate = user.dir.parent().unwrap().join("artifact");
    let bootstrap = user.dir.parent().unwrap().join("dev-auth-bootstrap");

    let upstream_log = root.path().join("native-git.log");
    let native_git = root.path().join("native-git");
    fs::write(
        &native_git,
        format!(
            "#!/bin/sh\nprintf 'editor=%s\\n' \"${{GIT_EDITOR-}}\" > '{}'\nprintf 'arg=%s\\n' \"$@\" >> '{}'\nexit 23\n",
            upstream_log.display(),
            upstream_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&native_git, fs::Permissions::from_mode(0o700)).unwrap();
    let native_gh = root.path().join("native-gh");
    let op = root.path().join("op");
    let ssh = root.path().join("ssh");
    let ssh_keygen = root.path().join("ssh-keygen");
    for path in [&native_gh, &op, &ssh, &ssh_keygen] {
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let policy = root.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"version = 2
mode = "user_only"
allowed_users = ["{}"]
[programs]
op = "{}"
git = "{}"
gh = "{}"
ssh = "{}"
ssh_keygen = "{}"
[trusted_launchers]
[github_apps]
[credential_slots]
[authority_caps]
[workspace_caps]
"#,
            user.name,
            op.display(),
            native_git.display(),
            native_gh.display(),
            ssh.display(),
            ssh_keygen.display()
        ),
    )
    .unwrap();
    let config = root.path().join("config.toml");
    fs::write(&config, b"version = 2\n").unwrap();
    for path in [&policy, &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let deployment = parse_deployment_document(
        format!(
            r#"schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "transparent"
administrator_policy = "{}"

[[users]]
name = "{}"
config = "{}"
"#,
            policy.display(),
            user.name,
            config.display()
        )
        .as_bytes(),
    )
    .unwrap();
    let intent = normalize_deployment(Some(deployment), DeploymentCliInput::default()).unwrap();
    let paths = SetupPaths::user_only(&user.dir);
    let installation = build_plan(
        &paths,
        &InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.3.0-clean-device-test".into(),
            source_executable: candidate,
            native_git,
            native_gh,
            activate_transparent_launchers: false,
        },
    )
    .unwrap();
    let plan = build_setup_plan_v3_at(intent, installation, false).unwrap();
    let plan_path = root.path().join("setup-plan.json");
    let digest = write_setup_plan_v3_at(&plan_path, &plan).unwrap();
    let first = Command::new(&bootstrap)
        .arg0("dev-auth")
        .args([
            "setup",
            "apply",
            "--plan",
            plan_path.to_str().unwrap(),
            "--sha256",
            &digest,
            "--format",
            "json",
        ])
        .env_clear()
        .env("HOME", &user.dir)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "candidate setup handoff failed: stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["changed"], true);
    assert_eq!(first["verified"], true);

    let trace_path = root.path().join("doctor.trace");
    let mut doctor_command = if trace_doctor {
        let mut command = Command::new("/usr/bin/strace");
        command
            .args([
                "--kill-on-exit", "-f", "-qq", "-s", "64", "-e",
                "trace=network,process,openat,unlink,unlinkat,rename,renameat,renameat2,flock,fsync,fdatasync",
                "-o",
            ])
            .arg(&trace_path)
            .arg(user.dir.join(".local/bin/dev-auth"));
        command
    } else {
        Command::new(user.dir.join(".local/bin/dev-auth"))
    };
    let doctor = bounded_output(
        doctor_command
            .args(["doctor", "--json"])
            .env_clear()
            .env("PATH", "/missing")
            .current_dir(&user.dir),
    );
    assert_eq!(doctor.status.code(), Some(0));
    assert!(doctor.stderr.is_empty());
    let doctor: serde_json::Value = serde_json::from_slice(&doctor.stdout).unwrap();
    assert_eq!(doctor["operation"], "doctor");
    assert_eq!(doctor["changed"], false);
    assert_eq!(doctor["installation_state"], "managed");
    assert_eq!(doctor["details"]["broker_state"], "not_probed");
    assert_eq!(doctor["details"]["credential_observation"], "not_required");
    assert_eq!(doctor["details"]["provider_use_observation"], "not_checked");
    if trace_doctor {
        assert!(fs::metadata(&trace_path).unwrap().len() <= PUBLIC_SUBPROCESS_OUTPUT_LIMIT);
        let trace = fs::read_to_string(&trace_path).unwrap();
        assert_eq!(trace.matches("execve(").count(), 1);
        for forbidden in [
            "socket(",
            "connect(",
            "sendto(",
            "sendmsg(",
            "recvfrom(",
            "recvmsg(",
            "clone(",
            "clone3(",
            "fork(",
            "vfork(",
            "O_WRONLY",
            "O_RDWR",
            "O_CREAT",
            "O_TRUNC",
            "O_APPEND",
            "unlink(",
            "unlinkat(",
            "rename(",
            "renameat(",
            "renameat2(",
            "flock(",
            "fsync(",
            "fdatasync(",
        ] {
            assert!(
                !trace.contains(forbidden),
                "doctor crossed local observation boundary: {forbidden}"
            );
        }
    }

    let second = Command::new(user.dir.join(".local/bin/dev-auth"))
        .args([
            "setup",
            "apply",
            "--plan",
            plan_path.to_str().unwrap(),
            "--sha256",
            &digest,
            "--format",
            "json",
        ])
        .env_clear()
        .env("HOME", &user.dir)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(second.status.success());
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second["changed"], false);
    assert_eq!(second["verified"], true);

    let installation_lock = paths.data_root.join("installation.lock");
    fs::set_permissions(&installation_lock, fs::Permissions::from_mode(0o000)).unwrap();
    for arguments in [&["status", "--broker"][..], &["explain", "git"][..]] {
        let output = Command::new(user.dir.join(".local/bin/dev-auth"))
            .args(arguments)
            .env_clear()
            .env("HOME", &user.dir)
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let reconcile_plan = root.path().join("reconcile-plan.json");
    let reconcile = Command::new(user.dir.join(".local/bin/dev-auth"))
        .args([
            "reconcile",
            "plan",
            "--source",
            config.to_str().unwrap(),
            "--output",
            reconcile_plan.to_str().unwrap(),
            "--format",
            "json",
        ])
        .env_clear()
        .env("HOME", &user.dir)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(
        reconcile.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&reconcile.stdout),
        String::from_utf8_lossy(&reconcile.stderr)
    );
    fs::remove_file(reconcile_plan).unwrap();

    let unresolved_workload = user.dir.join(".local/bin/future-agent");
    assert!(!user
        .dir
        .join(".local/share/dev-auth/workload-aliases-v1.json")
        .exists());
    symlink(
        paths
            .data_root
            .join("versions/0.3.0-clean-device-test/dev-auth"),
        &unresolved_workload,
    )
    .unwrap();
    let workload = Command::new(&unresolved_workload)
        .arg("--version")
        .env_clear()
        .env("HOME", &user.dir)
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(!workload.status.success());
    assert!(workload.stdout.is_empty());
    let workload_error = String::from_utf8(workload.stderr).unwrap();
    assert!(
        workload_error.contains("workload launcher receipt is not installed"),
        "{workload_error}"
    );
    assert!(!workload_error.contains("installation lock"));
    fs::remove_file(unresolved_workload).unwrap();
    fs::set_permissions(&installation_lock, fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(user.dir.join(".local/bin/git"))
        .args(["future-command", "--new-option", "value"])
        .env_clear()
        .env("GIT_EDITOR", "code-insiders --wait")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    let log = fs::read_to_string(upstream_log).unwrap();
    assert!(log.contains("editor=code-insiders --wait"));
    assert!(log.contains("arg=future-command"));
    assert!(log.contains("arg=--new-option"));
    assert!(log.contains("arg=value"));

    let receipt_before = fs::read(paths.data_root.join("install-v2.json")).unwrap();
    let admission_lock = std::path::PathBuf::from(format!(
        "/run/user/{}/dev-auth-setup-v3.lock",
        user.uid.as_raw()
    ));
    let workload_lease =
        dev_tools_installation::InstallationLock::try_acquire_shared(&admission_lock)
            .unwrap()
            .unwrap();
    let check_configuration_refusal = |expected: &str| {
        use sha2::Digest;
        for (operation, source) in [
            ("install-user-policy", &policy),
            ("update-user-policy", &policy),
            ("install-user-config", &config),
            ("update-user-config", &config),
        ] {
            let digest = format!("{:x}", sha2::Sha256::digest(fs::read(source).unwrap()));
            let mut command = Command::new(user.dir.join(".local/bin/dev-auth"));
            command
                .env_clear()
                .args(["setup", operation, "--source"])
                .arg(source)
                .args(["--sha256", &digest]);
            if operation.starts_with("update-") {
                command.args(["--current-sha256", &digest]);
            }
            let output = command.output().unwrap();
            assert!(
                !output.status.success(),
                "{operation} bypassed coordinated setup authority"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{operation}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    };
    check_configuration_refusal("requires active workloads and setup to finish");
    let busy_rollback = Command::new(user.dir.join(".local/bin/dev-auth"))
        .args(["setup", "rollback", "--mode", "user-only"])
        .env_clear()
        .output()
        .unwrap();
    assert!(!busy_rollback.status.success());
    assert!(String::from_utf8_lossy(&busy_rollback.stderr)
        .contains("rollback requires active workloads and setup to finish"));
    assert_eq!(
        fs::read(paths.data_root.join("install-v2.json")).unwrap(),
        receipt_before
    );
    for operation in ["repair", "uninstall"] {
        let busy = Command::new(user.dir.join(".local/bin/dev-auth"))
            .args(["setup", operation, "--mode", "user-only"])
            .env_clear()
            .output()
            .unwrap();
        assert!(
            !busy.status.success(),
            "{operation} bypassed an admitted workload"
        );
        assert!(String::from_utf8_lossy(&busy.stderr)
            .contains("requires active workloads and setup to finish"));
        assert_eq!(
            fs::read(paths.data_root.join("install-v2.json")).unwrap(),
            receipt_before
        );
    }
    drop(workload_lease);
    check_configuration_refusal("full setup generation requires transaction-aware maintenance");
    let rollback = Command::new(user.dir.join(".local/bin/dev-auth"))
        .args(["setup", "rollback", "--mode", "user-only"])
        .env_clear()
        .output()
        .unwrap();
    assert!(!rollback.status.success());
    assert!(String::from_utf8_lossy(&rollback.stderr)
        .contains("binary-only rollback cannot restore a full setup generation"));
    assert_eq!(
        fs::read(paths.data_root.join("install-v2.json")).unwrap(),
        receipt_before
    );
    for operation in ["repair", "uninstall"] {
        let refused = Command::new(user.dir.join(".local/bin/dev-auth"))
            .args(["setup", operation, "--mode", "user-only"])
            .env_clear()
            .output()
            .unwrap();
        assert!(
            !refused.status.success(),
            "{operation} bypassed retained setup"
        );
        assert!(String::from_utf8_lossy(&refused.stderr)
            .contains("full setup generation requires transaction-aware maintenance"));
        assert_eq!(
            fs::read(paths.data_root.join("install-v2.json")).unwrap(),
            receipt_before
        );
    }
    assert!(user.dir.join(".local/bin/git").exists());
    let deactivated = deactivate_transparent_launchers_at(&paths).unwrap();
    assert!(!deactivated.transparent_launchers_active);
    assert!(!user.dir.join(".local/bin/git").exists());
    assert!(!user.dir.join(".local/bin/gh").exists());
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupRecoveryFixture {
    PriorInstallation,
    InitialAbsence,
    InitialProcessDeath,
    MissingInitialReceipt,
    InitialUncommittedBinary,
    CommittedUpgradeReceipt,
    UncommittedUpgradeBinary,
    UnstagedUpgradeBinary,
    UnstagedInitialBinary,
}

fn run_missing_credential_stages_no_workload_launchers_child(
    logical: bool,
    recovery: Option<SetupRecoveryFixture>,
) {
    use dev_auth::deployment::{
        normalize_deployment, parse_deployment_document, DeploymentCliInput,
    };
    use dev_auth::setup::{build_plan, InstallMode, InstallRequest, SetupPaths};
    use dev_auth::setup_v3::{apply_setup_plan_v3, build_setup_plan_v3_at, render_setup_plan_v3};
    use std::os::unix::process::CommandExt;

    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let root = tempfile::Builder::new()
        .prefix("dev-auth-inactive-home-")
        .tempdir_in(&user.dir)
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let candidate = user.dir.parent().unwrap().join("product");
    let native_git = root.path().join("git");
    let native_gh = root.path().join("gh");
    let op = root.path().join("op");
    let ssh = root.path().join("ssh");
    let ssh_keygen = root.path().join("ssh-keygen");
    let future_agent = root.path().join("future-agent");
    for path in [
        &native_git,
        &native_gh,
        &op,
        &ssh,
        &ssh_keygen,
        &future_agent,
    ] {
        fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let policy = root.path().join("policy.toml");
    fs::write(
        &policy,
        format!(
            r#"version = 2
mode = "user_only"
allowed_users = ["{}"]
[programs]
op = "{}"
git = "{}"
gh = "{}"
ssh = "{}"
ssh_keygen = "{}"
[trusted_launchers]
future-agent = "{}"
[github_apps]
[credential_slots.automation]
users = ["{}"]
authority_caps = ["automation"]
secret_references = ["op://Automation/Agent/token"]
[authority_caps.automation]
secret_references = ["op://Automation/Agent/token"]
[workspace_caps]
"#,
            user.name,
            op.display(),
            native_git.display(),
            native_gh.display(),
            ssh.display(),
            ssh_keygen.display(),
            future_agent.display(),
            user.name,
        ),
    )
    .unwrap();
    let config = root.path().join("config.toml");
    fs::write(
        &config,
        br#"version = 2
[authority_profiles.automation]
cap = "automation"
signing = false
ssh = false
secret_references = []

[[workloads]]
name = "future-agent"
launcher = "future-agent"
profile = "automation"
secret_references = []
workspace_roots = []
[workloads.sandbox]
mode = "none"
"#,
    )
    .unwrap();
    let prior_policy = fs::read(&policy).unwrap();
    let prior_config = fs::read(&config).unwrap();
    if matches!(
        recovery,
        Some(
            SetupRecoveryFixture::PriorInstallation
                | SetupRecoveryFixture::CommittedUpgradeReceipt
                | SetupRecoveryFixture::UncommittedUpgradeBinary
                | SetupRecoveryFixture::UnstagedUpgradeBinary
        )
    ) {
        let directory = user.dir.join(".config/dev-auth");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(user.dir.join(".config"), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        for (name, bytes) in [
            ("policy-v2.toml", &prior_policy),
            ("config-v2.toml", &prior_config),
        ] {
            let path = directory.join(name);
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let prior_source = root.path().join("prior-product");
        fs::copy(&candidate, &prior_source).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&prior_source)
            .unwrap()
            .write_all(b"retained fixture identity")
            .unwrap();
        dev_auth::setup::install_at(
            &SetupPaths::user_only(&user.dir),
            &InstallRequest {
                mode: InstallMode::UserOnly,
                version: "0.3.11".into(),
                source_executable: prior_source,
                native_git: native_git.clone(),
                native_gh: native_gh.clone(),
                activate_transparent_launchers: false,
            },
        )
        .unwrap();
    }
    if logical {
        fs::write(
            &policy,
            format!(
                r#"schema = "dev-auth-administrator-policy-v3"
mode = "user_only"
allowed_users = ["{user}"]
[programs]
git = "{git}"
gh = "{gh}"
ssh = "{ssh}"
ssh_keygen = "{keygen}"
[trusted_launchers]
future-agent = "{launcher}"
[credentials.providers.primary]
kind = "one_password"
executable = "{op}"
[credentials.credential_slots.automation]
provider = "primary"
users = ["{user}"]
[credentials.resources.token]
credential_slot = "automation"
reference = "op://Fixture/Agent/token"
kind = "exportable"
purposes = ["read"]
[credentials.resource_caps.automation]
users = ["{user}"]
[credentials.resource_caps.automation.resources.token]
purposes = ["read"]
[workload_caps.automation]
users = ["{user}"]
resource_cap = "automation"
launchers = ["future-agent"]
admission = ["approval_required"]
max_duration_seconds = 86400
"#,
                user = user.name,
                git = native_git.display(),
                gh = native_gh.display(),
                ssh = ssh.display(),
                keygen = ssh_keygen.display(),
                launcher = future_agent.display(),
                op = op.display()
            ),
        )
        .unwrap();
        fs::write(
            &config,
            r#"schema = "dev-auth-user-config-v3"
[authority_profiles.automation]
cap = "automation"
[authority_profiles.automation.resources.token]
purposes = ["read"]
[[workloads]]
name = "future-agent"
launcher = "future-agent"
profile = "automation"
admission = "approval_required"
duration_seconds = 43200
[workloads.resources.token]
purposes = ["read"]
[workloads.desktop]
display_name = "Retained Candidate Fixture"
"#,
        )
        .unwrap();
    }
    for path in [&policy, &config] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let deployment = parse_deployment_document(
        format!(
            r#"schema = "dev-auth-deployment-v1"
mode = "user-only"
channel = "stable"
activation = "transparent"
administrator_policy = "{}"

[[users]]
name = "{}"
config = "{}"

[[credentials]]
slot = "automation"
intent = "enroll-if-absent"
"#,
            policy.display(),
            user.name,
            config.display(),
        )
        .as_bytes(),
    )
    .unwrap();
    let intent = normalize_deployment(Some(deployment), DeploymentCliInput::default()).unwrap();
    let paths = SetupPaths::user_only(&user.dir);
    let installation = build_plan(
        &paths,
        &InstallRequest {
            mode: InstallMode::UserOnly,
            version: if logical {
                "0.4.0"
            } else {
                "0.3.0-inactive-test"
            }
            .into(),
            source_executable: candidate,
            native_git,
            native_gh,
            activate_transparent_launchers: false,
        },
    )
    .unwrap();
    let plan = build_setup_plan_v3_at(intent, installation, false).unwrap();
    let (_, digest) = render_setup_plan_v3(&plan).unwrap();
    let prior_binary_receipts = matches!(
        recovery,
        Some(
            SetupRecoveryFixture::CommittedUpgradeReceipt
                | SetupRecoveryFixture::UncommittedUpgradeBinary
                | SetupRecoveryFixture::UnstagedUpgradeBinary
        )
    )
    .then(|| {
        let product = fs::read(paths.data_root.join("install-v2.json")).unwrap();
        let shared: serde_json::Value = serde_json::from_slice(
            &fs::read(paths.data_root.join("installation-receipt-v1.json")).unwrap(),
        )
        .unwrap();
        (product, shared)
    });
    let report = apply_setup_plan_v3(&plan, &digest, &std::collections::BTreeMap::new()).unwrap();
    assert_eq!(report.input_required, ["automation"]);
    if matches!(
        recovery,
        Some(
            SetupRecoveryFixture::MissingInitialReceipt
                | SetupRecoveryFixture::InitialUncommittedBinary
                | SetupRecoveryFixture::UnstagedInitialBinary
                | SetupRecoveryFixture::CommittedUpgradeReceipt
                | SetupRecoveryFixture::UncommittedUpgradeBinary
                | SetupRecoveryFixture::UnstagedUpgradeBinary
        )
    ) {
        let uncommitted = matches!(
            recovery,
            Some(
                SetupRecoveryFixture::InitialUncommittedBinary
                    | SetupRecoveryFixture::UnstagedInitialBinary
                    | SetupRecoveryFixture::UncommittedUpgradeBinary
                    | SetupRecoveryFixture::UnstagedUpgradeBinary
            )
        );
        let receipt_path = paths.data_root.join("install-v2.json");
        let expected_receipt = fs::read(&receipt_path).unwrap();
        let candidate_receipt: serde_json::Value =
            serde_json::from_slice(&expected_receipt).unwrap();
        let mut recovery_executable =
            PathBuf::from(candidate_receipt["executable"].as_str().unwrap());
        let transition_path = paths.data_root.join("setup-transition-v1.json");
        let retained = fs::read(&transition_path).unwrap();
        let snapshot_path = paths
            .data_root
            .join("setup-generations")
            .join(format!("{digest}.json"));
        let snapshot = fs::read(&snapshot_path).unwrap();
        let shared: serde_json::Value = serde_json::from_slice(
            &fs::read(paths.data_root.join("installation-receipt-v1.json")).unwrap(),
        )
        .unwrap();
        let journal_path = paths.data_root.join("installation-transition-v1.json");
        let journal = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1", "prior": prior_binary_receipts.as_ref().map(|(_, shared)| shared), "next": shared,
        }))
        .unwrap();
        fs::write(&journal_path, &journal).unwrap();
        fs::set_permissions(&journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        if let Some((prior_product, _)) = &prior_binary_receipts {
            fs::write(&receipt_path, prior_product).unwrap();
        } else {
            fs::remove_file(&receipt_path).unwrap();
        }
        if uncommitted {
            let shared_path = paths.data_root.join("installation-receipt-v1.json");
            if let Some((_, prior_shared)) = &prior_binary_receipts {
                fs::write(&shared_path, serde_json::to_vec(prior_shared).unwrap()).unwrap();
            } else {
                fs::remove_file(&shared_path).unwrap();
            }
            fs::remove_file(paths.bin_dir.join("dev-auth")).unwrap();
            fs::remove_file(paths.data_root.join("active")).unwrap();
        }
        if matches!(
            recovery,
            Some(
                SetupRecoveryFixture::UnstagedUpgradeBinary
                    | SetupRecoveryFixture::UnstagedInitialBinary
            )
        ) {
            let layout = dev_tools_installation::VersionedLayout {
                product: "dev-auth".into(),
                data_root: paths.data_root.clone(),
                bin_dir: paths.bin_dir.clone(),
                artifact_name: "dev-auth".into(),
                owner_uid: user.uid.as_raw(),
                directory_mode: 0o755,
                bin_directory_mode: None,
            };
            let prior = prior_binary_receipts
                .as_ref()
                .map(|(_, shared)| serde_json::from_value(shared.clone()).unwrap());
            let next = serde_json::from_value(shared).unwrap();
            dev_tools_installation::recover_versioned_installation_transition(
                &layout,
                prior.as_ref(),
                &next,
                256 * 1024 * 1024,
                |_| Ok(()),
            )
            .unwrap();
            let recovery_directory = root.path().join("recovery");
            fs::create_dir(&recovery_directory).unwrap();
            let external_candidate = recovery_directory.join("dev-auth");
            fs::copy(&recovery_executable, &external_candidate).unwrap();
            fs::remove_file(&recovery_executable).unwrap();
            fs::remove_dir(recovery_executable.parent().unwrap()).unwrap();
            if prior.is_none() {
                fs::remove_dir(paths.data_root.join("versions")).unwrap();
                fs::remove_file(paths.data_root.join("installation.lock")).unwrap();
                fs::remove_dir(&paths.bin_dir).unwrap();
            }
            recovery_executable = external_candidate;
        }
        let expected_journal = fs::read(&journal_path).ok();
        for source in plan
            .source_documents
            .iter()
            .map(|document| &document.path)
            .collect::<std::collections::BTreeSet<_>>()
        {
            fs::remove_file(source).unwrap();
        }
        fs::remove_file(&plan.installation.request.source_executable).unwrap();
        if prior_binary_receipts.is_some() {
            fs::remove_file(root.path().join("prior-product")).unwrap();
        }
        let run = |stage: &'static str, timeout: Duration| {
            bounded_output_with_timeout(
                Command::new(&recovery_executable)
                    .args([
                        "setup",
                        "recover",
                        "--mode",
                        "user-only",
                        "--format",
                        "json",
                    ])
                    .env_clear()
                    .env("HOME", &user.dir)
                    .env("PATH", "/usr/bin:/bin"),
                timeout,
                stage,
            )
        };
        let mut accepted: serde_json::Value = serde_json::from_slice(&retained).unwrap();
        accepted["phase"] = serde_json::json!("accepted");
        fs::write(&transition_path, serde_json::to_vec(&accepted).unwrap()).unwrap();
        let rejected = run(
            "reject accepted binary recovery replay",
            Duration::from_secs(20),
        );
        assert_eq!(
            rejected.status.code(),
            Some(3),
            "stderr={}",
            String::from_utf8_lossy(&rejected.stderr)
        );
        let rejected: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
        assert_eq!(rejected["changed"], false);
        if let Some((prior_product, _)) = &prior_binary_receipts {
            assert_eq!(fs::read(&receipt_path).unwrap(), *prior_product);
        } else {
            assert!(!receipt_path.exists());
        }
        assert_eq!(fs::read(&journal_path).ok(), expected_journal);
        fs::write(&transition_path, &retained).unwrap();
        // This new upgrade path restores and verifies the prior installation,
        // then verifies and activates a distinct candidate. Each binary stage
        // retains the fixture's 20-second budget; other recovery paths do not
        // acquire this extra allowance. Release performance is a separate gate.
        let forward_budget = if uncommitted && prior_binary_receipts.is_some() {
            Duration::from_secs(40)
        } else {
            Duration::from_secs(20)
        };
        let recovered = run("complete pending binary recovery", forward_budget);
        assert_eq!(
            recovered.status.code(),
            Some(3),
            "stderr={}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        assert!(recovered.stderr.is_empty());
        let recovered: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
        assert_eq!(recovered["changed"], true);
        assert_eq!(
            recovered["input_required"],
            serde_json::json!(["automation"])
        );
        assert!(recovered["actions"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!(if uncommitted {
                if prior_binary_receipts.is_some() {
                    "complete_upgrade_binary_installation"
                } else {
                    "complete_initial_binary_installation"
                }
            } else if prior_binary_receipts.is_some() {
                "complete_upgrade_binary_receipt"
            } else {
                "complete_initial_binary_receipt"
            })));
        assert_eq!(fs::read(&receipt_path).unwrap(), expected_receipt);
        assert!(!journal_path.exists());
        let repeated = run("repeat completed binary recovery", Duration::from_secs(20));
        assert_eq!(repeated.status.code(), Some(3));
        let repeated: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
        assert_eq!(repeated["changed"], false);
        assert_eq!(fs::read(&transition_path).unwrap(), retained);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        return;
    }
    if let Some(restoration) = recovery {
        let prior_installation = restoration == SetupRecoveryFixture::PriorInstallation;
        let transition_path = paths.data_root.join("setup-transition-v1.json");
        let snapshot_path = paths
            .data_root
            .join("setup-generations")
            .join(format!("{digest}.json"));
        let snapshot = fs::read(&snapshot_path).unwrap();
        let credential_receipt_path = paths.data_root.join("credential-actions-v2.json");
        let credential_receipt = fs::read(&credential_receipt_path).ok();
        let immutable_candidate = paths.data_root.join("versions/0.4.0/dev-auth");
        // Model interrupted publication before either integration receipt was
        // written. Retained candidate policy must still bound their retirement.
        // Keep the process-death fixture's first unlink at its existing
        // configuration boundary; it has a separate interruption oracle.
        let candidate_desktop = user
            .dir
            .join(".local/share/applications/dev-auth-future-agent.desktop");
        let unrelated_link = user.dir.join(".local/bin/unrelated-candidate-link");
        let publish_candidate_integrations = || {
            std::os::unix::fs::symlink(
                &immutable_candidate,
                user.dir.join(".local/bin/future-agent"),
            )
            .unwrap();
            fs::create_dir_all(candidate_desktop.parent().unwrap()).unwrap();
            let content = format!("[Desktop Entry]\nType=Application\nVersion=1.0\nName=Retained Candidate Fixture\nExec=\"{}\"\nTerminal=false\nCategories=Development;\nX-Dev-Auth-Workload=future-agent\n", user.dir.join(".local/bin/future-agent").display());
            fs::write(&candidate_desktop, content).unwrap();
            fs::set_permissions(&candidate_desktop, fs::Permissions::from_mode(0o644)).unwrap();
        };
        if restoration != SetupRecoveryFixture::InitialProcessDeath {
            publish_candidate_integrations();
            std::os::unix::fs::symlink(&immutable_candidate, &unrelated_link).unwrap();
        }
        for source in [
            &policy,
            &config,
            &plan.installation.request.source_executable,
        ] {
            fs::remove_file(source).unwrap();
        }
        if restoration != SetupRecoveryFixture::InitialProcessDeath {
            let recovered = bounded_output_with_timeout(
                Command::new(&immutable_candidate)
                    .args([
                        "setup",
                        "recover",
                        "--mode",
                        "user-only",
                        "--format",
                        "json",
                    ])
                    .env_clear(),
                Duration::from_secs(120),
                "forward recovery retires partially published candidate integrations",
            );
            assert_eq!(
                recovered.status.code(),
                Some(3),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&recovered.stdout),
                String::from_utf8_lossy(&recovered.stderr)
            );
            let recovered: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
            assert_eq!(
                recovered["input_required"],
                serde_json::json!(["automation"])
            );
            assert!(
                fs::symlink_metadata(user.dir.join(".local/bin/future-agent")).is_err(),
                "forward recovery left an unreceipted candidate launcher active"
            );
            assert!(
                fs::symlink_metadata(&candidate_desktop).is_err(),
                "forward recovery left an unreceipted candidate desktop entry active"
            );
            assert_eq!(
                recovered["changed"], true,
                "retirement must report established progress"
            );
            assert_eq!(fs::read_link(&unrelated_link).unwrap(), immutable_candidate);
            assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
            publish_candidate_integrations();
        }
        // Drift must be rejected before selecting restoration direction.
        let active_config = user.dir.join(".config/dev-auth/config-v3.toml");
        let candidate_config = fs::read(&active_config).unwrap();
        fs::write(&active_config, b"unrelated owner edit").unwrap();
        let before = fs::read(&transition_path).unwrap();
        let invoke = || {
            bounded_output_with_timeout(
                Command::new(&immutable_candidate)
                    .args([
                        "setup",
                        "restore",
                        "--mode",
                        "user-only",
                        "--format",
                        "json",
                    ])
                    .env_clear(),
                Duration::from_secs(120),
                "retained native restoration",
            )
        };
        let rejected = invoke();
        assert_eq!(
            rejected.status.code(),
            Some(4),
            "{}",
            String::from_utf8_lossy(&rejected.stderr)
        );
        let rejected: serde_json::Value = serde_json::from_slice(&rejected.stdout).unwrap();
        assert_eq!(rejected["changed"], false);
        assert_eq!(fs::read(&transition_path).unwrap(), before);
        fs::write(&active_config, &candidate_config).unwrap();
        if restoration == SetupRecoveryFixture::InitialProcessDeath {
            let trace = root.path().join("restoration-process-death.trace");
            let killed = bounded_output_with_timeout(
                Command::new("/usr/bin/strace")
                    .args([
                        "--kill-on-exit",
                        "-f",
                        "-qq",
                        "-e",
                        "trace=unlinkat",
                        "-e",
                        "inject=unlinkat:signal=SIGKILL:when=1",
                        "-o",
                    ])
                    .arg(&trace)
                    .arg(&immutable_candidate)
                    .args([
                        "setup",
                        "restore",
                        "--mode",
                        "user-only",
                        "--format",
                        "json",
                    ])
                    .env_clear(),
                Duration::from_secs(120),
                "initial restoration process-death boundary",
            );
            assert!(!killed.status.success());
            let trace = fs::read_to_string(trace).unwrap();
            assert!(trace.contains("SIGKILL"), "{trace}");
            assert!(
                trace.contains("policy-v3.toml") || trace.contains("config-v3.toml"),
                "{trace}"
            );
            let marker: serde_json::Value =
                serde_json::from_slice(&fs::read(&transition_path).unwrap()).unwrap();
            assert_eq!(marker["phase"], "restoring");
            assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
            assert!(paths.data_root.join("install-v2.json").is_file());
        }
        for expected_changed in [true, false] {
            let output = invoke();
            assert_eq!(
                output.status.code(),
                Some(0),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty());
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["schema"], "dev-auth-setup-restore-v1");
            assert_eq!(report["changed"], expected_changed);
            assert_eq!(report["verified"], true);
            assert_eq!(report["next_action"], "create_setup_plan");
        }
        let marker: serde_json::Value =
            serde_json::from_slice(&fs::read(&transition_path).unwrap()).unwrap();
        assert_eq!(marker["phase"], "restored_inactive");
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        assert_eq!(fs::read(&credential_receipt_path).ok(), credential_receipt);
        if prior_installation {
            assert_eq!(
                fs::read(user.dir.join(".config/dev-auth/policy-v2.toml")).unwrap(),
                prior_policy
            );
            assert_eq!(
                fs::read(user.dir.join(".config/dev-auth/config-v2.toml")).unwrap(),
                prior_config
            );
            let installed = dev_auth::setup::verify_at_read_only(&paths).unwrap();
            assert_eq!(installed.version, "0.3.11");
            assert!(!installed.transparent_launchers_active);
        } else {
            for path in [
                user.dir.join(".config/dev-auth/policy-v2.toml"),
                user.dir.join(".config/dev-auth/config-v2.toml"),
                paths.data_root.join("install-v2.json"),
                paths.data_root.join("installation-receipt-v1.json"),
                paths.data_root.join("active"),
                paths.data_root.join("previous"),
                paths.bin_dir.join("dev-auth"),
                paths.bin_dir.join("git-dev-auth"),
                paths.bin_dir.join("gh-dev-auth"),
                paths.bin_dir.join("git-credential-dev-auth"),
                paths.bin_dir.join("git"),
                paths.bin_dir.join("gh"),
            ] {
                assert!(fs::symlink_metadata(&path).is_err(), "{}", path.display());
            }
            assert!(immutable_candidate.is_file());
        }
        assert!(!active_config.exists());
        assert!(!user.dir.join(".config/dev-auth/policy-v3.toml").exists());
        assert!(!user.dir.join(".local/bin/future-agent").exists());
        assert!(fs::symlink_metadata(&candidate_desktop).is_err());
        if restoration != SetupRecoveryFixture::InitialProcessDeath {
            assert_eq!(fs::read_link(&unrelated_link).unwrap(), immutable_candidate);
        }
        let forward = bounded_output_with_timeout(
            Command::new(&immutable_candidate)
                .args([
                    "setup",
                    "recover",
                    "--mode",
                    "user-only",
                    "--format",
                    "json",
                ])
                .env_clear(),
            Duration::from_secs(15),
            "restored generation rejects forward recovery",
        );
        assert_eq!(forward.status.code(), Some(3));
        return;
    }
    if logical {
        let transition_path = paths.data_root.join("setup-transition-v1.json");
        assert!(
            transition_path.is_file(),
            "staging must durably close workload admission"
        );
        let retained = fs::read(&transition_path).unwrap();
        let transition: serde_json::Value = serde_json::from_slice(&retained).unwrap();
        assert_eq!(transition["phase"], "pending");
        assert_eq!(transition["plan_sha256"], digest);
        let snapshot_path = paths
            .data_root
            .join("setup-generations")
            .join(format!("{digest}.json"));
        assert!(
            snapshot_path.is_file(),
            "setup must retain the prior generation before mutation"
        );
        let snapshot = fs::read(&snapshot_path).unwrap();
        let generation: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        let sources = generation["candidate_documents"].as_array().expect(
            "recovery must retain approved candidate documents independently of source paths",
        );
        assert_eq!(sources.len(), plan.source_documents.len());
        for (source, expected) in sources.iter().zip(&plan.source_documents) {
            assert_eq!(source["identity"], serde_json::to_value(expected).unwrap());
            let bytes: Vec<u8> = serde_json::from_value(source["bytes"].clone()).unwrap();
            assert_eq!(bytes, fs::read(&expected.path).unwrap());
        }
        assert!(user.dir.join(".config/dev-auth/policy-v3.toml").is_file());
        assert!(user.dir.join(".config/dev-auth/config-v3.toml").is_file());
        assert!(!user.dir.join(".config/dev-auth/policy-v2.toml").exists());
        assert!(!user.dir.join(".config/dev-auth/config-v2.toml").exists());
        for source in plan
            .source_documents
            .iter()
            .map(|document| &document.path)
            .collect::<std::collections::BTreeSet<_>>()
        {
            fs::remove_file(source).unwrap();
        }
        let repeated =
            apply_setup_plan_v3(&plan, &digest, &std::collections::BTreeMap::new()).unwrap();
        assert!(!repeated.changed);
        assert_eq!(repeated.input_required, ["automation"]);
        assert_eq!(fs::read(&transition_path).unwrap(), retained);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        let wrong_candidate = root.path().join("wrong-recovery-candidate");
        fs::copy(paths.bin_dir.join("dev-auth"), &wrong_candidate).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&wrong_candidate)
            .unwrap()
            .write_all(b"!")
            .unwrap();
        let binary_journal_path = paths.data_root.join("installation-transition-v1.json");
        let shared_receipt: serde_json::Value = serde_json::from_slice(
            &fs::read(paths.data_root.join("installation-receipt-v1.json")).unwrap(),
        )
        .unwrap();
        let binary_journal = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1",
            "prior": null,
            "next": shared_receipt,
        }))
        .unwrap();
        fs::write(&binary_journal_path, &binary_journal).unwrap();
        fs::set_permissions(&binary_journal_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            apply_setup_plan_v3(&plan, &digest, &std::collections::BTreeMap::new()).is_err(),
            "ordinary setup retry must not implicitly recover a binary journal"
        );
        assert_eq!(fs::read(&binary_journal_path).unwrap(), binary_journal);
        assert_eq!(fs::read(&transition_path).unwrap(), retained);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        let observation = bounded_output_with_timeout(
            Command::new(paths.bin_dir.join("dev-auth"))
                .args(["setup", "verify", "--mode", "user-only"])
                .env_clear()
                .env("HOME", &user.dir)
                .env("PATH", "/usr/bin:/bin"),
            Duration::from_secs(20),
            "setup verification must not recover a binary journal",
        );
        assert!(!observation.status.success());
        assert_eq!(fs::read(&binary_journal_path).unwrap(), binary_journal);
        let wrong = bounded_output_with_timeout(
            Command::new(&wrong_candidate)
                .arg0("dev-auth")
                .args([
                    "setup",
                    "recover",
                    "--mode",
                    "user-only",
                    "--format",
                    "json",
                ])
                .env_clear()
                .env("HOME", &user.dir)
                .env("PATH", "/usr/bin:/bin"),
            Duration::from_secs(20),
            "reject differently hashed recovery executable",
        );
        assert_eq!(wrong.status.code(), Some(4));
        assert!(wrong.stderr.is_empty());
        let wrong: serde_json::Value = serde_json::from_slice(&wrong.stdout).unwrap();
        assert_eq!(wrong["schema"], "dev-auth-setup-recover-v1");
        assert_eq!(wrong["changed"], false);
        assert_eq!(wrong["error_kind"], "setup_recovery_authority");
        assert_eq!(
            fs::read(&binary_journal_path)
                .expect("authority rejection must not recover the binary journal"),
            binary_journal
        );
        let noninitial_journal = serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1",
            "prior": shared_receipt,
            "next": shared_receipt,
        }))
        .unwrap();
        fs::write(&binary_journal_path, &noninitial_journal).unwrap();
        let rejected_journal = bounded_output_with_timeout(
            Command::new(paths.bin_dir.join("dev-auth"))
                .args([
                    "setup",
                    "recover",
                    "--mode",
                    "user-only",
                    "--format",
                    "json",
                ])
                .env_clear()
                .env("HOME", &user.dir)
                .env("PATH", "/usr/bin:/bin"),
            Duration::from_secs(20),
            "recovery rejects an unapproved prior endpoint before mutation",
        );
        assert_eq!(rejected_journal.status.code(), Some(4));
        assert!(rejected_journal.stderr.is_empty());
        let rejected_journal: serde_json::Value =
            serde_json::from_slice(&rejected_journal.stdout).unwrap();
        assert_eq!(rejected_journal["changed"], false);
        assert_eq!(fs::read(&binary_journal_path).unwrap(), noninitial_journal);
        assert_eq!(fs::read(&transition_path).unwrap(), retained);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        fs::write(&binary_journal_path, &binary_journal).unwrap();
        fs::remove_file(&plan.installation.request.source_executable).unwrap();
        let recovered_journal = bounded_output_with_timeout(
            Command::new(paths.bin_dir.join("dev-auth"))
                .args([
                    "setup",
                    "recover",
                    "--mode",
                    "user-only",
                    "--format",
                    "json",
                ])
                .env_clear()
                .env("HOME", &user.dir)
                .env("PATH", "/usr/bin:/bin"),
            Duration::from_secs(20),
            "explicit recovery settles the retained candidate's committed binary journal",
        );
        assert_eq!(recovered_journal.status.code(), Some(3));
        assert!(recovered_journal.stderr.is_empty());
        let recovered_journal: serde_json::Value =
            serde_json::from_slice(&recovered_journal.stdout).unwrap();
        assert_eq!(recovered_journal["changed"], true);
        assert_eq!(
            recovered_journal["input_required"],
            serde_json::json!(["automation"])
        );
        assert!(!binary_journal_path.exists());
        assert_eq!(fs::read(&transition_path).unwrap(), retained);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        let recovered = bounded_output_with_timeout(
            Command::new(paths.bin_dir.join("dev-auth"))
                .args([
                    "setup",
                    "recover",
                    "--mode",
                    "user-only",
                    "--format",
                    "json",
                ])
                .env_clear()
                .env("HOME", &user.dir)
                .env("PATH", "/usr/bin:/bin"),
            Duration::from_secs(45),
            "candidate-independent setup recovery",
        );
        assert_eq!(
            recovered.status.code(),
            Some(3),
            "recovery must report missing input, not depend on discarded candidates: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        let recovered: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
        assert_eq!(recovered["schema"], "dev-auth-setup-recover-v1");
        assert_eq!(recovered["changed"], false);
        assert_eq!(recovered["verified"], false);
        assert_eq!(
            recovered["input_required"],
            serde_json::json!(["automation"])
        );
        assert_eq!(fs::read(&transition_path).unwrap(), retained);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        for (slot, exit, changed, error_kind) in [
            (
                "outside",
                2,
                serde_json::json!(false),
                "setup_recovery_input",
            ),
            (
                "automation",
                1,
                serde_json::Value::Null,
                "setup_recovery_failed",
            ),
        ] {
            let failed = bounded_output_with_timeout(
                Command::new(paths.bin_dir.join("dev-auth"))
                    .args([
                        "setup",
                        "recover",
                        "--mode",
                        "user-only",
                        "--format",
                        "json",
                        "--credential-fd",
                    ])
                    .arg(format!("{slot}=999999"))
                    .env_clear()
                    .env("HOME", &user.dir)
                    .env("PATH", "/usr/bin:/bin"),
                Duration::from_secs(30),
                "recovery failure progress boundary",
            );
            assert_eq!(failed.status.code(), Some(exit));
            assert!(failed.stderr.is_empty());
            let failed: serde_json::Value = serde_json::from_slice(&failed.stdout).unwrap();
            assert_eq!(failed["changed"], changed);
            assert_eq!(failed["error_kind"], error_kind);
            assert_eq!(fs::read(&transition_path).unwrap(), retained);
            assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        }
        for phase in ["restoring", "restored_inactive"] {
            let mut marker = transition.clone();
            marker["phase"] = phase.into();
            let marker = serde_json::to_vec(&marker).unwrap();
            fs::write(&transition_path, &marker).unwrap();
            let output = bounded_output_with_timeout(
                Command::new(paths.bin_dir.join("dev-auth"))
                    .args([
                        "setup",
                        "recover",
                        "--mode",
                        "user-only",
                        "--format",
                        "json",
                    ])
                    .env_clear(),
                Duration::from_secs(15),
                "restoration direction must reject forward recovery",
            );
            assert_eq!(output.status.code(), Some(3));
            assert!(output.stderr.is_empty());
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["changed"], false);
            assert_eq!(report["error_kind"], "setup_recovery_blocked");
            assert_eq!(fs::read(&transition_path).unwrap(), marker);
            assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot);
        }
        fs::write(&transition_path, &retained).unwrap();
    }
    assert!(!report.verified);
    assert!(!user.dir.join(".local/bin/future-agent").exists());
    assert!(!user
        .dir
        .join(".local/share/dev-auth/workload-aliases-v1.json")
        .exists());
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_legacy_setup_keeps_native_repair_rollback_and_uninstall() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        use dev_auth::setup::{install_at, InstallMode, InstallRequest, SetupPaths};
        let paths = SetupPaths::user_only(&user.dir);
        let native_git = user.dir.join("native-git");
        let native_gh = user.dir.join("native-gh");
        for program in [&native_git, &native_gh] {
            fs::write(program, b"#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(program, fs::Permissions::from_mode(0o700)).unwrap();
        }
        install_at(
            &paths,
            &InstallRequest {
                mode: InstallMode::UserOnly,
                version: env!("CARGO_PKG_VERSION").into(),
                source_executable: user.dir.parent().unwrap().join("artifact"),
                native_git,
                native_gh,
                activate_transparent_launchers: false,
            },
        )
        .unwrap();
        assert!(!paths.data_root.join("setup-transition-v1.json").exists());
        // Legacy direct configuration remains usable when no full generation
        // owns it. The public commands must release their leases on return.
        let policy_source = user.dir.join("legacy-policy.toml");
        let config_source = user.dir.join("legacy-config.toml");
        fs::write(&policy_source, format!(
            "schema = \"dev-auth-administrator-policy-v3\"\nmode = \"user_only\"\nallowed_users = [\"{}\"]\n[programs]\ngit = \"{git_path}\"\ngh = \"{gh_path}\"\nssh = \"{git_path}\"\nssh_keygen = \"{git_path}\"\n[trusted_launchers]\n[credentials.providers]\n[credentials.credential_slots]\n[credentials.resources]\n[credentials.resource_caps]\n[workload_caps]\n",
            user.name, git_path = user.dir.join("native-git").display(), gh_path = user.dir.join("native-gh").display()
        )).unwrap();
        fs::write(
            &config_source,
            b"schema = \"dev-auth-user-config-v3\"\nworkloads = []\n[authority_profiles]\n",
        )
        .unwrap();
        for action in ["install", "update"] {
            for (kind, source) in [
                ("user-policy", &policy_source),
                ("user-config", &config_source),
            ] {
                use sha2::Digest;
                fs::set_permissions(source, fs::Permissions::from_mode(0o600)).unwrap();
                let digest = format!("{:x}", sha2::Sha256::digest(fs::read(source).unwrap()));
                let operation = format!("{action}-{kind}");
                let mut command = Command::new(paths.bin_dir.join("dev-auth"));
                command
                    .env_clear()
                    .args(["setup", &operation, "--source"])
                    .arg(source)
                    .args(["--sha256", &digest]);
                if action == "update" {
                    command.args(["--current-sha256", &digest]);
                }
                let output = command.output().unwrap();
                assert!(
                    output.status.success(),
                    "{operation}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        let alias = paths.bin_dir.join("git-dev-auth");
        fs::remove_file(&alias).unwrap();
        for operation in ["repair", "rollback", "uninstall"] {
            let output = Command::new(paths.bin_dir.join("dev-auth"))
                .args(["setup", operation, "--mode", "user-only"])
                .env_clear()
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{operation}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if operation == "repair" {
                assert!(fs::symlink_metadata(&alias)
                    .unwrap()
                    .file_type()
                    .is_symlink());
            }
        }
        assert!(!paths.data_root.join("install-v2.json").exists());
        assert!(!paths.bin_dir.join("dev-auth").exists());
        assert!(user.dir.join("native-git").is_file());
        return;
    }
    let sandbox = NativeUserSandbox::new();
    sandbox.install_binary(&sandbox.root.join("artifact"));
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "standalone_legacy_setup_keeps_native_repair_rollback_and_uninstall",
            "--nocapture",
        ]),
        Duration::from_secs(90),
        "standalone legacy maintenance subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_user_only_setup_is_idempotent_transparent_and_deactivatable() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_standalone_user_only_setup_child(false);
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("artifact");
    let bootstrap = sandbox.root.join("dev-auth-bootstrap");
    sandbox.install_binary(&product);
    sandbox.install_binary(&bootstrap);
    assert!(Command::new("/usr/bin/strip")
        .args(["--strip-debug"])
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "standalone_user_only_setup_is_idempotent_transparent_and_deactivatable",
            "--nocapture",
        ]),
        Duration::from_secs(90),
        "standalone setup acceptance subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires native Bubblewrap and strace; exercises a disposable installed public binary"]
fn standalone_doctor_has_no_network_helpers_or_mutation() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_standalone_user_only_setup_child(true);
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("artifact");
    let bootstrap = sandbox.root.join("dev-auth-bootstrap");
    sandbox.install_binary(&product);
    sandbox.install_binary(&bootstrap);
    assert!(Command::new("/usr/bin/strip")
        .args(["--strip-debug"])
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "standalone_doctor_has_no_network_helpers_or_mutation",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ]),
        Duration::from_secs(150),
        "standalone doctor native boundary acceptance",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn missing_credential_stages_no_workload_launchers() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_missing_credential_stages_no_workload_launchers_child(false, None);
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "missing_credential_stages_no_workload_launchers",
            "--nocapture",
        ]),
        Duration::from_secs(90),
        "inactive setup acceptance subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn installed_user_only_workload_validates_selected_slots_without_key_export() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_installed_user_only_validation_child();
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    assert!(Command::new("/usr/bin/strip")
        .arg("--strip-debug")
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let store = enrolled_store::EnrolledStore::start(
        &sandbox.runtime,
        std::collections::BTreeMap::from([
            ("automation".into(), "fixture-enrollment-one".into()),
            ("secondary".into(), "fixture-enrollment-two".into()),
        ]),
    );
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "installed_user_only_workload_validates_selected_slots_without_key_export",
            "--nocapture",
        ]),
        Duration::from_secs(120),
        "installed user-only validation fixture",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let observations = store.observations.lock().unwrap();
    assert_eq!(observations.reads, ["automation", "secondary"]);
    assert_eq!(observations.searches.len(), 2);
}

#[cfg(target_os = "linux")]
fn run_installed_user_only_validation_child() {
    use dev_auth::setup::{
        install_at, reconcile_workload_launchers_at, InstallMode, InstallRequest, SetupPaths,
    };
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    let paths = SetupPaths::user_only(&user.dir);
    let root = user.dir.join("acceptance");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let native = root.join("native-tool");
    let native_gh = root.join("native-gh");
    fs::write(&native, b"#!/bin/sh\nexit 91\n").unwrap();
    fs::set_permissions(&native, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(&native, &native_gh).unwrap();
    let primary = root.join("op-primary");
    let secondary = root.join("op-secondary");
    for (path, token, reference, value) in [
        (
            &primary,
            "fixture-enrollment-one",
            "op://Fixture/Token/value",
            "fixture-export".to_owned(),
        ),
        (
            &secondary,
            "fixture-enrollment-two",
            "op://Fixture/Release/value",
            "09".repeat(32),
        ),
    ] {
        fs::write(path, format!(
            "#!/bin/sh\n[ \"$OP_SERVICE_ACCOUNT_TOKEN\" = '{token}' ] || exit 90\nprintf '%s\\n' \"$1\" >> '{}.calls'\ncase \"$*\" in\n'user get --me --format json') printf '%s' '{{\"id\":\"fixture\",\"state\":\"ACTIVE\",\"type\":\"SERVICE_ACCOUNT\"}}' ;;\n'read --no-newline {reference}') printf '%s' '{value}' ;;\n*) exit 92 ;;\nesac\n", path.display()
        )).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let installed = paths.bin_dir.join("dev-auth");
    let launcher = root.join("generic-worker");
    let exported = root.join("exported");
    let denied_key = root.join("denied-key");
    let hint = root.join("session-hint");
    fs::write(&launcher, format!(
        "#!/bin/sh\nset -eu\n[ -z \"${{GH_ENTERPRISE_TOKEN+x}}${{GITHUB_ENTERPRISE_TOKEN+x}}\" ] || exit 94\nprintf '%s\\n%s\\n' \"$DEV_AUTH_USER_BROKER_SOCKET\" \"$DEV_AUTH_USER_SESSION\" > '{}'\n'{}' validate --component providers --online --non-interactive --json\n'{}' secret read token --non-interactive > '{}'\nif '{}' secret read release --non-interactive > '{}' 2>/dev/null; then exit 93; fi\n",
        hint.display(), installed.display(), installed.display(), exported.display(), installed.display(), denied_key.display()
    )).unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
    let config_root = user.dir.join(".config/dev-auth");
    fs::create_dir_all(&config_root).unwrap();
    fs::set_permissions(user.dir.join(".config"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&config_root, fs::Permissions::from_mode(0o700)).unwrap();
    let public_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let policy = format!(
        r#"schema = "dev-auth-administrator-policy-v3"
mode = "user_only"
allowed_users = ["{user}"]
[programs]
git = "{native}"
gh = "{native_gh}"
ssh = "{native}"
ssh_keygen = "{native}"
[trusted_launchers]
generic-worker = "{launcher}"
[credentials.providers.primary]
kind = "one_password"
executable = "{primary}"
[credentials.providers.secondary]
kind = "one_password"
executable = "{secondary}"
[credentials.credential_slots.automation]
provider = "primary"
users = ["{user}"]
[credentials.credential_slots.secondary]
provider = "secondary"
users = ["{user}"]
[credentials.resources.token]
credential_slot = "automation"
reference = "op://Fixture/Token/value"
kind = "exportable"
purposes = ["read"]
[credentials.resources.release]
credential_slot = "secondary"
reference = "op://Fixture/Release/value"
kind = "operation_only"
purposes = ["release_signing"]
[credentials.resource_caps.worker]
users = ["{user}"]
[credentials.resource_caps.worker.resources.token]
purposes = ["read"]
[credentials.resource_caps.worker.resources.release]
purposes = ["release_signing"]
[workload_caps.worker]
users = ["{user}"]
resource_cap = "worker"
launchers = ["generic-worker"]
admission = ["enrolled_noninteractive"]
max_duration_seconds = 120
[workload_caps.worker.operations.release_signing.release]
public_key = "{public_key}"
products = ["fixture"]
"#,
        user = user.name,
        native = native.display(),
        native_gh = native_gh.display(),
        launcher = launcher.display(),
        primary = primary.display(),
        secondary = secondary.display()
    );
    let config = r#"schema = "dev-auth-user-config-v3"
[authority_profiles.worker]
cap = "worker"
[authority_profiles.worker.resources.token]
purposes = ["read"]
[authority_profiles.worker.resources.release]
purposes = ["release_signing"]
[[workloads]]
name = "generic-worker"
launcher = "generic-worker"
profile = "worker"
admission = "enrolled_noninteractive"
duration_seconds = 120
[workloads.resources.token]
purposes = ["read"]
[workloads.resources.release]
purposes = ["release_signing"]
[workloads.operations.release_signing]
resource = "release"
products = ["fixture"]
"#;
    for (name, bytes) in [
        ("policy-v3.toml", policy.as_bytes()),
        ("config-v3.toml", config.as_bytes()),
    ] {
        let path = config_root.join(name);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    // Construct the installed-runtime fixture with public installation primitives.
    // This is not signed-release or journaled setup-v3 acceptance.
    let receipt = install_at(
        &paths,
        &InstallRequest {
            mode: InstallMode::UserOnly,
            version: "0.4.0".into(),
            source_executable: user.dir.parent().unwrap().join("product"),
            native_git: native.clone(),
            native_gh,
            activate_transparent_launchers: false,
        },
    )
    .unwrap();
    reconcile_workload_launchers_at(
        &user.dir,
        Path::new(&receipt.executable),
        &["generic-worker".into()],
        user.uid.as_raw(),
    )
    .unwrap();
    let output = bounded_output(
        Command::new(&installed)
            .args([
                "workload",
                "launch",
                "generic-worker",
                "--non-interactive",
                "--",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("GH_ENTERPRISE_TOKEN", "synthetic-human-token")
            .env("GITHUB_ENTERPRISE_TOKEN", "synthetic-human-token")
            .current_dir(&root),
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["authority"], "installed_broker");
    assert_eq!(report["exit_code"], 0);
    let json = String::from_utf8(output.stdout.clone()).unwrap();
    for forbidden in [
        "09".repeat(32),
        "fixture-enrollment-one".into(),
        "fixture-enrollment-two".into(),
        "op://".into(),
    ] {
        assert!(!json.contains(&forbidden));
    }
    for (component, count) in [
        ("provider_authentication", 2),
        ("provider_resources", 2),
        ("key_material", 1),
    ] {
        let check = report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|check| check["component"] == component)
            .unwrap();
        assert_eq!(check["status"], "passed");
        assert_eq!(check["checked"], count);
        assert_eq!(check["total"], count);
    }
    assert_eq!(fs::read(&exported).unwrap(), b"fixture-export");
    assert!(fs::read(denied_key).unwrap().is_empty());
    assert_eq!(
        fs::read_to_string(primary.with_extension("calls")).unwrap(),
        "user\nread\nread\n"
    );
    assert_eq!(
        fs::read_to_string(secondary.with_extension("calls")).unwrap(),
        "user\nread\n"
    );
    let hint = fs::read_to_string(hint).unwrap();
    let mut lines = hint.lines();
    let socket = lines.next().unwrap();
    let session = lines.next().unwrap();
    assert!(!Path::new(socket).exists());
    assert!(!Path::new(socket).parent().unwrap().exists());
    let stale = bounded_output(
        Command::new(&installed)
            .args([
                "validate",
                "--component",
                "providers",
                "--online",
                "--non-interactive",
                "--json",
            ])
            .env_clear()
            .env("DEV_AUTH_USER_BROKER_SOCKET", socket)
            .env("DEV_AUTH_USER_SESSION", session),
    );
    assert!(!stale.status.success());
    assert_eq!(
        fs::read_to_string(primary.with_extension("calls")).unwrap(),
        "user\nread\nread\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logical_setup_stages_versioned_authority_and_resumes_without_activation() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_missing_credential_stages_no_workload_launchers_child(true, None);
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    assert!(Command::new("/usr/bin/strip")
        .arg("--strip-debug")
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let current = std::env::current_exe().unwrap();
    let output = bounded_output_with_timeout(
        sandbox.command(&current, &sandbox.home).args([
            "--exact",
            "logical_setup_stages_versioned_authority_and_resumes_without_activation",
            "--nocapture",
        ]),
        Duration::from_secs(90),
        "logical setup native subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logical_setup_recovers_a_committed_initial_binary_without_its_product_receipt() {
    run_binary_receipt_recovery_test(
        SetupRecoveryFixture::MissingInitialReceipt,
        "logical_setup_recovers_a_committed_initial_binary_without_its_product_receipt",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logical_setup_recovers_an_uncommitted_initial_binary_without_original_sources() {
    run_binary_receipt_recovery_test(
        SetupRecoveryFixture::InitialUncommittedBinary,
        "logical_setup_recovers_an_uncommitted_initial_binary_without_original_sources",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logical_setup_completes_a_committed_upgrade_with_the_retained_prior_product_receipt() {
    run_binary_receipt_recovery_test(
        SetupRecoveryFixture::CommittedUpgradeReceipt,
        "logical_setup_completes_a_committed_upgrade_with_the_retained_prior_product_receipt",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logical_setup_recovers_an_uncommitted_upgrade_from_the_retained_prior_receipts() {
    run_binary_receipt_recovery_test(
        SetupRecoveryFixture::UncommittedUpgradeBinary,
        "logical_setup_recovers_an_uncommitted_upgrade_from_the_retained_prior_receipts",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logical_setup_recovers_an_unstaged_upgrade_from_the_approved_running_candidate() {
    run_binary_receipt_recovery_test(
        SetupRecoveryFixture::UnstagedUpgradeBinary,
        "logical_setup_recovers_an_unstaged_upgrade_from_the_approved_running_candidate",
    );
}

#[cfg(target_os = "linux")]
#[test]
fn logical_setup_recovers_an_unstaged_initial_binary_without_installation_layout() {
    run_binary_receipt_recovery_test(
        SetupRecoveryFixture::UnstagedInitialBinary,
        "logical_setup_recovers_an_unstaged_initial_binary_without_installation_layout",
    );
}

#[cfg(target_os = "linux")]
fn run_binary_receipt_recovery_test(recovery: SetupRecoveryFixture, test_name: &'static str) {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_missing_credential_stages_no_workload_launchers_child(true, Some(recovery));
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    // Native CLI behavior does not require debug or static symbol tables. Keep
    // custody hashing focused on the executable artifact, as in distribution.
    assert!(Command::new("/usr/bin/strip")
        .arg("--strip-all")
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let output = bounded_output_with_timeout(
        sandbox
            .command(&std::env::current_exe().unwrap(), &sandbox.home)
            .args(["--exact", test_name, "--nocapture"]),
        if matches!(
            recovery,
            SetupRecoveryFixture::UncommittedUpgradeBinary
                | SetupRecoveryFixture::UnstagedUpgradeBinary
        ) {
            Duration::from_secs(120)
        } else {
            Duration::from_secs(90)
        },
        "product receipt recovery native subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn native_user_setup_restores_retained_generation_inactive() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_missing_credential_stages_no_workload_launchers_child(
            true,
            Some(SetupRecoveryFixture::PriorInstallation),
        );
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    assert!(Command::new("/usr/bin/strip")
        .arg("--strip-debug")
        .arg(&product)
        .status()
        .unwrap()
        .success());
    // This fixture installs two distinct source-binary identities and invokes
    // rejection, full restore, repeat and forward rejection. Its debug-build
    // liveness bound is not a released-product latency acceptance threshold.
    let output = bounded_output_with_timeout(
        sandbox
            .command(&std::env::current_exe().unwrap(), &sandbox.home)
            .args([
                "--exact",
                "native_user_setup_restores_retained_generation_inactive",
                "--nocapture",
            ]),
        Duration::from_secs(240),
        "retained generation restoration native subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

#[test]
fn native_user_setup_restores_initial_installation_absence() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_missing_credential_stages_no_workload_launchers_child(
            true,
            Some(SetupRecoveryFixture::InitialAbsence),
        );
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    assert!(Command::new("/usr/bin/strip")
        .arg("--strip-debug")
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let output = bounded_output_with_timeout(
        sandbox
            .command(&std::env::current_exe().unwrap(), &sandbox.home)
            .args([
                "--exact",
                "native_user_setup_restores_initial_installation_absence",
                "--nocapture",
            ]),
        Duration::from_secs(240),
        "initial absence restoration native subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

#[test]
#[ignore = "requires native Linux strace process-death acceptance"]
fn native_user_setup_restoration_resumes_after_process_death() {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
        .unwrap()
        .unwrap();
    if user.name == "dev-auth-test" {
        run_missing_credential_stages_no_workload_launchers_child(
            true,
            Some(SetupRecoveryFixture::InitialProcessDeath),
        );
        return;
    }
    let sandbox = NativeUserSandbox::new();
    let product = sandbox.root.join("product");
    sandbox.install_binary(&product);
    assert!(Command::new("/usr/bin/strip")
        .arg("--strip-debug")
        .arg(&product)
        .status()
        .unwrap()
        .success());
    let output = bounded_output_with_timeout(
        sandbox
            .command(&std::env::current_exe().unwrap(), &sandbox.home)
            .args([
                "--exact",
                "native_user_setup_restoration_resumes_after_process_death",
                "--ignored",
                "--nocapture",
            ]),
        Duration::from_secs(240),
        "initial restoration process-death native subprocess",
    );
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
}

fn credential_helper(operation: &str, input: &str) -> std::process::Output {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
        .arg(operation)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn get_failure_stops_git_from_falling_back_to_human_credentials() {
    let secret = "must-not-appear";
    let output = credential_helper(
        "get",
        &format!(
            "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\npassword={secret}\n\n"
        ),
    );
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains(secret));
}

#[test]
fn store_discards_git_supplied_secrets_without_output() {
    let output = credential_helper(
        "store",
        "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\nusername=x-access-token\npassword=must-not-appear\n\n",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn store_accepts_git_eof_without_parsing_or_retaining_the_credential() {
    let output = credential_helper(
        "store",
        "protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\nusername=x-access-token\npassword=must-not-appear\n",
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn help_is_product_generic_and_lists_the_bounded_surface() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-auth"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for command in [
        "enroll",
        "validate",
        "exec",
        "agent",
        "agent-endpoint",
        "ssh-load",
        "ssh-public",
        "workspace-status",
        "status",
        "purge",
    ] {
        assert!(help.contains(command));
    }
    assert!(!help.to_ascii_lowercase().contains("codex"));
    assert!(!help.to_ascii_lowercase().contains("homelab"));
}

#[test]
fn unsafe_gh_operations_are_rejected_before_configuration_or_credentials_are_read() {
    let directory = tempfile::tempdir().unwrap();
    let frontend = directory.path().join("gh-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &frontend).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();

    for arguments in [
        vec![
            "pr",
            "create",
            "--head",
            "automation/change",
            "--base",
            "main",
            "--title",
            "Bounded change",
            "--body",
            "Reviewed body",
            "--dry-run",
        ],
        vec![
            "pr",
            "create",
            "--head=automation/change",
            "--base=main",
            "--title=Bounded change",
            "--body-file=/proc/self/environ",
        ],
        vec!["pr", "comment", "42", "--body-file=private-link"],
        vec!["pr", "review", "42", "-aF/proc/self/environ"],
        vec!["pr", "merge", "42", "--admin", "--squash"],
        vec!["run", "download", "42", "--dir=/tmp"],
        vec!["repo", "view", "-RExampleOrg/sample-repo"],
        vec![
            "pr",
            "comment",
            "https://github.com/OtherOrg/other-repo/pull/42",
            "--body",
            "cross-repository",
        ],
        vec!["pr", "view", "42", "--unknown"],
    ] {
        let output = Command::new(&frontend)
            .args(&arguments)
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .output()
            .unwrap();

        assert!(!output.status.success(), "{arguments:?}");
        assert!(output.stdout.is_empty(), "{arguments:?}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(!error.contains("configuration"), "{arguments:?}: {error}");
        assert!(!error.contains("credential"), "{arguments:?}: {error}");
    }
}

#[test]
fn invalid_ambient_gh_repository_is_rejected_before_configuration_or_runtime_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let frontend = directory.path().join("gh-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &frontend).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();

    let output = Command::new(&frontend)
        .args(["repo", "view", "--json", "nameWithOwner"])
        .env_clear()
        .env("GH_REPO", "not/an/exact/repository")
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("exact github.com owner/repository"),
        "{error}"
    );
    assert!(!error.contains("configuration"), "{error}");
    assert!(!runtime.path().join("dev-auth").exists());
}

#[test]
fn configured_git_resolves_literal_origin_without_caller_path_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let frontend = directory.path().join("gh-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &frontend).unwrap();
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args(["init", "--quiet"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            "remote.origin.url",
            "https://github.com/ExampleOrg/too/many.git",
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "/usr/bin/git"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Automation/app/private key"
repository_selection = "all"
discover_installations = true
permissions = { actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }
"#,
    )
    .unwrap();
    fs::set_permissions(
        config_dir.join("config.toml"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let attacker_bin = directory.path().join("attacker-bin");
    fs::create_dir(&attacker_bin).unwrap();
    let marker = directory.path().join("caller-path-git-ran");
    let attacker_git = attacker_bin.join("git");
    fs::write(
        &attacker_git,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nprintf 'https://github.com/ExampleOrg/too/many.git\\0'\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&attacker_git, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = private_runtime();

    let output = Command::new(&frontend)
        .args(["repo", "view", "--json", "nameWithOwner"])
        .current_dir(&repository)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", format!("{}:/usr/bin", attacker_bin.display()))
        .env("XDG_RUNTIME_DIR", runtime.path())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(
        error.contains("exactly owner/repository"),
        "unexpected error: {error}"
    );
    assert!(!error.contains("configuration"), "{error}");
    assert!(!error.contains("credential"), "{error}");
    assert!(!marker.exists());
    assert!(!runtime.path().join("dev-auth").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn provider_validation_is_independent_of_github_cli_and_does_not_prompt() {
    let sandbox = NativeUserSandbox::new();
    let binary = sandbox.home.join("dev-auth");
    sandbox.install_binary(&binary);
    let marker = sandbox.home.join("gh-was-executed");
    let gh = sandbox.home.join("gh");
    fs::write(
        &gh,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nexit 99\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let config_dir = sandbox.home.join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "{}"
gh = "{}"
git = "/nonexistent/git"
ssh_add = "/nonexistent/ssh-add"
ssh_keygen = "/nonexistent/ssh-keygen"
[github]
app_id = 42
private_key_ref = "op://private-metadata-sentinel/app/key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
"#,
        gh.display(),
        gh.display()
    );
    let path = config_dir.join("config.toml");
    fs::write(&path, config).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

    for online in [false, true] {
        let mut command = sandbox.command(&binary, &sandbox.home);
        command.args([
            "validate",
            "--component",
            "providers",
            "--non-interactive",
            "--json",
        ]);
        if online {
            command.arg("--online");
        }
        let output = bounded_output(&mut command);
        assert_eq!(output.status.code(), Some(if online { 3 } else { 0 }));
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["schema"], "dev-auth-validation-v1");
        assert_eq!(report["authority"], "legacy_v1");
        let checks = report["checks"].as_array().unwrap();
        let check = |name| {
            checks
                .iter()
                .find(|check| check["component"] == name)
                .unwrap()
        };
        assert_eq!(check("configuration")["status"], "passed");
        assert_eq!(check("github_cli")["status"], "not_checked");
        assert_eq!(check("git")["status"], "not_checked");
        assert_eq!(
            check("enrollment")["status"],
            if online { "blocked" } else { "not_checked" }
        );
        assert_eq!(check("provider_resources")["checked"], 0);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-metadata-sentinel"));
        assert!(!marker.exists());
        assert!(!sandbox.runtime.join("dev-auth").exists());
    }
}

#[test]
fn validation_invalid_arguments_return_one_value_free_json_result() {
    let output = bounded_output(
        Command::new(env!("CARGO_BIN_EXE_dev-auth"))
            .env_clear()
            .args([
                "validate",
                "--json",
                "--component",
                "private-invalid-component",
            ]),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "dev-auth-validation-v1");
    assert_eq!(report["error_kind"], "invalid_invocation");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-invalid-component"));
}

#[cfg(target_os = "linux")]
#[test]
fn offline_validation_is_value_free_and_pins_the_gh_protocol() {
    let sandbox = NativeUserSandbox::new();
    let home = &sandbox.home;
    let gh = home.join("gh");
    let binary = home.join("dev-auth");
    sandbox.install_binary(&binary);
    fs::write(
        &gh,
        "#!/bin/sh\n\
         [ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 91\n\
         [ -z \"${GH_TOKEN+x}\" ] || exit 92\n\
         [ -z \"${GITHUB_TOKEN+x}\" ] || exit 93\n\
         [ -z \"${GH_REPO+x}\" ] || exit 94\n\
         [ -z \"${DEV_AUTH_GH_CHILD+x}\" ] || exit 95\n\
         [ -z \"${DEV_AUTH_GH_GIT+x}\" ] || exit 96\n\
         case \"$HOME\" in */gh-sandbox/home) ;; *) exit 97 ;; esac\n\
         case \"$GH_CONFIG_DIR\" in */gh-sandbox/config) ;; *) exit 98 ;; esac\n\
         printf 'gh version 2.98.0 (2026-08-21)\\nhttps://github.com/cli/cli/releases/tag/v2.98.0\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o700)).unwrap();
    let config_dir = home.join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(home.join(".config"), fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "{}"
gh = "{}"
git = "/usr/bin/false"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Example Vault/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[profiles.plan]
executables = ["/usr/bin/false"]
environment = {{ EXAMPLE_TOKEN = "op://Example Vault/plan/token" }}
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Example Vault/auth/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Example Vault/signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        gh.display(),
        gh.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let output = bounded_output(sandbox.command(&binary, home).arg("validate"));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "config_valid=true online=false declared_exec_profiles=1 declared_ssh_profiles=1 declared_secret_references=4\n"
    );
    assert!(output.stderr.is_empty());

    fs::write(
        &gh,
        "#!/bin/sh\nprintf 'gh version 2.99.0 (2026-08-28)\\nhttps://github.com/cli/cli/releases/tag/v2.99.0\\n'\n",
    )
    .unwrap();
    let rejected = bounded_output(sandbox.command(&binary, home).arg("validate"));
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    let error = String::from_utf8(rejected.stderr).unwrap();
    assert!(error.contains("legacy_gh_protocol_unsupported"));
    assert!(!error.contains("2.99.0"));

    let aggregate = bounded_output(sandbox.command(&binary, home).args([
        "validate",
        "--online",
        "--non-interactive",
        "--json",
    ]));
    assert_eq!(aggregate.status.code(), Some(3));
    assert!(aggregate.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&aggregate.stdout).unwrap();
    let checks = report["checks"].as_array().unwrap();
    let check = |name| {
        checks
            .iter()
            .find(|check| check["component"] == name)
            .unwrap()
    };
    assert_eq!(
        check("github_cli")["error_kind"],
        "legacy_gh_protocol_unsupported"
    );
    assert_eq!(check("enrollment")["status"], "blocked");
    assert_eq!(check("enrollment")["error_kind"], "enrollment_unavailable");
    assert_eq!(check("provider_resources")["checked"], 0);
    assert!(!String::from_utf8_lossy(&aggregate.stdout).contains("Example Vault"));
}

#[test]
fn one_released_binary_serves_the_git_helper_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
        .arg("get")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
}

#[test]
fn one_released_binary_serves_every_declared_symlink_frontend() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    for frontend in [
        "git-dev-auth",
        "git-credential-dev-auth",
        "gh-dev-auth",
        "ssh-keygen-dev-auth",
        "git-dev-auth.exe",
        "git-credential-dev-auth.exe",
        "gh-dev-auth.exe",
        "ssh-keygen-dev-auth.exe",
    ] {
        let path = directory.path().join(frontend);
        symlink(env!("CARGO_BIN_EXE_dev-auth"), &path).unwrap();
        let output = Command::new(&path)
            .arg("--help")
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .output()
            .unwrap();
        assert!(!output.status.success(), "{frontend}");
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .starts_with(&format!("{frontend}: ")),
            "{frontend}"
        );
    }
}

#[test]
fn managed_git_child_admits_only_its_exact_private_helper_identities() {
    let directory = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    for (frontend, arguments) in [
        ("git-credential-dev-auth", vec!["get"]),
        ("ssh-keygen-dev-auth", vec!["--help"]),
    ] {
        let path = directory.path().join(frontend);
        symlink(env!("CARGO_BIN_EXE_dev-auth"), &path).unwrap();
        let mut command = Command::new(&path);
        command
            .args(arguments)
            .env_clear()
            .env("DEV_AUTH_GIT_CHILD", "1")
            .env("HOME", home.path())
            .env("PATH", "/usr/bin")
            .env("XDG_RUNTIME_DIR", runtime.path());
        let output = bounded_output(&mut command);
        assert!(!output.status.success(), "{frontend}");
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            !error.contains("unrecognized private child launcher identity"),
            "{frontend}: {error}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn public_git_frontend_uses_one_native_policy_and_propagates_managed_results() {
    let sandbox = NativeUserSandbox::new();
    let bin = sandbox.home.join("bin");
    let managed = sandbox.home.join("repos");
    let repository = managed.join("repository");
    let attacker_home = sandbox.root.join("attacker-home");
    let attacker_config = sandbox.root.join("attacker-config");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&repository).unwrap();
    fs::create_dir_all(&attacker_home).unwrap();
    fs::create_dir_all(&attacker_config).unwrap();
    for path in [
        &bin,
        &managed,
        &repository,
        &attacker_home,
        &attacker_config,
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let frontend = bin.join("git-dev-auth");
    let binary = bin.join("dev-auth");
    sandbox.install_binary(&binary);
    symlink(&binary, &frontend).unwrap();
    let fake_git = bin.join("git");
    let force_exit = sandbox.root.join("force-exit");
    fs::write(
        &fake_git,
        format!(
            r#"#!/bin/sh
if [ "${{1:-}}" = --version ]; then
  printf 'git version 2.53.0\n'
  exit 0
fi
while [ "${{1:-}}" = -c ]; do shift 2; done
case "${{1:-}}" in
  status)
    [ ! -e '{}' ] || exit 23
    exec /usr/bin/git "$@"
    ;;
  clone)
    for argument in "$@"; do destination=$argument; done
    /usr/bin/git init --quiet "$destination" || exit
    /usr/bin/git -C "$destination" config remote.origin.url https://github.com/ExampleOrg/cloned.git || exit
    exit 0
    ;;
  *) exec /usr/bin/git "$@" ;;
esac
"#,
            force_exit.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_git, fs::Permissions::from_mode(0o700)).unwrap();
    let fake_gh = bin.join("gh");
    fs::write(
        &fake_gh,
        "#!/bin/sh\n[ \"$#\" -eq 1 ] && [ \"$1\" = --version ] || exit 91\nprintf 'gh version 2.98.0 (2026-08-21)\\nhttps://github.com/cli/cli/releases/tag/v2.98.0\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args(["init", "--quiet"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "remote.origin.url",
            "https://github.com/ExampleOrg/repository.git",
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    let config_dir = sandbox.home.join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        sandbox.home.join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "{}"
gh = "{}"
git = "{}"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[git]
workspace_roots = ["~/repos"]
author_name = "Automation Worker"
author_email = "automation@example.invalid"
ssh_profile = "automation"
[github]
app_id = 42
private_key_ref = "op://Automation/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Automation/authentication/private-key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Automation/signing/private-key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        fake_gh.display(),
        fake_gh.display(),
        fake_git.display(),
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let human_marker = sandbox.root.join("human-helper-ran");
    let human_helper = sandbox.root.join("human-helper");
    fs::write(
        &human_helper,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", human_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&human_helper, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        attacker_home.join(".gitconfig"),
        format!(
            "[core]\n\tfsmonitor = {}\n[credential]\n\thelper = !{}\n",
            human_helper.display(),
            human_helper.display()
        ),
    )
    .unwrap();
    fs::create_dir_all(attacker_config.join("dev-auth")).unwrap();
    fs::write(
        attacker_config.join("dev-auth/config.toml"),
        "this alternate policy must never be parsed\n",
    )
    .unwrap();

    let validate = bounded_output(sandbox.command(&binary, &repository).arg("validate"));
    assert!(
        validate.status.success(),
        "{}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let status = bounded_output(
        sandbox
            .command(&binary, &repository)
            .arg("workspace-status"),
    );
    assert_eq!(status.stdout, b"managed\n");
    assert!(status.stderr.is_empty());

    let managed_status = bounded_output(
        sandbox
            .command(&frontend, &repository)
            .args(["status", "--short"]),
    );
    assert!(
        managed_status.status.success(),
        "{}",
        String::from_utf8_lossy(&managed_status.stderr)
    );
    assert!(!human_marker.exists());

    let managed_version = bounded_output(sandbox.command(&frontend, &repository).arg("--version"));
    assert!(
        managed_version.status.success(),
        "{}",
        String::from_utf8_lossy(&managed_version.stderr)
    );
    assert_eq!(managed_version.stdout, b"git version 2.53.0\n");
    assert!(managed_version.stderr.is_empty());
    assert!(!human_marker.exists());

    let sentinel = "PUBLIC-CREDENTIAL-SENTINEL-DO-NOT-PRINT";
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            &format!("http.https://{sentinel}@example.invalid.extraheader"),
            "value",
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());
    let rejected = bounded_output(
        sandbox
            .command(&frontend, &repository)
            .args(["status", "--short"]),
    );
    assert!(!rejected.status.success());
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains(sentinel));
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains(sentinel));
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            "--unset-all",
            &format!("http.https://{sentinel}@example.invalid.extraheader"),
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let clone = bounded_output_with_timeout(
        sandbox.command(&frontend, &managed).args([
            "clone",
            "--no-checkout",
            "https://github.com/ExampleOrg/cloned.git",
            "cloned",
        ]),
        Duration::from_secs(60),
        "public managed clone subprocess",
    );
    assert!(
        clone.status.success(),
        "{}",
        String::from_utf8_lossy(&clone.stderr)
    );
    assert!(managed.join("cloned/.git").is_dir());
    assert!(!human_marker.exists());

    fs::write(&force_exit, b"exit 23\n").unwrap();
    let propagated = bounded_output(
        sandbox
            .command(&frontend, &repository)
            .args(["status", "--short"]),
    );
    assert_eq!(propagated.status.code(), Some(23));
    assert!(!human_marker.exists());
}

#[test]
fn internal_gh_children_do_not_forward_the_installation_token_to_git() {
    let directory = private_program_root();
    let home = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let upstream_git = directory.path().join("upstream-git");
    fs::write(
        &upstream_git,
        format!(
            "#!/bin/sh\n[ -z \"${{GH_TOKEN+x}}\" ] || exit 90\n[ -z \"${{GITHUB_TOKEN+x}}\" ] || exit 91\n[ \"$GIT_TERMINAL_PROMPT\" = 0 ] || exit 92\n[ \"$1 $2\" = 'remote -v' ] || exit 93\nprintf passed > '{}'\n",
            home.path().join("git-child-result").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&upstream_git, fs::Permissions::from_mode(0o700)).unwrap();

    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "{}"
ssh_add = "/usr/bin/false"
ssh_keygen = "/usr/bin/false"
[github]
app_id = 42
private_key_ref = "op://Example Vault/app/private-key"
repository_selection = "all"
discover_installations = true
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
"#,
        upstream_git.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let marker = home.path().join("git-child-result");
    let output = Command::new(&git_frontend)
        .args(["remote", "-v"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", &upstream_git)
        .env("GH_TOKEN", "must-not-reach-git")
        .env("GITHUB_TOKEN", "must-not-reach-git")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), "passed");
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn internal_gh_git_child_rejects_url_scoped_repository_credential_helpers() {
    let directory = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let repository = directory.path().join("repository");
    fs::create_dir(&repository).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args(["init", "--quiet"])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let marker = directory.path().join("credential-helper-ran");
    let helper = directory.path().join("credential-helper");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf invoked > '{}'\nif [ \"${{1:-}}\" = get ]; then\n  printf 'username=human\\npassword=human-secret\\n'\nfi\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(Command::new("/usr/bin/git")
        .args([
            "config",
            "--local",
            "credential.https://github.com.helper",
            &format!("!{}", helper.display()),
        ])
        .current_dir(&repository)
        .status()
        .unwrap()
        .success());

    let home = tempfile::tempdir().unwrap();
    let mut child = Command::new(&git_frontend)
        .args(["credential", "fill"])
        .current_dir(&repository)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", "/usr/bin/git")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let write_result = child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/repository.git\n\n");
    if let Err(error) = write_result {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "unexpected credential-input write failure: {error}"
        );
    }
    let output = child.wait_with_output().unwrap();

    assert!(!output.status.success());
    assert!(!marker.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("human-secret"));
}

#[test]
fn internal_gh_git_child_rejects_explicit_config_overrides() {
    let directory = tempfile::tempdir().unwrap();
    let git_frontend = directory.path().join("git");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &git_frontend).unwrap();
    let marker = directory.path().join("upstream-git-ran");
    let upstream_git = directory.path().join("upstream-git");
    fs::write(
        &upstream_git,
        format!("#!/bin/sh\nprintf invoked > '{}'\n", marker.display()),
    )
    .unwrap();
    fs::set_permissions(&upstream_git, fs::Permissions::from_mode(0o700)).unwrap();
    let home = tempfile::tempdir().unwrap();

    let output = Command::new(&git_frontend)
        .args(["-ccredential.helper=!attacker", "status"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", directory.path())
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("DEV_AUTH_GH_GIT", &upstream_git)
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!marker.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("outside the bounded read-only surface")
    );
}

#[test]
fn internal_gh_pager_copies_only_standard_input() {
    let directory = tempfile::tempdir().unwrap();
    let pager = directory.path().join("cat");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &pager).unwrap();
    let mut child = Command::new(&pager)
        .env_clear()
        .env("DEV_AUTH_GH_CHILD", "1")
        .env("GH_TOKEN", "must-not-be-rendered")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"bounded output\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"bounded output\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn windows_credential_helper_name_preserves_fail_closed_git_output() {
    let directory = tempfile::tempdir().unwrap();
    let helper = directory.path().join("git-credential-dev-auth.exe");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let home = tempfile::tempdir().unwrap();
    let runtime = private_runtime();
    let mut child = Command::new(&helper)
        .arg("get")
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", runtime.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"protocol=https\nhost=github.com\npath=ExampleOrg/sample-repo.git\n\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "quit=true\n");
}

#[test]
fn git_verification_does_not_require_the_secret_runtime_or_ssh_agent() {
    let directory = private_program_root();
    let helper = directory.path().join("ssh-keygen-dev-auth");
    symlink(env!("CARGO_BIN_EXE_dev-auth"), &helper).unwrap();
    let verifier = directory.path().join("ssh-keygen");
    fs::write(
        &verifier,
        "#!/bin/sh\n[ \"$1\" = -Y ] && [ \"$2\" = verify ]\n",
    )
    .unwrap();
    fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700)).unwrap();

    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/dev-auth");
    fs::create_dir_all(&config_dir).unwrap();
    fs::set_permissions(
        home.path().join(".config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let config = format!(
        r#"version = 1
[credential_store]
service = "test-dev-auth"
account = "service-token"
[programs]
op = "/usr/bin/false"
gh = "/usr/bin/false"
git = "/usr/bin/git"
ssh_add = "/usr/bin/false"
ssh_keygen = "{}"
[github]
app_id = 42
private_key_ref = "op://Automation/app/key"
repository_selection = "all"
permissions = {{ actions = "read", checks = "read", contents = "write", metadata = "read", pull_requests = "write", statuses = "read" }}
discover_installations = true
[[ssh_profiles.automation.keys]]
purpose = "authentication"
private_key_ref = "op://Automation/auth/private key"
fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
[[ssh_profiles.automation.keys]]
purpose = "signing"
private_key_ref = "op://Automation/sign/private key"
fingerprint = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
"#,
        verifier.display()
    );
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, config).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

    let absent_runtime = home.path().join("absent-runtime");
    let output = Command::new(&helper)
        .args(["-Y", "verify", "-n", "git"])
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin")
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_RUNTIME_DIR", &absent_runtime)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!absent_runtime.exists());
}
