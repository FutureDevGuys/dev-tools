use std::fs;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::process::{Child, ExitStatus, Stdio};
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;

use tempfile::TempDir;

fn sync_configs() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sync-configs"))
}

#[cfg(target_os = "linux")]
fn interrupt_after_ready(child: &mut Child, ready: &std::path::Path) -> ExitStatus {
    let child_group = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw)
        .expect("child process group");
    let ready_deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < ready_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if !ready.exists() {
        let _ = rustix::process::kill_process_group(child_group, rustix::process::Signal::KILL);
        let _ = child.wait();
        panic!("child did not complete its readiness handshake");
    }
    rustix::process::kill_process_group(child_group, rustix::process::Signal::INT)
        .expect("send Ctrl-C");

    let exit_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("poll sync-configs") {
            return status;
        }
        if Instant::now() >= exit_deadline {
            let _ = rustix::process::kill_process_group(child_group, rustix::process::Signal::KILL);
            let _ = child.wait();
            panic!("sync-configs did not exit within the cancellation bound");
        }
        thread::sleep(Duration::from_millis(10));
    }
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
        "json-overlay",
        "toml-overlay",
        "managed-path-policy",
    ] {
        assert!(stdout.contains(expected), "missing {expected} in {stdout}");
    }
}

#[test]
fn standalone_overlay_commands_preserve_check_and_dry_run_semantics() {
    let root = TempDir::new().expect("tempdir");
    let json_source = root.path().join("source.json");
    let json_target = root.path().join("target.json");
    fs::write(&json_source, "{\"managed\":true}\n").expect("JSON source");
    fs::write(&json_target, "{\"local\":true}\n").expect("JSON target");

    let check = sync_configs()
        .arg("json-overlay")
        .arg(&json_source)
        .arg(&json_target)
        .arg("--check")
        .output()
        .expect("check JSON overlay");
    assert_eq!(check.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&check.stdout),
        format!(
            "would-update {} added=1 overwritten=0 replaced=0 removed=0 ownership_changed=0\n",
            json_target.display()
        )
    );
    assert_eq!(
        fs::read_to_string(&json_target).expect("unchanged JSON target"),
        "{\"local\":true}\n"
    );

    let apply = sync_configs()
        .arg("json-overlay")
        .arg(&json_source)
        .arg(&json_target)
        .output()
        .expect("apply JSON overlay");
    assert!(apply.status.success());
    assert!(String::from_utf8_lossy(&apply.stdout).starts_with("updated "));

    let toml_source = root.path().join("source.toml");
    let toml_target = root.path().join("target.toml");
    fs::write(&toml_source, "managed = true\n").expect("TOML source");
    fs::write(&toml_target, "local = true\n").expect("TOML target");
    let dry_run = sync_configs()
        .arg("--dry-run")
        .arg("toml-overlay")
        .arg(&toml_source)
        .arg(&toml_target)
        .output()
        .expect("dry-run TOML overlay");
    assert!(dry_run.status.success());
    assert_eq!(
        String::from_utf8_lossy(&dry_run.stdout),
        format!(
            "would-update {} added=1 overwritten=0 removed=0 ownership_changed=0\n",
            toml_target.display()
        )
    );
    assert_eq!(
        fs::read_to_string(&toml_target).expect("unchanged TOML target"),
        "local = true\n"
    );
}

#[test]
fn standalone_overlay_commands_expand_home_paths_and_keep_inactive_receipt_flags_nonmutating() {
    let root = TempDir::new().expect("tempdir");
    let home = root.path().join("home");
    let state = root.path().join("state");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&state).expect("state");

    fs::write(home.join("source.json"), "{\"managed\":true}\n").expect("JSON source");
    fs::write(home.join("target.json"), "{\"local\":true}\n").expect("JSON target");
    let json = sync_configs()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .arg("json-overlay")
        .arg("~/source.json")
        .arg("~/target.json")
        .arg("--check")
        .arg("--managed-overlay-id")
        .arg("ignored")
        .arg("--state-root")
        .arg(&state)
        .output()
        .expect("JSON overlay with home paths");
    assert_eq!(json.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&json.stdout),
        format!(
            "would-update {} added=1 overwritten=0 replaced=0 removed=0 ownership_changed=0\n",
            home.join("target.json").display()
        )
    );

    fs::write(home.join("source.toml"), "managed = true\n").expect("TOML source");
    fs::write(home.join("target.toml"), "managed = false\nlocal = true\n").expect("TOML target");
    let toml = sync_configs()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .arg("toml-overlay")
        .arg("~/source.toml")
        .arg("~/target.toml")
        .arg("--dry-run")
        .arg("--remove")
        .arg("--commented-target-policy")
        .arg("error")
        .arg("--managed-overlay-id")
        .arg("ignored")
        .arg("--state-root")
        .arg(&state)
        .output()
        .expect("TOML overlay with home paths");
    assert!(toml.status.success());
    assert_eq!(
        String::from_utf8_lossy(&toml.stdout),
        format!(
            "would-remove {} removed=1\n",
            home.join("target.toml").display()
        )
    );
}

#[test]
fn standalone_overlay_commands_expand_environment_variable_paths() {
    let root = TempDir::new().expect("tempdir");
    let fixture_root = root.path().join("standalone fixtures");
    fs::create_dir_all(&fixture_root).expect("fixture root");

    let json_source = fixture_root.join("source.json");
    let json_target = fixture_root.join("target.json");
    fs::write(&json_source, "{\"managed\":true}\n").expect("JSON source");
    fs::write(&json_target, "{\"local\":true}\n").expect("JSON target");
    let json = sync_configs()
        .env("SYNC_CONFIGS_STANDALONE_ROOT", &fixture_root)
        .arg("json-overlay")
        .arg("$SYNC_CONFIGS_STANDALONE_ROOT/source.json")
        .arg("${SYNC_CONFIGS_STANDALONE_ROOT}/target.json")
        .arg("--check")
        .output()
        .expect("JSON overlay with environment paths");
    assert_eq!(json.status.code(), Some(1));
    assert_eq!(
        String::from_utf8_lossy(&json.stdout),
        format!(
            "would-update {} added=1 overwritten=0 replaced=0 removed=0 ownership_changed=0\n",
            json_target.display()
        )
    );

    let toml_source = fixture_root.join("source.toml");
    let toml_target = fixture_root.join("target.toml");
    fs::write(&toml_source, "managed = true\n").expect("TOML source");
    fs::write(&toml_target, "local = true\n").expect("TOML target");
    let toml = sync_configs()
        .env("SYNC_CONFIGS_STANDALONE_ROOT", &fixture_root)
        .arg("toml-overlay")
        .arg("${SYNC_CONFIGS_STANDALONE_ROOT}/source.toml")
        .arg("$SYNC_CONFIGS_STANDALONE_ROOT/target.toml")
        .arg("--dry-run")
        .output()
        .expect("TOML overlay with environment paths");
    assert!(toml.status.success());
    assert_eq!(
        String::from_utf8_lossy(&toml.stdout),
        format!(
            "would-update {} added=1 overwritten=0 removed=0 ownership_changed=0\n",
            toml_target.display()
        )
    );
}

#[test]
fn managed_path_policy_command_supports_human_and_json_output() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source");
    let target = root.path().join("target");
    fs::write(&source, "managed\n").expect("source");

    let human = sync_configs()
        .arg("managed-path-policy")
        .arg(&source)
        .arg(&target)
        .output()
        .expect("classify human");
    assert!(human.status.success());
    assert_eq!(
        String::from_utf8_lossy(&human.stdout),
        format!("absent: create {}\n", target.display())
    );

    let json = sync_configs()
        .args(["--format", "json"])
        .arg("managed-path-policy")
        .arg(&source)
        .arg(&target)
        .args(["--policy", "strict"])
        .output()
        .expect("classify JSON");
    assert!(json.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("JSON");
    assert_eq!(value["state"], "absent");
    assert_eq!(value["action"], "create");
    assert_eq!(value["policy"], "strict");
}

#[test]
fn managed_path_policy_command_expands_every_path_argument() {
    let root = TempDir::new().expect("tempdir");
    let home = root.path().join("home");
    let fixture_root = root.path().join("managed fixtures");
    fs::create_dir_all(&home).expect("home");
    fs::create_dir_all(&fixture_root).expect("fixture root");
    let source = fixture_root.join("source");
    let target = fixture_root.join("target");
    let skeleton = home.join("skeleton");
    fs::write(&source, "managed\n").expect("source");
    fs::write(&target, "stock\n").expect("target");
    fs::write(&skeleton, "stock\n").expect("skeleton");

    let output = sync_configs()
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("SYNC_CONFIGS_STANDALONE_ROOT", &fixture_root)
        .arg("managed-path-policy")
        .arg("${SYNC_CONFIGS_STANDALONE_ROOT}/source")
        .arg("$SYNC_CONFIGS_STANDALONE_ROOT/target")
        .arg("--skeleton")
        .arg("~/skeleton")
        .arg("--format")
        .arg("json")
        .output()
        .expect("classify expanded paths");

    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["source"], source.to_string_lossy().as_ref());
    assert_eq!(value["target"], target.to_string_lossy().as_ref());
    assert_eq!(value["state"], "skeleton_default");
    assert_eq!(value["action"], "replace");
    assert_eq!(value["backup_required"], true);
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

#[test]
fn list_profiles_json_uses_the_resolved_profile_selection() {
    let root = TempDir::new().expect("tempdir");
    let manifest = root.path().join("manifest.yaml");
    let profile_map = root.path().join("profiles.yaml");
    fs::write(
        &manifest,
        "entries:\n  - name: desktop\n    source: ./desktop\n    target: ./desktop-target\n    profiles: [desktop]\n",
    )
    .expect("manifest");
    fs::write(
        &profile_map,
        "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
    )
    .expect("profile map");

    let output = sync_configs()
        .arg("--log-style")
        .arg("off")
        .arg("--list-profiles")
        .arg("--format")
        .arg("json")
        .arg("--host-profile")
        .arg("workstation")
        .arg("--profile")
        .arg("desktop")
        .arg("--profile-map")
        .arg(&profile_map)
        .arg("--config")
        .arg(&manifest)
        .env("HOME", root.path().join("home"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .output()
        .expect("list profiles");

    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["profiles"], serde_json::json!(["linux", "desktop"]));
}

#[cfg(target_os = "linux")]
#[test]
fn ctrl_c_terminalizes_the_run_and_its_owned_hook_group() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source");
    let target = root.path().join("target");
    let ready = root.path().join("hook-ready");
    let hook_pid = root.path().join("hook-pid");
    let manifest = root.path().join("manifest.yaml");
    let runs = root.path().join("runs");
    fs::write(&source, "managed\n").expect("source");
    let script = format!(
        "printf '%s' \"$$\" > '{}'; touch '{}'; trap '' HUP TERM; while :; do /usr/bin/sleep 1; done",
        hook_pid.display(),
        ready.display(),
    );
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: blocking-hook\n    source: {}\n    target: {}\n    pre_script: {script:?}\n",
            source.display(),
            target.display(),
        ),
    )
    .expect("manifest");

    let mut command = sync_configs();
    command
        .process_group(0)
        .args(["--log-style", "events", "--log-root"])
        .arg(&runs)
        .arg("--config")
        .arg(&manifest)
        .env("HOME", root.path().join("home"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn sync-configs");
    let status = interrupt_after_ready(&mut child, &ready);
    assert_eq!(status.code(), Some(130));

    let pid = fs::read_to_string(&hook_pid)
        .expect("hook pid")
        .trim()
        .parse::<u32>()
        .expect("numeric hook pid");
    assert!(
        !std::path::Path::new("/proc").join(pid.to_string()).exists(),
        "owned hook process survived cancellation"
    );
    assert!(!target.exists());

    let run = fs::read_dir(&runs)
        .expect("run root")
        .next()
        .expect("one run")
        .expect("run entry")
        .path();
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("run.json")).expect("run metadata"))
            .expect("parse run metadata");
    assert_eq!(metadata["status"], "interrupted");
    assert_eq!(metadata["exit_code"], 130);
    assert!(metadata["ended_at"].as_str().is_some());
    let events = fs::read_to_string(run.join("events.jsonl")).expect("events");
    assert!(events.contains("run_finished"));
    assert!(events.contains("interrupted"));
}

#[cfg(target_os = "linux")]
#[test]
fn ctrl_c_cancels_a_reconciler_without_running_later_protocol_phases() {
    use std::os::unix::fs::PermissionsExt;

    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.json");
    let reconciler = root.path().join("blocking-reconciler");
    let ready = root.path().join("reconciler-ready");
    let reconciler_pid = root.path().join("reconciler-pid");
    let history = root.path().join("history");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "{}\n").expect("source");
    fs::write(
        &reconciler,
        format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '%s' \"$$\" > '{}'\ntouch '{}'\ntrap '' HUP TERM\nwhile :; do /usr/bin/sleep 1; done\n",
            history.display(),
            reconciler_pid.display(),
            ready.display(),
        ),
    )
    .expect("reconciler");
    fs::set_permissions(&reconciler, fs::Permissions::from_mode(0o700)).expect("reconciler mode");
    fs::write(
        &manifest,
        format!(
            "reconcilers:\n  - name: blocking\n    executable: {}\n    source: {}\n    scope: user\n    privilege: user\n    protocol: dev-tools-reconcile-v1\n",
            reconciler.display(),
            source.display(),
        ),
    )
    .expect("manifest");

    let mut command = sync_configs();
    command
        .process_group(0)
        .args(["--format", "json", "--log-style", "off", "--config"])
        .arg(&manifest)
        .env("HOME", root.path().join("home"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn sync-configs");
    let status = interrupt_after_ready(&mut child, &ready);

    assert_eq!(status.code(), Some(130));
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .expect("piped stdout")
        .read_to_end(&mut stdout)
        .expect("read stdout");
    let value: serde_json::Value = serde_json::from_slice(&stdout).expect("interrupted JSON");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["outcome"], "interrupted");
    assert_eq!(value["exit_code"], 130);
    assert_eq!(value["error_kind"], "interrupted");
    assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 1);
    let pid = fs::read_to_string(&reconciler_pid)
        .expect("reconciler pid")
        .trim()
        .parse::<u32>()
        .expect("numeric reconciler pid");
    assert!(
        !std::path::Path::new("/proc").join(pid.to_string()).exists(),
        "owned reconciler survived cancellation"
    );
    let invocations = fs::read_to_string(&history).expect("history");
    assert!(invocations.starts_with("reconcile plan "));
    assert_eq!(invocations.lines().count(), 1);
}
