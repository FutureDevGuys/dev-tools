use std::fs;
use std::path::Path;
use std::process::Command;
#[cfg(unix)]
use std::process::Stdio;
use std::time::Duration;

use tempfile::TempDir;

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sync-configs"));
    command
        .arg("--log-style")
        .arg("off")
        .env("HOME", root.join("home"))
        .env("XDG_STATE_HOME", root.join("state"));
    command
}

#[test]
#[cfg(any(debug_assertions, feature = "test-support"))]
fn reconciler_timeout_matches_the_python_013_contract() {
    assert_eq!(
        sync_configs::engine::reconciler_timeout_for_test(),
        Duration::from_secs(120),
    );
}

#[test]
fn relative_xdg_roots_fall_back_to_the_absolute_home_conventions() {
    let root = TempDir::new().expect("tempdir");
    let home = root.path().join("home");
    let config = home.join(".config/sync-configs/manifest.yaml");
    let source = root.path().join("source.txt");
    let target = root.path().join("target.txt");
    fs::create_dir_all(config.parent().expect("config parent")).expect("create config parent");
    fs::write(&source, "desired\n").expect("source");
    fs::write(
        &config,
        format!(
            "entries:\n  - name: example\n    source: {}\n    target: {}\n    mode: copy\n",
            source.display(),
            target.display()
        ),
    )
    .expect("manifest");

    let output = command(root.path())
        .current_dir(root.path())
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", "relative-config")
        .env("XDG_STATE_HOME", "relative-state")
        .output()
        .expect("convergence");
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(&target).expect("target"), "desired\n");
    assert!(!root.path().join("relative-config").exists());
    assert!(!root.path().join("relative-state").exists());
    assert!(home.join(".local/state/sync-configs").exists());
}

#[test]
fn regular_file_copy_is_idempotent() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("nested/target.txt");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").unwrap();
    fs::write(
        &manifest,
        format!(
            "default_mode: copy\nentries:\n  - name: example\n    source: {}\n    target: {}\n",
            source.display(),
            target.display()
        ),
    )
    .unwrap();

    let first = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("first convergence");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "desired\n");
    assert!(String::from_utf8_lossy(&first.stdout).contains("1 updated, 0 up-to-date"));

    let before = fs::metadata(&target).unwrap().modified().unwrap();
    let second = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("second convergence");
    assert!(second.status.success());
    assert_eq!(fs::metadata(&target).unwrap().modified().unwrap(), before);
    assert!(String::from_utf8_lossy(&second.stdout).contains("0 updated, 1 up-to-date"));
}

#[test]
fn structured_dry_run_executes_no_hook_or_write() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("target.txt");
    let hook_marker = root.path().join("hook-marker");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").unwrap();
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: example\n    source: {}\n    target: {}\n    mode: copy\n    profiles: [desktop]\n    pre_script: '/usr/bin/touch {}'\n    post_script: '/usr/bin/touch {}'\n",
            source.display(),
            target.display(),
            hook_marker.display(),
            hook_marker.display()
        ),
    )
    .unwrap();

    let output = command(root.path())
        .args([
            "--profile",
            "desktop",
            "--dry-run",
            "--format",
            "json",
            "--config",
        ])
        .arg(&manifest)
        .output()
        .expect("dry run");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("one JSON value");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["outcome"], "completed");
    assert_eq!(value["dry_run"], true);
    assert_eq!(value["profiles"], serde_json::json!(["desktop"]));
    assert!(!target.exists());
    assert!(!hook_marker.exists());
}

#[test]
fn profile_map_order_is_preserved_and_deduplicated() {
    let root = TempDir::new().expect("tempdir");
    let manifest = root.path().join("manifest.yaml");
    let profile_map = root.path().join("profiles.yaml");
    fs::write(&manifest, "entries: []\n").unwrap();
    fs::write(
        &profile_map,
        "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
    )
    .unwrap();
    let output = command(root.path())
        .args([
            "--validate",
            "--format",
            "json",
            "--host-profile",
            "workstation",
            "--profile",
            "desktop",
            "--config",
        ])
        .arg(&manifest)
        .arg("--profile-map")
        .arg(&profile_map)
        .output()
        .expect("validate");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["profiles"], serde_json::json!(["linux", "desktop"]));
}

#[test]
fn validation_checks_state_preconditions_and_expanded_target_conflicts_without_writes() {
    let root = TempDir::new().expect("tempdir");
    let first_source = root.path().join("first.txt");
    let second_source = root.path().join("second.txt");
    let target = root.path().join("target.txt");
    let marker = root.path().join("hook-marker");
    let state = root.path().join("state.json");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&first_source, "first\n").expect("first source");
    fs::write(&second_source, "second\n").expect("second source");
    fs::write(
        &manifest,
        format!(
            "state_preconditions:\n  - type: json_fields\n    path: {}\n    fields: {{ready: true}}\n    remediation: initialize required state\nentries:\n  - name: first\n    source: {}\n    target: {}\n    mode: copy\n    pre_script: '/usr/bin/touch {}'\n  - name: second\n    source: {}\n    target: {}\n    mode: copy\n",
            state.display(),
            first_source.display(),
            target.display(),
            marker.display(),
            second_source.display(),
            target.display(),
        ),
    )
    .expect("manifest");

    let precondition = command(root.path())
        .args(["--validate", "--config"])
        .arg(&manifest)
        .output()
        .expect("validate precondition");
    assert_eq!(precondition.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&precondition.stderr).contains("initialize required state"));
    assert!(!target.exists());
    assert!(!marker.exists());

    fs::write(&state, "{\"ready\":true}\n").expect("state");
    let duplicate = command(root.path())
        .args(["--validate", "--config"])
        .arg(&manifest)
        .output()
        .expect("validate duplicate target");
    assert_eq!(duplicate.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&duplicate.stderr).contains("target"),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&duplicate.stdout),
        String::from_utf8_lossy(&duplicate.stderr),
    );
    assert!(!target.exists());
    assert!(!marker.exists());
}

#[test]
fn convergence_defers_potential_target_conflicts_until_after_pre_hooks() {
    let root = TempDir::new().expect("tempdir");
    let first_source = root.path().join("first.txt");
    let second_source = root.path().join("second.txt");
    let target = root.path().join("target.txt");
    let marker = root.path().join("hook-marker");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&first_source, "first\n").expect("first source");
    fs::write(&second_source, "second\n").expect("second source");
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: first\n    source: {}\n    target: {}\n    mode: copy\n    pre_script: '/usr/bin/touch {}'\n  - name: second\n    source: {}\n    target: {}\n    mode: copy\n",
            first_source.display(),
            target.display(),
            marker.display(),
            second_source.display(),
            target.display(),
        ),
    )
    .expect("manifest");

    let output = command(root.path())
        .args(["--config"])
        .arg(&manifest)
        .output()
        .expect("convergence");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("target"));
    assert!(
        marker.exists(),
        "a potentially removable target conflict bypassed its pre-hook"
    );
    assert!(!target.exists());
}

#[test]
fn failed_skip_pre_hook_removes_its_entry_before_target_deduplication() {
    let root = TempDir::new().expect("tempdir");
    let first_source = root.path().join("first.txt");
    let second_source = root.path().join("second.txt");
    let target = root.path().join("target.txt");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&first_source, "first\n").expect("first source");
    fs::write(&second_source, "second\n").expect("second source");
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: skipped\n    source: {}\n    target: {}\n    mode: copy\n    pre_script: /usr/bin/false\n    pre_script_on_fail: skip\n  - name: active\n    source: {}\n    target: {}\n    mode: copy\n",
            first_source.display(),
            target.display(),
            second_source.display(),
            target.display(),
        ),
    )
    .expect("manifest");

    let output = command(root.path())
        .args(["--format", "json", "--config"])
        .arg(&manifest)
        .output()
        .expect("convergence");

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON convergence report");
    assert_eq!(report["outcome"], "completed");
    assert_eq!(
        fs::read_to_string(&target).expect("active target"),
        "second\n"
    );
}

#[test]
fn convergence_allows_pre_hooks_to_create_filtered_recursive_sources() {
    let root = TempDir::new().expect("tempdir");
    let source_dir = root.path().join("generated-tree");
    let target_dir = root.path().join("target");
    let manifest = root.path().join("manifest.yaml");
    let hook = root.path().join("prepare.sh");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nset -eu\nmkdir -p '{}'\nprintf 'keep\\n' > '{}/keep.txt'\nprintf 'drop\\n' > '{}/drop.log'\n",
            source_dir.display(),
            source_dir.display(),
            source_dir.display()
        ),
    )
    .expect("hook");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&hook).expect("hook metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&hook, permissions).expect("hook permissions");
    }
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: generated\n    source: {}\n    target: {}\n    mode: copy\n    directory_strategy: recursive\n    include: ['*.txt']\n    discover_ignore_files: false\n    use_default_filters: false\n    pre_script: /usr/bin/sh {}\n",
            source_dir.display(),
            target_dir.display(),
            hook.display()
        ),
    )
    .expect("manifest");

    let output = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("convergence");

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(target_dir.join("keep.txt")).expect("kept target"),
        "keep\n"
    );
    assert!(!target_dir.join("drop.log").exists());
}

#[cfg(unix)]
#[test]
fn validation_rejects_a_linked_source_before_hooks_or_writes() {
    use std::os::unix::fs::symlink;

    let root = TempDir::new().expect("tempdir");
    let real_source = root.path().join("real.txt");
    let linked_source = root.path().join("linked.txt");
    let target = root.path().join("target.txt");
    let marker = root.path().join("hook-marker");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&real_source, "desired\n").expect("source");
    symlink(&real_source, &linked_source).expect("source link");
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: linked-source\n    source: {}\n    target: {}\n    mode: copy\n    pre_script: '/usr/bin/touch {}'\n",
            linked_source.display(),
            target.display(),
            marker.display(),
        ),
    )
    .expect("manifest");

    let output = command(root.path())
        .args(["--validate", "--config"])
        .arg(&manifest)
        .output()
        .expect("validate linked source");
    assert_eq!(output.status.code(), Some(1));
    assert!(!target.exists());
    assert!(!marker.exists());
}

#[test]
fn list_profiles_json_reports_the_resolved_profile_selection() {
    let root = TempDir::new().expect("tempdir");
    let manifest = root.path().join("manifest.yaml");
    let profile_map = root.path().join("profiles.yaml");
    fs::write(
        &manifest,
        "entries:\n  - name: desktop\n    source: ./desktop\n    target: ./desktop-target\n    profiles: [desktop]\nreconcilers:\n  - name: linux-owner\n    executable: /bin/true\n    source: ./desktop\n    scope: user\n    privilege: user\n    protocol: dev-tools-reconcile-v1\n    profiles: [linux]\n",
    )
    .unwrap();
    fs::write(
        &profile_map,
        "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
    )
    .unwrap();

    let output = command(root.path())
        .args([
            "--list-profiles",
            "--format",
            "json",
            "--host-profile",
            "workstation",
            "--profile",
            "desktop",
            "--config",
        ])
        .arg(&manifest)
        .arg("--profile-map")
        .arg(&profile_map)
        .output()
        .expect("list profiles");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["profiles"], serde_json::json!(["linux", "desktop"]));
    assert_eq!(
        value["available_profiles"],
        serde_json::json!(["desktop", "linux"])
    );
}

#[test]
fn init_json_reports_the_resolved_profile_selection() {
    let root = TempDir::new().expect("tempdir");
    let manifest = root.path().join("manifest.yaml");
    let profile_map = root.path().join("profiles.yaml");
    fs::write(
        &profile_map,
        "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
    )
    .unwrap();

    let output = command(root.path())
        .args([
            "--init",
            "--format",
            "json",
            "--host-profile",
            "workstation",
            "--profile",
            "desktop",
            "--config",
        ])
        .arg(&manifest)
        .arg("--profile-map")
        .arg(&profile_map)
        .output()
        .expect("init");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["action"], "initialized");
    assert_eq!(value["profiles"], serde_json::json!(["linux", "desktop"]));
    assert!(manifest.is_file());
}

#[test]
fn failed_state_precondition_is_read_only_and_value_conscious() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("target.txt");
    let state = root.path().join("state.json");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").unwrap();
    fs::write(&state, "{}\n").unwrap();
    fs::write(
        &manifest,
        format!(
            "state_preconditions:\n  - type: json_fields\n    path: {}\n    fields:\n      enabled: null\n    remediation: repair state first\nentries:\n  - name: example\n    source: {}\n    target: {}\n    mode: copy\n",
            state.display(),
            source.display(),
            target.display()
        ),
    )
    .unwrap();
    let output = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("precondition");
    assert_eq!(output.status.code(), Some(1));
    assert!(!target.exists());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("repair state first"));
    assert!(!stderr.contains("desired"));
}

#[test]
fn failed_json_output_keeps_the_resolved_profile_selection() {
    let root = TempDir::new().expect("tempdir");
    let manifest = root.path().join("manifest.yaml");
    let profile_map = root.path().join("profiles.yaml");
    fs::write(
        &manifest,
        "state_preconditions:\n  - type: json_fields\n    path: ./missing.json\n    fields: {enabled: true}\n    remediation: repair state first\nentries: []\n",
    )
    .unwrap();
    fs::write(
        &profile_map,
        "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
    )
    .unwrap();

    let output = command(root.path())
        .args([
            "--format",
            "json",
            "--host-profile",
            "workstation",
            "--profile",
            "desktop",
            "--config",
        ])
        .arg(&manifest)
        .arg("--profile-map")
        .arg(&profile_map)
        .output()
        .expect("failure JSON");

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(value["outcome"], "failed");
    assert_eq!(value["profiles"], serde_json::json!(["linux", "desktop"]));
}

#[cfg(unix)]
#[test]
fn dry_run_sudo_reconciler_stays_no_auth_and_reports_structured_deferral() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("desired.toml");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired = true\n").expect("source");
    fs::write(
        &manifest,
        format!(
            "reconcilers:\n  - name: privileged\n    executable: /bin/true\n    source: {}\n    scope: user\n    privilege: sudo\n    protocol: dev-tools-reconcile-v1\n",
            source.display(),
        ),
    )
    .expect("manifest");

    let output = command(root.path())
        .args(["--dry-run", "--format", "json", "--config"])
        .arg(&manifest)
        .output()
        .expect("dry run");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(
        value["reconcilers"][0]["schema"],
        "dev-tools-reconcile-result-v1"
    );
    assert_eq!(value["reconcilers"][0]["deferred"], true);
    assert_eq!(value["reconcilers"][0]["next_action"], "privilege_required");
}

#[cfg(unix)]
#[test]
fn concurrent_mutating_runs_never_overlap() {
    let root = TempDir::new().expect("tempdir");
    let source = root.path().join("source.txt");
    let target = root.path().join("target.txt");
    let entered = root.path().join("entered");
    let release = root.path().join("release");
    let manifest = root.path().join("manifest.yaml");
    fs::write(&source, "desired\n").expect("source");
    fs::write(
        &manifest,
        format!(
            "entries:\n  - name: serialized\n    source: {}\n    target: {}\n    mode: copy\n    pre_script: 'printf ready > {}; while [ ! -e {} ]; do :; done'\n",
            source.display(),
            target.display(),
            entered.display(),
            release.display(),
        ),
    )
    .expect("manifest");

    let mut first = command(root.path());
    first
        .arg("--config")
        .arg(&manifest)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let first = first.spawn().expect("first convergence");
    for _ in 0..200 {
        if entered.is_file() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if !entered.is_file() {
        let _ = fs::write(&release, "continue\n");
        let _ = first.wait_with_output();
        panic!("first run never entered its hook");
    }

    let second = command(root.path())
        .arg("--config")
        .arg(&manifest)
        .output()
        .expect("overlapping convergence");
    fs::write(&release, "continue\n").expect("release first run");
    let first = first.wait_with_output().expect("first result");

    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(second.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&second.stderr)
        .contains("another sync-configs convergence is already running"));
    assert_eq!(fs::read_to_string(&target).expect("target"), "desired\n");
}
