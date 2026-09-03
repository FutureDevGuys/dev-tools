#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sync_configs::hooks::{
    EntryConvergence, HookDecision, HookPhase, HookPlan, HookRunMode, HookShell, HookState,
    PostHookDecision,
};
use sync_configs::manifest::{load_manifest, select_entries_for_profiles, LoadOptions, Manifest};
use sync_configs::paths::{PathContext, PathPlatform};
use sync_configs::privilege::PrivilegeSession;
use tempfile::TempDir;

fn path_context(root: &Path) -> PathContext {
    PathContext::new(
        PathPlatform::Posix,
        root.to_path_buf(),
        Some(root.join("home")),
        root.join("temp"),
        BTreeMap::new(),
    )
}

fn load(root: &Path, yaml: &str) -> Manifest {
    let path = root.join("manifest.yaml");
    fs::write(&path, yaml).expect("write manifest");
    load_manifest(
        &path,
        &LoadOptions::default().with_path_context(path_context(root)),
    )
    .expect("load manifest")
}

fn write_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod executable");
}

fn forwarding_shell(root: &Path) -> (HookShell, PathBuf) {
    let executable = root.join("trusted-shell");
    let log = root.join("shell-argv.jsonl");
    write_executable(
        &executable,
        &format!(
            r#"#!/usr/bin/python3
import json
import pathlib
import subprocess
import sys

log = pathlib.Path({log:?})
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[1:]) + "\n")
completed = subprocess.run(["/bin/sh", *sys.argv[1:]], check=False)
raise SystemExit(completed.returncode)
"#,
            log = log.display().to_string(),
        ),
    );
    (
        HookShell::posix(executable).expect("trusted test shell"),
        log,
    )
}

fn forwarding_sudo(root: &Path) -> (PathBuf, PathBuf) {
    let executable = root.join("sudo");
    let log = root.join("sudo-argv.jsonl");
    write_executable(
        &executable,
        &format!(
            r#"#!/usr/bin/python3
import json
import pathlib
import subprocess
import sys

arguments = sys.argv[1:]
log = pathlib.Path({log:?})
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(arguments) + "\n")
if arguments == ["-n", "-v"] or arguments == ["-v"]:
    raise SystemExit(0)
if arguments[:2] == ["-n", "--"]:
    completed = subprocess.run(arguments[2:], check=False)
    raise SystemExit(completed.returncode)
raise SystemExit(64)
"#,
            log = log.display().to_string(),
        ),
    );
    (executable, log)
}

fn read_argv_log(path: &Path) -> Vec<Vec<String>> {
    fs::read_to_string(path)
        .expect("read argv log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("argv JSON"))
        .collect()
}

#[test]
fn hooks_run_in_manifest_order_and_post_hooks_follow_successful_convergence() {
    let root = TempDir::new().expect("temp root");
    let marker = root.path().join("order");
    let manifest = load(
        root.path(),
        &format!(
            r#"
entries:
  - name: first
    source: ./first
    target: ./out-first
    mode: copy
    pre_script: printf 'pre-first\n' >> '{marker}'
    post_script: printf 'post-first\n' >> '{marker}'
  - name: second
    source: ./second
    target: ./out-second
    mode: copy
    pre_script: printf 'pre-second\n' >> '{marker}'
    post_script: printf 'post-second\n' >> '{marker}'
"#,
            marker = marker.display(),
        ),
    );
    let (shell, _) = forwarding_shell(root.path());
    let plan = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare hooks");

    let pre = plan.run_pre_hooks(None).expect("run pre hooks");
    assert_eq!(
        pre.iter().map(|item| item.decision).collect::<Vec<_>>(),
        vec![HookDecision::Proceed, HookDecision::Proceed]
    );
    let post = plan
        .run_post_hooks(None, |_| EntryConvergence::Changed)
        .expect("run post hooks");
    assert_eq!(post.len(), 2);
    assert_eq!(
        fs::read_to_string(marker).expect("order marker"),
        "pre-first\npre-second\npost-first\npost-second\n"
    );
}

#[test]
fn override_manifest_hooks_are_part_of_the_executable_plan() {
    let root = TempDir::new().expect("temp root");
    let marker = root.path().join("override-ran");
    let base = root.path().join("manifest.yaml");
    fs::write(
        &base,
        "entries:\n  - name: base\n    source: ./same\n    target: ./base-target\n    mode: copy\n",
    )
    .expect("base manifest");
    fs::write(
        root.path().join("manifest.override.yaml"),
        format!(
            "entries:\n  - name: override\n    source: ./same\n    target: ./override-target\n    mode: copy\n    pre_script: printf override > '{}'\n",
            marker.display()
        ),
    )
    .expect("override manifest");
    let manifest = load_manifest(
        &base,
        &LoadOptions::default().with_path_context(path_context(root.path())),
    )
    .expect("merged manifest");
    let (shell, _) = forwarding_shell(root.path());
    let plan = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare override hook");

    let results = plan.run_pre_hooks(None).expect("run override hook");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].entry.name, "override");
    assert_eq!(fs::read_to_string(marker).unwrap(), "override");
}

#[test]
fn pre_hook_abort_skip_and_continue_are_distinct_without_stopping_later_hooks() {
    let root = TempDir::new().expect("temp root");
    let marker = root.path().join("attempts");
    let manifest = load(
        root.path(),
        &format!(
            r#"
entries:
  - name: aborting
    source: ./a
    target: ./out-a
    pre_script: printf a >> '{marker}'; printf abort-output; exit 7
    pre_script_on_fail: abort
  - name: skipping
    source: ./b
    target: ./out-b
    pre_script: printf b >> '{marker}'; exit 8
    pre_script_on_fail: skip
  - name: continuing
    source: ./c
    target: ./out-c
    pre_script: printf c >> '{marker}'; exit 9
    pre_script_on_fail: continue
"#,
            marker = marker.display(),
        ),
    );
    let (shell, _) = forwarding_shell(root.path());
    let plan = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare hooks");

    let results = plan.run_pre_hooks(None).expect("run hooks");
    assert_eq!(
        results.iter().map(|item| item.decision).collect::<Vec<_>>(),
        vec![
            HookDecision::Abort,
            HookDecision::Skip,
            HookDecision::Proceed
        ]
    );
    assert_eq!(
        results
            .iter()
            .map(|item| item.execution.as_ref().unwrap().status().state)
            .collect::<Vec<_>>(),
        vec![
            HookState::FailedAbort,
            HookState::FailedSkip,
            HookState::FailedContinue,
        ]
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), "abc");
    assert_eq!(
        results[0].execution.as_ref().unwrap().stdout(),
        b"abort-output"
    );
}

#[test]
fn post_hooks_never_run_for_failed_missing_or_skipped_entries() {
    let root = TempDir::new().expect("temp root");
    let marker = root.path().join("post-ran");
    let mut rows = String::new();
    for name in ["changed", "current", "failed", "missing", "skipped"] {
        rows.push_str(&format!(
            "  - name: {name}\n    source: ./{name}\n    target: ./out-{name}\n    post_script: printf '{name}\\n' >> '{}'\n",
            marker.display()
        ));
    }
    let manifest = load(root.path(), &format!("entries:\n{rows}"));
    let (shell, _) = forwarding_shell(root.path());
    let plan = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare hooks");

    let results = plan
        .run_post_hooks(None, |entry| match entry.name.as_str() {
            "changed" => EntryConvergence::Changed,
            "current" => EntryConvergence::UpToDate,
            "failed" => EntryConvergence::Failed,
            "missing" => EntryConvergence::MissingSource,
            _ => EntryConvergence::Skipped,
        })
        .expect("run eligible post hooks");

    assert_eq!(results.len(), 2);
    assert_eq!(
        results
            .iter()
            .map(|result| result.entry.name.as_str())
            .collect::<Vec<_>>(),
        ["changed", "current"]
    );
    assert_eq!(fs::read_to_string(marker).unwrap(), "changed\ncurrent\n");
}

#[test]
fn one_shared_sudo_authentication_executes_exact_shell_argv_for_both_phases() {
    let root = TempDir::new().expect("temp root");
    let marker = root.path().join("privileged-order");
    let pre = format!("printf pre >> '{}'", marker.display());
    let post = format!("printf post >> '{}'", marker.display());
    let manifest = load(
        root.path(),
        &format!(
            r#"
entries:
  - name: privileged
    source: ./source
    target: ./target
    pre_script: {pre:?}
    pre_script_privilege: sudo
    post_script: {post:?}
    post_script_privilege: sudo
"#,
        ),
    );
    let (shell, _) = forwarding_shell(root.path());
    let shell_path = shell.executable().to_path_buf();
    let (sudo, sudo_log) = forwarding_sudo(root.path());
    let mut session = PrivilegeSession::new(sudo).expect("sudo session");
    let plan = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare hooks");

    assert!(plan.requires_privilege());
    plan.authenticate(&mut session).expect("authenticate once");
    plan.authenticate(&mut session)
        .expect("reuse authentication");
    plan.run_pre_hooks(Some(&session)).expect("privileged pre");
    plan.run_post_hooks(Some(&session), |_| EntryConvergence::Changed)
        .expect("privileged post");

    assert_eq!(fs::read_to_string(marker).unwrap(), "prepost");
    assert_eq!(
        read_argv_log(&sudo_log),
        vec![
            vec!["-n".to_owned(), "-v".to_owned()],
            vec![
                "-n".into(),
                "--".into(),
                shell_path.display().to_string(),
                "-c".into(),
                pre,
            ],
            vec![
                "-n".into(),
                "--".into(),
                shell_path.display().to_string(),
                "-c".into(),
                post,
            ],
        ]
    );
}

#[test]
fn dry_run_validation_disabled_profiles_and_no_hook_plans_execute_nothing() {
    let root = TempDir::new().expect("temp root");
    let marker = root.path().join("must-not-run");
    let command = format!("printf bad > '{}'", marker.display());
    let manifest = load(
        root.path(),
        &format!(
            r#"
entries:
  - name: enabled
    profiles: [enabled]
    source: ./enabled
    target: ./out-enabled
    pre_script: {command:?}
    pre_script_privilege: sudo
  - name: disabled
    profiles: [disabled]
    source: ./disabled
    target: ./out-disabled
    pre_script: {command:?}
    pre_script_privilege: sudo
"#,
        ),
    );
    let enabled = select_entries_for_profiles(&manifest.entries, &["enabled".to_owned()]);
    assert_eq!(enabled.len(), 1);
    let (sudo, sudo_log) = forwarding_sudo(root.path());
    let mut session = PrivilegeSession::new(sudo).expect("sudo session");

    for mode in [HookRunMode::DryRun, HookRunMode::Validate] {
        let (shell, shell_log) = forwarding_shell(root.path());
        let plan = HookPlan::prepare(enabled.iter().copied(), root.path(), shell, mode)
            .expect("prepare non-applying hooks");
        assert!(!plan.requires_privilege());
        plan.authenticate(&mut session)
            .expect("no-op authentication");
        let pre = plan.run_pre_hooks(None).expect("non-applying pre phase");
        if mode == HookRunMode::DryRun {
            assert_eq!(
                pre[0].execution.as_ref().unwrap().status().state,
                HookState::Planned
            );
        } else {
            assert!(pre[0].execution.is_none());
        }
        assert!(!shell_log.exists());
    }

    let (shell, shell_log) = forwarding_shell(root.path());
    let no_hooks = load(
        root.path(),
        "entries:\n  - name: plain\n    source: ./plain\n    target: ./out-plain\n",
    );
    let plan = HookPlan::prepare(
        no_hooks.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare no-hook plan");
    assert!(!plan.requires_privilege());
    assert!(plan.run_pre_hooks(None).expect("no-hook pre phase")[0]
        .execution
        .is_none());
    assert!(!shell_log.exists());
    assert!(!sudo_log.exists());
    assert!(!marker.exists());
}

#[test]
fn every_selected_privileged_hook_is_validated_before_authentication() {
    let root = TempDir::new().expect("temp root");
    let mut manifest = load(
        root.path(),
        r#"
entries:
  - name: first
    source: ./first
    target: ./out-first
    pre_script: "printf safe"
    pre_script_privilege: sudo
  - name: invalid-later-hook
    source: ./second
    target: ./out-second
    post_script: "printf initially-valid"
    post_script_privilege: sudo
"#,
    );
    manifest.entries[1].post_script = Some("invalid\0script".to_owned());
    let (shell, _) = forwarding_shell(root.path());
    let (sudo, sudo_log) = forwarding_sudo(root.path());
    let _session = PrivilegeSession::new(sudo).expect("sudo session");

    let error = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect_err("NUL-bearing hook must fail preflight");
    assert!(error.to_string().contains("invalid hook command"));
    assert!(
        !sudo_log.exists(),
        "validation must precede sudo authentication"
    );
}

#[test]
fn captured_values_are_explicit_and_structured_status_is_value_free() {
    let root = TempDir::new().expect("temp root");
    let secret = "TOP_SECRET_HOOK_VALUE";
    let command = format!("printf '{secret}'; printf 'PRIVATE_ERR' >&2");
    let manifest = load(
        root.path(),
        &format!(
            "entries:\n  - name: secret-output\n    source: ./source\n    target: ./target\n    pre_script: {command:?}\n"
        ),
    );
    let (shell, argv_log) = forwarding_shell(root.path());
    let plan = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare hook");

    let result = plan.run_pre_hooks(None).expect("run hook");
    let execution = result[0].execution.as_ref().expect("hook execution");
    assert_eq!(execution.stdout(), secret.as_bytes());
    assert_eq!(execution.stderr(), b"PRIVATE_ERR");
    let status = serde_json::to_string(execution.status()).expect("status JSON");
    let progress = serde_json::to_string(&result[0].progress.unwrap()).expect("progress JSON");
    let debug = format!("{:?}", result[0]);
    for structured in [&status, &progress, &debug] {
        assert!(!structured.contains(secret));
        assert!(!structured.contains("PRIVATE_ERR"));
        assert!(!structured.contains(&command));
        assert!(!structured.contains("secret-output"));
    }
    assert_eq!(
        read_argv_log(&argv_log),
        vec![vec!["-c".to_owned(), command]]
    );
}

#[test]
fn post_failure_policy_changes_outcome_without_hiding_captured_output() {
    let root = TempDir::new().expect("temp root");
    let manifest = load(
        root.path(),
        r#"
entries:
  - name: aborting
    source: ./a
    target: ./out-a
    post_script: "printf abort; exit 2"
    post_script_on_fail: abort
  - name: continuing
    source: ./b
    target: ./out-b
    post_script: "printf continue; exit 3"
    post_script_on_fail: continue
  - name: skipping-policy
    source: ./c
    target: ./out-c
    post_script: "printf skip; exit 4"
    post_script_on_fail: skip
"#,
    );
    let (shell, _) = forwarding_shell(root.path());
    let plan = HookPlan::prepare(
        manifest.entries.iter(),
        root.path(),
        shell,
        HookRunMode::Apply,
    )
    .expect("prepare hooks");

    let results = plan
        .run_post_hooks(None, |_| EntryConvergence::UpToDate)
        .expect("run post hooks");
    assert_eq!(
        results.iter().map(|item| item.decision).collect::<Vec<_>>(),
        [
            PostHookDecision::Abort,
            PostHookDecision::Complete,
            PostHookDecision::Complete,
        ]
    );
    assert_eq!(results[0].execution.stdout(), b"abort");
    assert_eq!(results[1].execution.stdout(), b"continue");
    assert_eq!(results[2].execution.stdout(), b"skip");
}

#[test]
fn hook_phase_and_progress_names_are_stable_public_tokens() {
    assert_eq!(
        serde_json::to_string(&HookPhase::Pre).unwrap(),
        "\"pre_script\""
    );
    assert_eq!(
        serde_json::to_string(&HookPhase::Post).unwrap(),
        "\"post_script\""
    );
    assert_eq!(
        HookShell::current().unwrap().executable(),
        Path::new("/bin/sh")
    );
}
