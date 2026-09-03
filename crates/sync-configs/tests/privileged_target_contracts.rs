#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use sync_configs::manifest::{
    CommentedTargetPolicy, DirectoryStrategy, Entry, FileMode, Mode, PermissionPolicy, Privilege,
    ScriptFailurePolicy,
};
use sync_configs::privilege::PrivilegeSession;
use sync_configs::privileged_target::{
    apply_privileged_plans, plan_selected_privileged_entries, IdentityResolver, PrivilegedCommands,
    PrivilegedTargetOutcome,
};
use tempfile::TempDir;

#[derive(Clone, Debug)]
struct FixedIdentities {
    users: BTreeMap<String, u32>,
    groups: BTreeMap<String, u32>,
}

impl FixedIdentities {
    fn current(root: &Path) -> Self {
        let metadata = fs::metadata(root).expect("temporary root metadata");
        Self {
            users: BTreeMap::from([("operator".to_owned(), metadata.uid())]),
            groups: BTreeMap::from([("operators".to_owned(), metadata.gid())]),
        }
    }
}

impl IdentityResolver for FixedIdentities {
    fn user_id(&self, name: &str) -> Result<Option<u32>, String> {
        Ok(self.users.get(name).copied())
    }

    fn group_id(&self, name: &str) -> Result<Option<u32>, String> {
        Ok(self.groups.get(name).copied())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct FakeBehavior<'a> {
    drift_source_on_auth: Option<&'a Path>,
    drift_target_after_stage: Option<&'a Path>,
    corrupt_target_after_move: Option<&'a Path>,
    fail_stage_install: bool,
}

fn shell_literal(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}

fn fake_sudo(root: &Path, behavior: FakeBehavior<'_>) -> PathBuf {
    let sudo = root.join("sudo");
    let log = root.join("sudo.log");
    let state = root.join("sudo.state");
    let auth_drift = behavior.drift_source_on_auth.map_or_else(
        || ":".to_owned(),
        |path| format!("printf 'drifted-on-auth\\n' > {}", shell_literal(path)),
    );
    let stage_drift = behavior.drift_target_after_stage.map_or_else(
        || ":".to_owned(),
        |path| format!("printf 'drifted-before-move\\n' > {}", shell_literal(path)),
    );
    let move_corruption = behavior.corrupt_target_after_move.map_or_else(
        || ":".to_owned(),
        |path| format!("printf 'corrupt-after-move\\n' > {}", shell_literal(path)),
    );
    let stage_failure = if behavior.fail_stage_install {
        "if [ \"$command_name\" = install ] && [ \"${2:-}\" != -d ]; then exit 42; fi"
    } else {
        ":"
    };
    let script = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> {log}
if [ "${{1:-}} ${{2:-}}" = '-n -v' ]; then
  [ -f {state} ]
  exit
fi
if [ "${{1:-}}" = '-v' ]; then
  : > {state}
  {auth_drift}
  exit 0
fi
if [ "${{1:-}} ${{2:-}}" = '-n --' ]; then
  shift 2
  command_name=${{1##*/}}
  {stage_failure}
  "$@"
  status=$?
  if [ "$status" = 0 ] && [ "$command_name" = install ] && [ "${{2:-}}" != -d ]; then
    {stage_drift}
  fi
  if [ "$status" = 0 ] && [ "$command_name" = mv ]; then
    {move_corruption}
  fi
  exit "$status"
fi
exit 64
"#,
        log = shell_literal(&log),
        state = shell_literal(&state),
    );
    fs::write(&sudo, script).expect("write fake sudo");
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).expect("chmod fake sudo");
    sudo
}

fn system_command(name: &str) -> PathBuf {
    ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .into_iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("missing test command {name}"))
}

fn commands() -> PrivilegedCommands {
    PrivilegedCommands::new(
        system_command("chmod"),
        system_command("install"),
        system_command("mv"),
        system_command("rm"),
    )
    .expect("validated system commands")
}

fn entry(source: &Path, target: &Path) -> Entry {
    let parent_mode = target
        .parent()
        .and_then(|parent| fs::metadata(parent).ok())
        .map_or(0o700, |metadata| metadata.mode() & 0o7777);
    Entry {
        name: target
            .file_name()
            .expect("target filename")
            .to_string_lossy()
            .into_owned(),
        source: source.to_path_buf(),
        target: target.to_path_buf(),
        mode: Mode::Copy,
        directory_strategy: DirectoryStrategy::AsDirectory,
        profiles: Vec::new(),
        include: Vec::new(),
        exclude: Vec::new(),
        ignore_files: Vec::new(),
        discover_ignore_files: true,
        use_default_filters: true,
        group: None,
        subgroup: None,
        permissions: Some(PermissionPolicy {
            file: Some(FileMode::new(0o600).expect("file mode")),
            dir: None,
            recursive: false,
        }),
        source_permissions: None,
        pre_script: None,
        pre_script_on_fail: ScriptFailurePolicy::Abort,
        pre_script_privilege: Privilege::User,
        post_script: None,
        post_script_on_fail: ScriptFailurePolicy::Continue,
        post_script_privilege: Privilege::User,
        target_privilege: Privilege::Sudo,
        target_owner: Some("operator".to_owned()),
        target_group: Some("operators".to_owned()),
        target_parent_mode: Some(FileMode::new(parent_mode).expect("parent mode")),
        reconcile_existing: true,
        reconcile_removed_keys: false,
        managed_overlay_id: None,
        commented_target_policy: CommentedTargetPolicy::Respect,
        exclusive_sibling_groups: Vec::new(),
    }
}

fn history(root: &Path) -> Vec<Vec<String>> {
    let path = root.join("sudo.log");
    if !path.exists() {
        return Vec::new();
    }
    fs::read_to_string(path)
        .expect("read sudo history")
        .lines()
        .map(|line| line.split_whitespace().map(ToOwned::to_owned).collect())
        .collect()
}

fn invoked_commands(history: &[Vec<String>]) -> Vec<String> {
    history
        .iter()
        .filter(|argv| {
            argv.first().is_some_and(|arg| arg == "-n")
                && argv.get(1).is_some_and(|arg| arg == "--")
        })
        .map(|argv| {
            Path::new(&argv[2])
                .file_name()
                .expect("command filename")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

fn temporary_candidates(target: &Path) -> Vec<PathBuf> {
    let prefix = format!(
        ".{}.sync-configs-",
        target
            .file_name()
            .expect("target filename")
            .to_string_lossy()
    );
    fs::read_dir(target.parent().expect("target parent"))
        .expect("read target parent")
        .filter_map(Result::ok)
        .map(|row| row.path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
        })
        .collect()
}

#[test]
fn plans_every_selected_entry_before_authentication() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let first_source = root.path().join("first.conf");
    let real_source = root.path().join("real.conf");
    let unsafe_source = root.path().join("unsafe.conf");
    fs::write(&first_source, "first\n").expect("first source");
    fs::write(&real_source, "second\n").expect("real source");
    std::os::unix::fs::symlink(&real_source, &unsafe_source).expect("source symlink");
    let entries = vec![
        entry(&first_source, &root.path().join("first-target.conf")),
        entry(&unsafe_source, &root.path().join("second-target.conf")),
    ];
    let sudo = fake_sudo(root.path(), FakeBehavior::default());
    let _session = PrivilegeSession::new(sudo).expect("unused session");

    let error = plan_selected_privileged_entries(&entries, false, &identities)
        .expect_err("unsafe late source must reject the whole batch");

    assert!(error.to_string().contains("must not be a symbolic link"));
    assert!(history(root.path()).is_empty());
    assert!(!entries[0].target.exists());
}

#[test]
fn first_pass_is_atomic_and_second_pass_invokes_no_sudo() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let target = root.path().join("target.conf");
    fs::write(&source, "managed\n").expect("source");
    let selected = vec![entry(&source, &target)];
    let sudo = fake_sudo(root.path(), FakeBehavior::default());
    let mut session = PrivilegeSession::new(sudo).expect("session");
    let plans = plan_selected_privileged_entries(&selected, false, &identities).expect("plan");

    let outcomes = apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect("first apply");

    assert_eq!(outcomes, vec![PrivilegedTargetOutcome::Changed]);
    assert_eq!(fs::read_to_string(&target).expect("target"), "managed\n");
    assert_eq!(
        fs::metadata(&target).expect("target metadata").mode() & 0o7777,
        0o600
    );
    let target_metadata = fs::metadata(&target).expect("target metadata");
    let invoking_metadata = fs::metadata(root.path()).expect("invoking identity");
    assert_eq!(
        (target_metadata.uid(), target_metadata.gid()),
        (invoking_metadata.uid(), invoking_metadata.gid())
    );
    let first_history = history(root.path());
    assert_eq!(first_history[0], ["-n", "-v"]);
    assert_eq!(first_history[1], ["-v"]);
    assert_eq!(invoked_commands(&first_history), ["install", "mv"]);
    let temporary = first_history[2].last().expect("temporary target");
    assert!(Path::new(temporary)
        .file_name()
        .expect("temporary filename")
        .to_string_lossy()
        .starts_with(".target.conf.sync-configs-"));
    assert_eq!(
        first_history[2],
        vec![
            "-n".to_owned(),
            "--".to_owned(),
            system_command("install").display().to_string(),
            "-o".to_owned(),
            invoking_metadata.uid().to_string(),
            "-g".to_owned(),
            invoking_metadata.gid().to_string(),
            "-m".to_owned(),
            "0600".to_owned(),
            "--".to_owned(),
            source.display().to_string(),
            temporary.clone(),
        ]
    );
    assert_eq!(
        first_history[3],
        vec![
            "-n".to_owned(),
            "--".to_owned(),
            system_command("mv").display().to_string(),
            "-f".to_owned(),
            "--".to_owned(),
            temporary.clone(),
            target.display().to_string(),
        ]
    );

    let second = plan_selected_privileged_entries(&selected, false, &identities).expect("replan");
    let outcomes = apply_privileged_plans(&second, false, &identities, None, None)
        .expect("no-op apply without a session");

    assert_eq!(outcomes, vec![PrivilegedTargetOutcome::UpToDate]);
    assert_eq!(history(root.path()), first_history);
}

#[test]
fn dry_run_reports_change_without_authentication_or_mutation() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let target = root.path().join("target.conf");
    fs::write(&source, "managed\n").expect("source");
    let plans = plan_selected_privileged_entries(&[entry(&source, &target)], false, &identities)
        .expect("plan");

    let outcomes = apply_privileged_plans(&plans, true, &identities, None, None)
        .expect("dry run needs no session");

    assert_eq!(outcomes, vec![PrivilegedTargetOutcome::WouldChange]);
    assert!(!target.exists());
    assert!(history(root.path()).is_empty());
}

#[test]
fn authentication_drift_is_detected_before_any_privileged_mutation() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let target = root.path().join("target.conf");
    fs::write(&source, "managed\n").expect("source");
    let plans = plan_selected_privileged_entries(&[entry(&source, &target)], false, &identities)
        .expect("plan");
    let sudo = fake_sudo(
        root.path(),
        FakeBehavior {
            drift_source_on_auth: Some(&source),
            ..FakeBehavior::default()
        },
    );
    let mut session = PrivilegeSession::new(sudo).expect("session");

    let error = apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect_err("drift must fail");

    assert!(error.to_string().contains("drifted between plan and apply"));
    assert_eq!(
        history(root.path()),
        [
            vec!["-n".to_owned(), "-v".to_owned()],
            vec!["-v".to_owned()]
        ]
    );
    assert!(!target.exists());
}

#[test]
fn existing_parent_mode_is_reconciled_without_reowning_or_replacing_current_file() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let parent = root.path().join("etc");
    fs::create_dir(&parent).expect("parent");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).expect("initial mode");
    let source = root.path().join("source.conf");
    let target = parent.join("target.conf");
    fs::write(&source, "managed\n").expect("source");
    fs::write(&target, "managed\n").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    let parent_before = fs::metadata(&parent).expect("parent metadata");
    let target_inode = fs::metadata(&target).expect("target metadata").ino();
    let mut selected_entry = entry(&source, &target);
    selected_entry.target_parent_mode = Some(FileMode::new(0o700).expect("parent mode"));
    let selected = vec![selected_entry];
    let plans = plan_selected_privileged_entries(&selected, false, &identities).expect("plan");
    let sudo = fake_sudo(root.path(), FakeBehavior::default());
    let mut session = PrivilegeSession::new(sudo).expect("session");

    apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect("parent repair");

    let parent_after = fs::metadata(&parent).expect("parent metadata");
    assert_eq!(parent_after.mode() & 0o7777, 0o700);
    assert_eq!(
        (parent_after.uid(), parent_after.gid()),
        (parent_before.uid(), parent_before.gid())
    );
    assert_eq!(
        fs::metadata(&target).expect("target metadata").ino(),
        target_inode
    );
    let calls = history(root.path());
    assert_eq!(invoked_commands(&calls), ["chmod"]);
    assert_eq!(
        calls[2],
        vec![
            "-n".to_owned(),
            "--".to_owned(),
            system_command("chmod").display().to_string(),
            "0700".to_owned(),
            "--".to_owned(),
            parent.display().to_string(),
        ]
    );
}

#[test]
fn missing_parent_is_materialized_with_declared_identity_and_mode() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let parent = root.path().join("fresh").join("etc").join("codex");
    let target = parent.join("config.toml");
    fs::write(&source, "managed\n").expect("source");
    let selected = vec![entry(&source, &target)];
    let plans = plan_selected_privileged_entries(&selected, false, &identities).expect("plan");
    let sudo = fake_sudo(root.path(), FakeBehavior::default());
    let mut session = PrivilegeSession::new(sudo).expect("session");

    apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect("fresh parent install");

    let parent_metadata = fs::metadata(&parent).expect("parent metadata");
    let identity_metadata = fs::metadata(root.path()).expect("identity metadata");
    assert_eq!(parent_metadata.mode() & 0o7777, 0o700);
    assert_eq!(
        (parent_metadata.uid(), parent_metadata.gid()),
        (identity_metadata.uid(), identity_metadata.gid())
    );
    assert_eq!(fs::read_to_string(&target).expect("target"), "managed\n");
    let calls = history(root.path());
    assert_eq!(invoked_commands(&calls), ["install", "install", "mv"]);
    assert_eq!(
        calls[2],
        vec![
            "-n".to_owned(),
            "--".to_owned(),
            system_command("install").display().to_string(),
            "-d".to_owned(),
            "-o".to_owned(),
            identity_metadata.uid().to_string(),
            "-g".to_owned(),
            identity_metadata.gid().to_string(),
            "-m".to_owned(),
            "0700".to_owned(),
            "--".to_owned(),
            parent.display().to_string(),
        ]
    );
}

#[test]
fn staging_drift_preserves_target_and_removes_adjacent_temporary() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let target = root.path().join("target.conf");
    fs::write(&source, "new\n").expect("source");
    fs::write(&target, "old\n").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    let plans = plan_selected_privileged_entries(&[entry(&source, &target)], false, &identities)
        .expect("plan");
    let sudo = fake_sudo(
        root.path(),
        FakeBehavior {
            drift_target_after_stage: Some(&target),
            ..FakeBehavior::default()
        },
    );
    let mut session = PrivilegeSession::new(sudo).expect("session");

    let error = apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect_err("target drift must block replace");

    assert!(error
        .to_string()
        .contains("immediately before atomic replace"));
    assert_eq!(
        fs::read_to_string(&target).expect("target"),
        "drifted-before-move\n"
    );
    assert_eq!(invoked_commands(&history(root.path())), ["install", "rm"]);
    assert!(temporary_candidates(&target).is_empty());
}

#[test]
fn failed_stage_install_preserves_the_existing_target() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let target = root.path().join("target.conf");
    fs::write(&source, "new\n").expect("source");
    fs::write(&target, "old\n").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    let plans = plan_selected_privileged_entries(&[entry(&source, &target)], false, &identities)
        .expect("plan");
    let sudo = fake_sudo(
        root.path(),
        FakeBehavior {
            fail_stage_install: true,
            ..FakeBehavior::default()
        },
    );
    let mut session = PrivilegeSession::new(sudo).expect("session");

    let error = apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect_err("failed install must fail the entry");

    assert!(
        error.to_string().contains("privileged file install failed"),
        "unexpected error: {error}"
    );
    assert_eq!(fs::read_to_string(&target).expect("target"), "old\n");
    assert_eq!(invoked_commands(&history(root.path())), ["install"]);
    assert!(temporary_candidates(&target).is_empty());
}

#[test]
fn exact_postcondition_detects_corruption_after_atomic_replace() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let target = root.path().join("target.conf");
    fs::write(&source, "managed\n").expect("source");
    let plans = plan_selected_privileged_entries(&[entry(&source, &target)], false, &identities)
        .expect("plan");
    let sudo = fake_sudo(
        root.path(),
        FakeBehavior {
            corrupt_target_after_move: Some(&target),
            ..FakeBehavior::default()
        },
    );
    let mut session = PrivilegeSession::new(sudo).expect("session");

    let error = apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect_err("postcondition must detect corruption");

    assert!(error
        .to_string()
        .contains("failed exact postcondition verification"));
    assert_eq!(invoked_commands(&history(root.path())), ["install", "mv"]);
}

#[test]
fn unreconciled_existing_content_is_skipped_without_authentication() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let source = root.path().join("source.conf");
    let target = root.path().join("target.conf");
    fs::write(&source, "managed\n").expect("source");
    fs::write(&target, "local\n").expect("target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("target mode");
    let mut selected = entry(&source, &target);
    selected.reconcile_existing = false;
    let plans = plan_selected_privileged_entries(&[selected], false, &identities).expect("plan");

    let outcomes = apply_privileged_plans(&plans, false, &identities, None, None)
        .expect("skip needs no privilege");

    assert_eq!(outcomes, vec![PrivilegedTargetOutcome::SkippedExisting]);
    assert_eq!(fs::read_to_string(&target).expect("target"), "local\n");
    assert!(history(root.path()).is_empty());
}

#[test]
fn multiple_targets_share_exactly_one_authentication_session() {
    let root = TempDir::new().expect("temp root");
    let identities = FixedIdentities::current(root.path());
    let first_source = root.path().join("first.conf");
    let second_source = root.path().join("second.conf");
    let first_target = root.path().join("first-target.conf");
    let second_target = root.path().join("second-target.conf");
    fs::write(&first_source, "first\n").expect("first source");
    fs::write(&second_source, "second\n").expect("second source");
    let plans = plan_selected_privileged_entries(
        &[
            entry(&first_source, &first_target),
            entry(&second_source, &second_target),
        ],
        false,
        &identities,
    )
    .expect("plans");
    let sudo = fake_sudo(root.path(), FakeBehavior::default());
    let mut session = PrivilegeSession::new(sudo).expect("session");

    let outcomes = apply_privileged_plans(
        &plans,
        false,
        &identities,
        Some(&mut session),
        Some(&commands()),
    )
    .expect("batch apply");

    assert_eq!(
        outcomes,
        [
            PrivilegedTargetOutcome::Changed,
            PrivilegedTargetOutcome::Changed
        ]
    );
    let calls = history(root.path());
    assert_eq!(
        calls
            .iter()
            .filter(|argv| argv.as_slice() == ["-n", "-v"])
            .count(),
        1
    );
    assert_eq!(
        calls
            .iter()
            .filter(|argv| argv.as_slice() == ["-v"])
            .count(),
        1
    );
    assert_eq!(invoked_commands(&calls), ["install", "mv", "install", "mv"]);
}
