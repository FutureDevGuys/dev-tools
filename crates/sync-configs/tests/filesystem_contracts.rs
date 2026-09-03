use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sync_configs::filesystem::{
    apply_source_permissions, converge_entry, expand_entries, ConvergeOptions, EntryAction,
    EntryStatus, ExpansionOptions, ManagedPathPolicy,
};
use sync_configs::manifest::{
    CommentedTargetPolicy, DirectoryStrategy, Entry, FileMode, Mode, PermissionPolicy, Privilege,
    ScriptFailurePolicy,
};
use tempfile::TempDir;

fn entry(source: PathBuf, target: PathBuf, mode: Mode) -> Entry {
    Entry {
        name: "fixture".to_owned(),
        source,
        target,
        mode,
        directory_strategy: DirectoryStrategy::AsDirectory,
        profiles: Vec::new(),
        include: Vec::new(),
        exclude: Vec::new(),
        ignore_files: Vec::new(),
        discover_ignore_files: true,
        use_default_filters: true,
        group: None,
        subgroup: None,
        permissions: None,
        source_permissions: None,
        pre_script: None,
        pre_script_on_fail: ScriptFailurePolicy::Abort,
        pre_script_privilege: Privilege::User,
        post_script: None,
        post_script_on_fail: ScriptFailurePolicy::Continue,
        post_script_privilege: Privilege::User,
        target_privilege: Privilege::User,
        target_owner: None,
        target_group: None,
        target_parent_mode: None,
        reconcile_existing: false,
        reconcile_removed_keys: false,
        managed_overlay_id: None,
        commented_target_policy: CommentedTargetPolicy::Respect,
        exclusive_sibling_groups: Vec::new(),
    }
}

fn options<'a>(backup_root: &'a Path) -> ConvergeOptions<'a> {
    ConvergeOptions {
        dry_run: false,
        managed_path_policy: ManagedPathPolicy::Safe,
        backup_root,
        previous_sources: &[],
        skeleton: None,
        max_backup_candidates: 16,
    }
}

#[test]
fn regular_file_copy_is_idempotent() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source.conf");
    let target = temp.path().join("home/config/target.conf");
    fs::write(&source, b"managed\n").expect("write source");
    let fixture = entry(source.clone(), target.clone(), Mode::Copy);

    let first = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("initial convergence");
    let second = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("idempotent convergence");

    assert_eq!(first.status, EntryStatus::Changed);
    assert_eq!(first.action, EntryAction::Create);
    assert_eq!(second.status, EntryStatus::UpToDate);
    assert_eq!(fs::read(&target).expect("read target"), b"managed\n");
}

#[test]
fn directory_copy_compares_all_content_before_reporting_current() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    fs::create_dir(&source).expect("create source");
    fs::write(source.join("nested.txt"), b"one\n").expect("write source child");
    let mut fixture = entry(source.clone(), target.clone(), Mode::Copy);
    fixture.reconcile_existing = true;

    converge_entry(&fixture, &options(&temp.path().join("backups"))).expect("initial convergence");
    fs::write(source.join("nested.txt"), b"two\n").expect("change source child");
    let changed = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("replace changed directory");
    let current = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("verify current directory");

    assert_eq!(changed.status, EntryStatus::Changed);
    assert_eq!(changed.action, EntryAction::Replace);
    assert_eq!(current.status, EntryStatus::UpToDate);
    assert_eq!(
        fs::read(target.join("nested.txt")).expect("read copied child"),
        b"two\n"
    );
}

#[test]
fn strict_policy_never_adopts_an_identical_regular_file_as_a_symlink() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    fs::write(&source, b"same\n").expect("write source");
    fs::write(&target, b"same\n").expect("write target");
    let fixture = entry(source, target.clone(), Mode::Symlink);
    let backup_root = temp.path().join("backups");
    let mut converge = options(&backup_root);
    converge.managed_path_policy = ManagedPathPolicy::Strict;

    let outcome = converge_entry(&fixture, &converge).expect("classify strict target");

    assert_eq!(outcome.status, EntryStatus::SkippedExisting);
    assert_eq!(outcome.action, EntryAction::Block);
    assert!(!fs::symlink_metadata(&target)
        .expect("target metadata")
        .file_type()
        .is_symlink());
}

#[test]
fn copy_conflicts_require_reconciliation_or_takeover() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    fs::write(&source, b"managed\n").expect("write source");
    fs::write(&target, b"personal\n").expect("write target");
    let fixture = entry(source, target.clone(), Mode::Copy);

    let outcome = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("classify copy conflict");

    assert_eq!(outcome.status, EntryStatus::SkippedExisting);
    assert_eq!(outcome.action, EntryAction::Block);
    assert_eq!(fs::read(target).expect("read target"), b"personal\n");
}

#[test]
fn safe_policy_adopts_an_identical_regular_file_as_a_symlink() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    fs::write(&source, b"same\n").expect("write source");
    fs::write(&target, b"same\n").expect("write target");
    let fixture = entry(source, target.clone(), Mode::Symlink);

    let outcome = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("adopt identical file");

    assert_eq!(outcome.status, EntryStatus::Changed);
    assert_eq!(outcome.action, EntryAction::Adopt);
    assert!(fs::symlink_metadata(&target)
        .expect("target metadata")
        .file_type()
        .is_symlink());
}

#[test]
fn only_an_exact_declared_previous_link_source_is_adopted() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("current/tool");
    let previous = temp.path().join("previous/tool");
    let arbitrary = temp.path().join("arbitrary/tool");
    let target = temp.path().join("home/tool");
    fs::create_dir_all(source.parent().expect("source parent")).expect("create source parent");
    fs::create_dir_all(target.parent().expect("target parent")).expect("create target parent");
    fs::write(&source, b"managed\n").expect("write source");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&previous, &target).expect("create previous link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&previous, &target).expect("create previous link");
    let fixture = entry(source.clone(), target.clone(), Mode::Symlink);
    let previous_sources = [previous];
    let backup_root = temp.path().join("backups");
    let mut converge = options(&backup_root);
    converge.previous_sources = &previous_sources;

    let adopted = converge_entry(&fixture, &converge).expect("adopt previous source");
    assert_eq!(adopted.action, EntryAction::Adopt);
    assert_eq!(fs::read_link(&target).expect("read current link"), source);

    fs::remove_file(&target).expect("remove current link");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&arbitrary, &target).expect("create arbitrary link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&arbitrary, &target).expect("create arbitrary link");
    let blocked = converge_entry(&fixture, &converge).expect("block arbitrary source");
    assert_eq!(blocked.status, EntryStatus::SkippedExisting);
    assert_eq!(
        fs::read_link(&target).expect("read arbitrary link"),
        arbitrary
    );
}

#[test]
fn takeover_preserves_the_exact_conflict_in_a_bounded_backup() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("home/target");
    let backup_root = temp.path().join("backups");
    fs::write(&source, b"managed\n").expect("write source");
    fs::create_dir_all(target.parent().expect("target parent")).expect("create target parent");
    fs::write(&target, b"personal\n").expect("write target");
    let fixture = entry(source, target.clone(), Mode::Symlink);
    let mut converge = options(&backup_root);
    converge.managed_path_policy = ManagedPathPolicy::Takeover;

    let outcome = converge_entry(&fixture, &converge).expect("take over target");

    let backup = outcome.backup.expect("persistent takeover backup");
    assert!(backup.starts_with(&backup_root));
    assert_eq!(fs::read(backup).expect("read backup"), b"personal\n");
    assert!(fs::symlink_metadata(target)
        .expect("managed target")
        .file_type()
        .is_symlink());
}

#[test]
fn takeover_refuses_to_overwrite_when_the_bounded_backup_namespace_is_full() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("home/target");
    let backup_root = temp.path().join("backups");
    fs::write(&source, b"managed\n").expect("write source");
    fs::create_dir_all(target.parent().expect("target parent")).expect("create target parent");
    fs::write(&target, b"first personal value\n").expect("write first target");
    let fixture = entry(source, target.clone(), Mode::Symlink);
    let mut converge = options(&backup_root);
    converge.managed_path_policy = ManagedPathPolicy::Takeover;
    converge.max_backup_candidates = 1;
    converge_entry(&fixture, &converge).expect("consume only backup name");
    fs::remove_file(&target).expect("remove managed link");
    fs::write(&target, b"second personal value\n").expect("write second target");

    let error = converge_entry(&fixture, &converge).expect_err("bounded namespace is full");

    assert!(error.to_string().contains("no free bounded backup name"));
    assert_eq!(
        fs::read(&target).expect("conflict remains intact"),
        b"second personal value\n"
    );
}

#[test]
fn dry_run_reports_change_without_creating_parents_or_backup_state() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("missing/target");
    let backup_root = temp.path().join("backups");
    fs::write(&source, b"managed\n").expect("write source");
    let fixture = entry(source, target.clone(), Mode::Copy);
    let mut converge = options(&backup_root);
    converge.dry_run = true;

    let outcome = converge_entry(&fixture, &converge).expect("dry-run convergence");

    assert_eq!(outcome.status, EntryStatus::WouldChange);
    assert!(!target.exists());
    assert!(!backup_root.exists());
}

#[test]
fn recursive_expansion_applies_default_and_declared_filters() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested")).expect("create source tree");
    fs::create_dir_all(source.join("target/debug")).expect("create default ignored tree");
    fs::write(source.join("keep.txt"), b"keep").expect("write kept file");
    fs::write(source.join("nested/also.txt"), b"keep").expect("write nested file");
    fs::write(source.join("nested/drop.log"), b"drop").expect("write excluded file");
    fs::write(source.join("target/debug/build.bin"), b"drop").expect("write default ignored file");
    fs::write(source.join(".gitignore"), b"nested/also.txt\n").expect("write ignore file");
    let mut fixture = entry(source, temp.path().join("target"), Mode::Copy);
    fixture.directory_strategy = DirectoryStrategy::Recursive;
    fixture.exclude = vec!["*.log".to_owned()];

    let expanded =
        expand_entries(&[fixture], &ExpansionOptions::default()).expect("expand recursive entry");
    let relative: Vec<PathBuf> = expanded
        .iter()
        .map(|entry| {
            entry
                .target
                .strip_prefix(temp.path().join("target"))
                .expect("relative target")
                .to_owned()
        })
        .collect();

    assert_eq!(relative, vec![PathBuf::from("keep.txt")]);
}

#[test]
fn glob_and_children_strategies_keep_their_target_relative_paths() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("nested")).expect("create source tree");
    fs::write(source.join("one.toml"), b"one").expect("write first source");
    fs::write(source.join("two.txt"), b"two").expect("write second source");
    fs::write(source.join("nested/three.toml"), b"three").expect("write nested source");

    let glob_source = source.join("*.toml");
    let glob = entry(glob_source, temp.path().join("glob-target"), Mode::Copy);
    let globbed =
        expand_entries(&[glob], &ExpansionOptions::default()).expect("expand source glob");
    assert_eq!(globbed.len(), 1);
    assert!(globbed[0].source.ends_with("one.toml"));
    assert!(globbed[0].target.ends_with("glob-target/one.toml"));

    let mut children = entry(source, temp.path().join("children-target"), Mode::Copy);
    children.directory_strategy = DirectoryStrategy::Children;
    children.include = vec!["*.txt".to_owned()];
    let expanded = expand_entries(&[children], &ExpansionOptions::default())
        .expect("expand selected direct children");
    assert_eq!(expanded.len(), 1);
    assert!(expanded[0].source.ends_with("two.txt"));
    assert!(expanded[0].target.ends_with("children-target/two.txt"));
}

#[test]
fn a_selected_override_file_does_not_replace_the_base_source_twice() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("create source");
    fs::write(source.join("tool.json"), b"base").expect("write base");
    fs::write(source.join("tool.override.json"), b"override").expect("write override");
    let mut fixture = entry(source, temp.path().join("target"), Mode::Copy);
    fixture.directory_strategy = DirectoryStrategy::Recursive;

    let expanded =
        expand_entries(&[fixture], &ExpansionOptions::default()).expect("expand directory");
    let sources: Vec<PathBuf> = expanded.iter().map(|entry| entry.source.clone()).collect();

    assert_eq!(sources.len(), 2);
    assert!(sources.iter().any(|path| path.ends_with("tool.json")));
    assert!(sources
        .iter()
        .any(|path| path.ends_with("tool.override.json")));
}

#[test]
fn an_unselected_sibling_override_is_preferred_and_can_be_disabled() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("tool.toml");
    let override_source = temp.path().join("tool.override.toml");
    fs::write(&source, b"base").expect("write base");
    fs::write(&override_source, b"override").expect("write override");
    let fixture = entry(source.clone(), temp.path().join("target.toml"), Mode::Copy);

    let preferred = expand_entries(std::slice::from_ref(&fixture), &ExpansionOptions::default())
        .expect("select source override");
    let disabled = expand_entries(
        &[fixture],
        &ExpansionOptions {
            prefer_source_overrides: false,
            ..ExpansionOptions::default()
        },
    )
    .expect("keep base source");

    assert_eq!(preferred[0].source, override_source);
    assert_eq!(disabled[0].source, source);
}

#[test]
fn explicit_copy_permissions_are_enforced_recursively_and_idempotently() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let target = temp.path().join("target");
    fs::create_dir_all(source.join("nested")).expect("create source tree");
    fs::write(source.join("nested/file"), b"payload").expect("write source file");
    let mut fixture = entry(source, target.clone(), Mode::Copy);
    fixture.permissions = Some(PermissionPolicy {
        file: Some(FileMode::new(0o600).expect("file mode")),
        dir: Some(FileMode::new(0o700).expect("directory mode")),
        recursive: true,
    });

    let first = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("copy with permissions");
    let second = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect("permissions current");

    assert_eq!(first.status, EntryStatus::Changed);
    assert_eq!(second.status, EntryStatus::UpToDate);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&target)
                .expect("target mode")
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        assert_eq!(
            fs::metadata(target.join("nested/file"))
                .expect("file mode")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[cfg(unix)]
#[test]
fn overlay_callers_can_apply_source_permissions_without_running_filesystem_convergence() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("overlay.json");
    fs::write(&source, b"{}\n").expect("write overlay source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).expect("set initial mode");
    let mut fixture = entry(
        source.clone(),
        temp.path().join("target.json"),
        Mode::JsonOverlay,
    );
    fixture.source_permissions = Some(PermissionPolicy {
        file: Some(FileMode::new(0o600).expect("source mode")),
        dir: None,
        recursive: false,
    });

    assert!(apply_source_permissions(&fixture, true).expect("dry-run permission plan"));
    assert_eq!(
        fs::metadata(&source)
            .expect("source metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o644
    );
    assert!(apply_source_permissions(&fixture, false).expect("apply source permissions"));
    assert!(!apply_source_permissions(&fixture, false).expect("idempotent source permissions"));
    assert_eq!(
        fs::metadata(source)
            .expect("source metadata")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
}

#[test]
fn target_parent_symlinks_are_rejected_instead_of_written_through() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let outside = temp.path().join("outside");
    let linked_parent = temp.path().join("linked-parent");
    fs::write(&source, b"managed").expect("write source");
    fs::create_dir(&outside).expect("create outside directory");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &linked_parent).expect("link parent");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&outside, &linked_parent).expect("link parent");
    let fixture = entry(source, linked_parent.join("target"), Mode::Copy);

    let error = converge_entry(&fixture, &options(&temp.path().join("backups")))
        .expect_err("reject linked target parent");

    assert!(error.to_string().contains("target ancestor"));
    assert!(!outside.join("target").exists());
}

#[cfg(unix)]
#[test]
fn non_utf8_child_names_survive_recursive_expansion() {
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("create source");
    let name = std::ffi::OsString::from_vec(vec![b'n', 0x80, b'm', b'e']);
    fs::write(source.join(&name), b"managed").expect("write non-UTF-8 source");
    let mut fixture = entry(source, temp.path().join("target"), Mode::Copy);
    fixture.directory_strategy = DirectoryStrategy::Recursive;

    let expanded =
        expand_entries(&[fixture], &ExpansionOptions::default()).expect("expand non-UTF-8 child");

    assert_eq!(expanded.len(), 1);
    assert_eq!(expanded[0].source.file_name(), Some(name.as_os_str()));
    assert_eq!(expanded[0].target.file_name(), Some(name.as_os_str()));
}

#[test]
fn expansion_rejects_source_links_instead_of_following_them() {
    let temp = TempDir::new().expect("temporary directory");
    let source = temp.path().join("source");
    let outside = temp.path().join("outside");
    fs::create_dir(&source).expect("create source");
    fs::write(&outside, b"outside").expect("write outside file");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, source.join("linked")).expect("link source child");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&outside, source.join("linked")).expect("link source child");
    let mut fixture = entry(source, temp.path().join("target"), Mode::Copy);
    fixture.directory_strategy = DirectoryStrategy::Recursive;

    let error =
        expand_entries(&[fixture], &ExpansionOptions::default()).expect_err("reject source link");

    assert!(error.to_string().contains("source link"));
}

#[test]
fn expansion_options_are_deterministic_without_environment_state() {
    let options = ExpansionOptions {
        prefer_source_overrides: false,
        environment: BTreeMap::new(),
        home: None,
    };
    assert!(!options.prefer_source_overrides);
}
