use std::fs;

use serde_json::json;
use sync_configs::overlay::toml::{CommentedTargetPolicy, TomlConflictPolicy};
use sync_configs::standalone::{
    classify_managed_path, execute_json_overlay, execute_toml, JsonOverlayRequest,
    ManagedPathAction, ManagedPathPolicy, ManagedPathRequest, ManagedPathState, TomlOperation,
    TomlRequest,
};
use tempfile::tempdir;

#[test]
fn json_check_plans_exact_pointer_replacement_without_mutating() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.json");
    let target = directory.path().join("target.json");
    fs::write(&source, r#"{"managed":{"value":2}}"#).expect("source");
    fs::write(&target, r#"{"managed":{"value":1,"local":true}}"#).expect("target");
    let before = fs::read(&target).expect("target before");

    let mut request = JsonOverlayRequest::new(source, target.clone());
    request.check = true;
    request.replace_json_pointers = vec!["/managed".to_owned()];
    let outcome = execute_json_overlay(&request).expect("JSON check");

    assert!(outcome.overlay.changed);
    assert_eq!(outcome.overlay.replaced, 1);
    assert!(outcome.check_failed);
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(fs::read(target).expect("target after"), before);
}

#[test]
fn json_reconciliation_updates_and_then_retires_only_owned_paths() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.json");
    let target = directory.path().join("target.json");
    let state_root = directory.path().join("state");
    fs::write(&source, r#"{"managed":{"keep":1,"retire":2}}"#).expect("source");
    fs::write(&target, r#"{"managed":{"local":3}}"#).expect("target");

    let mut request = JsonOverlayRequest::new(source.clone(), target.clone());
    request.reconcile_removed_keys = true;
    request.managed_overlay_id = Some("standalone-json".to_owned());
    request.state_root = Some(state_root.clone());
    assert!(
        execute_json_overlay(&request)
            .expect("initial JSON overlay")
            .overlay
            .ownership_changed
    );

    fs::write(&source, r#"{"managed":{"keep":1}}"#).expect("updated source");
    let retired = execute_json_overlay(&request).expect("retire JSON key");
    let target_value: serde_json::Value =
        serde_json::from_slice(&fs::read(target).expect("target bytes")).expect("target JSON");
    assert_eq!(retired.overlay.removed, 1);
    assert_eq!(target_value, json!({"managed": {"keep": 1, "local": 3}}));

    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state_root.join("overlays/standalone-json.json")).expect("receipt"),
    )
    .expect("receipt JSON");
    assert_eq!(receipt["managed_paths"], json!([["managed", "keep"]]));
}

#[test]
fn toml_overlay_forwards_target_conflicts_comments_and_check_semantics() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let target = directory.path().join("target.toml");
    fs::write(&source, "managed = 2\nsecret = \"source-private\"\n").expect("source");
    fs::write(
        &target,
        "managed = 1\nlocal = true\n# secret = \"target-private\"\n",
    )
    .expect("target");
    let before = fs::read(&target).expect("before");

    let mut request = TomlRequest::new(source, target.clone());
    request.check = true;
    request.conflict_policy = TomlConflictPolicy::Target;
    request.commented_target_policy = CommentedTargetPolicy::Respect;
    let outcome = execute_toml(&request).expect("TOML check");

    assert!(!outcome.check_failed);
    assert!(!outcome.overlay.changed);
    assert_eq!(outcome.overlay.added, 0);
    assert_eq!(outcome.overlay.overwritten, 0);
    assert_eq!(outcome.overlay.suppressed, vec![vec!["secret".to_owned()]]);
    assert_eq!(fs::read(target).expect("after"), before);
}

#[test]
fn toml_remove_prunes_source_owned_keys_and_retains_target_only_values() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let target = directory.path().join("target.toml");
    fs::write(&source, "root = 1\n[managed]\nremove = true\n").expect("source");
    fs::write(
        &target,
        "root = 2\nlocal = true\n\n[managed]\nremove = false\nkeep = \"yes\"\n",
    )
    .expect("target");

    let mut request = TomlRequest::new(source, target.clone());
    request.operation = TomlOperation::Remove;
    let outcome = execute_toml(&request).expect("remove TOML keys");

    assert!(outcome.overlay.changed);
    assert_eq!(outcome.overlay.removed, 2);
    let parsed = fs::read_to_string(target)
        .expect("target text")
        .parse::<toml_edit::DocumentMut>()
        .expect("target TOML");
    assert_eq!(parsed["local"].as_bool(), Some(true));
    assert_eq!(parsed["managed"]["keep"].as_str(), Some("yes"));
    assert!(parsed.get("root").is_none());
    assert!(parsed["managed"].get("remove").is_none());
}

#[test]
fn toml_remove_check_does_not_mutate_and_reports_difference() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let target = directory.path().join("target.toml");
    fs::write(&source, "managed = true\n").expect("source");
    fs::write(&target, "managed = false\nlocal = true\n").expect("target");
    let before = fs::read(&target).expect("before");

    let mut request = TomlRequest::new(source, target.clone());
    request.operation = TomlOperation::Remove;
    request.check = true;
    let outcome = execute_toml(&request).expect("remove check");

    assert!(outcome.check_failed);
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(fs::read(target).expect("after"), before);
}

#[test]
fn toml_remove_rejects_structural_mismatch_without_broadening_ownership() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let target = directory.path().join("target.toml");
    fs::write(&source, "managed = true\n").expect("source");
    fs::write(&target, "[managed]\nlocal = \"private-target\"\n").expect("target");
    let before = fs::read(&target).expect("before");

    let mut request = TomlRequest::new(source, target.clone());
    request.operation = TomlOperation::Remove;
    let error = execute_toml(&request).expect_err("structural mismatch must fail closed");

    assert!(format!("{error:#}").contains("normalize the target structure"));
    assert!(!format!("{error:#}").contains("private-target"));
    assert_eq!(fs::read(target).expect("after"), before);
}

#[test]
fn toml_overlay_reconciliation_retires_only_previously_owned_paths() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let target = directory.path().join("target.toml");
    let state_root = directory.path().join("state");
    fs::write(&source, "[managed]\nkeep = 1\nretire = 2\n").expect("source");
    fs::write(&target, "[managed]\nlocal = 3\n").expect("target");

    let mut request = TomlRequest::new(source.clone(), target.clone());
    request.reconcile_removed_keys = true;
    request.managed_overlay_id = Some("standalone-toml".to_owned());
    request.state_root = Some(state_root.clone());
    assert!(
        execute_toml(&request)
            .expect("initial TOML overlay")
            .overlay
            .ownership_changed
    );

    fs::write(&source, "[managed]\nkeep = 1\n").expect("updated source");
    let retired = execute_toml(&request).expect("retire TOML key");
    assert_eq!(retired.overlay.removed, 1);
    let parsed = fs::read_to_string(target)
        .expect("target")
        .parse::<toml_edit::DocumentMut>()
        .expect("target TOML");
    assert_eq!(parsed["managed"]["keep"].as_integer(), Some(1));
    assert_eq!(parsed["managed"]["local"].as_integer(), Some(3));
    assert!(parsed["managed"].get("retire").is_none());

    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state_root.join("overlays/standalone-toml.json")).expect("receipt"),
    )
    .expect("receipt JSON");
    assert_eq!(receipt["managed_paths"], json!([["managed", "keep"]]));
}

#[test]
fn toml_remove_deletes_a_target_when_no_target_only_keys_remain() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let target = directory.path().join("target.toml");
    fs::write(&source, "managed = true\n").expect("source");
    fs::write(&target, "managed = false\n").expect("target");

    let mut request = TomlRequest::new(source, target.clone());
    request.operation = TomlOperation::Remove;
    let outcome = execute_toml(&request).expect("remove whole TOML target");

    assert!(outcome.overlay.changed);
    assert_eq!(outcome.overlay.removed, 1);
    assert!(!target.exists());
}

#[cfg(unix)]
#[test]
fn toml_remove_rejects_a_symlinked_target_parent_before_read_or_mutation() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let outside = directory.path().join("outside");
    let linked_parent = directory.path().join("linked-parent");
    fs::write(&source, "managed = true\n").expect("source");
    fs::create_dir(&outside).expect("outside");
    fs::write(outside.join("target.toml"), "managed = false\n").expect("target");
    symlink(&outside, &linked_parent).expect("parent symlink");

    let mut request = TomlRequest::new(source, linked_parent.join("target.toml"));
    request.operation = TomlOperation::Remove;
    let error = execute_toml(&request).expect_err("symlinked parent must fail closed");

    assert!(format!("{error:#}").contains("parent must be a real directory"));
    assert_eq!(
        fs::read_to_string(outside.join("target.toml")).expect("unchanged target"),
        "managed = false\n"
    );
}

#[test]
fn toml_remove_missing_target_is_up_to_date_without_parsing_unused_source() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("invalid-source.toml");
    let target = directory.path().join("missing-target.toml");
    fs::write(&source, "not valid = [\n").expect("source");

    let mut request = TomlRequest::new(source, target);
    request.operation = TomlOperation::Remove;
    let outcome = execute_toml(&request).expect("missing target is already removed");

    assert!(!outcome.overlay.changed);
    assert_eq!(outcome.overlay.removed, 0);
    assert_eq!(outcome.exit_code(), 0);
}

#[cfg(unix)]
#[test]
fn toml_remove_rejects_a_symlinked_parent_even_when_the_target_is_absent() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let outside = directory.path().join("outside");
    let linked_parent = directory.path().join("linked-parent");
    fs::write(&source, "managed = true\n").expect("source");
    fs::create_dir(&outside).expect("outside");
    symlink(&outside, &linked_parent).expect("parent symlink");

    let mut request = TomlRequest::new(source, linked_parent.join("missing.toml"));
    request.operation = TomlOperation::Remove;
    let error = execute_toml(&request).expect_err("symlinked parent must fail closed");

    assert!(format!("{error:#}").contains("parent must be a real directory"));
    assert!(!outside.join("missing.toml").exists());
}

#[cfg(unix)]
#[test]
fn toml_remove_materializes_a_changed_symlink_without_mutating_its_referent() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let referent = directory.path().join("referent.toml");
    let target = directory.path().join("target.toml");
    fs::write(&source, "managed = true\n").expect("source");
    fs::write(&referent, "managed = false\nlocal = true\n").expect("referent");
    symlink(&referent, &target).expect("target symlink");

    let mut request = TomlRequest::new(source, target.clone());
    request.operation = TomlOperation::Remove;
    let outcome = execute_toml(&request).expect("remove from symlink target");

    assert!(outcome.overlay.materialized_symlink);
    assert!(!fs::symlink_metadata(&target)
        .expect("target metadata")
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_to_string(&target).expect("target"),
        "local = true\n"
    );
    assert_eq!(
        fs::read_to_string(&referent).expect("referent"),
        "managed = false\nlocal = true\n"
    );
}

#[test]
fn safe_classification_distinguishes_absent_identical_skeleton_and_conflict() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source");
    let target = directory.path().join("target");
    let skeleton = directory.path().join("skeleton");
    fs::create_dir(&source).expect("source directory");
    fs::write(source.join("config"), b"managed").expect("source file");

    let absent = classify_managed_path(&ManagedPathRequest::new(source.clone(), target.clone()));
    assert_eq!(absent.state, ManagedPathState::Absent);
    assert_eq!(absent.action, ManagedPathAction::Create);

    fs::create_dir(&target).expect("target directory");
    fs::write(target.join("config"), b"managed").expect("target file");
    let identical = classify_managed_path(&ManagedPathRequest::new(source.clone(), target.clone()));
    assert_eq!(identical.state, ManagedPathState::IdenticalSource);
    assert_eq!(identical.action, ManagedPathAction::Adopt);

    fs::remove_dir_all(&target).expect("remove target");
    fs::create_dir(&skeleton).expect("skeleton directory");
    fs::write(skeleton.join("default"), b"stock").expect("skeleton file");
    fs::create_dir(&target).expect("target directory");
    fs::write(target.join("default"), b"stock").expect("target default");
    let mut skeleton_request = ManagedPathRequest::new(source.clone(), target.clone());
    skeleton_request.skeleton = Some(skeleton);
    let skeleton_default = classify_managed_path(&skeleton_request);
    assert_eq!(skeleton_default.state, ManagedPathState::SkeletonDefault);
    assert_eq!(skeleton_default.action, ManagedPathAction::Replace);
    assert!(skeleton_default.backup_required);

    fs::write(target.join("local"), b"private").expect("local file");
    let conflict = classify_managed_path(&skeleton_request);
    assert_eq!(conflict.state, ManagedPathState::Conflict);
    assert_eq!(conflict.action, ManagedPathAction::Block);
}

#[test]
fn strict_and_takeover_classification_and_json_shape_are_stable() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source");
    let target = directory.path().join("target");
    fs::write(&source, b"same").expect("source");
    fs::write(&target, b"same").expect("target");

    let mut request = ManagedPathRequest::new(source.clone(), target.clone());
    request.policy = ManagedPathPolicy::Strict;
    let strict = classify_managed_path(&request);
    assert_eq!(strict.state, ManagedPathState::IdenticalSource);
    assert_eq!(strict.action, ManagedPathAction::Block);

    fs::write(&target, b"different").expect("different target");
    request.policy = ManagedPathPolicy::Takeover;
    let takeover = classify_managed_path(&request);
    assert_eq!(takeover.state, ManagedPathState::Conflict);
    assert_eq!(takeover.action, ManagedPathAction::Replace);
    assert!(takeover.backup_required);
    assert_eq!(takeover.policy.to_string(), "takeover");
    assert_eq!(takeover.state.to_string(), "conflict");
    assert_eq!(takeover.action.to_string(), "replace");
    assert_eq!(
        serde_json::to_value(&takeover).expect("classification JSON"),
        json!({
            "source": source,
            "target": target,
            "policy": "takeover",
            "state": "conflict",
            "action": "replace",
            "backup_required": true,
        })
    );
}

#[cfg(unix)]
#[test]
fn managed_link_classification_accepts_relative_link_to_source() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source");
    let target = directory.path().join("target");
    fs::write(&source, b"managed").expect("source");
    symlink("source", &target).expect("relative managed link");

    let result = classify_managed_path(&ManagedPathRequest::new(source, target));
    assert_eq!(result.state, ManagedPathState::ManagedLink);
    assert_eq!(result.action, ManagedPathAction::None);
    assert!(!result.backup_required);
}
