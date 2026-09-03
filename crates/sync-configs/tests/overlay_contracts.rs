#[path = "../src/overlay/mod.rs"]
mod overlay;
#[allow(dead_code)]
#[path = "../src/paths.rs"]
mod paths;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};

use overlay::json::{self, JsonOverlayOptions};
use overlay::toml::{
    self, CommentedTargetPolicy, ExclusiveSiblingGroup, TomlConflictPolicy, TomlOverlayOptions,
};
use overlay::PathKey;
use paths::PathPlatform;
use serde_json::json;
use tempfile::tempdir;

fn key(parts: &[&str]) -> PathKey {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[test]
fn ownership_receipt_requires_an_absolute_explicit_state_root() {
    let error = overlay::ownership::receipt_path("fixture", Some(Path::new("relative")))
        .expect_err("relative receipt state root must fail closed");

    assert!(format!("{error:#}").contains("absolute"));
}

#[test]
fn ownership_receipt_state_root_uses_only_absolute_platform_environment_roots() {
    struct Case {
        name: &'static str,
        platform: PathPlatform,
        environment: &'static [(&'static str, &'static str)],
        expected: &'static str,
    }

    for case in [
        Case {
            name: "absolute XDG state root",
            platform: PathPlatform::Posix,
            environment: &[
                ("XDG_STATE_HOME", "/var/state/operator"),
                ("HOME", "/home/operator"),
            ],
            expected: "/var/state/operator/sync-configs",
        },
        Case {
            name: "relative XDG state root falls back to HOME",
            platform: PathPlatform::Posix,
            environment: &[
                ("XDG_STATE_HOME", "relative-state"),
                ("HOME", "/home/operator"),
            ],
            expected: "/home/operator/.local/state/sync-configs",
        },
        Case {
            name: "absolute Windows local app data",
            platform: PathPlatform::Windows,
            environment: &[
                ("LOCALAPPDATA", r"D:\State"),
                ("USERPROFILE", r"C:\Users\operator"),
            ],
            expected: r"D:\State\sync-configs\state",
        },
        Case {
            name: "relative Windows local app data falls back to profile",
            platform: PathPlatform::Windows,
            environment: &[
                ("LOCALAPPDATA", "relative-state"),
                ("USERPROFILE", r"C:\Users\operator"),
            ],
            expected: r"C:\Users\operator\AppData\Local\sync-configs\state",
        },
        Case {
            name: "Windows drive and home path fallback",
            platform: PathPlatform::Windows,
            environment: &[("HOMEDRIVE", "C:"), ("HOMEPATH", r"\Users\operator")],
            expected: r"C:\Users\operator\AppData\Local\sync-configs\state",
        },
    ] {
        let environment: BTreeMap<OsString, OsString> = case
            .environment
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect();
        let actual = overlay::ownership::default_state_root_with(case.platform, |name| {
            environment.get(OsStr::new(name)).cloned()
        })
        .unwrap_or_else(|error| panic!("{}: {error:#}", case.name));

        assert_eq!(actual, PathBuf::from(case.expected), "{}", case.name);
    }
}

#[test]
fn ownership_receipt_state_root_rejects_a_relative_home_fallback() {
    let error = overlay::ownership::default_state_root_with(PathPlatform::Posix, |name| {
        (name == "HOME").then(|| OsString::from("relative-home"))
    })
    .expect_err("relative HOME must not anchor ownership receipts");

    assert!(format!("{error:#}").contains("absolute"));
}

#[test]
fn non_symlink_reparse_leaf_classification_is_fail_closed() {
    for (is_symlink, is_reparse_point, expected) in [
        (false, false, false),
        (true, true, false),
        (true, false, false),
        (false, true, true),
    ] {
        assert_eq!(
            overlay::ownership::is_unsupported_reparse_leaf(is_symlink, is_reparse_point),
            expected,
            "is_symlink={is_symlink}, is_reparse_point={is_reparse_point}"
        );
    }
}

#[test]
fn json_overlay_is_source_wins_recursive_and_retains_target_only_values() {
    let source = r#"{"nested":{"same":1,"changed":2,"added":3},"shape":null}"#;
    let target = r#"{"nested":{"same":1,"changed":1,"local":4},"shape":{"local":true},"only":5}"#;

    let result =
        json::overlay_json_text(source, target, &[], &BTreeSet::new()).expect("overlay valid JSON");
    let merged: serde_json::Value = serde_json::from_str(&result.text).expect("merged JSON");

    assert_eq!(
        merged,
        json!({
            "nested": {"same": 1, "changed": 2, "added": 3, "local": 4},
            "shape": null,
            "only": 5
        })
    );
    assert_eq!(result.added, 1);
    assert_eq!(result.overwritten, 2);
    assert_eq!(result.replaced, 0);
    assert_eq!(result.removed, 0);
    assert!(result.changed);
}

#[test]
fn json_pointer_replacement_is_rfc6901_exact_and_missing_is_not_null() {
    let source = r#"{"a/b":{"~key":{"managed":1}},"present":null}"#;
    let target = r#"{"a/b":{"~key":{"managed":0,"local":2}},"present":null}"#;

    let result = json::overlay_json_text(
        source,
        target,
        &["/a~1b/~0key".to_owned()],
        &BTreeSet::new(),
    )
    .expect("replace escaped pointer");
    let merged: serde_json::Value = serde_json::from_str(&result.text).expect("merged JSON");

    assert_eq!(merged["a/b"]["~key"], json!({"managed": 1}));
    assert_eq!(result.replaced, 1);
    assert!(json::get_pointer_value(&merged, "/missing").is_err());
    assert_eq!(
        json::get_pointer_value(&merged, "/present").unwrap(),
        &json!(null)
    );
}

#[test]
fn json_removed_key_receipt_retires_only_previously_owned_leaves() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.json");
    let target = directory.path().join("target.json");
    let state = directory.path().join("state");
    fs::write(&source, "{\"managed\":{\"kept\":1,\"retired\":2}}\n").unwrap();
    fs::write(&target, "{\"managed\":{\"local\":3}}\n").unwrap();

    let options = JsonOverlayOptions {
        reconcile_removed_keys: true,
        managed_overlay_id: Some("fixture".to_owned()),
        state_root: Some(state.clone()),
        ..JsonOverlayOptions::default()
    };
    let first = json::overlay_json_file(&source, &target, &options).expect("first overlay");
    assert!(first.ownership_changed);

    fs::write(&source, "{\"managed\":{\"kept\":1}}\n").unwrap();
    let second = json::overlay_json_file(&source, &target, &options).expect("retire key");
    let merged: serde_json::Value =
        serde_json::from_slice(&fs::read(&target).unwrap()).expect("target JSON");
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(state.join("overlays/fixture.json")).expect("ownership receipt"),
    )
    .expect("receipt JSON");

    assert_eq!(second.removed, 1);
    assert_eq!(merged, json!({"managed": {"kept": 1, "local": 3}}));
    assert_eq!(
        receipt,
        json!({
            "schema_version": 1,
            "managed_overlay_id": "fixture",
            "managed_paths": [["managed", "kept"]]
        })
    );

    let third = json::overlay_json_file(&source, &target, &options).expect("idempotent overlay");
    assert!(!third.changed);
    assert!(!third.ownership_changed);
}

#[cfg(unix)]
#[test]
fn atomic_overlay_preserves_regular_target_mode_and_materializes_symlink_safely() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.json");
    let target = directory.path().join("target.json");
    fs::write(&source, "{\"managed\":true}\n").unwrap();
    fs::write(&target, "{\"managed\":false}\n").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
    let before = fs::metadata(&target).unwrap();

    json::overlay_json_file(&source, &target, &JsonOverlayOptions::default())
        .expect("replace regular target");
    let after = fs::metadata(&target).unwrap();
    assert_eq!(after.mode() & 0o7777, 0o640);
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));

    let referent = directory.path().join("referent.json");
    let link = directory.path().join("link.json");
    fs::write(&referent, "{\"managed\":false}\n").unwrap();
    symlink(&referent, &link).unwrap();
    let result = json::overlay_json_file(&source, &link, &JsonOverlayOptions::default())
        .expect("materialize target symlink");
    assert!(result.materialized_symlink);
    assert!(!fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read_to_string(&referent).unwrap(),
        "{\"managed\":false}\n"
    );
}

#[test]
fn ownership_receipts_fail_closed_without_disclosing_payload_values() {
    let directory = tempdir().expect("tempdir");
    let receipt = directory.path().join("receipt.json");
    fs::write(
        &receipt,
        r#"{"schema_version":1,"managed_overlay_id":"fixture","managed_paths":[["secret-value"],["secret-value"]]}"#,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&receipt, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let error = overlay::ownership::load_paths(&receipt, "fixture")
        .expect_err("duplicate receipt paths must fail");
    let message = format!("{error:#}");
    assert!(message.contains("duplicate managed path"));
    assert!(!message.contains("secret-value"));
}

#[cfg(unix)]
#[test]
fn ownership_receipt_symlink_is_rejected_without_following_it() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let referent = directory.path().join("referent.json");
    let receipt = directory.path().join("receipt.json");
    fs::write(
        &referent,
        r#"{"schema_version":1,"managed_overlay_id":"fixture","managed_paths":[["managed"]]}"#,
    )
    .unwrap();
    symlink(&referent, &receipt).unwrap();

    let error = overlay::ownership::load_paths(&receipt, "fixture")
        .expect_err("receipt symlink must fail closed");
    assert!(format!("{error:#}").contains("must be a regular file"));
}

#[cfg(unix)]
#[test]
fn ownership_receipt_rejects_a_symlinked_parent_boundary() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempdir().expect("tempdir");
    let external = directory.path().join("external");
    let state = directory.path().join("state");
    fs::create_dir_all(&external).unwrap();
    fs::create_dir_all(&state).unwrap();
    let external_receipt = external.join("fixture.json");
    fs::write(
        &external_receipt,
        r#"{"schema_version":1,"managed_overlay_id":"fixture","managed_paths":[["managed"]]}"#,
    )
    .unwrap();
    fs::set_permissions(&external_receipt, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&external, state.join("overlays")).unwrap();

    let error = overlay::ownership::load_paths(&state.join("overlays/fixture.json"), "fixture")
        .expect_err("parent symlink must fail closed");
    assert!(format!("{error:#}").contains("real directory"));
}

#[cfg(unix)]
#[test]
fn json_overlay_rejects_a_symlinked_target_parent_before_reading_or_writing() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.json");
    let external = directory.path().join("external");
    let target_parent = directory.path().join("target-parent");
    let external_target = external.join("target.json");
    fs::write(&source, "{\"managed\":true}\n").unwrap();
    fs::create_dir(&external).unwrap();
    fs::write(&external_target, "{\"private\":\"unchanged\"}\n").unwrap();
    symlink(&external, &target_parent).unwrap();

    let error = json::overlay_json_file(
        &source,
        &target_parent.join("target.json"),
        &JsonOverlayOptions::default(),
    )
    .expect_err("target parent symlink must fail closed");

    assert!(format!("{error:#}").contains("JSON overlay target parent must be a real directory"));
    assert_eq!(
        fs::read_to_string(&external_target).unwrap(),
        "{\"private\":\"unchanged\"}\n"
    );
}

#[cfg(unix)]
#[test]
fn toml_overlay_rejects_a_symlinked_target_parent_before_reading_or_writing() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let external = directory.path().join("external");
    let target_parent = directory.path().join("target-parent");
    let external_target = external.join("target.toml");
    fs::write(&source, "managed = true\n").unwrap();
    fs::create_dir(&external).unwrap();
    fs::write(&external_target, "private = \"unchanged\"\n").unwrap();
    symlink(&external, &target_parent).unwrap();

    let error = toml::overlay_toml_file(
        &source,
        &target_parent.join("target.toml"),
        &TomlOverlayOptions::default(),
    )
    .expect_err("target parent symlink must fail closed");

    assert!(format!("{error:#}").contains("TOML overlay target parent must be a real directory"));
    assert_eq!(
        fs::read_to_string(&external_target).unwrap(),
        "private = \"unchanged\"\n"
    );
}

#[cfg(unix)]
#[test]
fn target_snapshot_rejects_a_symlinked_parent_before_reading() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let external = directory.path().join("external");
    let target_parent = directory.path().join("target-parent");
    let external_target = external.join("target.json");
    fs::create_dir(&external).unwrap();
    fs::write(&external_target, "{\"private\":\"unchanged\"}\n").unwrap();
    symlink(&external, &target_parent).unwrap();

    let error = overlay::ownership::snapshot_file(&target_parent.join("target.json"))
        .expect_err("snapshot parent symlink must fail closed");

    assert!(
        format!("{error:#}").contains("overlay target snapshot parent must be a real directory")
    );
    assert_eq!(
        fs::read_to_string(&external_target).unwrap(),
        "{\"private\":\"unchanged\"}\n"
    );
}

#[cfg(unix)]
#[test]
fn atomic_target_write_rejects_a_symlinked_parent_without_external_effects() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let external = directory.path().join("external");
    let target_parent = directory.path().join("target-parent");
    let external_target = external.join("target.json");
    fs::create_dir(&external).unwrap();
    fs::write(&external_target, "{\"private\":\"unchanged\"}\n").unwrap();
    symlink(&external, &target_parent).unwrap();

    let error = overlay::ownership::atomic_write_preserving_target(
        &target_parent.join("target.json"),
        b"{\"managed\":true}\n",
    )
    .expect_err("write parent symlink must fail closed");

    assert!(format!("{error:#}").contains("overlay target parent must be a real directory"));
    assert_eq!(
        fs::read_to_string(&external_target).unwrap(),
        "{\"private\":\"unchanged\"}\n"
    );
}

#[cfg(unix)]
#[test]
fn ownership_receipt_write_rejects_a_symlinked_parent_without_external_effects() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let state = directory.path().join("state");
    let external = directory.path().join("external");
    fs::create_dir_all(&state).unwrap();
    fs::create_dir(&external).unwrap();
    symlink(&external, state.join("overlays")).unwrap();
    let receipt = state.join("overlays/fixture.json");
    let paths = BTreeSet::from([key(&["managed"])]);

    let error = overlay::ownership::write_paths_atomic(&receipt, "fixture", &paths)
        .expect_err("receipt parent symlink must fail closed");

    assert!(
        format!("{error:#}").contains("overlay ownership receipt parent must be a real directory")
    );
    assert!(!external.join("fixture.json").exists());
}

#[cfg(unix)]
#[test]
fn rollback_rejects_a_symlinked_target_parent_without_touching_the_referent() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let target_parent = directory.path().join("target-parent");
    let displaced_parent = directory.path().join("displaced-parent");
    let external = directory.path().join("external");
    let target = target_parent.join("target.json");
    fs::create_dir(&target_parent).unwrap();
    fs::write(&target, "{\"before\":true}\n").unwrap();
    let snapshot = overlay::ownership::snapshot_file(&target).expect("snapshot safe target");
    fs::rename(&target_parent, &displaced_parent).unwrap();
    fs::create_dir(&external).unwrap();
    let external_target = external.join("target.json");
    fs::write(&external_target, "{\"external\":\"unchanged\"}\n").unwrap();
    symlink(&external, &target_parent).unwrap();

    let error = overlay::ownership::restore_file(&target, &snapshot)
        .expect_err("rollback parent symlink must fail closed");

    assert!(
        format!("{error:#}").contains("overlay target rollback parent must be a real directory")
    );
    assert_eq!(
        fs::read_to_string(&external_target).unwrap(),
        "{\"external\":\"unchanged\"}\n"
    );
    assert_eq!(
        fs::read_to_string(displaced_parent.join("target.json")).unwrap(),
        "{\"before\":true}\n"
    );
}

#[cfg(unix)]
#[test]
fn toml_target_leaf_symlink_is_still_materialized_without_changing_its_referent() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let referent = directory.path().join("referent.toml");
    let target = directory.path().join("target.toml");
    fs::write(&source, "managed = true\n").unwrap();
    fs::write(&referent, "managed = false\n").unwrap();
    symlink(&referent, &target).unwrap();

    let result = toml::overlay_toml_file(&source, &target, &TomlOverlayOptions::default())
        .expect("materialize a safe target leaf symlink");

    assert!(result.materialized_symlink);
    assert!(!fs::symlink_metadata(&target)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_to_string(&target).unwrap(), "managed = true\n");
    assert_eq!(fs::read_to_string(&referent).unwrap(), "managed = false\n");
}

#[test]
fn toml_respect_policy_suppresses_assignments_and_table_descendants() {
    let source =
        "[bridge]\nenv_key = \"SOURCE_PRIVATE\"\nmodel = \"new\"\n[disabled]\na = 1\nb = 2\n";
    let target = "[bridge]\n  # env_key = \"TARGET_PRIVATE\"\nmodel = \"old\"\n# [disabled]\n";
    let options = TomlOverlayOptions::default();

    let result = toml::overlay_toml_text(source, target, &options, &BTreeSet::new())
        .expect("comment-aware overlay");
    let parsed: toml_edit::DocumentMut = result.text.parse().expect("merged TOML");

    assert_eq!(
        result.suppressed,
        vec![
            key(&["bridge", "env_key"]),
            key(&["disabled", "a"]),
            key(&["disabled", "b"])
        ]
    );
    assert_eq!(parsed["bridge"]["model"].as_str(), Some("new"));
    assert!(parsed["bridge"].get("env_key").is_none());
    assert!(parsed.get("disabled").is_none());
    assert!(result.text.contains("TARGET_PRIVATE"));
    assert!(!result.text.contains("SOURCE_PRIVATE"));
}

#[test]
fn toml_activate_and_error_comment_policies_are_value_blind() {
    let activate = TomlOverlayOptions {
        commented_target_policy: CommentedTargetPolicy::Activate,
        ..TomlOverlayOptions::default()
    };
    let activated = toml::overlay_toml_text(
        "secret = \"SOURCE_PRIVATE\"\n",
        "# secret = \"TARGET_PRIVATE\"\n",
        &activate,
        &BTreeSet::new(),
    )
    .expect("activate source key");
    assert_eq!(activated.suppressed, Vec::<PathKey>::new());
    let parsed: toml_edit::DocumentMut = activated.text.parse().unwrap();
    assert_eq!(parsed["secret"].as_str(), Some("SOURCE_PRIVATE"));

    let reject = TomlOverlayOptions {
        commented_target_policy: CommentedTargetPolicy::Error,
        ..TomlOverlayOptions::default()
    };
    let error = toml::overlay_toml_text(
        "secret = \"SOURCE_PRIVATE\"\n",
        "# secret = \"TARGET_PRIVATE\"\n",
        &reject,
        &BTreeSet::new(),
    )
    .expect_err("comment suppression must be rejected");
    let message = format!("{error:#}");
    assert!(message.contains("secret"));
    assert!(!message.contains("SOURCE_PRIVATE"));
    assert!(!message.contains("TARGET_PRIVATE"));
}

#[test]
fn toml_exclusive_siblings_support_wildcards_and_exact_accounting() {
    let options = TomlOverlayOptions {
        exclusive_sibling_groups: vec![ExclusiveSiblingGroup {
            parent_pattern: key(&["model_providers", "*"]),
            keys: key(&["auth", "env_key"]),
        }],
        ..TomlOverlayOptions::default()
    };
    let result = toml::overlay_toml_text(
        "[model_providers.bridge]\nenv_key = \"NAME\"\nmodel = \"new\"\n",
        "[model_providers.bridge]\nauth = \"PRIVATE\"\nmodel = \"old\"\nlocal = true\n",
        &options,
        &BTreeSet::new(),
    )
    .expect("exclusive sibling overlay");
    let parsed: toml_edit::DocumentMut = result.text.parse().unwrap();
    let bridge = parsed["model_providers"]["bridge"].as_table().unwrap();

    assert!(bridge.get("auth").is_none());
    assert_eq!(bridge["env_key"].as_str(), Some("NAME"));
    assert_eq!(bridge["model"].as_str(), Some("new"));
    assert_eq!(bridge["local"].as_bool(), Some(true));
    assert_eq!(result.added, 1);
    assert_eq!(result.overwritten, 1);
    assert_eq!(result.removed, 1);
}

#[test]
fn toml_manifest_key_parser_accepts_one_level_wildcards_and_quoted_dots() {
    assert_eq!(
        toml::parse_toml_key_path(r#"model_providers.*."key.with.dot""#).unwrap(),
        key(&["model_providers", "*", "key.with.dot"])
    );
    assert_eq!(
        toml::render_toml_key_path(&["line\nbreak\"slash\\".to_owned()]),
        r#""line\nbreak\"slash\\""#
    );
}

#[test]
fn toml_invalid_exclusive_source_reports_keys_but_never_values() {
    let options = TomlOverlayOptions {
        exclusive_sibling_groups: vec![ExclusiveSiblingGroup {
            parent_pattern: key(&["provider"]),
            keys: key(&["auth", "env_key"]),
        }],
        ..TomlOverlayOptions::default()
    };
    let error = toml::overlay_toml_text(
        "[provider]\nauth = \"PRIVATE_A\"\nenv_key = \"PRIVATE_B\"\n",
        "",
        &options,
        &BTreeSet::new(),
    )
    .expect_err("invalid source must fail");
    let message = format!("{error:#}");
    assert!(message.contains("auth"));
    assert!(message.contains("env_key"));
    assert!(!message.contains("PRIVATE_A"));
    assert!(!message.contains("PRIVATE_B"));
}

#[test]
fn toml_receipt_excludes_suppressed_paths_and_is_idempotent() {
    let directory = tempdir().expect("tempdir");
    let source = directory.path().join("source.toml");
    let target = directory.path().join("target.toml");
    let state = directory.path().join("state");
    fs::write(&source, "[bridge]\nenv_key = \"NAME\"\nmodel = \"new\"\n").unwrap();
    fs::write(
        &target,
        "[bridge]\n# env_key = \"PRIVATE\"\nmodel = \"old\"\n",
    )
    .unwrap();

    let options = TomlOverlayOptions {
        reconcile_removed_keys: true,
        managed_overlay_id: Some("comment-aware".to_owned()),
        state_root: Some(state.clone()),
        ..TomlOverlayOptions::default()
    };
    let first = toml::overlay_toml_file(&source, &target, &options).expect("first overlay");
    assert!(first.ownership_changed);
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("overlays/comment-aware.json")).unwrap())
            .unwrap();
    assert_eq!(receipt["managed_paths"], json!([["bridge", "model"]]));

    let second = toml::overlay_toml_file(&source, &target, &options).expect("second overlay");
    assert!(!second.changed);
    assert!(!second.ownership_changed);
}

#[test]
fn target_wins_toml_mode_only_adds_missing_values() {
    let options = TomlOverlayOptions {
        conflict_policy: TomlConflictPolicy::Target,
        ..TomlOverlayOptions::default()
    };
    let result = toml::overlay_toml_text(
        "managed = 1\nmissing = 2\n",
        "# local layout\nmanaged = 9\nlocal = 3\n",
        &options,
        &BTreeSet::new(),
    )
    .expect("target-wins overlay");
    let parsed: toml_edit::DocumentMut = result.text.parse().unwrap();

    assert_eq!(parsed["managed"].as_integer(), Some(9));
    assert_eq!(parsed["missing"].as_integer(), Some(2));
    assert_eq!(parsed["local"].as_integer(), Some(3));
    assert_eq!(result.added, 1);
    assert_eq!(result.overwritten, 0);
}
