use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use sync_configs::manifest::{
    check_state_preconditions, deduplicate_and_validate_targets, load_manifest, load_profile_map,
    select_entries_for_profiles, select_reconcilers_for_profiles, Capability, DirectoryStrategy,
    LoadOptions, Mode, Privilege, StatePrecondition,
};
use sync_configs::paths::{
    lexical_normalize, normalize_user_path, resolve_config_path, PathContext, PathPlatform,
};
use tempfile::TempDir;

fn path_context(root: &Path) -> PathContext {
    let mut environment = BTreeMap::new();
    environment.insert(
        OsString::from("CONFIG_ROOT"),
        root.join("from-env").into_os_string(),
    );
    PathContext::new(
        PathPlatform::Posix,
        root.to_path_buf(),
        Some(root.join("home")),
        root.join("temp"),
        environment,
    )
}

fn load(root: &Path, manifest: &Path) -> sync_configs::manifest::Manifest {
    load_manifest(
        manifest,
        &LoadOptions::default().with_path_context(path_context(root)),
    )
    .expect("load manifest")
}

#[test]
fn loads_complete_root_fragments_defaults_and_typed_preconditions() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path();
    fs::create_dir_all(root.join("entries/nested")).expect("entries directory");
    fs::write(root.join("desired.toml"), "enabled = true\n").expect("source");
    fs::write(
        root.join("entries/nested/10-main.yaml"),
        r#"
entries:
  - name: app
    group: CLI
    subgroup: Example
    profiles: [desktop, linux]
    source: ./desired.toml
    target: ~/.config/example/config.toml
    directory_strategy: as_directory
    permissions:
      file: "0640"
      dir: 750
      recursive: true
    source_permissions:
      file: "0600"
    reconcile_existing: true
    pre_script: python ./prepare.py
    pre_script_on_fail: skip
    pre_script_privilege: user
    post_script: ./refresh
    post_script_on_fail: abort
    post_script_privilege: user
"#,
    )
    .expect("fragment");
    fs::write(
        root.join("manifest.yaml"),
        r#"
schema_version: 1
required_capabilities: [manifest-schema-v1, entries-directory-v1]
default_mode: copy
entries_dir: ./entries
state_preconditions:
  - type: json_fields
    path: ~/.local/state/example.json
    fields:
      current_version: 3
      pending: null
    remediation: Run the owner migration.
reconcilers:
  - name: owner
    executable: /usr/local/bin/owner
    source: ./desired.toml
    scope: user
    privilege: user
    protocol: dev-tools-reconcile-v1
    profiles: [desktop]
"#,
    )
    .expect("root manifest");

    let loaded = load(root, &root.join("manifest.yaml"));

    assert_eq!(loaded.schema_version, 1);
    assert_eq!(
        loaded.required_capabilities,
        vec![Capability::ManifestSchemaV1, Capability::EntriesDirectoryV1]
    );
    assert_eq!(loaded.default_mode, Mode::Copy);
    assert_eq!(loaded.entries.len(), 1);
    let entry = &loaded.entries[0];
    assert_eq!(entry.mode, Mode::Copy);
    assert_eq!(entry.directory_strategy, DirectoryStrategy::AsDirectory);
    assert_eq!(entry.source, root.join("desired.toml"));
    assert_eq!(entry.target, root.join("home/.config/example/config.toml"));
    assert_eq!(entry.profiles, vec!["desktop", "linux"]);
    assert_eq!(
        entry.permissions.as_ref().unwrap().file.unwrap().get(),
        0o640
    );
    assert_eq!(
        entry.permissions.as_ref().unwrap().dir.unwrap().get(),
        0o750
    );
    assert!(entry.permissions.as_ref().unwrap().recursive);
    assert_eq!(
        entry
            .source_permissions
            .as_ref()
            .unwrap()
            .file
            .unwrap()
            .get(),
        0o600
    );
    assert_eq!(entry.scope_label(), "CLI / Example");
    assert_eq!(loaded.reconcilers.len(), 1);
    assert_eq!(loaded.reconcilers[0].privilege, Privilege::User);
    assert_eq!(loaded.reconcilers[0].source, root.join("desired.toml"));
    assert!(matches!(
        loaded.state_preconditions.as_slice(),
        [StatePrecondition::JsonFields { .. }]
    ));
}

#[test]
fn rejects_unknown_fields_at_every_manifest_boundary() {
    let temp = TempDir::new().expect("temporary directory");
    let cases = [
        (
            "root",
            "entries: []\nfuture_root: true\n",
            "future_root",
        ),
        (
            "entry",
            "entries:\n  - source: ./a\n    target: ./b\n    future_entry: true\n",
            "future_entry",
        ),
        (
            "reconciler",
            "reconcilers:\n  - name: owner\n    executable: /bin/true\n    source: ./a\n    scope: user\n    privilege: user\n    protocol: dev-tools-reconcile-v1\n    future_reconciler: true\n",
            "future_reconciler",
        ),
    ];

    for (name, yaml, expected) in cases {
        let path = temp.path().join(format!("{name}.yaml"));
        fs::write(&path, yaml).expect("manifest case");
        let error = load_manifest(
            &path,
            &LoadOptions::default().with_path_context(path_context(temp.path())),
        )
        .expect_err("unknown field must fail closed");
        assert!(error.to_string().contains(expected), "{name}: {error}");
    }
}

#[test]
fn capability_contract_rejects_unknown_and_duplicate_requirements() {
    let temp = TempDir::new().expect("temporary directory");
    for (name, requirements, expected) in [
        (
            "unknown",
            "[manifest-schema-v1, teleport-config-v9]",
            "teleport-config-v9",
        ),
        (
            "duplicate",
            "[manifest-schema-v1, manifest-schema-v1]",
            "duplicate",
        ),
    ] {
        let path = temp.path().join(format!("{name}.yaml"));
        fs::write(
            &path,
            format!("schema_version: 1\nrequired_capabilities: {requirements}\nentries: []\n"),
        )
        .expect("manifest");
        let error = load_manifest(
            &path,
            &LoadOptions::default().with_path_context(path_context(temp.path())),
        )
        .expect_err("bad requirement must fail");
        assert!(error.to_string().contains(expected), "{name}: {error}");
    }
}

#[test]
fn client_capability_precondition_is_an_opt_in_old_client_exclusion_sentinel() {
    let temp = TempDir::new().expect("temporary directory");
    let path = temp.path().join("manifest.yaml");
    fs::write(
        &path,
        r#"
entries: []
state_preconditions:
  - type: client_capabilities
    schema_version: 1
    required_capabilities:
      - manifest-schema-v1
      - client-capabilities-precondition-v1
    remediation: Install the declared sync-configs release.
"#,
    )
    .expect("manifest");

    let loaded = load(temp.path(), &path);
    check_state_preconditions(&loaded).expect("compiled client satisfies requirements");
    assert!(matches!(
        loaded.state_preconditions.as_slice(),
        [StatePrecondition::ClientCapabilities { .. }]
    ));
}

#[test]
fn unsupported_schema_and_malformed_capability_preconditions_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    for (name, yaml, expected) in [
        (
            "root-schema",
            "schema_version: 2\nentries: []\n",
            "schema_version must be 1",
        ),
        (
            "precondition-schema",
            "state_preconditions:\n  - type: client_capabilities\n    schema_version: 2\n    required_capabilities: [manifest-schema-v1]\n    remediation: Upgrade.\nentries: []\n",
            "client_capabilities schema_version must be 1",
        ),
        (
            "precondition-unknown-field",
            "state_preconditions:\n  - type: json_fields\n    path: ./state.json\n    fields: {version: 1}\n    remediation: Repair.\n    guessed: true\nentries: []\n",
            "guessed",
        ),
        (
            "precondition-duplicate",
            "state_preconditions:\n  - type: client_capabilities\n    schema_version: 1\n    required_capabilities: [manifest-schema-v1, manifest-schema-v1]\n    remediation: Upgrade.\nentries: []\n",
            "duplicate",
        ),
    ] {
        let path = temp.path().join(format!("schema-{name}.yaml"));
        fs::write(&path, yaml).expect("manifest");
        let error = load_manifest(
            &path,
            &LoadOptions::default().with_path_context(path_context(temp.path())),
        )
        .expect_err("invalid schema contract");
        assert!(error.to_string().contains(expected), "{name}: {error}");
    }
}

#[test]
fn duplicate_targets_deduplicate_only_when_semantically_equivalent() {
    let temp = TempDir::new().expect("temporary directory");
    let equivalent = temp.path().join("equivalent.yaml");
    fs::write(
        &equivalent,
        r#"
default_mode: copy
entries:
  - name: first
    source: ./source
    target: ./target
    profiles: [one]
    post_script: 'printf first'
  - name: second
    source: ./source
    target: ./target
    profiles: [two]
    post_script: 'printf second'
"#,
    )
    .expect("equivalent manifest");
    let equivalent_manifest = load(temp.path(), &equivalent);
    assert_eq!(
        deduplicate_and_validate_targets(
            equivalent_manifest.entries,
            &path_context(temp.path()),
            &equivalent,
        )
        .expect("equivalent duplicates")
        .len(),
        1
    );

    let conflicting = temp.path().join("conflicting.yaml");
    fs::write(
        &conflicting,
        r#"
default_mode: copy
entries:
  - source: ./first
    target: ./target
  - source: ./second
    target: ./target
"#,
    )
    .expect("conflicting manifest");
    let conflicting_manifest = load(temp.path(), &conflicting);
    let error = deduplicate_and_validate_targets(
        conflicting_manifest.entries,
        &path_context(temp.path()),
        &conflicting,
    )
    .expect_err("conflicting duplicates must fail cleanly");
    assert!(
        error.to_string().contains("duplicate target conflict"),
        "{error}"
    );
}

#[test]
fn entry_dependencies_and_privileged_constraints_fail_closed() {
    let temp = TempDir::new().expect("temporary directory");
    let cases = [
        (
            "removed-keys",
            "entries:\n  - source: ./a\n    target: ./b\n    mode: json_overlay\n    reconcile_removed_keys: true\n",
            "managed_overlay_id",
        ),
        (
            "permission-mode",
            "entries:\n  - source: ./a\n    target: ./b\n    mode: symlink\n    permissions: {file: '0644'}\n",
            "only supported for copy",
        ),
        (
            "privileged-target",
            "entries:\n  - source: ./a\n    target: /etc/example\n    mode: copy\n    target_privilege: sudo\n    target_owner: root\n    target_group: root\n    target_parent_mode: '0755'\n",
            "permissions.file",
        ),
        (
            "comment-policy",
            "entries:\n  - source: ./a\n    target: ./b\n    mode: copy\n    commented_target_policy: respect\n",
            "toml_overlay",
        ),
    ];

    for (name, yaml, expected) in cases {
        let path = temp.path().join(format!("dependency-{name}.yaml"));
        fs::write(&path, yaml).expect("manifest");
        let error = load_manifest(
            &path,
            &LoadOptions::default().with_path_context(path_context(temp.path())),
        )
        .expect_err("invalid dependency must fail");
        assert!(error.to_string().contains(expected), "{name}: {error}");
    }
}

#[test]
fn valid_privileged_copy_and_toml_policies_preserve_their_full_contract() {
    let temp = TempDir::new().expect("temporary directory");
    fs::write(temp.path().join("source.conf"), "managed\n").expect("source");
    fs::write(
        temp.path().join("source.toml"),
        "[providers.primary]\nauth = 'env'\n",
    )
    .expect("toml source");
    let path = temp.path().join("manifest.yaml");
    fs::write(
        &path,
        r#"
entries:
  - name: system-policy
    source: ./source.conf
    target: /etc/example/policy.conf
    mode: copy
    target_privilege: sudo
    target_owner: root
    target_group: root
    target_parent_mode: "0755"
    permissions: {file: "0644"}
    reconcile_existing: true
  - name: provider
    source: ./source.toml
    target: ~/.config/example/providers.toml
    mode: toml_overlay
    commented_target_policy: error
    managed_overlay_id: providers
    reconcile_removed_keys: true
    mutually_exclusive_sibling_keys:
      - under: providers.*
        keys: [auth, env_key]
"#,
    )
    .expect("manifest");

    let loaded = load(temp.path(), &path);
    let privileged = &loaded.entries[0];
    assert_eq!(privileged.target_privilege, Privilege::Sudo);
    assert_eq!(privileged.target_parent_mode.unwrap().get(), 0o755);
    assert_eq!(
        privileged.permissions.as_ref().unwrap().file.unwrap().get(),
        0o644
    );
    assert!(privileged.reconcile_existing);
    let overlay = &loaded.entries[1];
    assert!(overlay.reconcile_removed_keys);
    assert_eq!(overlay.managed_overlay_id.as_deref(), Some("providers"));
    assert_eq!(
        overlay.exclusive_sibling_groups[0].under,
        vec!["providers", "*"]
    );
    assert_eq!(
        overlay.exclusive_sibling_groups[0].keys,
        vec!["auth", "env_key"]
    );
}

#[test]
fn source_and_manifest_overrides_are_resolved_without_double_selecting_sources() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path();
    fs::write(root.join("base.json"), "{}\n").expect("base source");
    fs::write(root.join("base.override.json"), "{}\n").expect("source override");
    fs::write(root.join("added.json"), "{}\n").expect("added source");
    fs::write(
        root.join("manifest.yaml"),
        "entries:\n  - name: base\n    source: ./base.json\n    target: ./base-target.json\n    mode: copy\n",
    )
    .expect("base manifest");
    fs::write(
        root.join("manifest.override.yaml"),
        "entries:\n  - name: replaced\n    source: ./base.json\n    target: ./replacement-target.json\n    mode: copy\n  - name: added\n    source: ./added.json\n    target: ./added-target.json\n    mode: copy\n",
    )
    .expect("manifest override");

    let loaded = load(root, &root.join("manifest.yaml"));
    assert_eq!(loaded.entries.len(), 2);
    assert_eq!(loaded.entries[0].name, "replaced");
    assert_eq!(loaded.entries[0].source, root.join("base.override.json"));
    assert_eq!(loaded.entries[1].name, "added");
    assert_eq!(
        loaded.override_path,
        Some(root.join("manifest.override.yaml"))
    );
}

#[test]
fn source_overrides_skip_privileged_targets_but_still_apply_to_user_targets() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path();
    for source in [
        "user.conf",
        "user.override.conf",
        "system.conf",
        "system.override.conf",
    ] {
        fs::write(root.join(source), "managed\n").expect("source fixture");
    }
    fs::write(
        root.join("manifest.yaml"),
        r#"
entries:
  - name: user-policy
    source: ./user.conf
    target: ./user-target.conf
    mode: copy
  - name: system-policy
    source: ./system.conf
    target: /etc/example/system.conf
    mode: copy
    target_privilege: sudo
    target_owner: root
    target_group: root
    target_parent_mode: "0755"
    permissions: {file: "0644"}
"#,
    )
    .expect("manifest");

    let loaded = load(root, &root.join("manifest.yaml"));

    assert_eq!(loaded.entries[0].source, root.join("user.override.conf"));
    assert_eq!(loaded.entries[1].source, root.join("system.conf"));
}

#[test]
fn profile_map_is_strict_at_root_and_preserves_first_seen_order() {
    let temp = TempDir::new().expect("temporary directory");
    let map = temp.path().join("profiles.yaml");
    fs::write(
        &map,
        "schema_version: 1\nprofiles:\n  laptop:\n    title: Example\n    selected: [linux, desktop, linux, '']\n",
    )
    .expect("profile map");
    let profiles = load_profile_map(&map, "laptop", Some("selected"), &path_context(temp.path()))
        .expect("profile selection");
    assert_eq!(profiles, vec!["linux", "desktop"]);

    fs::write(
        &map,
        "schema_version: 1\nprofiles: {laptop: [linux]}\nunknown: true\n",
    )
    .expect("invalid map");
    assert!(
        load_profile_map(&map, "laptop", None, &path_context(temp.path()))
            .expect_err("unknown root field")
            .to_string()
            .contains("unknown")
    );
}

#[test]
fn profile_selection_matches_the_python_013_contract_for_entries_and_reconcilers() {
    let temp = TempDir::new().expect("temporary directory");
    let path = temp.path().join("manifest.yaml");
    fs::write(
        &path,
        r#"
entries:
  - name: default
    source: ./default
    target: ./default-target
  - name: desktop
    profiles: [desktop]
    source: ./desktop
    target: ./desktop-target
reconcilers:
  - name: default-owner
    executable: /bin/true
    source: ./default
    scope: user
    privilege: user
    protocol: dev-tools-reconcile-v1
  - name: desktop-owner
    executable: /bin/true
    source: ./desktop
    scope: user
    privilege: user
    protocol: dev-tools-reconcile-v1
    profiles: [desktop]
"#,
    )
    .expect("manifest");
    let loaded = load(temp.path(), &path);

    assert_eq!(select_entries_for_profiles(&loaded.entries, &[]).len(), 1);
    assert_eq!(
        select_reconcilers_for_profiles(&loaded.reconcilers, &[]).len(),
        1
    );
    let active = vec!["desktop".to_owned()];
    assert_eq!(
        select_entries_for_profiles(&loaded.entries, &active)[0].name,
        "desktop"
    );
    assert_eq!(
        select_reconcilers_for_profiles(&loaded.reconcilers, &active)[0].name,
        "desktop-owner"
    );
}

#[test]
fn missing_json_field_does_not_satisfy_an_expected_null() {
    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path();
    fs::create_dir_all(root.join("home/.local/state")).expect("state parent");
    fs::write(root.join("home/.local/state/example.json"), "{}\n").expect("state");
    fs::write(
        root.join("manifest.yaml"),
        "state_preconditions:\n  - type: json_fields\n    path: ~/.local/state/example.json\n    fields: {pending: null}\n    remediation: Repair it.\nentries: []\n",
    )
    .expect("manifest");
    let loaded = load(root, &root.join("manifest.yaml"));
    let error = check_state_preconditions(&loaded).expect_err("missing differs from null");
    assert!(error.to_string().contains("pending"));
    assert!(error.to_string().contains("Repair it."));
}

#[test]
fn path_expansion_covers_posix_environment_home_and_windows_temp_aliases() {
    let root = PathBuf::from("/workspace");
    let mut env = BTreeMap::new();
    env.insert(OsString::from("ROOT"), OsString::from("/opt/config"));
    let posix = PathContext::new(
        PathPlatform::Posix,
        root,
        Some(PathBuf::from("/home/operator")),
        PathBuf::from("/tmp"),
        env,
    );
    assert_eq!(
        normalize_user_path("$ROOT/app", &posix).expect("env path"),
        PathBuf::from("/opt/config/app")
    );
    assert_eq!(
        normalize_user_path("${ROOT}/app", &posix).expect("braced env path"),
        PathBuf::from("/opt/config/app")
    );
    assert_eq!(
        normalize_user_path("~/.config/app", &posix).expect("home path"),
        PathBuf::from("/home/operator/.config/app")
    );

    let windows = PathContext::new(
        PathPlatform::Windows,
        PathBuf::from(r"C:\workspace"),
        Some(PathBuf::from(r"C:\Users\operator")),
        PathBuf::from(r"D:\Temp"),
        BTreeMap::new(),
    );
    assert_eq!(
        normalize_user_path("/tmp/sync-configs/plan", &windows).expect("temp alias"),
        PathBuf::from(r"D:\Temp\sync-configs\plan")
    );
    assert_eq!(
        normalize_user_path("~/AppData/Local", &windows).expect("windows home"),
        PathBuf::from(r"C:\Users\operator\AppData\Local")
    );
    assert_eq!(
        lexical_normalize(Path::new("../../config/../state"), PathPlatform::Posix),
        PathBuf::from("../../state")
    );

    let mut relative_environment = BTreeMap::new();
    relative_environment.insert(OsString::from("NAME"), OsString::from("manifest.yaml"));
    let relative = PathContext::new(
        PathPlatform::Posix,
        PathBuf::from("/work/config"),
        Some(PathBuf::from("/home/operator")),
        PathBuf::from("/tmp"),
        relative_environment,
    );
    assert_eq!(
        resolve_config_path("./nested/../$NAME", &relative).expect("relative config"),
        PathBuf::from("/work/config/manifest.yaml")
    );

    let mut windows_environment = BTreeMap::new();
    windows_environment.insert(
        OsString::from("LOCALAPPDATA"),
        OsString::from(r"C:\Users\operator\AppData\Local"),
    );
    let windows_with_environment = PathContext::new(
        PathPlatform::Windows,
        PathBuf::from(r"C:\workspace"),
        Some(PathBuf::from(r"C:\Users\operator")),
        PathBuf::from(r"D:\Temp"),
        windows_environment,
    );
    assert_eq!(
        normalize_user_path("%localappdata%/sync-configs", &windows_with_environment)
            .expect("case-insensitive Windows environment"),
        PathBuf::from(r"C:\Users\operator\AppData\Local\sync-configs")
    );
}
