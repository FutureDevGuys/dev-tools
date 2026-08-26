use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use dev_cache::adapter::{Adapter, AdapterContext};
use dev_cache::artifacts;
use dev_cache::cargo_intercept::{
    is_help_request, persistent_layout_override, repository_start, rustup_cargo_args,
};
use dev_cache::config::{Config, EnvironmentOverrides};
use dev_cache::dispatch::{classify_invocation, Dispatch};
use dev_cache::entrypoint::{self, EntrypointMode};
use dev_cache::gc::{self, GcOverrides};
use dev_cache::install;
use dev_cache::lease::RootLease;
use dev_cache::migrate;
use dev_cache::provenance;
use dev_cache::repository::Repository;
use dev_cache::resources::{self, NativeTool, ResourceKind};
use dev_cache::root::RootHandle;

#[cfg(unix)]
fn create_executable_alias(path: &Path) {
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_dev-cache"), path)
        .expect("publish executable alias");
}

#[test]
fn environment_overrides_machine_configuration_without_erasing_defaults() {
    let machine = Config::parse(
        r#"
version = 2
enabled = true
root = "/machine/cache"

[gc]
stale_after_days = 90
"#,
    )
    .expect("valid machine configuration");
    let resolved = machine
        .with_environment(EnvironmentOverrides {
            root: Some(PathBuf::from("/environment/cache")),
            mode: Some(true),
            real_cargo: None,
        })
        .expect("valid merged configuration");

    assert_eq!(resolved.root, Some(PathBuf::from("/environment/cache")));
    assert_eq!(resolved.gc.stale_after_days, 90);
    assert_eq!(resolved.gc.pressure_min_age_hours, 24);
}

#[test]
fn omitted_adapter_fields_in_v2_configs_keep_product_defaults() {
    let config = Config::parse(
        r#"
version = 2
enabled = true
root = "/machine/cache"

[adapters]
go = true
npm = true
"#,
    )
    .expect("valid earlier V2 configuration");

    assert!(config.adapters.go);
    assert!(config.adapters.npm);
    assert!(config.adapters.zig);
    assert!(config.adapters.meson);
    assert!(config.adapters.bun);
    assert!(config.adapters.yarn);
}

#[test]
fn build_info_exposes_checkout_independent_build_metadata() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .arg("--build-info")
        .output()
        .expect("run build-info");
    assert!(output.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("build-info JSON");
    assert!(payload["profile"].as_str().is_some());
    assert!(payload["built_unix"]
        .as_u64()
        .is_some_and(|value| value > 0));
    assert!(payload["git_commit"].as_str().is_some());
    assert!(payload["git_dirty"].as_str().is_some());
    assert!(payload.get("manifest_dir").is_none());
    assert!(payload.get("source_fingerprint").is_none());
}

#[test]
fn dev_cache_has_one_canonical_binary_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .arg("--version")
        .output()
        .expect("run canonical command name");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("dev-cache "));
}

#[test]
fn indirect_dispatch_matches_only_exact_supported_command_grammar() {
    assert_eq!(
        classify_invocation("python3.12", &["-m".into(), "pip".into(), "install".into()]),
        Dispatch::Adapter(Adapter::Pip)
    );
    assert_eq!(
        classify_invocation("py", &["-3.12".into(), "-m".into(), "pip".into()]),
        Dispatch::Adapter(Adapter::Pip)
    );
    assert_eq!(
        classify_invocation("corepack", &["pnpm".into(), "install".into()]),
        Dispatch::Adapter(Adapter::Pnpm)
    );
    assert_eq!(
        classify_invocation("corepack", &["yarn".into(), "install".into()]),
        Dispatch::Adapter(Adapter::Yarn)
    );
    assert_eq!(
        classify_invocation("bun", &["x".into(), "eslint".into()]),
        Dispatch::Adapter(Adapter::Bun)
    );
    for (command, args) in [
        ("python3", vec!["-mpip".into()]),
        ("python3", vec!["-m".into(), "pipx".into()]),
        (
            "python3",
            vec!["script.py".into(), "-m".into(), "pip".into()],
        ),
        ("py", vec!["-m".into(), "mesonbuild.mesonmain".into()]),
        ("corepack", vec!["pn".into(), "install".into()]),
    ] {
        assert_eq!(classify_invocation(command, &args), Dispatch::Delegate);
    }
}

#[test]
fn shared_entrypoint_inventory_drives_static_dynamic_and_mediated_dispatch() {
    for spec in entrypoint::STATIC_ENTRYPOINTS {
        assert!(
            dev_cache::dispatch::is_intercept_name(spec.command),
            "{}",
            spec.command
        );
        if let EntrypointMode::Direct(adapter) = spec.mode {
            assert_eq!(
                classify_invocation(spec.command, &[]),
                Dispatch::Adapter(adapter)
            );
        }
    }
    for (command, args, expected) in [
        ("pip3.12", vec![], Dispatch::Adapter(Adapter::Pip)),
        (
            "python3.12",
            vec!["-m".into(), "pip".into()],
            Dispatch::Adapter(Adapter::Pip),
        ),
        (
            "python3.12",
            vec!["-m".into(), "mesonbuild.mesonmain".into()],
            Dispatch::Adapter(Adapter::Meson),
        ),
        (
            "py",
            vec!["-3.12".into(), "-m".into(), "pip".into()],
            Dispatch::Adapter(Adapter::Pip),
        ),
        (
            "corepack",
            vec!["pnpm".into(), "install".into()],
            Dispatch::Adapter(Adapter::Pnpm),
        ),
        (
            "corepack",
            vec!["yarn".into(), "install".into()],
            Dispatch::Adapter(Adapter::Yarn),
        ),
    ] {
        assert_eq!(classify_invocation(command, &args), expected, "{command}");
    }
    for (command, args) in [
        ("npmx", vec![]),
        ("pnpmx", vec![]),
        ("pipx", vec![]),
        ("pip3.12x", vec![]),
        ("python3.12x", vec!["-m".into(), "pip".into()]),
        ("python3.12", vec!["-mpip".into()]),
        ("python3.12", vec!["-m".into(), "pipx".into()]),
        ("corepack", vec!["pnpmx".into()]),
        ("corepack", vec!["yarnx".into()]),
    ] {
        assert_eq!(
            classify_invocation(command, &args),
            Dispatch::Delegate,
            "{command}"
        );
        if command != "python3.12" && command != "corepack" {
            assert!(
                !dev_cache::dispatch::is_intercept_name(command),
                "{command}"
            );
        }
    }
}

#[test]
fn bun_and_yarn_route_only_independently_disposable_caches() {
    let context = AdapterContext {
        worktree_cache: PathBuf::from("/root/workspaces/id"),
        shared_cache: PathBuf::from("/root/cache"),
        domain_id: "test-domain".to_owned(),
        inherited: HashMap::new(),
    };
    let bun = Adapter::Bun.environment(&context);
    assert_eq!(
        bun.get("BUN_INSTALL_CACHE_DIR").map(String::as_str),
        Some("/root/cache/bun/install")
    );
    assert_eq!(
        bun.get("BUN_RUNTIME_TRANSPILER_CACHE_PATH")
            .map(String::as_str),
        Some("/root/cache/bun/transpiler")
    );
    assert!(!bun.keys().any(|key| key.contains("INSTALL_DIR")));

    let yarn = Adapter::Yarn.environment(&context);
    assert_eq!(
        yarn.get("YARN_CACHE_FOLDER").map(String::as_str),
        Some("/root/cache/yarn/classic")
    );
    assert_eq!(yarn.len(), 1);
}

#[test]
fn adapters_use_their_native_version_grammar() {
    assert_eq!(Adapter::Go.version_args(), ["version"]);
    assert_eq!(Adapter::Zig.version_args(), ["version"]);
    assert_eq!(Adapter::Cargo.version_args(), ["--version"]);
    assert!(Adapter::Temp.version_args().is_empty());
}

#[cfg(not(windows))]
#[test]
fn default_intercept_directory_is_product_owned_xdg_data() {
    let temp = tempfile::tempdir().expect("temporary data home");
    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["status", "--json"])
        .env("XDG_DATA_HOME", temp.path())
        .env("DEV_CACHE_MODE", "off")
        .output()
        .expect("inspect intercept directory");
    assert!(output.status.success());
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    assert_eq!(
        payload["intercept_directory"],
        temp.path()
            .join("dev-cache/intercepts")
            .to_string_lossy()
            .as_ref()
    );
}

#[test]
fn nested_routing_replaces_only_values_with_exact_managed_provenance() {
    let base = AdapterContext {
        worktree_cache: PathBuf::from("/root/workspaces/old"),
        shared_cache: PathBuf::from("/root/cache"),
        domain_id: "test-domain".to_owned(),
        inherited: HashMap::new(),
    };
    let mut upstream = Adapter::Go.environment(&base);
    provenance::attach(&base.inherited, &mut upstream, "go");

    let managed = Adapter::Go.environment(&AdapterContext {
        worktree_cache: PathBuf::from("/root/workspaces/new"),
        inherited: upstream.clone(),
        ..base.clone()
    });
    assert_eq!(
        managed.get("GOTMPDIR").map(String::as_str),
        Some("/root/workspaces/new/temp/go")
    );

    let mut changed = upstream;
    changed.insert("GOTMPDIR".to_owned(), "/user/chosen/temp".to_owned());
    let authoritative = Adapter::Go.environment(&AdapterContext {
        worktree_cache: PathBuf::from("/root/workspaces/new"),
        inherited: changed,
        ..base
    });
    assert!(!authoritative.contains_key("GOTMPDIR"));
}

#[test]
fn cache_root_relocation_is_atomic_and_preserves_domain_identity() {
    let temp = tempfile::tempdir().expect("temporary parent");
    let original = temp.path().join("foreign-cache");
    let replacement = temp.path().join("dev-cache");
    let root = RootHandle::initialize(&original).expect("initialize old-named root");
    fs::write(root.shared().join("sentinel"), b"preserved").expect("cache sentinel");
    let domain_id = root.domain_id.clone();
    let relocated = root.relocate(&replacement).expect("relocate cache root");
    assert!(!original.exists());
    assert_eq!(
        relocated.root,
        replacement.canonicalize().expect("canonical replacement")
    );
    assert_eq!(relocated.domain_id, domain_id);
    assert_eq!(
        fs::read(relocated.shared().join("sentinel")).unwrap(),
        b"preserved"
    );
}

#[test]
fn relocate_root_command_does_not_treat_the_destination_as_a_global_root_override() {
    let temp = tempfile::tempdir().expect("temporary parent");
    let original = temp.path().join("foreign-cache");
    let replacement = temp.path().join("dev-cache");
    let config_path = temp.path().join("config.toml");
    let root = RootHandle::initialize(&original).expect("initialize source root");
    fs::write(root.shared().join("sentinel"), b"preserved").expect("cache sentinel");
    fs::write(
        &config_path,
        format!(
            "version = 2\nenabled = true\nroot = {:?}\n",
            original.display().to_string()
        ),
    )
    .expect("write source configuration");

    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .arg("--config")
        .arg(&config_path)
        .args(["config", "relocate-root"])
        .arg(&replacement)
        .arg("--json")
        .output()
        .expect("relocate configured root through the public CLI");

    assert!(
        output.status.success(),
        "relocation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!original.exists());
    assert_eq!(
        fs::read(
            replacement
                .join("v2/domains")
                .join(&root.domain_id)
                .join("cache/sentinel")
        )
        .expect("read relocated sentinel"),
        b"preserved"
    );
    let config = Config::parse(&fs::read_to_string(&config_path).expect("read updated config"))
        .expect("parse updated config");
    assert_eq!(config.version, 2);
    assert_eq!(config.root, Some(replacement));
}

#[test]
fn cargo_help_classifier_covers_global_and_subcommand_forms() {
    for args in [
        vec![],
        vec!["--help"],
        vec!["-h"],
        vec!["help"],
        vec!["help", "build"],
        vec!["build", "--help"],
        vec!["+nightly", "test", "-h"],
    ] {
        assert!(is_help_request(args.iter().copied()), "not help: {args:?}");
    }
    assert!(!is_help_request(["build"]));
    assert!(!is_help_request(["test", "--", "--help"]));
}

#[test]
fn adapters_preserve_explicit_native_environment() {
    let mut inherited = HashMap::new();
    inherited.insert("GOCACHE".to_owned(), "/explicit/go-cache".to_owned());
    let context = AdapterContext {
        worktree_cache: PathBuf::from("/root/repos/id"),
        shared_cache: PathBuf::from("/root/shared"),
        domain_id: "test-domain".to_owned(),
        inherited,
    };

    let routed = Adapter::Go.environment(&context);
    assert!(!routed.contains_key("GOCACHE"));
    assert_eq!(
        routed.get("GOMODCACHE").map(String::as_str),
        Some("/root/shared/go-mod")
    );
    assert_eq!(
        routed.get("GOTMPDIR").map(String::as_str),
        Some("/root/repos/id/temp/go")
    );
}

#[test]
fn cargo_routes_only_intermediate_artifacts_with_native_workspace_hashing() {
    let context = AdapterContext {
        worktree_cache: PathBuf::from("/root/repos").join("a".repeat(160)),
        shared_cache: PathBuf::from("/root/shared"),
        domain_id: "test-domain".to_owned(),
        inherited: HashMap::new(),
    };

    let routed = Adapter::Cargo.environment(&context);
    assert_eq!(
        routed.get("CARGO_BUILD_BUILD_DIR").map(String::as_str),
        Some(
            format!(
                "/root/shared/cargo/intermediate/{}/{{workspace-path-hash}}",
                "a".repeat(160)
            )
            .as_str()
        )
    );
    assert!(!routed.contains_key("CARGO_TARGET_DIR"));
    for variable in ["TMPDIR", "TEMP", "TMP"] {
        assert!(!routed.contains_key(variable));
    }
}

#[test]
fn sccache_uses_a_stable_domain_endpoint_and_preserves_explicit_endpoints() {
    let context = AdapterContext {
        worktree_cache: PathBuf::from("/root/repos/id"),
        shared_cache: PathBuf::from("/root/shared"),
        domain_id: "stable-domain".to_owned(),
        inherited: HashMap::new(),
    };
    let first = Adapter::Sccache.environment(&context);
    let second = Adapter::Sccache.environment(&context);
    assert_eq!(
        first.get("SCCACHE_SERVER_PORT"),
        second.get("SCCACHE_SERVER_PORT")
    );
    let port = first["SCCACHE_SERVER_PORT"]
        .parse::<u16>()
        .expect("numeric port");
    assert!((10_000..60_000).contains(&port));

    let mut inherited = HashMap::new();
    inherited.insert("SCCACHE_SERVER_PORT".to_owned(), "4226".to_owned());
    let explicit = Adapter::Sccache.environment(&AdapterContext {
        inherited,
        ..context.clone()
    });
    assert!(!explicit.contains_key("SCCACHE_SERVER_PORT"));

    let mut remote = HashMap::new();
    remote.insert("SCCACHE_BUCKET".to_owned(), "user-selected".to_owned());
    let remote_backend = Adapter::Sccache.environment(&AdapterContext {
        inherited: remote,
        ..context
    });
    assert!(!remote_backend.contains_key("SCCACHE_DIR"));
    assert!(!remote_backend.contains_key("SCCACHE_SERVER_PORT"));
}

#[test]
fn v2_layout_is_isolated_by_the_persistent_domain_identity() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(temp.path()).expect("initialize root");
    assert!(root
        .platform_root
        .starts_with(root.root.join("v2").join("domains")));
    assert!(root.platform_root.ends_with(&root.domain_id));
    assert_ne!(root.marker.root_id, root.domain_id);
    assert!(root.shared().ends_with("cache"));
    assert!(root.repos().ends_with("workspaces"));
}

#[test]
fn root_initialization_is_owned_and_refuses_nonempty_directories() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(temp.path()).expect("initialize empty cache root");
    assert!(root.marker_path().is_file());
    assert_eq!(
        RootHandle::open(temp.path())
            .expect("reopen root")
            .marker
            .root_id,
        root.marker.root_id
    );

    let other = tempfile::tempdir().expect("other temporary directory");
    fs::write(other.path().join("unknown"), b"state").expect("write unknown state");
    let error = RootHandle::initialize(other.path()).expect_err("nonempty root must be rejected");
    assert!(error.to_string().contains("nonempty unmarked"));

    let unmarked = tempfile::tempdir().expect("unmarked root");
    let error = RootHandle::open(unmarked.path()).expect_err("unmarked root must be rejected");
    assert!(error.to_string().contains("cache-root marker"));
    assert_eq!(
        fs::read_dir(unmarked.path())
            .expect("inspect unmarked root")
            .count(),
        0
    );
}

#[test]
fn noncanonical_root_markers_are_not_adopted_implicitly() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let original = temp.path().join("unowned-root");
    fs::create_dir(&original).expect("unowned root");
    fs::write(original.join(".foreign-cache-root.json"), b"{}").expect("unknown marker");
    assert!(RootHandle::open(&original).is_err());
    assert!(RootHandle::initialize(&original).is_err());
}

#[test]
fn workspace_scope_exists_outside_git_and_uses_an_opaque_directory_name() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let project = temp.path().join("ordinary directory with spaces");
    fs::create_dir(&project).expect("project directory");
    fs::write(project.join("go.mod"), "module example.invalid/fixture\n").expect("project marker");

    let workspace = Repository::discover(&project, &root)
        .expect("discover workspace")
        .expect("non-Git workspace");
    assert_eq!(
        workspace.worktree,
        project.canonicalize().expect("canonical project")
    );
    let leaf = workspace
        .cache_dir
        .file_name()
        .and_then(|value| value.to_str())
        .expect("opaque scope leaf");
    assert_eq!(leaf.len(), 64);
    assert!(!workspace
        .cache_dir
        .to_string_lossy()
        .contains("ordinary directory"));
}

#[test]
fn artifact_cas_verifies_put_and_restore() {
    let root_dir = tempfile::tempdir().expect("root directory");
    let source_dir = tempfile::tempdir().expect("source directory");
    let root = RootHandle::initialize(root_dir.path()).expect("cache root");
    let source = source_dir.path().join("release.bin");
    fs::write(&source, b"finished build").expect("artifact source");

    let record = artifacts::put(&root, &source).expect("put artifact");
    assert_eq!(record.size, 14);
    let restored = source_dir.path().join("restored.bin");
    artifacts::get(&root, &record.digest, &restored).expect("restore artifact");
    assert_eq!(
        fs::read(restored).expect("read restored artifact"),
        b"finished build"
    );
    assert_eq!(
        artifacts::verify(&root, Some(&record.digest))
            .expect("verify artifact")
            .len(),
        1
    );
}

#[test]
fn garbage_collection_removes_artifact_objects_and_metadata_as_one_action() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let source = temp.path().join("artifact.bin");
    fs::write(&source, b"disposable artifact").expect("artifact source");
    let record = artifacts::put(&root, &source).expect("put artifact");
    let object = root
        .artifacts()
        .join(&record.digest[..2])
        .join(&record.digest);
    let metadata = root
        .platform_root
        .join("artifacts/metadata")
        .join(format!("{}.json", record.digest));
    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;

    let report = gc::collect(
        &root,
        &policy,
        0,
        &GcOverrides {
            stale_after_days: Some(0),
            ..GcOverrides::default()
        },
        true,
    )
    .expect("collect artifact");
    assert!(report.complete);
    assert_eq!(report.actions.len(), 1);
    assert_eq!(report.actions[0].kind, "artifact");
    assert!(!object.exists());
    assert!(!metadata.exists());
    assert_eq!(report.trash_backlog, 0);
}

#[test]
fn migration_is_dry_run_first_and_never_follows_symlinks() {
    let root_dir = tempfile::tempdir().expect("root directory");
    let source_dir = tempfile::tempdir().expect("source directory");
    let root = RootHandle::initialize(root_dir.path()).expect("cache root");
    fs::write(source_dir.path().join("cache.bin"), b"cache").expect("existing cache");

    let plan = migrate::migrate(&root, None, Adapter::Npm, source_dir.path(), false, false)
        .expect("migration plan");
    assert!(!plan.applied);
    assert!(!plan.destination.exists());
    let applied = migrate::migrate(&root, None, Adapter::Npm, source_dir.path(), true, false)
        .expect("migration apply");
    assert!(applied.destination.join("cache.bin").is_file());
    assert!(source_dir.path().join("cache.bin").is_file());
    let records = resources::list(&root).expect("migrated resource catalog");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, ResourceKind::NpmCache);
    assert_eq!(
        resources::absolute_path(&root, &records[0]).expect("catalog path"),
        applied.destination
    );
}

#[test]
fn migration_plan_reports_when_an_active_destination_cannot_be_replaced() {
    let root_dir = tempfile::tempdir().expect("root directory");
    let source_dir = tempfile::tempdir().expect("source directory");
    let root = RootHandle::initialize(root_dir.path()).expect("cache root");
    fs::write(source_dir.path().join("existing.bin"), b"existing").expect("existing cache");
    let destination = root.shared().join("npm");
    fs::create_dir_all(&destination).expect("active destination");
    fs::write(destination.join("active.bin"), b"active").expect("active cache");

    let plan = migrate::migrate(&root, None, Adapter::Npm, source_dir.path(), false, false)
        .expect("migration plan");

    assert_eq!(plan.destination_state, "nonempty");
    assert!(!plan.apply_supported);
    assert!(plan
        .abstention_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("not empty")));
    assert!(migrate::migrate(&root, None, Adapter::Npm, source_dir.path(), true, false).is_err());
    assert_eq!(
        fs::read(destination.join("active.bin")).expect("active cache remains"),
        b"active"
    );
}

#[cfg(unix)]
#[test]
fn migration_preserves_nested_symlinks_without_traversing_them() {
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::MetadataExt;

    let root_dir = tempfile::tempdir().expect("root directory");
    let source_dir = tempfile::tempdir().expect("source directory");
    let external_dir = tempfile::tempdir().expect("external directory");
    let root = RootHandle::initialize(root_dir.path()).expect("cache root");
    fs::write(source_dir.path().join("cache.bin"), b"cache").expect("cache object");
    fs::hard_link(
        source_dir.path().join("cache.bin"),
        source_dir.path().join("cache-hardlink.bin"),
    )
    .expect("hard link");
    fs::write(external_dir.path().join("durable.bin"), b"durable").expect("external object");
    symlink("cache.bin", source_dir.path().join("internal-link")).expect("internal link");
    symlink(
        source_dir.path().join("cache.bin"),
        source_dir.path().join("absolute-internal-link"),
    )
    .expect("absolute internal link");
    symlink(
        external_dir.path().join("durable.bin"),
        source_dir.path().join("external-link"),
    )
    .expect("external link");

    let applied = migrate::migrate(&root, None, Adapter::Npm, source_dir.path(), true, false)
        .expect("symlink-preserving migration");
    assert_eq!(
        fs::read_link(applied.destination.join("internal-link")).expect("internal link target"),
        PathBuf::from("cache.bin")
    );
    assert_eq!(
        fs::read_link(applied.destination.join("external-link")).expect("external link target"),
        external_dir.path().join("durable.bin")
    );
    assert_eq!(
        fs::read_link(applied.destination.join("absolute-internal-link"))
            .expect("rewritten internal link target"),
        applied.destination.join("cache.bin")
    );
    assert_eq!(
        fs::metadata(applied.destination.join("cache.bin"))
            .expect("cache metadata")
            .ino(),
        fs::metadata(applied.destination.join("cache-hardlink.bin"))
            .expect("hard-link metadata")
            .ino()
    );
    assert_eq!(
        fs::read(external_dir.path().join("durable.bin")).unwrap(),
        b"durable"
    );

    let source_link = external_dir.path().join("source-link");
    symlink(source_dir.path(), &source_link).expect("source root link");
    assert!(migrate::migrate(&root, None, Adapter::Pip, &source_link, false, false).is_err());

    let removable_source = external_dir.path().join("removable-cache");
    fs::create_dir(&removable_source).expect("removable source");
    fs::write(removable_source.join("cache.bin"), b"cache").expect("removable cache object");
    symlink(
        removable_source.join("cache.bin"),
        removable_source.join("absolute-internal-link"),
    )
    .expect("removable internal link");
    let removed = migrate::migrate(&root, None, Adapter::Pip, &removable_source, true, true)
        .expect("symlink-rewriting source removal");
    assert!(removed.source_removed);
    assert!(!removable_source.exists());
    assert_eq!(
        fs::read_link(removed.destination.join("absolute-internal-link"))
            .expect("published internal link target"),
        removed.destination.join("cache.bin")
    );
}

#[test]
fn migration_selects_independent_resources_without_guessing() {
    let root_dir = tempfile::tempdir().expect("root directory");
    let source_dir = tempfile::tempdir().expect("source directory");
    let root = RootHandle::initialize(root_dir.path()).expect("cache root");
    fs::write(source_dir.path().join("module.zip"), b"module").expect("existing module");

    let plan = migrate::migrate_resource(
        &root,
        None,
        Adapter::Go,
        Some("modules"),
        source_dir.path(),
        false,
        false,
    )
    .expect("Go module migration plan");
    assert_eq!(plan.destination, root.shared().join("go-mod"));
    assert!(migrate::migrate_resource(
        &root,
        None,
        Adapter::Go,
        Some("unknown"),
        source_dir.path(),
        false,
        false,
    )
    .is_err());
}

#[test]
fn migration_accepts_only_the_owned_v1_namespace_inside_the_root() {
    let root_dir = tempfile::tempdir().expect("root directory");
    let root = RootHandle::initialize(root_dir.path()).expect("cache root");
    let existing = root.root.join("v1").join(&root.platform).join("shared/npm");
    fs::create_dir_all(&existing).expect("existing cache");
    fs::write(existing.join("cache.bin"), b"cache").expect("existing object");
    assert!(migrate::migrate(&root, None, Adapter::Npm, &existing, false, false).is_ok());

    let unrelated = root.root.join("unrelated");
    fs::create_dir(&unrelated).expect("unrelated root child");
    assert!(migrate::migrate(&root, None, Adapter::Npm, &unrelated, false, false).is_err());
}

#[cfg(unix)]
#[test]
fn migration_removes_read_only_build_directories_after_copying() {
    use std::os::unix::fs::PermissionsExt;

    let root_dir = tempfile::tempdir().expect("root directory");
    let source_dir = tempfile::tempdir().expect("source parent");
    let source = source_dir.path().join("target");
    let locked = source.join("locked");
    fs::create_dir_all(&locked).expect("source build directory");
    fs::write(locked.join("cache.bin"), b"cache").expect("source build artifact");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).expect("lock source directory");
    let root = RootHandle::initialize(root_dir.path()).expect("cache root");

    let applied = migrate::migrate(&root, None, Adapter::Npm, &source, true, true)
        .expect("migration with source removal");

    assert!(applied.source_removed);
    assert!(!source.exists());
    assert!(applied.destination.join("locked/cache.bin").is_file());
}

#[test]
fn install_activation_owns_only_its_alias() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let bin = temp.path().join("bin");
    let intercept = temp.path().join("intercepts");
    install::install(&bin).expect("install current test executable");
    let activation = install::activate(&bin, &intercept).expect("activate Cargo alias");
    assert!(activation.changed);
    let cargo = activation.target;
    assert!(cargo.is_file());
    assert!(activation.rustup_target.is_file());
    assert!(install::deactivate(&intercept).expect("deactivate alias"));
    fs::create_dir_all(&intercept).expect("recreate intercept directory");
    fs::write(&cargo, b"unknown cargo").expect("unknown Cargo");
    assert!(install::deactivate(&intercept).is_err());
}

#[test]
fn deactivation_preflights_every_alias_before_removing_any() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let bin = temp.path().join("bin");
    let intercept = temp.path().join("intercepts");
    install::install(&bin).expect("install current test executable");
    let activation = install::activate(&bin, &intercept).expect("activate aliases");
    fs::remove_file(&activation.rustup_target).expect("replace Rustup alias");
    fs::write(&activation.rustup_target, b"unknown rustup").expect("unknown Rustup");

    assert!(install::deactivate(&intercept).is_err());
    assert!(
        activation.target.is_file(),
        "Cargo alias must remain untouched"
    );
}

#[test]
fn rustup_run_cargo_detection_preserves_every_cargo_argument() {
    let args = vec![
        "run".into(),
        "--install".into(),
        "stable".into(),
        "cargo".into(),
        "build".into(),
        "--release".into(),
    ];
    assert_eq!(
        rustup_cargo_args(&args).expect("Cargo command"),
        &[
            std::ffi::OsString::from("build"),
            std::ffi::OsString::from("--release")
        ]
    );
    assert!(rustup_cargo_args(&["show".into()]).is_none());
    assert!(rustup_cargo_args(&["run".into(), "stable".into(), "rustc".into()]).is_none());
}

#[test]
fn manifest_path_selects_the_repository_start_directory() {
    let current = Path::new("/tmp/caller");
    assert_eq!(
        repository_start(
            &[
                "build".into(),
                "--manifest-path".into(),
                "/workspace/project/Cargo.toml".into(),
            ],
            current,
        ),
        Path::new("/workspace/project")
    );
    assert_eq!(
        repository_start(
            &["metadata".into(), "--manifest-path=repo/Cargo.toml".into()],
            current,
        ),
        Path::new("/tmp/caller/repo")
    );
    assert_eq!(repository_start(&["check".into()], current), current);
}

#[test]
fn cargo_persistent_layout_configuration_is_authoritative() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let project = temp.path().join("project");
    fs::create_dir_all(project.join("nested")).expect("project");
    fs::create_dir(project.join(".cargo")).expect("Cargo config directory");
    fs::write(
        project.join(".cargo/config.toml"),
        "[build]\nbuild-dir = \"my-intermediate\"\n",
    )
    .expect("Cargo config");
    assert!(persistent_layout_override(&project.join("nested")).expect("inspect config"));

    fs::write(
        project.join(".cargo/config.toml"),
        "[build]\nrustc-wrapper = \"sccache\"\n",
    )
    .expect("wrapper-only Cargo config");
    assert!(!persistent_layout_override(&project.join("nested")).expect("inspect config"));
}

#[test]
fn activation_refreshes_an_owned_alias_after_binary_upgrade() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let bin = temp.path().join("bin");
    let intercept = temp.path().join("intercepts");
    let installed = install::install(&bin).expect("install current test executable");
    let first = install::activate(&bin, &intercept).expect("initial activation");
    assert!(first.changed);
    let canonical_marker = intercept.join(if cfg!(windows) {
        "cargo.exe.dev-cache-intercept.json"
    } else {
        "cargo.dev-cache-intercept.json"
    });
    assert!(canonical_marker.is_file());
    let mut upgraded = fs::read(&installed).expect("read installed binary");
    upgraded.extend_from_slice(b"upgrade");
    fs::remove_file(&installed).expect("replace installed binary inode");
    fs::write(&installed, &upgraded).expect("simulate installer upgrade");

    let refreshed = install::activate(&bin, &intercept).expect("refresh activation");
    assert!(refreshed.changed);
    assert_eq!(
        fs::read(refreshed.target).expect("read refreshed alias"),
        upgraded
    );
}

#[test]
fn central_rust_tool_receipt_supports_safe_adoption_and_uninstall() {
    fn prepare_install(root: &Path) -> (PathBuf, PathBuf) {
        let bin = root.join("bin");
        let dist = root.join("dist");
        fs::create_dir_all(&bin).expect("bin directory");
        fs::create_dir_all(&dist).expect("dist directory");
        let binary_name = if cfg!(windows) {
            "dev-cache.exe"
        } else {
            "dev-cache"
        };
        let source = dist.join(binary_name);
        let target = bin.join(binary_name);
        fs::copy(env!("CARGO_BIN_EXE_dev-cache"), &source).expect("dist binary");
        fs::copy(&source, &target).expect("installed binary");
        let marker = bin.join(format!(".{binary_name}.rust-tool.json"));
        fs::write(
            &marker,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 1,
                "package_name": "dev-cache",
                "binary_name": binary_name,
                "source_binary": source,
            }))
            .expect("ownership JSON"),
        )
        .expect("ownership receipt");
        (target, marker)
    }

    let adopted_root = tempfile::tempdir().expect("adoption root");
    let (adopted_target, external_marker) = prepare_install(adopted_root.path());
    assert_eq!(
        install::install(&adopted_root.path().join("bin")).expect("adopt central install"),
        adopted_target
    );
    assert!(!external_marker.exists());
    assert!(adopted_target
        .with_extension("dev-cache-owned.json")
        .is_file());
    assert!(!adopted_root.path().join("bin/foreign-cache").exists());
    let self_marker = adopted_target.with_extension("dev-cache-owned.json");
    let mut marker_payload: serde_json::Value =
        serde_json::from_slice(&fs::read(&self_marker).expect("self-owned marker"))
            .expect("self-owned marker JSON");
    marker_payload["created_unix"] = 1.into();
    fs::write(
        &self_marker,
        serde_json::to_vec_pretty(&marker_payload).expect("stable marker JSON"),
    )
    .expect("pin marker creation time");
    install::install(&adopted_root.path().join("bin")).expect("repeat self-install");
    let repeated_marker: serde_json::Value =
        serde_json::from_slice(&fs::read(&self_marker).expect("repeated marker"))
            .expect("repeated marker JSON");
    assert_eq!(repeated_marker["created_unix"], 1);
    marker_payload["digest"] = "stale-after-external-replacement".into();
    fs::write(
        &self_marker,
        serde_json::to_vec_pretty(&marker_payload).expect("stale marker JSON"),
    )
    .expect("write stale marker");
    install::install(&adopted_root.path().join("bin")).expect("repair matching install receipt");
    let repaired_marker: serde_json::Value =
        serde_json::from_slice(&fs::read(&self_marker).expect("repaired marker"))
            .expect("repaired marker JSON");
    assert_ne!(
        repaired_marker["digest"],
        "stale-after-external-replacement"
    );

    let removed_root = tempfile::tempdir().expect("removal root");
    let (removed_target, removed_marker) = prepare_install(removed_root.path());
    assert!(install::uninstall(
        &removed_root.path().join("bin"),
        &removed_root.path().join("intercepts")
    )
    .expect("remove central install"));
    assert!(!removed_target.exists());
    assert!(!removed_marker.exists());
}

#[cfg(unix)]
#[test]
fn cargo_alias_prepends_router_help_then_delegates_live_help() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let alias = temp.path().join("cargo");
    create_executable_alias(&alias);
    let real = temp.path().join("real-cargo");
    fs::write(&real, "#!/bin/sh\nprintf 'REAL CARGO HELP:%s\\n' \"$*\"\n").expect("fake Cargo");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("fake Cargo executable");

    let output = Command::new(&alias)
        .arg("build")
        .arg("--help")
        .env("DEV_CACHE_CONFIG", temp.path().join("missing.toml"))
        .env("DEV_CACHE_MODE", "off")
        .env("DEV_CACHE_REAL_CARGO", &real)
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("run Cargo alias");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(
        stdout.starts_with("dev-cache: routing disabled\n"),
        "{stdout}"
    );
    assert!(stdout.contains("Commands:\n"), "{stdout}");
    assert!(stdout.contains("artifacts"), "{stdout}");
    assert!(stdout.contains("REAL CARGO HELP:build --help"), "{stdout}");
}

#[cfg(unix)]
#[test]
fn active_alias_resolves_upstream_cargo_without_recursion() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    fs::create_dir_all(&intercept).expect("intercept directory");
    fs::create_dir_all(&upstream).expect("upstream directory");
    let alias = intercept.join("cargo");
    create_executable_alias(&alias);
    let real = upstream.join("cargo");
    fs::write(&real, "#!/bin/sh\nprintf 'UPSTREAM:%s\\n' \"$*\"\n").expect("fake Cargo");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("fake Cargo executable");

    let path = std::env::join_paths([intercept, upstream]).expect("test PATH");
    let output = Command::new(&alias)
        .arg("metadata")
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", temp.path().join("missing.toml"))
        .env("DEV_CACHE_MODE", "off")
        .env_remove("DEV_CACHE_REAL_CARGO")
        .output()
        .expect("run active Cargo alias");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "UPSTREAM:metadata\n"
    );
}

#[cfg(unix)]
#[test]
fn delegated_intercept_preserves_final_stdout_stderr_and_exit_code() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    fs::create_dir_all(&intercept).expect("intercept directory");
    fs::create_dir_all(&upstream).expect("upstream directory");
    let alias = intercept.join("go");
    create_executable_alias(&alias);
    let real = upstream.join("go");
    fs::write(
        &real,
        "#!/bin/sh\nprintf 'FINAL-STDOUT:%s\\n' \"$*\"\nprintf 'FINAL-STDERR:%s\\n' \"$*\" >&2\nexit 23\n",
    )
    .expect("fake Go");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("fake Go executable");

    let output = Command::new(&alias)
        .args(["test", "./..."])
        .env(
            "PATH",
            std::env::join_paths([intercept, upstream]).expect("test PATH"),
        )
        .env("DEV_CACHE_CONFIG", temp.path().join("missing.toml"))
        .env("DEV_CACHE_MODE", "off")
        .output()
        .expect("run delegated Go alias");
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "FINAL-STDOUT:test ./...\n"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "FINAL-STDERR:test ./...\n"
    );
}

#[cfg(unix)]
#[test]
fn go_alias_routes_shared_caches_outside_git_without_moving_outputs() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let project = temp.path().join("plain project");
    fs::create_dir(&project).expect("project directory");
    fs::write(
        project.join("go.mod"),
        "module example.invalid/cache-test\n",
    )
    .expect("Go marker");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        toml::to_string(&config).expect("serialize config"),
    )
    .expect("config");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    fs::create_dir(&intercept).expect("intercepts");
    fs::create_dir(&upstream).expect("upstream");
    let alias = intercept.join("go");
    create_executable_alias(&alias);
    let real = upstream.join("go");
    fs::write(
        &real,
        "#!/bin/sh\nprintf 'CACHE=%s\\nMOD=%s\\nTMP=%s\\nARGS=%s\\n' \"$GOCACHE\" \"$GOMODCACHE\" \"$GOTMPDIR\" \"$*\"\n",
    )
    .expect("fake Go");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("real mode");
    let path = std::env::join_paths([
        intercept,
        upstream,
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ])
    .expect("PATH");

    let output = Command::new(&alias)
        .args(["test", "./..."])
        .current_dir(&project)
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env_remove("GOCACHE")
        .env_remove("GOMODCACHE")
        .env_remove("GOTMPDIR")
        .output()
        .expect("run Go alias");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8");
    assert!(stdout.contains(root.shared().join("go-build").to_string_lossy().as_ref()));
    assert!(stdout.contains(root.shared().join("go-mod").to_string_lossy().as_ref()));
    assert!(stdout.contains("/temp/go"));
    assert!(stdout.ends_with("ARGS=test ./...\n"));
}

#[cfg(unix)]
#[test]
fn python_module_dispatch_routes_only_exact_pip_grammar() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).expect("config TOML")).expect("config");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    let project = temp.path().join("ordinary project");
    fs::create_dir(&intercept).expect("intercepts");
    fs::create_dir(&upstream).expect("upstream");
    fs::create_dir(&project).expect("project");
    let alias = intercept.join("python3");
    create_executable_alias(&alias);
    let real = upstream.join("python3");
    fs::write(
        &real,
        "#!/bin/sh\nprintf 'PIP_CACHE=%s\\nARGS=%s\\n' \"$PIP_CACHE_DIR\" \"$*\"\n",
    )
    .expect("fake Python");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("Python mode");
    let path =
        std::env::join_paths([intercept, upstream, PathBuf::from("/usr/bin")]).expect("PATH");

    let routed = Command::new(&alias)
        .args(["-m", "pip", "download", "fixture"])
        .current_dir(&project)
        .env("PATH", &path)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env_remove("PIP_CACHE_DIR")
        .output()
        .expect("run routed Python pip");
    assert!(routed.status.success());
    let routed_stdout = String::from_utf8_lossy(&routed.stdout);
    assert!(routed_stdout.contains(root.shared().join("pip").to_string_lossy().as_ref()));
    assert!(routed_stdout.ends_with("ARGS=-m pip download fixture\n"));

    let delegated = Command::new(&alias)
        .args(["-mpip", "download", "fixture"])
        .current_dir(&project)
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env_remove("PIP_CACHE_DIR")
        .output()
        .expect("delegate near-match Python grammar");
    assert!(delegated.status.success());
    assert_eq!(
        String::from_utf8_lossy(&delegated.stdout),
        "PIP_CACHE=\nARGS=-mpip download fixture\n"
    );
}

#[cfg(unix)]
#[test]
fn fully_overridden_adapter_delegates_even_when_the_managed_root_is_missing() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let config = Config {
        root: Some(temp.path().join("missing-root")),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).expect("config TOML")).expect("config");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    fs::create_dir(&intercept).expect("intercepts");
    fs::create_dir(&upstream).expect("upstream");
    let alias = intercept.join("npm");
    create_executable_alias(&alias);
    let real = upstream.join("npm");
    fs::write(
        &real,
        "#!/bin/sh\nprintf 'CACHE=<%s>\\nARGS=%s\\n' \"$npm_config_cache\" \"$*\"\n",
    )
    .expect("fake npm");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("npm mode");
    let path =
        std::env::join_paths([intercept, upstream, PathBuf::from("/usr/bin")]).expect("PATH");
    let output = Command::new(&alias)
        .args(["install", "fixture"])
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", config_path)
        .env("npm_config_cache", "")
        .output()
        .expect("delegate overridden npm");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "CACHE=<>\nARGS=install fixture\n"
    );
}

#[cfg(unix)]
#[test]
fn bun_global_store_and_yarn_berry_abstain_without_losing_other_resources() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).expect("config TOML")).expect("config");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    let project = temp.path().join("project");
    fs::create_dir(&intercept).expect("intercepts");
    fs::create_dir(&upstream).expect("upstream");
    fs::create_dir(&project).expect("project");
    fs::write(
        project.join("bunfig.toml"),
        "[install]\nglobalStore = true\n",
    )
    .expect("bunfig");
    let path = std::env::join_paths([
        intercept.clone(),
        upstream.clone(),
        PathBuf::from("/usr/bin"),
    ])
    .expect("PATH");

    let bun_alias = intercept.join("bun");
    create_executable_alias(&bun_alias);
    let real_bun = upstream.join("bun");
    fs::write(
        &real_bun,
        "#!/bin/sh\nif [ \"$1\" = --version ]; then printf '1.4.0\\n'; exit 0; fi\nprintf 'INSTALL=%s\\nTRANSPILE=%s\\n' \"$BUN_INSTALL_CACHE_DIR\" \"$BUN_RUNTIME_TRANSPILER_CACHE_PATH\"\n",
    )
    .expect("fake Bun");
    fs::set_permissions(&real_bun, fs::Permissions::from_mode(0o755)).expect("Bun mode");
    let bun = Command::new(&bun_alias)
        .arg("install")
        .current_dir(&project)
        .env("PATH", &path)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env_remove("BUN_INSTALL_CACHE_DIR")
        .env_remove("BUN_RUNTIME_TRANSPILER_CACHE_PATH")
        .output()
        .expect("run Bun");
    assert!(bun.status.success());
    let bun_stdout = String::from_utf8_lossy(&bun.stdout);
    assert!(bun_stdout.starts_with("INSTALL=\n"));
    assert!(bun_stdout.contains(
        root.shared()
            .join("bun/transpiler")
            .to_string_lossy()
            .as_ref()
    ));

    let yarn_alias = intercept.join("yarn");
    create_executable_alias(&yarn_alias);
    let real_yarn = upstream.join("yarn");
    fs::write(
        &real_yarn,
        "#!/bin/sh\nif [ \"$1\" = --version ]; then printf '4.5.0\\n'; exit 0; fi\nprintf 'YARN_CACHE=%s\\n' \"$YARN_CACHE_FOLDER\"\n",
    )
    .expect("fake Yarn");
    fs::set_permissions(&real_yarn, fs::Permissions::from_mode(0o755)).expect("Yarn mode");
    let yarn = Command::new(&yarn_alias)
        .arg("install")
        .current_dir(&project)
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env_remove("YARN_CACHE_FOLDER")
        .output()
        .expect("run Yarn Berry");
    assert!(yarn.status.success());
    assert_eq!(String::from_utf8_lossy(&yarn.stdout), "YARN_CACHE=\n");
}

#[cfg(unix)]
#[test]
fn compiler_alias_uses_ccache_and_disabled_mode_delegates_the_real_compiler() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let project = temp.path().join("plain project");
    fs::create_dir(&project).expect("project directory");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).expect("config TOML")).expect("config");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    fs::create_dir(&intercept).expect("intercepts");
    fs::create_dir(&upstream).expect("upstream");
    let alias = intercept.join("gcc");
    create_executable_alias(&alias);
    let compiler = upstream.join("gcc");
    fs::write(&compiler, "#!/bin/sh\nprintf 'REAL:%s\\n' \"$*\"\n").expect("compiler");
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755)).expect("compiler mode");
    let ccache = upstream.join("ccache");
    fs::write(
        &ccache,
        "#!/bin/sh\nprintf 'CCACHE_DIR=%s\\nCCACHE_TMP=%s\\nARGS=%s\\n' \"$CCACHE_DIR\" \"$CCACHE_TEMPDIR\" \"$*\"\n",
    )
    .expect("ccache");
    fs::set_permissions(&ccache, fs::Permissions::from_mode(0o755)).expect("ccache mode");
    let path =
        std::env::join_paths([intercept, upstream, PathBuf::from("/usr/bin")]).expect("PATH");

    let routed = Command::new(&alias)
        .args(["-c", "source.c", "-o", "source.o"])
        .current_dir(&project)
        .env("PATH", &path)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env_remove("CCACHE_DISABLE")
        .env_remove("CCACHE_DIR")
        .env_remove("CCACHE_TEMPDIR")
        .output()
        .expect("routed compiler");
    assert!(routed.status.success());
    let stdout = String::from_utf8_lossy(&routed.stdout);
    assert!(stdout.contains(root.shared().join("ccache").to_string_lossy().as_ref()));
    assert!(stdout.contains("/temp/ccache"));
    assert!(stdout.contains(compiler.to_string_lossy().as_ref()));

    let disabled = Command::new(&alias)
        .args(["-c", "disabled.c"])
        .current_dir(&project)
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", config_path)
        .env("CCACHE_DISABLE", "1")
        .output()
        .expect("disabled compiler routing");
    assert!(disabled.status.success());
    assert_eq!(
        String::from_utf8_lossy(&disabled.stdout),
        "REAL:-c disabled.c\n"
    );
}

#[cfg(unix)]
#[test]
fn native_cli_override_does_not_materialize_the_managed_resource() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let project = temp.path().join("project");
    fs::create_dir(&project).expect("project");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).expect("config TOML")).expect("config");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    fs::create_dir(&intercept).expect("intercepts");
    fs::create_dir(&upstream).expect("upstream");
    let alias = intercept.join("npm");
    create_executable_alias(&alias);
    let real = upstream.join("npm");
    fs::write(
        &real,
        "#!/bin/sh\nprintf 'CACHE=%s\\nARGS=%s\\n' \"$npm_config_cache\" \"$*\"\n",
    )
    .expect("npm");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("npm mode");
    let explicit = temp.path().join("explicit npm cache");
    let path =
        std::env::join_paths([intercept, upstream, PathBuf::from("/usr/bin")]).expect("PATH");

    let output = Command::new(&alias)
        .args(["install", "--cache"])
        .arg(&explicit)
        .current_dir(project)
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", config_path)
        .env_remove("npm_config_cache")
        .output()
        .expect("npm override");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("CACHE=\n"));
    assert!(!root.shared().join("npm").exists());
}

#[cfg(unix)]
#[test]
fn upstream_cargo_symlink_preserves_multicall_dispatch_name() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir().expect("temporary directory");
    let intercept = temp.path().join("intercepts");
    let upstream = temp.path().join("upstream");
    fs::create_dir_all(&intercept).expect("intercept directory");
    fs::create_dir_all(&upstream).expect("upstream directory");
    let alias = intercept.join("cargo");
    create_executable_alias(&alias);
    let dispatcher = upstream.join("rustup");
    fs::write(
        &dispatcher,
        "#!/bin/sh\n[ \"${0##*/}\" = cargo ] || exit 23\nprintf 'CARGO:%s\\n' \"$*\"\n",
    )
    .expect("fake multicall dispatcher");
    fs::set_permissions(&dispatcher, fs::Permissions::from_mode(0o755))
        .expect("fake dispatcher executable");
    symlink(&dispatcher, upstream.join("cargo")).expect("Cargo dispatcher symlink");

    let path = std::env::join_paths([intercept, upstream]).expect("test PATH");
    let output = Command::new(&alias)
        .arg("build")
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", temp.path().join("missing.toml"))
        .env("DEV_CACHE_MODE", "off")
        .env_remove("DEV_CACHE_REAL_CARGO")
        .output()
        .expect("run Cargo alias through multicall dispatcher");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "CARGO:build\n");
}

#[cfg(unix)]
#[test]
fn cargo_alias_routes_a_non_git_workspace_without_wrapper_noise() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root_dir = temp.path().join("cache-root");
    fs::create_dir(&root_dir).expect("root directory");
    let root = RootHandle::initialize(&root_dir).expect("cache root");
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).expect("repository directory");
    let manifest = repo.join("Cargo.toml");
    fs::write(
        &manifest,
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("fixture manifest");
    let caller = temp.path().join("caller");
    fs::create_dir(&caller).expect("caller directory");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        toml::to_string(&config).expect("serialize config"),
    )
    .expect("write config");
    let alias = temp.path().join("cargo");
    create_executable_alias(&alias);
    let real = temp.path().join("real-cargo");
    fs::write(
        &real,
        "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'cargo 1.98.0 (fixture)\\n'; exit 0; fi\nprintf 'BUILD=%s\\nTARGET=%s\\nARGS=%s\\n' \"$CARGO_BUILD_BUILD_DIR\" \"$CARGO_TARGET_DIR\" \"$*\"\n",
    )
    .expect("fake Cargo");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("fake Cargo executable");

    let output = Command::new(&alias)
        .args(["check", "--manifest-path"])
        .arg(&manifest)
        .current_dir(&caller)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env("DEV_CACHE_REAL_CARGO", &real)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_BUILD_DIR")
        .output()
        .expect("run routed Cargo");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(
        stdout.starts_with("BUILD="),
        "unexpected wrapper output: {stdout}"
    );
    assert!(
        stdout.contains(root.shared().to_string_lossy().as_ref()),
        "{stdout}"
    );
    assert!(stdout.contains("{workspace-path-hash}"), "{stdout}");
    assert!(stdout.contains("TARGET=\n"), "{stdout}");
    assert!(
        stdout.ends_with(&format!(
            "ARGS=check --manifest-path {}\n",
            manifest.display()
        )),
        "{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn older_cargo_preserves_native_targets_and_still_uses_sccache() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let project = temp.path().join("project");
    fs::create_dir(&project).expect("project");
    fs::write(
        project.join("Cargo.toml"),
        "[package]\nname='fixture'\nversion='0.1.0'\n",
    )
    .expect("manifest");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).expect("config TOML")).expect("config");
    let cargo_home = temp.path().join("cargo-home");
    fs::create_dir(&cargo_home).expect("Cargo home");
    let alias = temp.path().join("cargo");
    create_executable_alias(&alias);
    let real = temp.path().join("real-cargo");
    fs::write(
        &real,
        "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'cargo 1.90.0 (fixture)'; exit 0; fi\nprintf 'BUILD=%s\\nTARGET=%s\\nWRAPPER=%s\\nSCCACHE=%s\\n' \"$CARGO_BUILD_BUILD_DIR\" \"$CARGO_TARGET_DIR\" \"$RUSTC_WRAPPER\" \"$SCCACHE_DIR\"\n",
    )
    .expect("Cargo");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("Cargo mode");
    let upstream = temp.path().join("upstream");
    fs::create_dir(&upstream).expect("upstream");
    let sccache = upstream.join("sccache");
    fs::write(&sccache, "#!/bin/sh\nexit 0\n").expect("sccache");
    fs::set_permissions(&sccache, fs::Permissions::from_mode(0o755)).expect("sccache mode");
    let path = std::env::join_paths([upstream, PathBuf::from("/usr/bin")]).expect("PATH");

    let output = Command::new(alias)
        .arg("check")
        .current_dir(project)
        .env("PATH", path)
        .env("DEV_CACHE_CONFIG", config_path)
        .env("DEV_CACHE_REAL_CARGO", real)
        .env("CARGO_HOME", cargo_home)
        .env_remove("CARGO_BUILD_BUILD_DIR")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("SCCACHE_DIR")
        .output()
        .expect("older Cargo");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("BUILD=\nTARGET=\nWRAPPER=sccache\n"),
        "{stdout}"
    );
    assert!(stdout.contains(root.shared().join("sccache").to_string_lossy().as_ref()));
}

#[cfg(unix)]
#[test]
fn rustup_alias_routes_run_cargo_without_changing_rustup_arguments() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root_dir = temp.path().join("cache-root");
    fs::create_dir(&root_dir).expect("root directory");
    let root = RootHandle::initialize(&root_dir).expect("cache root");
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).expect("repository directory");
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("git init")
        .success());
    let manifest = repo.join("Cargo.toml");
    fs::write(
        &manifest,
        "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("fixture manifest");
    let caller = temp.path().join("caller");
    fs::create_dir(&caller).expect("caller directory");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        toml::to_string(&config).expect("serialize config"),
    )
    .expect("write config");
    let alias = temp.path().join("rustup");
    create_executable_alias(&alias);
    let real = temp.path().join("real-rustup");
    fs::write(
        &real,
        "#!/bin/sh\ncase \"$*\" in *'cargo --version') printf 'cargo 1.98.0 (fixture)\\n'; exit 0;; esac\nprintf 'BUILD=%s\\nTARGET=%s\\nARGS=%s\\n' \"$CARGO_BUILD_BUILD_DIR\" \"$CARGO_TARGET_DIR\" \"$*\"\n",
    )
    .expect("fake Rustup");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("fake Rustup executable");

    let output = Command::new(&alias)
        .args(["run", "stable", "cargo", "check", "--manifest-path"])
        .arg(&manifest)
        .arg("--locked")
        .current_dir(&caller)
        .env("DEV_CACHE_CONFIG", &config_path)
        .env("DEV_CACHE_REAL_RUSTUP", &real)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_BUILD_DIR")
        .output()
        .expect("run routed Rustup Cargo command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains(root.shared().to_string_lossy().as_ref()));
    assert!(stdout.contains("{workspace-path-hash}"));
    assert!(stdout.contains("TARGET=\n"));
    assert!(
        stdout.ends_with(&format!(
            "ARGS=run stable cargo check --manifest-path {} --locked\n",
            manifest.display()
        )),
        "{stdout}"
    );
}

#[cfg(unix)]
#[test]
fn rustup_cargo_alias_prepends_router_help_then_delegates_live_help() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let alias = temp.path().join("rustup");
    create_executable_alias(&alias);
    let real = temp.path().join("real-rustup");
    fs::write(
        &real,
        "#!/bin/sh\nprintf 'REAL RUSTUP CARGO HELP:%s\\n' \"$*\"\n",
    )
    .expect("fake Rustup");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).expect("fake Rustup executable");

    let output = Command::new(&alias)
        .args(["run", "stable", "cargo", "build", "--help"])
        .env("DEV_CACHE_CONFIG", temp.path().join("missing.toml"))
        .env("DEV_CACHE_MODE", "off")
        .env("DEV_CACHE_REAL_RUSTUP", &real)
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("run Rustup Cargo help through alias");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(
        stdout.starts_with("dev-cache: routing disabled\n"),
        "{stdout}"
    );
    assert!(stdout.contains("Commands:\n"), "{stdout}");
    assert!(stdout.contains("artifacts"), "{stdout}");
    assert!(
        stdout.contains("REAL RUSTUP CARGO HELP:run stable cargo build --help"),
        "{stdout}"
    );
}

#[test]
fn cli_usage_errors_return_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .arg("definitely-not-a-command")
        .output()
        .expect("run invalid command");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
}

#[test]
fn completion_scripts_are_generated_from_the_live_cli_for_supported_shells() {
    for shell in ["bash", "elvish", "fish", "power-shell", "zsh"] {
        let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
            .args(["completion", shell])
            .output()
            .expect("generate completion script");
        assert!(
            output.status.success(),
            "{shell}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("dev-cache"), "{shell}: {stdout}");
        assert!(stdout.contains("completion"), "{shell}: {stdout}");
    }
}

#[test]
fn completion_file_generation_is_atomic_and_idempotent() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let output_path = temp.path().join("nested/dev-cache.bash");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_dev-cache"))
            .args(["--json", "completion", "bash", "--output"])
            .arg(&output_path)
            .output()
            .expect("generate managed completion")
    };
    let first = run();
    assert!(first.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&first.stdout).unwrap()["changed"],
        true
    );
    let contents = fs::read(&output_path).expect("generated completion");
    let second = run();
    assert!(second.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&second.stdout).unwrap()["changed"],
        false
    );
    assert_eq!(fs::read(&output_path).unwrap(), contents);
    assert_eq!(
        fs::read_dir(output_path.parent().unwrap()).unwrap().count(),
        1
    );
}

#[test]
fn explicit_missing_configuration_is_an_operational_error() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["--config"])
        .arg(temp.path().join("missing.toml"))
        .arg("status")
        .output()
        .expect("run with missing explicit config");
    assert_eq!(output.status.code(), Some(10));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("explicit configuration does not exist")
    );
}

#[test]
fn root_initialization_is_idempotent_for_the_same_configured_volume() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = temp.path().join("cache-root");
    let config = temp.path().join("config.toml");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_dev-cache"))
            .args(["--config"])
            .arg(&config)
            .args(["config", "init-root"])
            .arg(&root)
            .output()
            .expect("initialize root")
    };

    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(String::from_utf8_lossy(&first.stdout).contains("initialized: true"));
    let second = run();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(String::from_utf8_lossy(&second.stdout).contains("initialized: false"));
}

#[test]
fn doctor_reports_an_invalid_root_without_aborting() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let config = Config {
        root: Some(temp.path().join("missing-root")),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        toml::to_string(&config).expect("serialize config"),
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["--json", "--config"])
        .arg(&config_path)
        .arg("doctor")
        .output()
        .expect("run doctor");
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let root = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "root")
        .expect("root check");
    assert_eq!(root["ok"], false);
    assert!(root["error"]
        .as_str()
        .is_some_and(|error| error.contains("missing-root")));
    assert!(report["status"]["error"]
        .as_str()
        .is_some_and(|error| error.contains("missing-root")));
}

#[cfg(unix)]
fn write_fake_tool(directory: &Path, command: &str, version: &str) {
    use std::os::unix::fs::PermissionsExt;

    let path = directory.join(command);
    fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{version}'\n")).expect("write fake tool");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
        .expect("make fake tool executable");
}

#[cfg(unix)]
fn doctor_fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("doctor fixture");
    let upstream = temp.path().join("upstream");
    let bin = temp.path().join("bin");
    let data = temp.path().join("data");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    fs::create_dir_all(&upstream).expect("upstream directory");
    for command in [
        "cargo",
        "rustup",
        "sccache",
        "go",
        "npm",
        "npx",
        "pnpm",
        "pnpx",
        "corepack",
        "uv",
        "uvx",
        "pip",
        "pip3",
        "pip3.12",
        "python",
        "python3",
        "python3.12",
        "ccache",
        "cc",
        "c++",
        "gcc",
        "g++",
        "clang",
        "clang++",
        "zig",
        "meson",
        "bun",
        "bunx",
        "yarn",
        "yarnpkg",
        "gradle",
        "mvn",
        "cmake",
        "ninja",
        "poetry",
        "pdm",
    ] {
        let version = match command {
            "meson" => "1.3.2",
            "bun" => "1.1.0",
            "yarn" => "1.22.22",
            "go" => "go version go1.24 linux/amd64",
            "zig" => "0.16.0",
            _ => "tool 1.0.0",
        };
        write_fake_tool(&upstream, command, version);
    }
    let config_path = temp.path().join("config.toml");
    let config = Config {
        root: Some(root.root),
        ..Config::default()
    };
    fs::write(&config_path, toml::to_string(&config).expect("config TOML")).expect("write config");

    let install = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["install", "--activate", "--bin-dir"])
        .arg(&bin)
        .arg("--intercept-dir")
        .arg(data.join("dev-cache/intercepts"))
        .env_clear()
        .env("HOME", temp.path())
        .env("XDG_DATA_HOME", &data)
        .env("PATH", &upstream)
        .output()
        .expect("install and activate fixture");
    assert!(
        install.status.success(),
        "{}",
        String::from_utf8_lossy(&install.stderr)
    );
    (temp, upstream, data, config_path)
}

#[cfg(unix)]
fn run_doctor(
    temp: &tempfile::TempDir,
    upstream: &Path,
    data: &Path,
    config: &Path,
    path: std::ffi::OsString,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["--json", "--config"])
        .arg(config)
        .arg("doctor")
        .current_dir(temp.path())
        .env_clear()
        .env("HOME", temp.path())
        .env("XDG_DATA_HOME", data)
        .env("PATH", path)
        .env("DEV_CACHE_TEST_UPSTREAM", upstream)
        .output()
        .expect("run doctor")
}

#[cfg(unix)]
#[test]
fn doctor_proves_every_installed_supported_entrypoint_is_globally_active() {
    let (temp, upstream, data, config) = doctor_fixture();
    let intercept = data.join("dev-cache/intercepts");
    let path = std::env::join_paths([&intercept, &upstream]).expect("doctor PATH");
    let output = run_doctor(&temp, &upstream, &data, &config, path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let entrypoints = report["activation"]["entrypoints"]
        .as_array()
        .expect("entrypoint matrix");
    for command in [
        "cargo",
        "rustup",
        "sccache",
        "go",
        "npm",
        "npx",
        "pnpm",
        "pnpx",
        "corepack",
        "uv",
        "uvx",
        "pip",
        "pip3",
        "pip3.12",
        "python",
        "python3",
        "python3.12",
        "ccache",
        "cc",
        "c++",
        "gcc",
        "g++",
        "clang",
        "clang++",
        "zig",
        "meson",
        "bun",
        "bunx",
        "yarn",
        "yarnpkg",
    ] {
        let entry = entrypoints
            .iter()
            .find(|entry| entry["command"] == command)
            .unwrap_or_else(|| panic!("missing {command} doctor entry"));
        assert_eq!(entry["state"], "routed", "{command}: {entry}");
        assert_eq!(entry["owned"], true, "{command}: {entry}");
        assert_eq!(entry["effective_is_intercept"], true, "{command}: {entry}");
        assert_eq!(entry["recursive"], false, "{command}: {entry}");
    }
    let active = report["status"]["routed_adapters"]
        .as_array()
        .expect("active adapters");
    for adapter in [
        "cargo", "sccache", "go", "npm", "pnpm", "uv", "pip", "ccache", "zig", "meson", "bun",
        "yarn",
    ] {
        assert!(active.iter().any(|value| value == adapter), "{adapter}");
    }
    assert_eq!(report["status"]["routing_complete"], true);
    let unmanaged = report["activation"]["unmanaged_by_design"]
        .as_array()
        .expect("unmanaged inventory");
    for command in ["gradle", "mvn", "cmake", "ninja", "poetry", "pdm"] {
        let entry = unmanaged
            .iter()
            .find(|entry| entry["command"] == command)
            .unwrap_or_else(|| panic!("missing unmanaged {command}"));
        assert_eq!(entry["state"], "unmanaged_by_design");
    }
}

#[cfg(unix)]
#[test]
fn doctor_fails_when_an_installed_entrypoint_is_shadowed() {
    let (temp, upstream, data, config) = doctor_fixture();
    let shadow = temp.path().join("shadow");
    fs::create_dir(&shadow).expect("shadow directory");
    write_fake_tool(&shadow, "npx", "shadow 1.0.0");
    let intercept = data.join("dev-cache/intercepts");
    let path = std::env::join_paths([&shadow, &intercept, &upstream]).expect("shadowed PATH");
    let output = run_doctor(&temp, &upstream, &data, &config, path);
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let entry = report["activation"]["entrypoints"]
        .as_array()
        .expect("entrypoint matrix")
        .iter()
        .find(|entry| entry["command"] == "npx")
        .expect("npx entry");
    assert_eq!(entry["state"], "shadowed");
    assert_eq!(entry["mandatory"], true);
    assert!(!report["status"]["routed_adapters"]
        .as_array()
        .expect("active adapters")
        .iter()
        .any(|value| value == "npm"));
}

#[cfg(unix)]
#[test]
fn doctor_distinguishes_stale_shell_from_missing_persistent_activation() {
    let (temp, upstream, data, config) = doctor_fixture();
    let intercept = data.join("dev-cache/intercepts");
    fs::write(
        temp.path().join(".profile"),
        format!("export PATH=\"{}:$PATH\"\n", intercept.display()),
    )
    .expect("persistent activation");
    let output = run_doctor(
        &temp,
        &upstream,
        &data,
        &config,
        std::env::join_paths([&upstream]).expect("inactive PATH"),
    );
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert_eq!(report["activation"]["path_state"], "stale_current_shell");

    fs::remove_file(temp.path().join(".profile")).expect("remove persistent activation");
    let output = run_doctor(
        &temp,
        &upstream,
        &data,
        &config,
        std::env::join_paths([&upstream]).expect("inactive PATH"),
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert_eq!(
        report["activation"]["path_state"],
        "persistent_configuration_missing"
    );
}

#[cfg(unix)]
#[test]
fn status_does_not_call_an_unactivated_installed_tool_routed() {
    let (temp, upstream, data, config) = doctor_fixture();
    let output = run_doctor(
        &temp,
        &upstream,
        &data,
        &config,
        std::env::join_paths([&upstream]).expect("inactive PATH"),
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert!(report["status"]["routed_adapters"]
        .as_array()
        .expect("active adapters")
        .is_empty());
}

#[cfg(unix)]
#[test]
fn status_does_not_call_a_native_resource_override_routed() {
    let (temp, upstream, data, config) = doctor_fixture();
    let intercept = data.join("dev-cache/intercepts");
    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["--json", "--config"])
        .arg(&config)
        .arg("status")
        .env_clear()
        .env("HOME", temp.path())
        .env("XDG_DATA_HOME", &data)
        .env(
            "PATH",
            std::env::join_paths([&intercept, &upstream]).expect("doctor PATH"),
        )
        .env("GOCACHE", "")
        .output()
        .expect("run status");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    assert!(!report["routed_adapters"]
        .as_array()
        .expect("routed adapters")
        .iter()
        .any(|adapter| adapter == "go"));
    assert!(report["override_reasons"]
        .as_array()
        .expect("override reasons")
        .iter()
        .any(|reason| reason
            .as_str()
            .is_some_and(|reason| reason.starts_with("go:GOCACHE:"))));
}

#[cfg(unix)]
#[test]
fn doctor_exits_unhealthy_when_status_report_generation_fails() {
    let (temp, upstream, data, config_path) = doctor_fixture();
    let config = Config::parse(&fs::read_to_string(&config_path).expect("read config"))
        .expect("parse config");
    let root =
        RootHandle::open(config.root.as_deref().expect("configured root")).expect("open root");
    let repository = Repository::discover(temp.path(), &root)
        .expect("discover repository")
        .expect("repository scope");
    repository
        .touch(&root)
        .expect("materialize repository identity");
    fs::write(repository.cache_dir.join("identity.json"), b"not-json")
        .expect("corrupt disposable identity fixture");

    let intercept = data.join("dev-cache/intercepts");
    let output = run_doctor(
        &temp,
        &upstream,
        &data,
        &config_path,
        std::env::join_paths([&intercept, &upstream]).expect("doctor PATH"),
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert!(report["status"]["error"]
        .as_str()
        .is_some_and(|error| error.contains("repository identity")));
    let status_check = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "status-report")
        .expect("status report check");
    assert_eq!(status_check["ok"], false);
}

#[cfg(unix)]
#[test]
fn doctor_reports_absence_unsupported_versions_overrides_and_abstentions_distinctly() {
    let (temp, upstream, data, config_path) = doctor_fixture();
    write_fake_tool(&upstream, "yarn", "3.8.0");
    let mut config = Config::parse(&fs::read_to_string(&config_path).expect("read config"))
        .expect("parse config");
    config.adapters.go = false;
    config.cargo.real_path = Some(upstream.join("cargo"));
    fs::write(
        &config_path,
        toml::to_string(&config).expect("serialize config"),
    )
    .expect("write config");
    let intercept = data.join("dev-cache/intercepts");
    let output = run_doctor(
        &temp,
        &upstream,
        &data,
        &config_path,
        std::env::join_paths([&intercept, &upstream]).expect("doctor PATH"),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let entrypoints = report["activation"]["entrypoints"]
        .as_array()
        .expect("entrypoint matrix");
    let state = |command: &str| {
        entrypoints
            .iter()
            .find(|entry| entry["command"] == command)
            .unwrap_or_else(|| panic!("missing {command}"))["state"]
            .as_str()
            .expect("state")
    };
    assert_eq!(state("py"), "absent");
    assert_eq!(state("go"), "intentional_abstention");
    assert_eq!(state("yarn"), "unsupported_version");
    let cargo = entrypoints
        .iter()
        .find(|entry| entry["command"] == "cargo")
        .expect("cargo entry");
    assert!(cargo["classifications"]
        .as_array()
        .expect("classifications")
        .iter()
        .any(|classification| classification == "explicit_override"));
    assert_eq!(cargo["state"], "routed");
    let active = report["status"]["routed_adapters"]
        .as_array()
        .expect("active adapters");
    assert!(!active.iter().any(|adapter| adapter == "go"));
    assert!(!active.iter().any(|adapter| adapter == "yarn"));
}

#[cfg(unix)]
#[test]
fn doctor_rejects_duplicate_and_stale_intercept_precedence() {
    let (temp, upstream, data, config) = doctor_fixture();
    let intercept = data.join("dev-cache/intercepts");
    let duplicate_path =
        std::env::join_paths([&intercept, &intercept, &upstream]).expect("duplicate PATH");
    let output = run_doctor(&temp, &upstream, &data, &config, duplicate_path);
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    assert_eq!(
        report["activation"]["path_state"],
        "duplicate_intercept_path"
    );

    let stale = temp.path().join("stale-intercepts");
    fs::create_dir(&stale).expect("stale intercept directory");
    fs::copy(intercept.join("npm"), stale.join("npm")).expect("stale npm intercept");
    fs::copy(
        intercept.join("npm.dev-cache-intercept.json"),
        stale.join("npm.dev-cache-intercept.json"),
    )
    .expect("stale npm ownership");
    let output = run_doctor(
        &temp,
        &upstream,
        &data,
        &config,
        std::env::join_paths([&stale, &intercept, &upstream]).expect("stale PATH"),
    );
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let npm = report["activation"]["entrypoints"]
        .as_array()
        .expect("entrypoint matrix")
        .iter()
        .find(|entry| entry["command"] == "npm")
        .expect("npm entry");
    assert_eq!(npm["state"], "stale_intercept_precedence");
    assert_eq!(npm["mandatory"], true);
}

#[test]
fn status_reports_an_intentionally_empty_native_override() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        toml::to_string(&config).expect("serialize config"),
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["--json", "--config"])
        .arg(&config_path)
        .arg("status")
        .env("GOCACHE", "")
        .output()
        .expect("inspect status overrides");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("status JSON");
    assert!(report["override_reasons"]
        .as_array()
        .expect("override reasons")
        .iter()
        .any(|reason| reason.as_str().is_some_and(
            |reason| reason.contains("go:GOCACHE: inherited native environment override")
        )));
    assert!(!report["effective_paths"]["go"]
        .as_array()
        .expect("Go paths")
        .iter()
        .any(|path| path
            .as_str()
            .is_some_and(|path| path.ends_with("/go-build"))));
}

#[cfg(unix)]
#[test]
fn explicit_cargo_exec_composes_sccache_environment() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).expect("repository directory");
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("git init")
        .success());
    let config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        toml::to_string(&config).expect("serialize config"),
    )
    .expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .args(["--config"])
        .arg(&config_path)
        .args([
            "exec",
            "cargo",
            "sh",
            "-c",
            "printf '%s\\n%s\\n' \"$CARGO_BUILD_BUILD_DIR\" \"$SCCACHE_DIR\"",
        ])
        .current_dir(&repo)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("SCCACHE_DIR")
        .output()
        .expect("run explicit Cargo adapter");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 output");
    assert!(stdout.contains("/cache/cargo/intermediate/"), "{stdout}");
    assert!(stdout.contains("/{workspace-path-hash}\n"), "{stdout}");
    assert!(stdout.contains("/cache/sccache\n"), "{stdout}");
}

#[test]
fn garbage_collection_is_dry_run_first_and_honors_active_leases() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let repo = temp.path().join("repo");
    fs::create_dir(&repo).expect("repository directory");
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(&repo)
        .status()
        .expect("git init")
        .success());
    let repository = Repository::discover(&repo, &root)
        .expect("discover repository")
        .expect("Git worktree");
    repository
        .touch(&root)
        .expect("materialize repository identity");
    let disposable = repository.cache_dir.join("temp/generic/cache.bin");
    fs::create_dir_all(disposable.parent().expect("cache parent")).expect("cache directory");
    fs::write(disposable, b"cache").expect("cache artifact");
    let resource_ids = resources::register_routed(
        &root,
        Adapter::Temp,
        &HashMap::from([(
            "TMPDIR".to_owned(),
            repository
                .cache_dir
                .join("temp/generic")
                .to_string_lossy()
                .into_owned(),
        )]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .expect("register generic temp resource");
    resources::complete(&root, &resource_ids).expect("complete generic temp resource");
    let policy = Config::default().gc;
    let overrides = GcOverrides {
        stale_after_days: Some(0),
        ..GcOverrides::default()
    };

    let lease = RootLease::shared(&root, "test-build").expect("shared build lease");
    assert!(gc::collect_if_idle(&root, &policy, 120, &overrides, true)
        .expect("automatic GC deferral")
        .is_none());
    let busy = gc::collect(&root, &policy, 120, &overrides, true)
        .expect_err("GC must refuse an active build lease");
    assert!(busy.to_string().contains("busy"));
    drop(lease);

    let plan = gc::collect(&root, &policy, 120, &overrides, false).expect("GC plan");
    assert!(!plan.applied);
    assert!(plan
        .actions
        .iter()
        .any(|action| action.kind == "repository"));
    assert!(repository.cache_dir.exists());
    let applied = gc::collect(&root, &policy, 120, &overrides, true).expect("GC apply");
    assert!(applied.applied);
    assert!(!repository.cache_dir.exists());
    assert!(resources::list(&root)
        .expect("reconciled resource catalog")
        .is_empty());
}

#[test]
fn garbage_collection_never_panics_or_escapes_on_malformed_artifact_metadata() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let metadata = root.platform_root.join("artifacts/metadata");
    fs::create_dir_all(&metadata).expect("artifact metadata directory");
    fs::write(
        metadata.join("malformed.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "digest": "x",
            "size": 1,
            "original_name": "untrusted",
            "created_unix": 0,
            "last_verified_unix": 0
        }))
        .expect("serialize malformed record"),
    )
    .expect("write malformed record");
    let sentinel = root.platform_root.join("must-not-move");
    fs::write(&sentinel, b"durable").expect("external sentinel");
    let policy = Config::default().gc;
    let overrides = GcOverrides {
        stale_after_days: Some(0),
        ..GcOverrides::default()
    };

    let result = std::panic::catch_unwind(|| gc::collect(&root, &policy, 0, &overrides, true));

    assert!(result.is_ok(), "malformed metadata must not panic");
    assert!(result.expect("non-panicking result").is_ok());
    assert_eq!(fs::read(sentinel).expect("sentinel remains"), b"durable");
    assert!(metadata.join("malformed.json").exists());
}

#[test]
fn repository_discovery_is_read_only_until_a_routed_command_starts() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    fs::write(
        workspace.join("go.mod"),
        b"module example.invalid/read-only\n",
    )
    .expect("workspace manifest");

    let repository = Repository::discover(&workspace, &root)
        .expect("workspace discovery")
        .expect("workspace scope");
    assert!(!repository.cache_dir.exists());
    repository.touch(&root).expect("start routed command");
    assert!(repository.cache_dir.join("identity.json").is_file());
}

#[test]
fn garbage_collection_abstains_from_forged_repository_ownership() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    fs::write(workspace.join("go.mod"), b"module example.invalid/forged\n")
        .expect("workspace manifest");
    let repository = Repository::discover(&workspace, &root)
        .expect("workspace discovery")
        .expect("workspace scope");
    repository.touch(&root).expect("repository ownership");
    let identity = repository.cache_dir.join("identity.json");
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(&identity).expect("identity bytes"))
            .expect("identity JSON");
    record["schema_version"] = serde_json::json!(1);
    fs::write(&identity, serde_json::to_vec(&record).expect("forged JSON"))
        .expect("forged identity");

    let report = gc::collect(
        &root,
        &Config::default().gc,
        120,
        &GcOverrides {
            stale_after_days: Some(0),
            ..GcOverrides::default()
        },
        true,
    )
    .expect("safe collection");
    assert!(report
        .abstentions
        .iter()
        .any(|item| item.reason.contains("invalid repository ownership")));
    assert!(repository.cache_dir.exists());
    assert_eq!(
        gc::maintenance_status(&root)
            .expect("maintenance status")
            .repository_issues
            .len(),
        1
    );
}

#[test]
fn resource_catalog_tracks_each_disposable_resource_independently() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let values = HashMap::from([
        (
            "GOCACHE".to_owned(),
            root.shared()
                .join("go-build")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "GOMODCACHE".to_owned(),
            root.shared().join("go-mod").to_string_lossy().into_owned(),
        ),
        (
            "GOTMPDIR".to_owned(),
            root.shared().join("go-tmp").to_string_lossy().into_owned(),
        ),
    ]);
    let ids = resources::register_routed(
        &root,
        Adapter::Go,
        &values,
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .expect("register Go resources");
    resources::complete(&root, &ids).expect("complete Go resources");

    let records = resources::list(&root).expect("resource catalog");
    let kinds = records
        .iter()
        .map(|record| record.kind)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        kinds,
        BTreeSet::from([
            ResourceKind::GoBuild,
            ResourceKind::GoModule,
            ResourceKind::GoTemp,
        ])
    );
    assert!(records.iter().all(|record| {
        resources::catalog_path(&root, &record.resource_id).starts_with(root.control())
            && !resources::catalog_path(&root, &record.resource_id)
                .starts_with(resources::absolute_path(&root, record).expect("resource path"))
    }));
}

#[test]
fn garbage_collection_abstains_from_tampered_catalog_paths() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let cache = root.shared().join("npm");
    fs::create_dir_all(&cache).expect("cache directory");
    fs::write(cache.join("cache.bin"), b"cache").expect("cache data");
    let values = HashMap::from([(
        "npm_config_cache".to_owned(),
        cache.to_string_lossy().into_owned(),
    )]);
    let ids = resources::register_routed(
        &root,
        Adapter::Npm,
        &values,
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .expect("register npm cache");
    let catalog = resources::catalog_path(&root, &ids[0]);
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(&catalog).expect("catalog bytes")).expect("catalog JSON");
    record["relative_path"] = serde_json::json!("../../outside");
    fs::write(
        &catalog,
        serde_json::to_vec(&record).expect("tampered JSON"),
    )
    .expect("tampered catalog");
    let sentinel = temp.path().join("outside");
    fs::write(&sentinel, b"durable").expect("external sentinel");

    let report = gc::collect(
        &root,
        &Config::default().gc,
        0,
        &GcOverrides {
            stale_after_days: Some(0),
            ..GcOverrides::default()
        },
        true,
    )
    .expect("safe GC");
    assert!(report.actions.is_empty());
    assert_eq!(report.abstentions.len(), 1);
    assert_eq!(fs::read(sentinel).expect("sentinel remains"), b"durable");
    assert!(cache.exists());
}

#[test]
fn garbage_collection_preserves_resources_with_sticky_safety_hazards() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let cache = root.shared().join("uv");
    let values = HashMap::from([(
        "UV_CACHE_DIR".to_owned(),
        cache.to_string_lossy().into_owned(),
    )]);
    let ids = resources::register_routed(
        &root,
        Adapter::Uv,
        &values,
        &NativeTool::default(),
        &BTreeSet::from(["uv-symlink-mode".to_owned()]),
    )
    .expect("register uv cache");
    resources::complete(&root, &ids).expect("complete uv cache");
    fs::create_dir_all(&cache).expect("cache directory");
    fs::write(cache.join("cache.bin"), b"cache").expect("cache data");

    let report = gc::collect(
        &root,
        &Config::default().gc,
        0,
        &GcOverrides {
            stale_after_days: Some(0),
            ..GcOverrides::default()
        },
        true,
    )
    .expect("safe GC");
    assert!(report.actions.is_empty());
    assert!(report
        .abstentions
        .iter()
        .any(|item| item.reason.contains("uv-symlink-mode")));
    assert!(cache.join("cache.bin").is_file());
}

#[test]
fn garbage_collection_recovers_committed_transactional_trash() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let transaction = "recoverable";
    let trash = root.trash().join(transaction);
    fs::create_dir_all(&trash).expect("transaction trash");
    fs::write(trash.join("cache.bin"), b"cache").expect("trash data");
    let journal = root.control().join("gc-journal/recoverable.json");
    fs::write(
        &journal,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "transaction_id": transaction,
            "resource_id": null,
            "original_paths": [],
            "trash_path": trash,
            "committed": true,
            "created_unix": 0
        }))
        .expect("journal JSON"),
    )
    .expect("journal");

    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;
    let report =
        gc::collect(&root, &policy, 120, &GcOverrides::default(), true).expect("recover trash");
    assert!(report.complete);
    assert_eq!(report.trash_backlog, 0);
    assert!(!trash.exists());
    assert!(!journal.exists());
}

#[test]
fn garbage_collection_rolls_back_uncommitted_transactional_trash() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let transaction = "interrupted";
    let original = root.platform_root.join("manual-original/cache.bin");
    let trash = root.trash().join(transaction);
    fs::create_dir_all(&trash).expect("transaction trash");
    fs::write(trash.join("0"), b"cache").expect("partially moved data");
    let journal = root.control().join("gc-journal/interrupted.json");
    fs::write(
        &journal,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "transaction_id": transaction,
            "resource_id": null,
            "original_paths": [original],
            "trash_path": trash,
            "committed": false,
            "created_unix": 0
        }))
        .expect("journal JSON"),
    )
    .expect("journal");
    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;

    let report =
        gc::collect(&root, &policy, 120, &GcOverrides::default(), true).expect("recover trash");
    assert!(report.complete);
    assert_eq!(fs::read(&original).expect("restored original"), b"cache");
    assert!(!trash.exists());
    assert!(!journal.exists());
}

#[test]
fn bounded_automatic_collection_reports_remaining_work_until_drained() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let values = HashMap::from([
        (
            "MESON_PACKAGE_CACHE_DIR".to_owned(),
            root.shared()
                .join("meson/packages")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "ZIG_GLOBAL_CACHE_DIR".to_owned(),
            root.shared()
                .join("zig/global")
                .to_string_lossy()
                .into_owned(),
        ),
    ]);
    for path in values.values() {
        let path = PathBuf::from(path);
        fs::create_dir_all(&path).expect("cache directory");
        fs::write(path.join("cache.bin"), b"cache").expect("cache data");
    }
    let mut ids = resources::register_routed(
        &root,
        Adapter::Meson,
        &HashMap::from([(
            "MESON_PACKAGE_CACHE_DIR".to_owned(),
            values["MESON_PACKAGE_CACHE_DIR"].clone(),
        )]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .expect("register Meson cache");
    ids.extend(
        resources::register_routed(
            &root,
            Adapter::Zig,
            &HashMap::from([(
                "ZIG_GLOBAL_CACHE_DIR".to_owned(),
                values["ZIG_GLOBAL_CACHE_DIR"].clone(),
            )]),
            &NativeTool::default(),
            &BTreeSet::new(),
        )
        .expect("register Zig cache"),
    );
    resources::complete(&root, &ids).expect("complete resources");
    let overrides = GcOverrides {
        stale_after_days: Some(0),
        max_actions: Some(1),
        ..GcOverrides::default()
    };

    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;
    let first =
        gc::collect(&root, &policy, 120, &overrides, true).expect("first bounded collection");
    assert!(!first.complete);
    assert_eq!(first.actions.len(), 1);
    let second =
        gc::collect(&root, &policy, 120, &overrides, true).expect("second bounded collection");
    assert!(second.complete);
    assert_eq!(second.actions.len(), 1);
    assert!(resources::list(&root).expect("drained catalog").is_empty());
}

#[test]
fn collection_reports_an_unattainable_space_target_without_false_failure() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    fs::write(root.control().join("unmanaged-control-state"), b"state")
        .expect("noncollectible control state");
    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;
    policy.max_bytes = Some(0);

    let report = gc::collect(&root, &policy, 120, &GcOverrides::default(), true)
        .expect("completed collection");
    assert!(report.complete);
    assert!(report.size_limit_shortfall_bytes > 0);
    assert!(report.failures.is_empty());
    assert_eq!(report.trash_backlog, 0);
}

#[cfg(unix)]
#[test]
fn native_cleanup_reuses_the_recorded_tool_and_exact_managed_path() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("temporary directory");
    let root = RootHandle::initialize(&temp.path().join("cache-root")).expect("cache root");
    let cache = root.shared().join("go-build");
    fs::create_dir_all(&cache).expect("Go cache");
    fs::write(cache.join("cache.bin"), b"cache").expect("Go cache data");
    let log = temp.path().join("native.log");
    let tool = temp.path().join("go-real");
    fs::write(
        &tool,
        format!(
            "#!/bin/sh\nprintf '%s\\n%s\\n%s\\n' \"$*\" \"$GOCACHE\" \"$DEV_CACHE_NATIVE_TEST\" > '{}'\n",
            log.display()
        ),
    )
    .expect("fake native tool");
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).expect("executable native tool");
    let native = NativeTool {
        program: Some(tool),
        prefix: Vec::new(),
        environment: std::collections::BTreeMap::from([(
            "DEV_CACHE_NATIVE_TEST".to_owned(),
            "recorded".to_owned(),
        )]),
    };
    let ids = resources::register_routed(
        &root,
        Adapter::Go,
        &HashMap::from([("GOCACHE".to_owned(), cache.to_string_lossy().into_owned())]),
        &native,
        &BTreeSet::new(),
    )
    .expect("register Go cache");
    resources::complete(&root, &ids).expect("complete Go cache");

    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;
    let report = gc::collect(
        &root,
        &policy,
        120,
        &GcOverrides {
            stale_after_days: Some(0),
            ..GcOverrides::default()
        },
        true,
    )
    .expect("native cleanup");
    assert!(report.complete);
    let output = fs::read_to_string(log).expect("native cleanup log");
    assert_eq!(
        output,
        format!("clean -cache\n{}\nrecorded\n", cache.display())
    );
    assert!(resources::get(&root, &ids[0])
        .expect("catalog read")
        .expect("catalog record")
        .last_maintained_unix
        .is_some());
}

#[cfg(unix)]
#[test]
fn doctor_fails_when_the_maintenance_catalog_is_invalid() {
    let (temp, upstream, data, config) = doctor_fixture();
    let config_value: toml::Value =
        toml::from_str(&fs::read_to_string(&config).expect("config source")).expect("config TOML");
    let root_path = PathBuf::from(config_value["root"].as_str().expect("configured root"));
    let root = RootHandle::open(&root_path).expect("cache root");
    fs::write(root.control().join("resources/invalid.json"), b"not JSON").expect("invalid catalog");
    let intercept = data.join("dev-cache/intercepts");
    let path = std::env::join_paths([&intercept, &upstream]).expect("doctor PATH");

    let output = run_doctor(&temp, &upstream, &data, &config, path);
    assert_eq!(output.status.code(), Some(1));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("doctor JSON");
    let maintenance = report["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["name"] == "maintenance")
        .expect("maintenance check");
    assert_eq!(maintenance["ok"], false);
    assert_eq!(
        maintenance["status"]["catalog_issues"]
            .as_array()
            .expect("catalog issues")
            .len(),
        1
    );
}
