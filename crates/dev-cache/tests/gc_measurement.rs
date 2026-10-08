//! GC size observation is separate from ownership and mutation authority.
use std::collections::{BTreeSet, HashMap};
use std::fs;

use dev_cache::adapter::Adapter;
use dev_cache::config::Config;
use dev_cache::gc::{self, GcOverrides};
use dev_cache::resources::{self, NativeTool};
use dev_cache::root::RootHandle;

#[test]
fn incomplete_size_scan_refuses_collection_actions_in_preview_and_apply() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
    let cache = root.shared().join("meson/packages");
    fs::create_dir_all(&cache).unwrap();
    let payload = cache.join("payload");
    fs::write(&payload, b"retained cache").unwrap();
    let ids = resources::register_routed(
        &root,
        Adapter::Meson,
        &HashMap::from([(
            "MESON_PACKAGE_CACHE_DIR".to_owned(),
            cache.to_string_lossy().into_owned(),
        )]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    resources::complete(&root, &ids).unwrap();
    let record_path = resources::catalog_path(&root, &ids[0]);
    let record_before = fs::read(&record_path).unwrap();
    let mut deep = root.shared().join("unrelated");
    fs::create_dir(&deep).unwrap();
    for _ in 0..257 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
    }
    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;
    let overrides = GcOverrides {
        stale_after_days: Some(0),
        ..GcOverrides::default()
    };
    for apply in [false, true] {
        let error = gc::collect(&root, &policy, 120, &overrides, apply).unwrap_err();
        assert!(format!("{error:#}").contains("depth-limit"));
        assert_eq!(fs::read(&payload).unwrap(), b"retained cache");
        assert_eq!(fs::read(&record_path).unwrap(), record_before);
        assert_eq!(fs::read_dir(root.trash()).unwrap().count(), 0);
        assert_eq!(
            fs::read_dir(root.control().join("gc-journal"))
                .unwrap()
                .count(),
            0
        );
    }
}

#[cfg(unix)]
#[test]
fn post_cleanup_observation_failure_warns_that_cache_state_already_changed() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
    let cache = root.shared().join("go-build");
    fs::create_dir(&cache).unwrap();
    let payload = cache.join("payload");
    fs::write(&payload, b"disposable payload").unwrap();
    let program = temp.path().join("synthetic-go-cleaner");
    fs::write(&program, "#!/bin/sh\nset -eu\n/bin/rm \"$GOCACHE/payload\"\np=\"$GOCACHE\"\ni=0\nwhile [ \"$i\" -lt 257 ]; do\n  p=\"$p/d\"\n  /bin/mkdir \"$p\"\n  i=$((i + 1))\ndone\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
    let ids = resources::register_routed(
        &root,
        Adapter::Go,
        &HashMap::from([("GOCACHE".to_owned(), cache.to_string_lossy().into_owned())]),
        &NativeTool {
            program: Some(program),
            ..NativeTool::default()
        },
        &BTreeSet::new(),
    )
    .unwrap();
    resources::complete(&root, &ids).unwrap();
    let mut policy = Config::default().gc;
    policy.min_free_bytes = 0;
    policy.target_free_bytes = 0;
    let error = gc::collect(
        &root,
        &policy,
        120,
        &GcOverrides {
            stale_after_days: Some(0),
            ..GcOverrides::default()
        },
        true,
    )
    .unwrap_err();
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("observe cache size after applied collection"));
    assert!(diagnostic.contains("actions may already have changed cache state"));
    assert!(diagnostic.contains("depth-limit"));
    assert!(!payload.exists());
    assert!(resources::get(&root, &ids[0])
        .unwrap()
        .unwrap()
        .last_maintained_unix
        .is_some());
}

#[test]
fn explicit_preview_progress_preserves_one_json_document_and_fixture_inventory() {
    fn snapshot(
        root: &std::path::Path,
    ) -> std::collections::BTreeMap<std::path::PathBuf, Option<Vec<u8>>> {
        walkdir::WalkDir::new(root)
            .into_iter()
            .map(|entry| {
                let entry = entry.unwrap();
                let path = entry.path().strip_prefix(root).unwrap().to_path_buf();
                let contents = entry
                    .file_type()
                    .is_file()
                    .then(|| fs::read(entry.path()).unwrap());
                (path, contents)
            })
            .collect()
    }
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
    let cache = root.shared().join("meson/packages");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("payload"), b"preview must retain this").unwrap();
    let ids = resources::register_routed(
        &root,
        Adapter::Meson,
        &HashMap::from([(
            "MESON_PACKAGE_CACHE_DIR".to_owned(),
            cache.to_string_lossy().into_owned(),
        )]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    resources::complete(&root, &ids).unwrap();
    let mut config = Config {
        root: Some(root.root.clone()),
        ..Config::default()
    };
    config.gc.min_free_bytes = 0;
    config.gc.target_free_bytes = 0;
    config.gc.stale_after_days = 0;
    let config_path = temp.path().join("config.toml");
    fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    let before = snapshot(&root.root);
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_dev-cache"));
    command
        .env_clear()
        .env("HOME", temp.path())
        .env("PATH", "/nonexistent")
        .current_dir(temp.path())
        .arg("--config")
        .arg(config_path)
        .args(["--json", "gc"]);
    for name in ["WSL_DISTRO_NAME", "WSL_INTEROP", "COMPUTERNAME"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["applied"], false);
    assert_eq!(report["bytes_reclaimed"], 0);
    assert!(!report["actions"].as_array().unwrap().is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("dev-cache gc: planning and observing cache sizes"));
    assert_eq!(snapshot(&root.root), before);
}
