//! Public command acceptance against disposable, synthetic cache roots only.
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use dev_cache::adapter::Adapter;
use dev_cache::lease::RootLease;
use dev_cache::resources::{self, NativeTool};
use dev_cache::root::RootHandle;

fn run(home: &Path, root: &RootHandle, args: &[&str]) -> Output {
    let mut command = assert_cmd::Command::new(env!("CARGO_BIN_EXE_dev-cache"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/nonexistent")
        .current_dir(home)
        .arg("--root")
        .arg(&root.root)
        .args(["--mode", "on", "--json", "inventory"])
        .args(args)
        .timeout(Duration::from_secs(10));
    for name in ["WSL_DISTRO_NAME", "WSL_INTEROP", "COMPUTERNAME"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.assert().get_output().clone()
}

fn register(root: &RootHandle, suffix: &str) -> PathBuf {
    let cache = root.shared().join("meson").join(suffix);
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("payload"), b"do not scan or prune").unwrap();
    let ids = resources::register_routed(
        root,
        Adapter::Meson,
        &HashMap::from([(
            "MESON_PACKAGE_CACHE_DIR".to_owned(),
            cache.to_string_lossy().into_owned(),
        )]),
        &NativeTool {
            environment: BTreeMap::from([(
                "PRIVATE_VALUE".to_owned(),
                "not-for-output".to_owned(),
            )]),
            ..NativeTool::default()
        },
        &BTreeSet::new(),
    )
    .unwrap();
    resources::catalog_path(root, &ids[0])
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
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

#[test]
fn inventory_observes_metadata_without_payload_walks_or_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let record = register(&root, "one");
    let _active = RootLease::shared(&root, "synthetic-active-work")
        .unwrap()
        .into_active(&[record.file_stem().unwrap().to_string_lossy().into_owned()])
        .unwrap();
    let mut deep = root.shared().join("unrelated");
    fs::create_dir(&deep).unwrap();
    for _ in 0..257 {
        deep.push("d");
        fs::create_dir(&deep).unwrap();
    }
    // Bad unrelated maintenance data is outside this diagnostic's scope.
    fs::write(root.control().join("leases/unread.json"), b"not JSON").unwrap();
    fs::write(root.control().join("last-automatic-gc.json"), b"not JSON").unwrap();
    let before = snapshot(&root.root);
    let output = run(temp.path(), &root, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "dev-cache-inventory-v1");
    assert_eq!(value["scope"], "resource-catalog-metadata");
    assert_eq!(value["complete"], true);
    assert_eq!(value["records_observed"], 1);
    assert_eq!(value["entries_observed"], 1);
    assert_eq!(value["activity_scope"], "not_observed");
    assert!(value["payload_bytes"].is_null());
    assert!(value["reclaimable_bytes"].is_null());
    assert!(value.get("actions").is_none());
    assert_eq!(value["resources"][0]["age_class"], "recent");
    assert_eq!(value["resources"][0]["stale_after_seconds"], 120 * 86_400);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("not-for-output"));
    assert_eq!(snapshot(&root.root), before);
}

#[test]
fn entry_budget_counts_non_json_entries_and_never_claims_a_complete_total() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    for index in 0..5 {
        fs::write(
            root.control().join(format!("resources/{index}.tmp")),
            b"ignored",
        )
        .unwrap();
    }
    let output = run(temp.path(), &root, &["--max-entries", "2"]);
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["enumeration_complete"], false);
    assert_eq!(value["entries_observed"], 2);
    assert_eq!(value["records_observed"], 0);
    assert_eq!(value["stopped_reason"], "entry-budget");
    assert_eq!(value["metadata_bytes_read"], 0);
    assert!(value["payload_bytes"].is_null());
}

#[test]
fn metadata_budget_never_reads_a_record_that_would_exceed_it() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    register(&root, "one");
    let output = run(temp.path(), &root, &["--max-metadata-bytes", "1"]);
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["stopped_reason"], "metadata-byte-budget");
    assert_eq!(value["metadata_bytes_read"], 0);
    assert_eq!(value["records_observed"], 0);
}

#[test]
fn inventory_distinguishes_age_from_retention_and_preserves_hazards() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let disposable = register(&root, "one");
    let output_path = root.platform_root.join("outputs/cargo/workspace/toolchain");
    let ids = resources::register_routed(
        &root,
        Adapter::Cargo,
        &HashMap::from([(
            "CARGO_TARGET_DIR".to_owned(),
            output_path.to_string_lossy().into_owned(),
        )]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    assert_eq!(ids.len(), 1);
    for path in [&disposable, &resources::catalog_path(&root, &ids[0])] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        value["last_started_unix"] = 1.into();
        value["last_completed_unix"] = 1.into();
        value["hazards"] = serde_json::json!(["synthetic-safety-hazard"]);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    let output = run(temp.path(), &root, &[]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let records = value["resources"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|v| v["age_class"] == "stale-by-age"));
    assert!(records
        .iter()
        .all(|v| v["hazards"][0] == "synthetic-safety-hazard"));
    assert_eq!(
        records
            .iter()
            .find(|v| v["kind"] == "cargo-final-output")
            .unwrap()["retention"],
        "retained-final-output"
    );
    assert_eq!(
        records
            .iter()
            .find(|v| v["kind"] == "meson-package")
            .unwrap()["retention"],
        "requires-current-gc-validation"
    );
    assert!(!output_path.exists());
}

#[test]
fn invalid_and_oversized_records_are_explicit_observation_failures() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let catalog = root.control().join("resources");
    fs::write(catalog.join("invalid.json"), b"not JSON").unwrap();
    fs::write(catalog.join("oversized.json"), vec![b' '; 65_537]).unwrap();
    let output = run(temp.path(), &root, &[]);
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["enumeration_complete"], true);
    assert_eq!(value["metadata_bytes_read"], 8);
    let kinds = value["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["error_kind"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        kinds,
        BTreeSet::from(["invalid-record-json", "record-too-large"])
    );
}

#[test]
fn read_only_inventory_requires_existing_coordination_and_defers_to_maintenance() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let exclusive = RootLease::exclusive(&root).unwrap();
    let busy = run(temp.path(), &root, &[]);
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("busy"));
    drop(exclusive);
    fs::remove_file(root.control().join("root.lock")).unwrap();
    let absent = run(temp.path(), &root, &[]);
    assert!(!absent.status.success());
    assert!(!root.control().join("root.lock").exists());
}

#[test]
fn invalid_budgets_are_rejected_before_root_observation() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    for (flag, value) in [
        ("--max-entries", "0"),
        ("--max-entries", "100001"),
        ("--max-metadata-bytes", "0"),
        ("--max-metadata-bytes", "67108865"),
        ("--max-millis", "0"),
        ("--max-millis", "60001"),
        ("--apply", "true"),
    ] {
        assert_eq!(
            run(temp.path(), &root, &[flag, value]).status.code(),
            Some(2)
        );
    }
}

#[cfg(unix)]
#[test]
fn inventory_rejects_redirected_catalog_and_special_record_files_without_opening_them() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let record = register(&root, "one");
    let catalog = root.control().join("resources");
    symlink(&record, catalog.join("link.json")).unwrap();
    let fifo = catalog.join("fifo.json");
    let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let output = run(temp.path(), &root, &[]);
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["issues"].as_array().unwrap().len(), 2);
    assert!(value["issues"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["error_kind"] == "unsafe-record-type"));
    fs::rename(&catalog, root.control().join("resources-retained")).unwrap();
    symlink(root.control().join("resources-retained"), &catalog).unwrap();
    let output = run(temp.path(), &root, &[]);
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["issues"][0]["error_kind"], "unsafe-catalog-directory");
    assert_eq!(value["entries_observed"], 0);
}

#[cfg(unix)]
#[test]
fn non_utf8_issue_paths_preserve_one_complete_json_observation() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let name = std::ffi::OsString::from_vec(b"invalid-\xff.json".to_vec());
    fs::write(root.control().join("resources").join(name), b"invalid").unwrap();
    let output = run(temp.path(), &root, &[]);
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["entries_observed"], 1);
    assert_eq!(value["issues"][0]["error_kind"], "invalid-record-json");
    assert!(value["issues"][0]["path"]
        .as_str()
        .unwrap()
        .contains("invalid-"));
}

#[test]
fn empty_catalog_is_complete_without_inventing_zero_payload_or_reclaimable_sizes() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let output = run(temp.path(), &root, &[]);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], true);
    assert_eq!(value["enumeration_complete"], true);
    assert_eq!(value["records_observed"], 0);
    assert!(value["payload_bytes"].is_null());
    assert!(value["reclaimable_bytes"].is_null());
}

#[test]
fn foreign_or_misnamed_catalog_records_cannot_be_presented_as_valid_resources() {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let record = register(&root, "one");
    let copied = root.control().join("resources/misnamed.json");
    fs::copy(&record, &copied).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&record).unwrap()).unwrap();
    value["root_id"] = "foreign-root".into();
    fs::write(record, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = run(temp.path(), &root, &[]);
    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["complete"], false);
    assert_eq!(value["records_observed"], 0);
    assert_eq!(value["issues"].as_array().unwrap().len(), 2);
    assert!(value["issues"]
        .as_array()
        .unwrap()
        .iter()
        .all(|issue| issue["error_kind"] == "invalid-resource-record"));
}

#[test]
fn inventory_and_its_budgets_are_discoverable_without_configuration() {
    for args in [&["--help"][..], &["completion", "bash"]] {
        let output = assert_cmd::Command::new(env!("CARGO_BIN_EXE_dev-cache"))
            .env_clear()
            .args(args)
            .timeout(Duration::from_secs(5))
            .assert()
            .success()
            .get_output()
            .clone();
        assert!(String::from_utf8_lossy(&output.stdout).contains("inventory"));
    }
    let output = assert_cmd::Command::new(env!("CARGO_BIN_EXE_dev-cache"))
        .env_clear()
        .args(["inventory", "--help"])
        .timeout(Duration::from_secs(5))
        .assert()
        .success()
        .get_output()
        .clone();
    let help = String::from_utf8_lossy(&output.stdout);
    for flag in ["--max-entries", "--max-metadata-bytes", "--max-millis"] {
        assert!(help.contains(flag));
    }
}
