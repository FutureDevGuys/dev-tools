use super::{load_runtime_config, validate_config};
use tempfile::TempDir;

#[test]
fn external_catalog_uses_top_level_tasks() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("config.toml");
    let catalog = tmp.path().join("catalog.toml");
    std::fs::write(
        &config,
        "[updaters]\nrun_all_detected = false\ncatalogs = [\"catalog.toml\"]\n",
    )
    .unwrap();
    std::fs::write(
        &catalog,
        "[tasks.\"team/index\"]\nlabel = \"Index\"\ncommand = \"indexer\"\n",
    )
    .unwrap();

    let runtime = load_runtime_config(Some(config)).unwrap();
    assert!(runtime.updaters.custom_tasks.contains_key("team/index"));
}

#[test]
fn external_catalog_rejects_config_file_shape() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("config.toml");
    let catalog = tmp.path().join("catalog.toml");
    std::fs::write(&config, "[updaters]\ncatalogs = [\"catalog.toml\"]\n").unwrap();
    std::fs::write(
        &catalog,
        "[updaters.tasks.\"team/index\"]\ncommand = \"indexer\"\n",
    )
    .unwrap();

    let error = load_runtime_config(Some(config)).unwrap_err().to_string();
    assert!(error.contains("parse updater catalog"), "{error}");
}

#[test]
fn managed_and_local_catalogs_require_owned_namespaces() {
    let tmp = TempDir::new().unwrap();
    let config_root = tmp.path().join("update-all");
    let managed = config_root.join("catalog.d/syscfg");
    let local = config_root.join("catalog.d/local");
    std::fs::create_dir_all(&managed).unwrap();
    std::fs::create_dir_all(&local).unwrap();
    let config = config_root.join("config.toml");
    std::fs::write(&config, "[updaters]\nrun_all_detected = false\n").unwrap();
    std::fs::write(
        managed.join("desktop.toml"),
        "[tasks.\"syscfg/desktop\"]\ncommand = \"desktop-refresh\"\n",
    )
    .unwrap();
    std::fs::write(
        local.join("notes.toml"),
        "[tasks.\"local/notes\"]\ncommand = \"notes-sync\"\n",
    )
    .unwrap();

    let runtime = load_runtime_config(Some(config)).unwrap();
    assert!(runtime.updaters.custom_tasks.contains_key("syscfg/desktop"));
    assert!(runtime.updaters.custom_tasks.contains_key("local/notes"));
}

#[test]
fn discovered_catalog_rejects_foreign_namespace() {
    let tmp = TempDir::new().unwrap();
    let config_root = tmp.path().join("update-all");
    let managed = config_root.join("catalog.d/syscfg");
    std::fs::create_dir_all(&managed).unwrap();
    let config = config_root.join("config.toml");
    std::fs::write(&config, "[updaters]\nrun_all_detected = false\n").unwrap();
    std::fs::write(
        managed.join("desktop.toml"),
        "[tasks.\"local/desktop\"]\ncommand = \"desktop-refresh\"\n",
    )
    .unwrap();

    let error = load_runtime_config(Some(config)).unwrap_err().to_string();
    assert!(
        error.contains("must use the 'syscfg/' namespace"),
        "{error}"
    );
}

#[test]
fn runtime_config_rejects_unknown_custom_updater_after_reference() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("config.toml");
    std::fs::write(
        &config,
        "[updaters.tasks.notes]\ncommand = \"notes-sync\"\nafter = [\"missing-updater\"]\n",
    )
    .unwrap();

    let error = load_runtime_config(Some(config)).unwrap_err().to_string();
    assert!(error.contains("updaters.tasks.notes.after"), "{error}");
    assert!(
        error.contains("unknown task selector 'missing-updater'"),
        "{error}"
    );
}

#[test]
fn duplicate_task_ids_fail_without_override() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("config.toml");
    let first = tmp.path().join("first.toml");
    let second = tmp.path().join("second.toml");
    std::fs::write(
        &config,
        "[updaters]\ncatalogs = [\"first.toml\", \"second.toml\"]\n",
    )
    .unwrap();
    for catalog in [&first, &second] {
        std::fs::write(catalog, "[tasks.\"team/index\"]\ncommand = \"indexer\"\n").unwrap();
    }

    let error = load_runtime_config(Some(config)).unwrap_err().to_string();
    assert!(
        error.contains("duplicate updater task id 'team/index'"),
        "{error}"
    );
    assert!(error.contains("already defined"), "{error}");
}

#[test]
fn strict_validation_accepts_minimal_current_config() {
    let tmp = TempDir::new().unwrap();
    let config = tmp.path().join("config.toml");
    std::fs::write(
        &config,
        "[install]\nauto_update = false\n\n[updaters]\nrun_all_detected = false\n",
    )
    .unwrap();

    let report = validate_config(Some(config), true).unwrap();
    assert!(report.warnings.is_empty());
}
