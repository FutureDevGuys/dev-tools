use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

fn command(home: &TempDir) -> Command {
    let mut command = Command::cargo_bin("update-all").expect("compiled update-all binary");
    command
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("config"))
        .env("XDG_STATE_HOME", home.path().join("state"))
        .env("PATH", "/usr/bin:/bin")
        .env_remove("UPDATE_ALL_ROOT_URL")
        .env_remove("UPDATE_ALL_MANIFEST_URL");
    command
}

#[test]
fn help_exposes_current_general_interfaces() {
    let home = TempDir::new().unwrap();
    command(&home)
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("--only"))
        .stdout(predicate::str::contains("--exclude"));

    command(&home)
        .args(["self", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("install"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("check"))
        .stdout(predicate::str::contains("update"))
        .stdout(predicate::str::contains("rollback"))
        .stdout(predicate::str::contains("repair").not());
}

#[test]
fn self_status_is_offline_and_machine_readable() {
    let home = TempDir::new().unwrap();
    command(&home)
        .args(["self", "status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("engine_version"))
        .stdout(predicate::str::contains("managed"));
}

#[test]
fn config_init_and_strict_validate_are_idempotent_read_surfaces() {
    let home = TempDir::new().unwrap();
    let config = home.path().join("update-all.toml");
    command(&home)
        .args(["config", "init", "--path"])
        .arg(&config)
        .assert()
        .success();
    command(&home)
        .args(["config", "validate", "--strict", "--path"])
        .arg(&config)
        .assert()
        .success();
    let before = fs::read(&config).unwrap();
    command(&home)
        .args(["config", "validate", "--strict", "--path"])
        .arg(&config)
        .assert()
        .success();
    assert_eq!(fs::read(&config).unwrap(), before);
}

#[test]
fn external_catalog_namespace_is_loaded_without_a_checkout() {
    let home = TempDir::new().unwrap();
    let config_dir = home.path().join("config/update-all");
    let catalog_dir = config_dir.join("catalog.d/local");
    fs::create_dir_all(&catalog_dir).unwrap();
    fs::write(
        config_dir.join("config.toml"),
        "[install]\nauto_update = false\n[ui]\nmode = \"plain\"\n",
    )
    .unwrap();
    fs::write(
        catalog_dir.join("demo.toml"),
        r#"
[tasks."local/demo"]
label = "Local Demo"
os = ["linux"]
detect_mode = "command_available"
category = "maintenance"
command = "sh"
args = ["-c", "printf 'demo complete\\n'"]
policy_key = "tool_update"
"#,
    )
    .unwrap();
    command(&home)
        .args(["--plain", "--only", "local/demo"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Local Demo"));
}

#[test]
fn invalid_catalog_plan_uses_documented_exit_code_three() {
    let home = TempDir::new().unwrap();
    let config = home.path().join("invalid.toml");
    fs::write(
        &config,
        "[updaters.tasks.\"builtin/npm\"]\ncommand = \"custom-npm\"\n",
    )
    .unwrap();

    command(&home)
        .args(["--config"])
        .arg(config)
        .arg("--plain")
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "invalid updater configuration or plan",
        ));
}

#[test]
fn public_and_legacy_completion_roots_are_mutually_exclusive_before_mutation() {
    let home = TempDir::new().unwrap();
    let managed = home.path().join("managed");
    let legacy = home.path().join("legacy");
    command(&home)
        .args([
            "completions",
            "sync",
            "--providers",
            "path",
            "--managed-root",
        ])
        .arg(&managed)
        .arg("--rc-root")
        .arg(&legacy)
        .assert()
        .failure()
        .stderr(predicate::str::contains("mutually exclusive"));
    assert!(!managed.exists());
    assert!(!legacy.exists());
}

#[test]
fn legacy_audit_requires_exact_executable_before_sync_mutation() {
    let home = TempDir::new().unwrap();
    let legacy = home.path().join("legacy");
    command(&home)
        .args(["completions", "sync", "--providers", "path", "--apply"])
        .arg("--rc-root")
        .arg(&legacy)
        .args(["--shell", "zsh", "--audit", "strict"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "requires an exact absolute --audit-command",
        ));
    assert!(!legacy.exists());
}

#[test]
fn fresh_public_completion_sync_uses_a_virtual_empty_catalog_and_then_reuses() {
    let home = TempDir::new().unwrap();
    let managed = home.path().join("managed");
    let args = [
        "completions",
        "sync",
        "--providers",
        "path",
        "--managed-root",
    ];
    command(&home)
        .args(args)
        .arg(&managed)
        .args(["--shell", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completion_outcome=published"));
    assert!(!managed.join("cache/managed-tools.json").exists());

    command(&home)
        .args(args)
        .arg(&managed)
        .args(["--shell", "bash"])
        .assert()
        .success()
        .stdout(predicate::str::contains("completion_outcome=reused"));
}
