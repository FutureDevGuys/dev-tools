#![cfg(target_os = "linux")]

use dev_tools_command::{run_bounded_command, BoundedCommand};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

const CONFIG: &str = r#"# User formatting and comments remain intact.
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "github", owner = "ExampleOrg", repository = "example" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "exact", pattern = "tool", os = "linux", architecture = "x86_64" }]
"#;

fn invoke(root: &Path, config: &Path, options: &[OsString]) -> (i32, serde_json::Value) {
    let mut arguments = vec![OsString::from("config")];
    arguments.extend_from_slice(options);
    arguments.extend([
        "--config".into(),
        config.as_os_str().to_owned(),
        "--json".into(),
    ]);
    let output = run_bounded_command(&BoundedCommand {
        executable: Path::new(env!("CARGO_BIN_EXE_artifact-update")),
        arguments: &arguments,
        environment: &Default::default(),
        cwd: Some(root),
        timeout: Duration::from_secs(5),
        output_limit: 16 * 1024,
    })
    .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
        panic!(
            "expected configuration operation JSON: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(result["schema"], "artifact-update-config-operation-v1");
    assert_eq!(result["network_accessed"], false);
    (output.status.code().unwrap(), result)
}

fn apply(root: &Path, config: &Path, source: &Path, expected: &str) -> (i32, serde_json::Value) {
    invoke(
        root,
        config,
        &[
            "apply".into(),
            "--from".into(),
            source.as_os_str().to_owned(),
            "--expect".into(),
            expected.into(),
        ],
    )
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[test]
fn calendar_proposals_preserve_bytes_and_reject_ignored_rule_options() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config/config.toml");
    let source = root.path().join("proposal.toml");
    let proposed = CONFIG.replace(
        "type = \"semver-tag\", prefix = \"v\"",
        "type = \"calendar-tag\", prefix = \"release/\", format = \"yyyy.mm.dd\"",
    );
    fs::write(&source, &proposed).unwrap();
    let (code, row) = apply(root.path(), &config, &source, "absent");
    assert_eq!(code, 0);
    assert_eq!(row["changed"], true);
    assert_eq!(fs::read(&config).unwrap(), proposed.as_bytes());
    for invalid in [
        CONFIG.replace(
            "type = \"semver-tag\", prefix = \"v\"",
            "type = \"calendar\", format = \"yyyymmdd\"",
        ),
        CONFIG.replace(
            "type = \"check-only\"",
            "type = \"check-only\", signature = \"not-effective\"",
        ),
    ] {
        fs::write(&source, invalid).unwrap();
        let (code, row) = apply(root.path(), &config, &source, &digest(proposed.as_bytes()));
        assert_eq!(code, 2);
        assert_eq!(row["changed"], false);
        assert_eq!(fs::read(&config).unwrap(), proposed.as_bytes());
    }
}

#[test]
fn inspection_of_absent_configuration_is_read_only() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("missing/config.toml");
    let (code, row) = invoke(root.path(), &config, &["inspect".into()]);
    assert_eq!(code, 0);
    assert_eq!(row["outcome"], "absent");
    assert_eq!(row["changed"], false);
    assert!(!config.parent().unwrap().exists());
}

#[test]
fn explicit_initialization_and_digest_guarded_replacement_preserve_exact_bytes() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("managed/config.toml");
    let source = root.path().join("proposal.toml");
    fs::write(&source, CONFIG).unwrap();
    let (code, row) = apply(root.path(), &config, &source, "absent");
    assert_eq!(code, 0);
    assert_eq!(row["outcome"], "initialized");
    assert_eq!(row["changed"], true);
    assert_eq!(fs::read(&config).unwrap(), CONFIG.as_bytes());
    assert_eq!(
        fs::metadata(&config).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(config.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let (code, row) = invoke(root.path(), &config, &["inspect".into()]);
    assert_eq!(code, 0);
    assert_eq!(row["outcome"], "valid");
    assert_eq!(row["sha256"], digest(CONFIG.as_bytes()));
    assert_eq!(row["artifact_count"], 1);
    assert_eq!(row["changed"], false);

    let (code, row) = apply(root.path(), &config, &source, "absent");
    assert_eq!(
        code, 3,
        "expected absence is not an overwrite or adoption grant"
    );
    assert_eq!(row["outcome"], "conflict");
    let (code, row) = apply(root.path(), &config, &source, &digest(CONFIG.as_bytes()));
    assert_eq!(code, 0);
    assert_eq!(row["outcome"], "unchanged");
    assert_eq!(row["changed"], false);

    let replacement = CONFIG.replace("ExampleOrg", "OtherOrg");
    fs::write(&source, &replacement).unwrap();
    let (code, row) = apply(root.path(), &config, &source, &digest(CONFIG.as_bytes()));
    assert_eq!(code, 0);
    assert_eq!(row["outcome"], "replaced");
    assert_eq!(row["changed"], true);
    assert_eq!(fs::read(&config).unwrap(), replacement.as_bytes());
    let (code, row) = apply(root.path(), &config, &source, &digest(CONFIG.as_bytes()));
    assert_eq!(
        code, 3,
        "identical proposed bytes cannot bypass a stale digest expectation"
    );
    assert_eq!(row["changed"], false);
    fs::write(&source, CONFIG).unwrap();
    let (code, row) = apply(root.path(), &config, &source, &digest(CONFIG.as_bytes()));
    assert_eq!(code, 3);
    assert_eq!(row["outcome"], "conflict");
    assert_eq!(row["changed"], false);
    assert_eq!(fs::read(&config).unwrap(), replacement.as_bytes());
}

#[test]
fn invalid_proposals_and_expected_missing_content_never_initialize_a_target() {
    for (bytes, code) in [
        (b"schema = 'not-a-catalog'".to_vec(), 2),
        (vec![0xff], 2),
        (vec![b' '; 1024 * 1024 + 1], 1),
    ] {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("missing/config.toml");
        let source = root.path().join("proposal.toml");
        fs::write(&source, bytes).unwrap();
        let (actual_code, row) = apply(root.path(), &config, &source, "absent");
        assert_eq!(actual_code, code);
        assert_eq!(row["changed"], false);
        assert!(!config.parent().unwrap().exists());
    }
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("missing/config.toml");
    let source = root.path().join("proposal.toml");
    fs::write(&source, CONFIG).unwrap();
    let (code, row) = apply(root.path(), &config, &source, &digest(CONFIG.as_bytes()));
    assert_eq!(code, 3);
    assert_eq!(row["outcome"], "conflict");
    assert!(!config.parent().unwrap().exists());
}

#[test]
fn invalid_existing_document_can_be_inspected_and_explicitly_repaired_by_digest() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("managed/config.toml");
    let source = root.path().join("proposal.toml");
    fs::write(&source, CONFIG).unwrap();
    assert_eq!(apply(root.path(), &config, &source, "absent").0, 0);
    let invalid = b"invalid user edit";
    fs::write(&config, invalid).unwrap();
    let (code, row) = invoke(root.path(), &config, &["inspect".into()]);
    assert_eq!(code, 2);
    assert_eq!(row["outcome"], "invalid-configuration");
    assert_eq!(row["sha256"], digest(invalid));
    assert_eq!(row["changed"], false);
    assert_eq!(fs::read(&config).unwrap(), invalid);
    let (code, row) = apply(root.path(), &config, &source, &digest(invalid));
    assert_eq!(code, 0);
    assert_eq!(row["outcome"], "replaced");
    assert_eq!(fs::read(&config).unwrap(), CONFIG.as_bytes());
}

#[test]
fn held_configuration_lock_rejects_writes_without_blocking_read_only_inspection() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("managed/config.toml");
    let source = root.path().join("proposal.toml");
    fs::write(&source, CONFIG).unwrap();
    assert_eq!(apply(root.path(), &config, &source, "absent").0, 0);
    let lock = dev_tools_installation::InstallationLock::try_acquire(
        &config
            .parent()
            .unwrap()
            .join(".artifact-update-config.lock"),
    )
    .unwrap()
    .unwrap();
    fs::write(&source, CONFIG.replace("ExampleOrg", "OtherOrg")).unwrap();
    let (code, row) = apply(root.path(), &config, &source, &digest(CONFIG.as_bytes()));
    assert_eq!(code, 3);
    assert_eq!(row["outcome"], "busy");
    assert_eq!(row["changed"], false);
    assert_eq!(fs::read(&config).unwrap(), CONFIG.as_bytes());
    let (code, row) = invoke(root.path(), &config, &["inspect".into()]);
    assert_eq!(code, 0);
    assert_eq!(row["outcome"], "valid");
    drop(lock);
    assert_eq!(
        apply(root.path(), &config, &source, &digest(CONFIG.as_bytes())).0,
        0
    );
}

#[test]
fn linked_or_unsafe_configuration_custody_is_not_adopted_or_modified() {
    for kind in [
        "symlink",
        "hardlink",
        "file-mode",
        "directory-mode",
        "ancestor-symlink",
    ] {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("managed");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let target = directory.join("target.toml");
        fs::write(&target, CONFIG).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let source = root.path().join("proposal.toml");
        fs::write(&source, CONFIG.replace("ExampleOrg", "OtherOrg")).unwrap();
        let config = match kind {
            "symlink" => {
                let path = directory.join("config.toml");
                std::os::unix::fs::symlink(&target, &path).unwrap();
                path
            }
            "hardlink" => {
                let path = directory.join("config.toml");
                fs::hard_link(&target, &path).unwrap();
                path
            }
            "file-mode" => {
                fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
                target.clone()
            }
            "directory-mode" => {
                fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();
                target.clone()
            }
            "ancestor-symlink" => {
                let alias = root.path().join("alias");
                std::os::unix::fs::symlink(&directory, &alias).unwrap();
                alias.join("target.toml")
            }
            _ => unreachable!(),
        };
        let (code, row) = invoke(root.path(), &config, &["inspect".into()]);
        assert_eq!(code, 4, "{kind}");
        assert_eq!(row["changed"], false);
        let (code, row) = apply(root.path(), &config, &source, &digest(CONFIG.as_bytes()));
        assert_eq!(code, 4, "{kind}");
        assert_eq!(row["changed"], false);
        assert_eq!(fs::read(&target).unwrap(), CONFIG.as_bytes());
    }
}
