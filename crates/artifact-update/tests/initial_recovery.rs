#![cfg(target_os = "linux")]

use dev_tools_command::{run_bounded_command, BoundedCommand};
use dev_tools_installation::{write_atomic_document, DocumentAuthority, InstallationLock};
use dev_tools_update::artifact::ArtifactCatalog;
use dev_tools_update::manifest_ledger::{ManifestLedger, MANIFEST_LEDGER_LIMIT};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

const CONFIG: &str = "schema = \"artifact-update-config-v1\"\nartifacts = []\n";
const SIGNED: &str = r#"
schema = "artifact-update-config-v1"
[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "static-manifest", url = "https://example.invalid/stable.json" }
version = { type = "semver-tag" }
verification = { type = "signed-manifest", root = "https://example.invalid/root.json", trusted_root_public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", product = "example", target = "linux-x86_64", artifact_url = "https://example.invalid/tool" }
selectors = [{ type = "exact", pattern = "tool" }]
"#;

fn invoke(root: &Path, config: &Path, arguments: &[&str]) -> (i32, serde_json::Value) {
    let mut argv: Vec<OsString> = arguments.iter().map(OsString::from).collect();
    argv.extend([
        "--config".into(),
        config.as_os_str().to_owned(),
        "--json".into(),
    ]);
    let environment = [
        ("XDG_STATE_HOME".into(), root.join("state").into_os_string()),
        ("XDG_CACHE_HOME".into(), root.join("cache").into_os_string()),
    ]
    .into_iter()
    .collect();
    let output = run_bounded_command(&BoundedCommand {
        executable: Path::new(env!("CARGO_BIN_EXE_artifact-update")),
        arguments: &argv,
        environment: &environment,
        cwd: Some(root),
        timeout: Duration::from_secs(5),
        output_limit: 16 * 1024,
    })
    .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap();
    (output.status.code().unwrap(), value)
}

// This product fixture uses the documented journal format. Actual process-death
// creation/ordering is exercised independently by the shared installation tests.
fn journal_fixture(
    target: &Path,
    document: &str,
    bytes: &[u8],
    limit: u64,
    published: bool,
) -> (PathBuf, PathBuf) {
    let parent = target.parent().unwrap();
    fs::create_dir_all(parent).unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = parent.metadata().unwrap();
    let owner = metadata.uid();
    let staged = parent.join(".dev-tools-initial-owned-fixture");
    fs::create_dir(&staged).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
    let stage_metadata = staged.metadata().unwrap();
    let mut digest = Sha256::new();
    digest.update(b"dev-tools-initial-directory-target-v1\0");
    digest.update(target.as_os_str().as_bytes());
    let key = format!("{:x}", digest.finalize());
    let journal = parent.join(format!(".dev-tools-initial-{key}.json"));
    let lock = InstallationLock::acquire(&journal.with_extension("lock")).unwrap();
    let value = serde_json::json!({
        "schema": "dev-tools-initial-directory-publication-v1", "target": key,
        "parent_device": metadata.dev(), "parent_inode": metadata.ino(),
        "stage": staged.file_name().unwrap().to_str().unwrap(),
        "stage_device": stage_metadata.dev(), "stage_inode": stage_metadata.ino(),
        "document": document, "limit": limit,
    });
    write_atomic_document(
        &journal,
        &serde_json::to_vec(&value).unwrap(),
        &DocumentAuthority {
            owner_uid: owner,
            mode: 0o600,
            limit: 4096,
        },
        None,
    )
    .unwrap();
    fs::write(staged.join(document), bytes).unwrap();
    fs::set_permissions(staged.join(document), fs::Permissions::from_mode(0o600)).unwrap();
    if published {
        fs::rename(&staged, target).unwrap();
    }
    drop(lock);
    (journal, staged)
}

#[test]
fn absent_recovery_creates_no_configuration_ledger_or_lock() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("missing/config.toml");
    let (code, value) = invoke(root.path(), &config, &["config", "recover"]);
    assert_eq!(code, 0);
    assert_eq!(value["changed"], false);
    assert_eq!(value["outcome"], "unchanged");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    let config = root.path().join("source.toml");
    fs::write(&config, SIGNED).unwrap();
    let (code, value) = invoke(root.path(), &config, &["trust", "recover", "example"]);
    assert_eq!(code, 0);
    assert_eq!(value["changed"], false);
    assert!(!root.path().join("state").exists());
    assert!(!root.path().join("cache").exists());
}

#[test]
fn config_recovery_is_explicit_preserves_published_bytes_and_repeats_without_change() {
    for published in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("configuration");
        let config = target.join("config.toml");
        let (journal, staged) = journal_fixture(
            &target,
            "config.toml",
            CONFIG.as_bytes(),
            1024 * 1024,
            published,
        );
        let initial_journal = fs::read(&journal).unwrap();
        let (code, _) = invoke(root.path(), &config, &["config", "inspect"]);
        assert_eq!(code, 0);
        assert_eq!(fs::read(&journal).unwrap(), initial_journal);
        if published {
            let (code, _) = invoke(root.path(), &config, &["doctor"]);
            assert_eq!(code, 0);
            assert_eq!(fs::read(&journal).unwrap(), initial_journal);
        }
        let (code, value) = invoke(root.path(), &config, &["config", "recover"]);
        assert_eq!(code, 0);
        assert_eq!(value["schema"], "artifact-update-config-operation-v1");
        assert_eq!(value["outcome"], "recovered");
        assert_eq!(value["changed"], true);
        assert_eq!(value["network_accessed"], false);
        assert!(!journal.exists());
        assert!(!staged.exists());
        assert_eq!(target.exists(), published);
        if published {
            assert_eq!(fs::read(&config).unwrap(), CONFIG.as_bytes());
        }
        let (code, value) = invoke(root.path(), &config, &["config", "recover"]);
        assert_eq!(code, 0);
        assert_eq!(value["changed"], false);
    }
}

#[test]
fn trust_recovery_neither_initializes_nor_rewinds_a_ledger() {
    for published in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("source.toml");
        fs::write(&config, SIGNED).unwrap();
        let catalog = ArtifactCatalog::parse(SIGNED).unwrap();
        let ledger = ManifestLedger::new(catalog.get("example").unwrap()).unwrap();
        let key: String = ledger
            .authority_id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let target = root
            .path()
            .join("state/artifact-update/release-ledgers-v1")
            .join(key);
        let bytes = ledger.to_bytes().unwrap();
        let (journal, staged) = journal_fixture(
            &target,
            "ledger.json",
            &bytes,
            MANIFEST_LEDGER_LIMIT as u64,
            published,
        );
        let original = fs::read(&journal).unwrap();
        let (code, value) = invoke(root.path(), &config, &["trust", "status", "example"]);
        assert_eq!(code, 0);
        assert_eq!(value["changed"], false);
        assert_eq!(fs::read(&journal).unwrap(), original);
        let (code, value) = invoke(root.path(), &config, &["trust", "recover", "example"]);
        assert_eq!(code, 0);
        assert_eq!(value["outcome"], "recovered");
        assert_eq!(value["changed"], true);
        assert_eq!(value["network_accessed"], false);
        assert_eq!(value["installation_authorized"], false);
        assert!(!journal.exists());
        assert!(!staged.exists());
        assert_eq!(target.exists(), published);
        if published {
            assert_eq!(fs::read(target.join("ledger.json")).unwrap(), bytes);
        }
        let (code, value) = invoke(root.path(), &config, &["trust", "recover", "example"]);
        assert_eq!(code, 0);
        assert_eq!(value["changed"], false);
    }
}

#[test]
fn config_recovery_preserves_unknown_content_and_refuses_a_live_publisher() {
    for busy in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("configuration");
        let (journal, staged) = journal_fixture(
            &target,
            "config.toml",
            CONFIG.as_bytes(),
            1024 * 1024,
            false,
        );
        let guard = if busy {
            Some(InstallationLock::acquire(&journal.with_extension("lock")).unwrap())
        } else {
            fs::write(staged.join("unowned"), b"preserve").unwrap();
            None
        };
        let (code, value) = invoke(
            root.path(),
            &target.join("config.toml"),
            &["config", "recover"],
        );
        assert_eq!(code, 4);
        assert_eq!(value["outcome"], "recovery-failed");
        assert!(value["changed"].is_null());
        assert_eq!(value["network_accessed"], false);
        assert!(journal.exists());
        assert_eq!(
            fs::read(staged.join("config.toml")).unwrap(),
            CONFIG.as_bytes()
        );
        drop(guard);
    }
}
