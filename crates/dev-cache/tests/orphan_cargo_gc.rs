//! Synthetic owned-storage fixtures. These tests never inspect a real cache.
#![cfg(unix)]

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use dev_cache::adapter::Adapter;
use dev_cache::config::{Config, GcConfig};
use dev_cache::gc::{self, GcOverrides, GcReport};
use dev_cache::lease::RootLease;
use dev_cache::repository::{IdentityRecord, Repository};
use dev_cache::resources::{self, NativeTool, ResourceRecord};
use dev_cache::root::RootHandle;
use dev_cache::util::{directory_size, now_unix, write_json_atomic};

struct Fixture {
    _temp: tempfile::TempDir,
    root: RootHandle,
    repo: Repository,
    cargo: PathBuf,
    id: String,
    policy: GcConfig,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = RootHandle::initialize(&temp.path().join("cache-root")).unwrap();
        let worktree = temp.path().join("checkouts/project");
        fs::create_dir_all(&worktree).unwrap();
        fs::write(worktree.join("Cargo.toml"), "[workspace]\n").unwrap();
        let repo = Repository::discover(&worktree, &root).unwrap().unwrap();
        repo.touch(&root).unwrap();
        let cargo = root
            .shared()
            .join("cargo/intermediate")
            .join(&repo.identity);
        fs::create_dir_all(&cargo).unwrap();
        fs::write(cargo.join("object"), b"disposable Cargo object").unwrap();
        let ids = resources::register_routed(
            &root,
            Adapter::Cargo,
            &HashMap::from([(
                "CARGO_BUILD_BUILD_DIR".to_owned(),
                cargo
                    .join("{workspace-path-hash}")
                    .to_string_lossy()
                    .into_owned(),
            )]),
            &NativeTool::default(),
            &BTreeSet::new(),
        )
        .unwrap();
        resources::complete(&root, &ids).unwrap();
        let mut fixture = Self {
            _temp: temp,
            root,
            repo,
            cargo,
            id: ids[0].clone(),
            policy: Config::default().gc,
        };
        fixture.policy.min_free_bytes = 0;
        fixture.policy.target_free_bytes = 0;
        fixture.policy.max_bytes = None;
        let old = now_unix() - 8 * 86_400;
        fixture.owner(|record| {
            record.created_unix = old;
            record.last_used_unix = old;
        });
        fixture.resource(|record| {
            record.created_unix = old;
            record.last_started_unix = old;
            record.last_completed_unix = Some(old);
            record.last_maintained_unix = None;
        });
        fixture
    }

    fn owner(&self, change: impl FnOnce(&mut IdentityRecord)) {
        let path = self.repo.cache_dir.join("identity.json");
        let mut record = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        change(&mut record);
        write_json_atomic(&path, &record).unwrap();
    }

    fn resource(&self, change: impl FnOnce(&mut ResourceRecord)) {
        let path = resources::catalog_path(&self.root, &self.id);
        let mut record = resources::get(&self.root, &self.id).unwrap().unwrap();
        change(&mut record);
        write_json_atomic(&path, &record).unwrap();
    }

    fn orphan(&self) {
        fs::remove_dir_all(&self.repo.worktree).unwrap();
    }

    fn stage_recovery(&self, committed: bool) -> (PathBuf, PathBuf, Vec<PathBuf>) {
        let transaction_id = uuid::Uuid::new_v4().simple().to_string();
        let trash = self.root.trash().join(&transaction_id);
        let journal = self
            .root
            .control()
            .join("gc-journal")
            .join(format!("{transaction_id}.json"));
        let mut originals = vec![self.repo.cache_dir.clone(), self.cargo.clone()];
        originals.sort();
        fs::create_dir(&trash).unwrap();
        for (index, original) in originals.iter().enumerate() {
            fs::rename(original, trash.join(index.to_string())).unwrap();
        }
        write_json_atomic(
            &journal,
            &serde_json::json!({
                "schema_version": 1,
                "transaction_id": transaction_id,
                "resource_id": self.id,
                "original_paths": originals,
                "trash_path": trash,
                "committed": committed,
                "created_unix": now_unix(),
            }),
        )
        .unwrap();
        (journal, trash, originals)
    }

    fn collect(&self, apply: bool, max_actions: Option<usize>) -> GcReport {
        gc::collect(
            &self.root,
            &self.policy,
            120,
            &GcOverrides {
                max_actions,
                ..GcOverrides::default()
            },
            apply,
        )
        .unwrap()
    }

    fn assert_preserved(&self, expected: &str) {
        for apply in [false, true] {
            let report = self.collect(apply, None);
            assert!(
                report.actions.is_empty(),
                "{expected}: {:?}",
                report.actions
            );
            assert!(
                report.failures.is_empty(),
                "{expected}: {:?}",
                report.failures
            );
            if !expected.is_empty() {
                assert!(
                    report
                        .abstentions
                        .iter()
                        .any(|a| a.reason.contains(expected)),
                    "{expected}: {:?}",
                    report.abstentions
                );
            }
            assert!(self.repo.cache_dir.is_dir());
            assert_eq!(
                fs::read(self.cargo.join("object")).unwrap(),
                b"disposable Cargo object"
            );
        }
    }

    fn command(&self) -> Command {
        let config = Config {
            root: Some(self.root.root.clone()),
            gc: self.policy.clone(),
            ..Config::default()
        };
        let config_path = self._temp.path().join("config.toml");
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_dev-cache"));
        command
            .env_clear()
            .env("HOME", self._temp.path())
            .env("PATH", "/nonexistent")
            .current_dir(self._temp.path())
            .arg("--config")
            .arg(config_path)
            .args(["--json", "gc"]);
        for name in ["WSL_DISTRO_NAME", "WSL_INTEROP", "COMPUTERNAME"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command
    }
}

struct DeniedTraversal {
    path: PathBuf,
    permissions: Option<fs::Permissions>,
}

impl DeniedTraversal {
    fn new(path: PathBuf) -> Self {
        let permissions = fs::metadata(&path).unwrap().permissions();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        Self {
            path,
            permissions: Some(permissions),
        }
    }

    fn restore(mut self) {
        fs::set_permissions(&self.path, self.permissions.as_ref().unwrap().clone()).unwrap();
        self.permissions = None;
    }
}

impl Drop for DeniedTraversal {
    fn drop(&mut self) {
        if let Some(permissions) = self.permissions.take() {
            let _ = fs::set_permissions(&self.path, permissions);
        }
    }
}

#[test]
fn public_gc_previews_then_collects_owner_and_cargo_in_one_action() {
    let fixture = Fixture::new();
    fixture.orphan();
    let expected = directory_size(&fixture.repo.cache_dir) + directory_size(&fixture.cargo);
    let owner_before = fs::read(fixture.repo.cache_dir.join("identity.json")).unwrap();
    for apply in [false, true] {
        let mut command = fixture.command();
        if apply {
            command.arg("--apply");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: GcReport = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report.complete);
        assert!(report.failures.is_empty());
        assert_eq!(report.applied, apply);
        assert_eq!(report.actions.len(), 1);
        let action = &report.actions[0];
        assert_eq!(action.kind, "orphan-workspace-cargo");
        assert_eq!(
            action.companion_paths,
            [fixture.repo.cache_dir.clone(), fixture.cargo.clone()]
        );
        assert_eq!(action.bytes, expected);
        assert_eq!(report.bytes_selected, expected);
        if !apply {
            assert_eq!(report.bytes_reclaimed, 0);
            assert_eq!(
                fs::read(fixture.repo.cache_dir.join("identity.json")).unwrap(),
                owner_before
            );
            assert!(fixture.cargo.is_dir());
        }
    }
    assert!(!fixture.repo.cache_dir.exists());
    assert!(!fixture.cargo.exists());
    assert!(resources::get(&fixture.root, &fixture.id)
        .unwrap()
        .is_none());
    assert!(fixture.collect(true, None).actions.is_empty());
}

#[test]
fn public_gc_recovery_retains_authority_on_native_permission_errors() {
    for (boundary, committed) in [
        ("trash", false),
        ("trash", true),
        ("staged", false),
        ("original", false),
    ] {
        let fixture = Fixture::new();
        let owner_before = fs::read(fixture.repo.cache_dir.join("identity.json")).unwrap();
        let (journal, trash, originals) = fixture.stage_recovery(committed);
        let journal_before = fs::read(&journal).unwrap();
        let owner_index = originals
            .iter()
            .position(|path| path == &fixture.repo.cache_dir)
            .unwrap();
        let cargo_index = originals
            .iter()
            .position(|path| path == &fixture.cargo)
            .unwrap();
        let (blocked, probe) = match boundary {
            "trash" => (fixture.root.trash(), trash.clone()),
            "staged" => (trash.clone(), trash.join(owner_index.to_string())),
            "original" => (
                fixture.repo.cache_dir.parent().unwrap().to_path_buf(),
                fixture.repo.cache_dir.clone(),
            ),
            _ => unreachable!(),
        };
        let denied = DeniedTraversal::new(blocked);
        assert_eq!(
            fs::symlink_metadata(&probe).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied,
            "native traversal denial required: {boundary}, committed={committed}"
        );
        let output = fixture.command().arg("--apply").output().unwrap();
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(10), "{diagnostic}");
        assert!(output.stdout.is_empty());
        assert!(diagnostic.contains("inspect GC path"), "{diagnostic}");
        assert!(
            diagnostic.contains(probe.to_string_lossy().as_ref()),
            "{diagnostic}"
        );
        assert_eq!(fs::read(&journal).unwrap(), journal_before);
        denied.restore();
        assert_eq!(
            fs::read(trash.join(owner_index.to_string()).join("identity.json")).unwrap(),
            owner_before
        );
        assert_eq!(
            fs::read(trash.join(cargo_index.to_string()).join("object")).unwrap(),
            b"disposable Cargo object"
        );
        for _ in 0..2 {
            let output = fixture.command().arg("--apply").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: GcReport = serde_json::from_slice(&output.stdout).unwrap();
            assert!(report.complete);
            assert!(report.actions.is_empty() && report.failures.is_empty());
            assert_eq!(report.trash_backlog, 0);
            assert!(!journal.exists() && !trash.exists());
            if committed {
                assert!(!fixture.repo.cache_dir.exists() && !fixture.cargo.exists());
            } else {
                assert_eq!(
                    fs::read(fixture.repo.cache_dir.join("identity.json")).unwrap(),
                    owner_before
                );
                assert_eq!(
                    fs::read(fixture.cargo.join("object")).unwrap(),
                    b"disposable Cargo object"
                );
            }
        }
    }
}

#[test]
fn action_cap_never_retires_only_the_owner() {
    let fixture = Fixture::new();
    fixture.orphan();
    let paused = fixture.collect(true, Some(0));
    assert!(!paused.complete);
    assert!(paused.actions.is_empty());
    assert!(fixture.repo.cache_dir.is_dir() && fixture.cargo.is_dir());
    let applied = fixture.collect(true, Some(1));
    assert!(applied.complete);
    assert_eq!(applied.actions.len(), 1);
    assert!(!fixture.repo.cache_dir.exists() && !fixture.cargo.exists());
}

#[test]
fn existing_or_recreated_worktree_is_not_orphan_authority() {
    let fixture = Fixture::new();
    fixture.assert_preserved("");
    fixture.orphan();
    fs::create_dir(&fixture.repo.worktree).unwrap();
    fixture.assert_preserved("");
}

#[test]
fn incomplete_recent_future_and_hazardous_cargo_preserve_owner() {
    for case in [
        "incomplete",
        "completion-before-start",
        "recent",
        "future",
        "hazard",
        "generation",
    ] {
        let fixture = Fixture::new();
        fixture.orphan();
        fixture.resource(|record| match case {
            "incomplete" => record.last_completed_unix = None,
            "completion-before-start" => {
                record.last_completed_unix = Some(record.last_started_unix - 1)
            }
            "recent" => record.last_completed_unix = Some(now_unix()),
            "future" => record.last_maintained_unix = Some(now_unix() + 86_400),
            "hazard" => {
                record.hazards.insert("unknown-planned-work".into());
            }
            "generation" => record.generation.clear(),
            _ => unreachable!(),
        });
        fixture.assert_preserved("orphan Cargo owner retained");
    }
}

#[test]
fn missing_invalid_or_redirected_catalog_preserves_owner() {
    for case in ["missing", "invalid", "redirected"] {
        let fixture = Fixture::new();
        fixture.orphan();
        let catalog = resources::catalog_path(&fixture.root, &fixture.id);
        if case == "invalid" {
            fs::write(&catalog, b"invalid").unwrap();
        } else {
            let backup = fixture._temp.path().join("catalog-backup");
            fs::rename(&catalog, &backup).unwrap();
            if case == "redirected" {
                std::os::unix::fs::symlink(backup, catalog).unwrap();
            }
        }
        fixture.assert_preserved("orphan Cargo owner retained");
    }
}

#[test]
fn missing_owner_does_not_authorize_orphan_cargo_cleanup() {
    let fixture = Fixture::new();
    fixture.orphan();
    fs::remove_dir_all(&fixture.repo.cache_dir).unwrap();
    for apply in [false, true] {
        assert!(fixture.collect(apply, None).actions.is_empty());
        assert!(fixture.cargo.is_dir());
        assert!(resources::get(&fixture.root, &fixture.id)
            .unwrap()
            .is_some());
    }
}

#[test]
fn unavailable_or_redirected_worktree_parent_is_not_absence_evidence() {
    for redirect in [false, true] {
        let fixture = Fixture::new();
        fixture.orphan();
        let parent = fixture.repo.worktree.parent().unwrap();
        let moved = fixture._temp.path().join("moved-checkouts");
        fs::rename(parent, &moved).unwrap();
        if redirect {
            std::os::unix::fs::symlink(&moved, parent).unwrap();
        }
        fixture.assert_preserved("orphan Cargo owner retained");
    }
}

#[test]
fn active_cargo_lease_preserves_owner_and_payload() {
    let fixture = Fixture::new();
    fixture.orphan();
    let _active = RootLease::shared(&fixture.root, "synthetic-work")
        .unwrap()
        .into_active(std::slice::from_ref(&fixture.id))
        .unwrap();
    fixture.assert_preserved("active routed command");
}

#[test]
fn overlapping_catalog_resource_preserves_owner() {
    let fixture = Fixture::new();
    fixture.orphan();
    let nested = fixture.cargo.join("nested");
    fs::create_dir(&nested).unwrap();
    resources::register_routed(
        &fixture.root,
        Adapter::Temp,
        &HashMap::from([("TMPDIR".to_owned(), nested.to_string_lossy().into_owned())]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    fixture.assert_preserved("another catalog resource");
}

#[test]
fn retained_outputs_are_outside_the_orphan_transaction() {
    let fixture = Fixture::new();
    fixture.orphan();
    let outputs = fixture
        .root
        .platform_root
        .join("outputs/cargo/workspace/toolchain");
    // Retained output registration refuses adoption, so register while empty.
    fs::create_dir_all(&outputs).unwrap();
    let ids = resources::register_routed(
        &fixture.root,
        Adapter::Cargo,
        &HashMap::from([(
            "CARGO_TARGET_DIR".to_owned(),
            outputs.to_string_lossy().into_owned(),
        )]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    fs::write(outputs.join("binary"), b"retained final output").unwrap();
    let report = fixture.collect(true, None);
    assert_eq!(report.actions.len(), 1);
    assert_eq!(
        fs::read(outputs.join("binary")).unwrap(),
        b"retained final output"
    );
    assert!(resources::get(&fixture.root, &ids[0]).unwrap().is_some());
    assert!(report
        .abstentions
        .iter()
        .any(|a| a.reason.contains("retained final")));
}

#[test]
fn owner_without_cargo_keeps_existing_metadata_only_policy() {
    let fixture = Fixture::new();
    fixture.orphan();
    fs::remove_dir_all(&fixture.cargo).unwrap();
    resources::remove_record(&fixture.root, &fixture.id).unwrap();
    let report = fixture.collect(true, None);
    assert_eq!(report.actions.len(), 1);
    assert_eq!(report.actions[0].kind, "repository");
    assert!(!fixture.repo.cache_dir.exists());
}

#[test]
fn unknown_or_duplicate_authority_fields_do_not_authorize_orphan_cleanup() {
    for owner in [false, true] {
        for unknown in [false, true] {
            let fixture = Fixture::new();
            fixture.orphan();
            let path = if owner {
                fixture.repo.cache_dir.join("identity.json")
            } else {
                resources::catalog_path(&fixture.root, &fixture.id)
            };
            let bytes = fs::read_to_string(&path).unwrap();
            let field = if unknown {
                "\"future_reservation\":true"
            } else {
                "\"schema_version\":1"
            };
            let changed = format!("{{{field},{}", &bytes[1..]);
            fs::write(path, changed).unwrap();
            fixture.assert_preserved(if unknown { "unknown fields" } else { "" });
        }
    }
}

#[test]
fn dangling_cargo_ancestor_never_enables_metadata_only_fallback() {
    let fixture = Fixture::new();
    fixture.orphan();
    let parent = fixture.cargo.parent().unwrap();
    let moved = fixture._temp.path().join("moved-cargo");
    fs::rename(parent, &moved).unwrap();
    std::os::unix::fs::symlink(fixture._temp.path().join("missing"), parent).unwrap();
    resources::remove_record(&fixture.root, &fixture.id).unwrap();
    for apply in [false, true] {
        let report = fixture.collect(apply, None);
        assert!(report.actions.is_empty());
        assert!(fixture.repo.cache_dir.is_dir());
        assert!(moved.join(&fixture.repo.identity).join("object").is_file());
        assert!(report
            .abstentions
            .iter()
            .any(|a| a.reason.contains("ancestry")));
    }
}

#[test]
fn reconciliation_cannot_add_hazardous_ownership_to_an_admitted_orphan() {
    let fixture = Fixture::new();
    fixture.orphan();
    let owner_path = fixture.repo.cache_dir.join("identity.json");
    let owner_before = fs::read(&owner_path).unwrap();
    let mut legacy: IdentityRecord = serde_json::from_slice(&owner_before).unwrap();
    let seed = format!(
        "v2\0{}\0{}\0{}",
        fixture.root.marker.root_id,
        legacy.canonical_worktree.display(),
        legacy.filesystem_identity
    );
    legacy.identity = blake3::hash(seed.as_bytes()).to_hex().to_string();
    let legacy_path = fixture
        .root
        .repos()
        .join(&legacy.identity[..2])
        .join(&legacy.identity);
    fs::create_dir_all(&legacy_path).unwrap();
    write_json_atomic(&legacy_path.join("identity.json"), &legacy).unwrap();
    let nested = legacy_path.join("temp/nested");
    fs::create_dir_all(&nested).unwrap();
    fs::write(nested.join("protected"), b"hazardous owned resource").unwrap();
    let ids = resources::register_routed(
        &fixture.root,
        Adapter::Temp,
        &HashMap::from([("TMPDIR".to_owned(), nested.to_string_lossy().into_owned())]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    let mut record = resources::get(&fixture.root, &ids[0]).unwrap().unwrap();
    record.hazards.insert("unknown-planned-work".into());
    write_json_atomic(
        &resources::catalog_path(&fixture.root, &record.resource_id),
        &record,
    )
    .unwrap();
    let report = fixture.collect(true, None);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.actions.len(), 1);
    assert_eq!(report.actions[0].kind, "repository-identity");
    assert!(report
        .abstentions
        .iter()
        .any(|a| a.reason.contains("reconciliation overlaps")));
    assert_eq!(
        fs::read(fixture.repo.cache_dir.join("temp/nested/protected")).unwrap(),
        b"hazardous owned resource"
    );
    let owner_after: IdentityRecord =
        serde_json::from_slice(&fs::read(owner_path).unwrap()).unwrap();
    assert_eq!(
        owner_after,
        serde_json::from_slice::<IdentityRecord>(&owner_before).unwrap()
    );
    fixture.assert_preserved("another catalog resource");
}

#[test]
fn malformed_catalog_blocks_metadata_only_fallback_even_without_payload() {
    let fixture = Fixture::new();
    fixture.orphan();
    fs::remove_dir_all(&fixture.cargo).unwrap();
    fs::write(
        resources::catalog_path(&fixture.root, &fixture.id),
        b"invalid",
    )
    .unwrap();
    for apply in [false, true] {
        let report = fixture.collect(apply, None);
        assert!(report.actions.is_empty());
        assert!(fixture.repo.cache_dir.is_dir());
        assert!(report
            .abstentions
            .iter()
            .any(|a| a.reason.contains("catalog records are invalid")));
    }
}
