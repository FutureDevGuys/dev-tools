#![cfg(test)]

//! Private authority and interrupted-transaction fixtures, never live storage.
use std::collections::{BTreeSet, HashMap};
use std::fs;

use super::*;
use crate::config::Config;
use crate::lease::RootLease;
use crate::repository::Repository;
use crate::resources::NativeTool;
use crate::util::{now_unix, write_json_atomic};

fn admitted_fixture() -> (tempfile::TempDir, RootHandle, GcConfig, GcAction, Evidence) {
    let temp = tempfile::tempdir().unwrap();
    let root = RootHandle::initialize(&temp.path().join("root")).unwrap();
    let worktree = temp.path().join("worktree");
    fs::create_dir(&worktree).unwrap();
    let repo = Repository::discover(&worktree, &root).unwrap().unwrap();
    repo.touch(&root).unwrap();
    let cargo = root
        .shared()
        .join("cargo/intermediate")
        .join(&repo.identity);
    fs::create_dir_all(&cargo).unwrap();
    fs::write(cargo.join("payload"), b"owned bytes").unwrap();
    let ids = resources::register_routed(
        &root,
        Adapter::Cargo,
        &HashMap::from([(
            "CARGO_BUILD_BUILD_DIR".to_owned(),
            cargo.to_string_lossy().into_owned(),
        )]),
        &NativeTool::default(),
        &BTreeSet::new(),
    )
    .unwrap();
    resources::complete(&root, &ids).unwrap();
    fs::remove_dir(&repo.worktree).unwrap();
    let mut policy = Config::default().gc;
    policy.orphan_grace_days = 0;
    let record = resources::get(&root, &ids[0]).unwrap().unwrap();
    let evidence = admit(
        &Admission {
            root: &root,
            policy: &policy,
            now: now_unix(),
            active_paths: &[],
        },
        &repo.cache_dir,
        &cargo,
        &record,
    )
    .unwrap();
    let action = GcAction {
        kind: ACTION_KIND.to_owned(),
        path: repo.cache_dir.clone(),
        destination: None,
        companion_paths: vec![repo.cache_dir, cargo],
        bytes: 0,
        reason: "orphan".to_owned(),
        strategy: "owneddirectory".to_owned(),
        resource_id: Some(record.resource_id),
        last_used_unix: now_unix(),
    };
    (temp, root, policy, action, evidence)
}

#[test]
fn mutation_rechecks_generation_owner_source_and_activity() {
    for change in ["generation", "owner", "source", "activity", "companion"] {
        let (_temp, root, policy, mut action, evidence) = admitted_fixture();
        match change {
            "generation" => {
                let mut record = evidence.resource.clone();
                record.generation = uuid::Uuid::new_v4().simple().to_string();
                write_json_atomic(
                    &resources::catalog_path(&root, &record.resource_id),
                    &record,
                )
                .unwrap();
            }
            "owner" => {
                let mut owner = evidence.owner.clone();
                owner.last_used_unix += 1;
                write_json_atomic(&evidence.owner_path.join("identity.json"), &owner).unwrap();
            }
            "source" => fs::create_dir(&evidence.owner.canonical_worktree).unwrap(),
            "activity" => {
                // Older participants publish activity then release root
                // coordination. Mutation must still reject that live record.
                write_json_atomic(
                    &root.control().join("leases/legacy-active.json"),
                    &serde_json::json!({
                        "schema_version": 1,
                        "pid": std::process::id(),
                        "started_unix": now_unix(),
                        "operation": "legacy-work",
                        "resource_ids": [&evidence.resource.resource_id],
                    }),
                )
                .unwrap();
            }
            "companion" => {
                action.companion_paths.pop();
            }
            _ => unreachable!(),
        }
        let _exclusive = RootLease::exclusive(&root).unwrap();
        assert!(
            apply(&root, &policy, &action, &evidence).is_err(),
            "{change}"
        );
        assert!(evidence.owner_path.is_dir(), "{change}");
        assert_eq!(
            fs::read(evidence.cargo_path.join("payload")).unwrap(),
            b"owned bytes",
            "{change}"
        );
    }
}

#[test]
fn pending_reconciliation_preserves_owner_without_catalog_rescan() {
    let (_temp, root, policy, mut owner, evidence) = admitted_fixture();
    owner.kind = "repository".to_owned();
    owner.companion_paths.clear();
    let mut rehome = owner.clone();
    rehome.kind = "repository-identity".to_owned();
    rehome.path = root.repos().join("legacy");
    rehome.destination = Some(owner.path.clone());
    let mut actions = vec![owner, rehome];
    let mut abstentions = Vec::new();
    let groups = link_actions(
        &Admission {
            root: &root,
            policy: &policy,
            now: now_unix(),
            active_paths: &[],
        },
        &[evidence.resource],
        true,
        &mut actions,
        &mut abstentions,
    );
    assert!(groups.is_empty());
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].kind, "repository-identity");
    assert!(abstentions[0].reason.contains("reconciliation"));
    assert!(evidence.owner_path.is_dir() && evidence.cargo_path.is_dir());
}

#[test]
fn filesystem_device_change_and_worktree_link_are_not_absence() {
    let (temp, _root, _policy, _action, evidence) = admitted_fixture();
    let mut owner = evidence.owner.clone();
    owner.filesystem_identity = "18446744073709551615:1".to_owned();
    assert!(prove_worktree_absent(&owner).is_err());
    std::os::unix::fs::symlink(
        temp.path().join("missing"),
        &evidence.owner.canonical_worktree,
    )
    .unwrap();
    assert!(prove_worktree_absent(&evidence.owner).is_err());
}

#[test]
fn compound_recovery_restores_every_uncommitted_member() {
    for staged_count in [1, 2] {
        let (_temp, root, _policy, action, _evidence) = admitted_fixture();
        let (journal, path) = stage(&root, &action, staged_count, false);
        super::super::recover_trash(&root).unwrap();
        for original in &journal.original_paths {
            assert!(original.is_dir());
        }
        assert!(!journal.trash_path.exists());
        assert!(!path.exists());
    }
}

#[test]
fn committed_compound_recovery_finishes_without_recreating_owner() {
    let (_temp, root, _policy, action, _evidence) = admitted_fixture();
    let (journal, path) = stage(&root, &action, 2, true);
    super::super::recover_trash(&root).unwrap();
    for original in &journal.original_paths {
        assert!(!original.exists());
    }
    assert!(!journal.trash_path.exists() && !path.exists());
    // A leftover catalog record cannot reconstruct missing workspace authority.
    assert!(
        resources::get(&root, action.resource_id.as_deref().unwrap())
            .unwrap()
            .is_some()
    );
}

#[test]
fn rollback_conflict_keeps_journal_and_original_staged_bytes() {
    let (_temp, root, _policy, action, _evidence) = admitted_fixture();
    let (journal, path) = stage(&root, &action, 2, false);
    let conflict = journal.original_paths.last().unwrap();
    fs::create_dir(conflict).unwrap();
    fs::write(conflict.join("replacement"), b"new owner").unwrap();
    assert!(super::super::recover_trash(&root).is_err());
    assert_eq!(
        fs::read(conflict.join("replacement")).unwrap(),
        b"new owner"
    );
    assert!(path.is_file());
    assert!(journal.trash_path.join("0").is_dir());
    assert!(journal.trash_path.join("1").is_dir());
}

fn stage(
    root: &RootHandle,
    action: &GcAction,
    count: usize,
    committed: bool,
) -> (super::super::TrashJournal, PathBuf) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let trash = root.trash().join(&id);
    fs::create_dir(&trash).unwrap();
    let mut paths = action.companion_paths.clone();
    paths.sort();
    for (index, path) in paths.iter().take(count).enumerate() {
        fs::rename(path, trash.join(index.to_string())).unwrap();
    }
    let journal = super::super::TrashJournal {
        schema_version: 1,
        transaction_id: id.clone(),
        resource_id: action.resource_id.clone(),
        original_paths: paths,
        trash_path: trash,
        committed,
        created_unix: now_unix(),
    };
    let path = root.control().join("gc-journal").join(format!("{id}.json"));
    write_json_atomic(&path, &journal).unwrap();
    (journal, path)
}
