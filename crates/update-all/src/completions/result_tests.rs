use super::result::CompletionObservation;
use super::CompletionSnapshotPublishOutcome;
use serde_json::Value;
use std::path::PathBuf;

fn payload(
    observation: &CompletionObservation,
    snapshot: Option<&CompletionSnapshotPublishOutcome>,
    install: bool,
) -> Value {
    let line = observation.result_footer(snapshot, install);
    assert!(line.len() <= 512, "{} bytes: {line}", line.len());
    let value: Value =
        serde_json::from_str(line.strip_prefix("UPDATE_ALL_RESULT ").unwrap()).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 2);
    assert!(value.get("current").is_none());
    assert!(value.get("latest").is_none());
    value
}

#[test]
fn completion_result_snapshot_change_is_distinct_from_candidate_refresh() {
    let facts = CompletionObservation::default();
    let published = CompletionSnapshotPublishOutcome::Published {
        snapshot: PathBuf::from("private-path-must-not-leak"),
    };
    let first = payload(&facts, Some(&published), false);
    assert_eq!(first["outcome"], "updated");
    assert!(first["detail"]
        .as_str()
        .unwrap()
        .contains("snapshot=published"));
    assert!(first["detail"]
        .as_str()
        .unwrap()
        .contains("candidate-shells:refreshed=0"));
    assert!(!first.to_string().contains("private-path"));
    let unchanged = CompletionSnapshotPublishOutcome::Unchanged {
        snapshot: PathBuf::new(),
    };
    assert_eq!(payload(&facts, Some(&unchanged), false)["outcome"], "no_op");
    let repaired = CompletionSnapshotPublishOutcome::Repaired {
        snapshot: PathBuf::new(),
    };
    assert_eq!(
        payload(&facts, Some(&repaired), false)["outcome"],
        "updated"
    );
}

#[test]
fn completion_result_requested_retention_and_failure_outrank_publication() {
    let published = CompletionSnapshotPublishOutcome::Published {
        snapshot: PathBuf::new(),
    };
    let mut facts = CompletionObservation {
        retained_requested: 1,
        ..Default::default()
    };
    assert_eq!(
        payload(&facts, Some(&published), false)["outcome"],
        "deferred"
    );
    facts.failed = 1;
    assert_eq!(
        payload(&facts, Some(&published), false)["outcome"],
        "failed"
    );
    facts.failed = 0;
    facts.inventory_failed = 1;
    assert_eq!(
        payload(&facts, Some(&published), false)["outcome"],
        "failed"
    );
}

#[test]
fn completion_result_configured_coverage_is_not_incomplete_work() {
    let mut facts = CompletionObservation {
        inventory_configured: 1,
        unchanged: 1,
        ..Default::default()
    };
    assert_eq!(payload(&facts, None, false)["outcome"], "no_op");
    facts.inventory_incomplete = 1;
    assert_eq!(payload(&facts, None, false)["outcome"], "deferred");
}

#[test]
fn completion_result_optional_unsupported_and_shadowing_are_not_failures() {
    let mut facts = CompletionObservation {
        unsupported: 1,
        shadowed: 1,
        ..Default::default()
    };
    assert_eq!(payload(&facts, None, false)["outcome"], "no_op");
    facts.refreshed = 1;
    assert_eq!(payload(&facts, None, false)["outcome"], "updated");
}

#[test]
fn completion_result_binding_removal_and_install_changes_are_observed() {
    let mut facts = CompletionObservation::default();
    assert_eq!(payload(&facts, None, true)["outcome"], "updated");
    facts.legacy_binding_changes = 1;
    assert_eq!(payload(&facts, None, false)["outcome"], "updated");
    facts.legacy_binding_changes = 0;
    facts.removed = 1;
    assert_eq!(payload(&facts, None, false)["outcome"], "updated");
}

#[test]
fn completion_result_maximum_counts_fit_bounded_version_free_footer() {
    let facts = CompletionObservation {
        refreshed: usize::MAX,
        unchanged: usize::MAX,
        retained_requested: usize::MAX,
        unsupported: usize::MAX,
        failed: usize::MAX,
        removed: usize::MAX,
        legacy_binding_changes: usize::MAX,
        shadowed: usize::MAX,
        inventory_complete: usize::MAX,
        inventory_configured: usize::MAX,
        inventory_incomplete: usize::MAX,
        inventory_failed: usize::MAX,
    };
    payload(&facts, None, true);
}

#[test]
fn completion_result_install_change_is_idempotent_and_self_repair_is_observed() {
    let temp = tempfile::TempDir::new().unwrap();
    let zsh = temp.path().join("zsh");
    assert!(super::completion_install_zsh(zsh.clone()).unwrap().changed);
    assert!(!super::completion_install_zsh(zsh.clone()).unwrap().changed);
    let powershell = temp.path().join("powershell");
    assert!(
        super::completion_install_powershell(&powershell)
            .unwrap()
            .changed
    );
    assert!(
        !super::completion_install_powershell(&powershell)
            .unwrap()
            .changed
    );
    std::fs::remove_file(powershell.join("modules/update-all.generated.ps1")).unwrap();
    assert!(
        super::completion_install_powershell(&powershell)
            .unwrap()
            .changed
    );
}
