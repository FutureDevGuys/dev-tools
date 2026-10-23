use super::CompletionSnapshotPublishOutcome;

/// Observed requested candidate-shell work, before retention and binding selection.
/// Candidate counters are exclusive; inventory and binding counters have separate scopes.
#[derive(Debug, Default)]
pub(crate) struct CompletionObservation {
    pub refreshed: usize,
    pub unchanged: usize,
    pub retained_requested: usize,
    pub unsupported: usize,
    pub failed: usize,
    pub removed: usize,
    pub legacy_binding_changes: usize,
    pub shadowed: usize,
    pub inventory_complete: usize,
    pub inventory_configured: usize,
    pub inventory_incomplete: usize,
    pub inventory_failed: usize,
}

impl CompletionObservation {
    pub(super) fn result_footer(
        &self,
        publication: Option<&CompletionSnapshotPublishOutcome>,
        install_changed: bool,
    ) -> String {
        let snapshot = match publication {
            Some(CompletionSnapshotPublishOutcome::Published { .. }) => "published",
            Some(CompletionSnapshotPublishOutcome::Repaired { .. }) => "repaired",
            Some(CompletionSnapshotPublishOutcome::Unchanged { .. }) => "unchanged",
            None => "not_requested",
        };
        let snapshot_changed = matches!(
            publication,
            Some(
                CompletionSnapshotPublishOutcome::Published { .. }
                    | CompletionSnapshotPublishOutcome::Repaired { .. }
            )
        );
        let outcome = if self.failed > 0 || self.inventory_failed > 0 {
            "failed"
        } else if self.retained_requested > 0 || self.inventory_incomplete > 0 {
            "deferred"
        } else if self.refreshed > 0
            || self.removed > 0
            || self.legacy_binding_changes > 0
            || snapshot_changed
            || install_changed
        {
            "updated"
        } else {
            "no_op"
        };
        // Fixed vocabulary and machine-sized counts keep even maximum values bounded.
        // Shadowing is an orthogonal binding observation, not another candidate outcome.
        let detail = format!(
            "snapshot={snapshot};candidate-shells:refreshed={},unchanged={},retained_requested={},unsupported={},failed={};removed={};legacy_bindings={};shadowed={};inventory:complete={},configured={},incomplete={},failed={};install_changed={install_changed}",
            self.refreshed, self.unchanged, self.retained_requested, self.unsupported,
            self.failed, self.removed, self.legacy_binding_changes, self.shadowed,
            self.inventory_complete, self.inventory_configured, self.inventory_incomplete,
            self.inventory_failed,
        );
        format!(
            "UPDATE_ALL_RESULT {}",
            serde_json::json!({"outcome": outcome, "detail": detail})
        )
    }
}
