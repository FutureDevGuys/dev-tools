---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0046: Completion sync result observations

status: proposed
verification: pending

## Context

Completion sync's existing event lines and successful process status do not tell a
generic task consumer whether requested candidate work changed, was unchanged,
failed, or retained prior artifacts. A published self snapshot is not evidence
that provider candidates refreshed, and binding shadowing can hide a candidate's
actual work from final records.

## Decision

Add one final `UPDATE_ALL_RESULT` v1 footer to the explicit completions sync CLI
only, after sync and any requested legacy install and audit return successfully.
Keep the existing generic task parser, process exit semantics, runtime policy,
retirement authority, and existing event output unchanged. Errors and observed
global cancellation emit no footer, including cancellation swallowed by the
existing final optional-candidate classification. This does not change that
pre-existing process-exit behavior.
The footer contains only outcome and detail, with fixed labels, enum values and
counts, and is bounded to 512 bytes including its prefix. It contains no versions,
paths, commands or error text. Other completion subcommands emit no footer.

Capture exclusive requested candidate-shell outcomes immediately after probing,
before broad provider retention or binding selection: refreshed, unchanged,
retained_requested, optional unsupported, or failed. A managed-required failure
that retains an old artifact counts once as failed. Inventory failures are
independent evidence even when their legacy records only say skipped. Existing
optional skipped candidate policy remains unchanged. Count removals and actual
legacy binding writes/removals separately; shadowing is orthogonal, not failure.
Retain typed snapshot publication and repair results. Carry existing installation
change facts without inferring changes from audit success or diagnostic text.

Inventory requested-scope completeness is typed separately from retirement
coverage. An intentionally configured subset remains partial for retirement but
is not incomplete requested work. Later budget exhaustion changes its requested
scope to incomplete. Unrequested cached candidates retained by that subset do
not count as requested retention.

Outcome priority is failed, deferred for incomplete requested work or requested
retention, updated for observed candidate/removal/snapshot/repair/binding/install
change, otherwise no_op. Detail labels snapshot state separately from
candidate-shell counts and complete/configured/incomplete/failed inventory counts.

## Invariants

- No generic parser special case, event-text parsing, provider update or new probe.
- Snapshot publication cannot conceal incomplete or failed requested work.
- Optional unsupported candidates and shadowing alone do not imply failure.
- Unrequested retained cache does not imply deferred requested work.
- No fabricated versions or audit-derived change facts.
- No runtime, retention, exit-code, startup or release-identity change.

## Rejected alternatives

Parsing event strings would turn diagnostics into authority. Reusing generated
counts would conflate candidate writes with binding repair. Reusing final records
would erase shadowed candidates' work. Treating every partial inventory as
incomplete would misreport intentional configured-subset runs.

## Consequences and known limitations

This is an additive producer observation, not independent verification by the
generic consumer. Candidate-shell counts are not package or installation counts.
Inventory and binding counts have separate scopes. Existing skipped optional
candidate policy remains in effect. Exceptional returns have no complete summary;
the existing process failure remains authoritative. No release or version bump is
part of this source slice. Native platform and signed-release acceptance remain
separate gates.

## Verification

- `completion_result_snapshot_change_is_distinct_from_candidate_refresh`
- `completion_result_requested_retention_and_failure_outrank_publication`
- `completion_result_configured_coverage_is_not_incomplete_work`
- `completion_result_optional_unsupported_and_shadowing_are_not_failures`
- `completion_result_binding_removal_and_install_changes_are_observed`
- `completion_result_maximum_counts_fit_bounded_version_free_footer`
- `completion_result_empty_snapshot_then_repeat_and_failed_empty_inventory`
- `completion_result_configured_subset_later_budget_partial_is_incomplete`
- `completion_result_configured_subset_retains_unrequested_cache_without_deferral`
- `completion_result_requested_retention_survives_publication_and_required_failure_is_exclusive`
- `completion_result_legacy_binding_repair_does_not_refresh_candidate`
- `completion_result_install_change_is_idempotent_and_self_repair_is_observed`
- `identity_change_with_identical_artifact_updates_only_memo_then_reuses`
- `same_binding_uses_path_winner_and_reports_other_provider_shadowed`
- `completion_sync_emits_scoped_result_after_publication`
- `actual_completion_producer_drives_generic_rows_in_both_engines`
- `failed_audit_never_emits_completion_success_footer`
- `canceled_final_ambient_probe_never_emits_success_footer`
- `legacy_install_only_change_and_other_subcommands_keep_their_scope`

## Runtime acceptance

Use disposable catalogs, managed roots and fixture executables only. Exercise
initial empty publication, repeated no-op, configured subset retention, genuine
incomplete inventory, failed inventory without configured tools, requested
retention, managed-required failure, shadowed candidate change, legacy binding
and install-only repair. Feed real producer output through both generic task
engines and verify updated, passed, deferred and failed rows without versions.
Verify the sole footer is last after successful legacy apply and absent on audit
error and on other completion subcommands. Do not run real provider updates.

## Supersession conditions

Supersede if the producer adopts another result protocol, changes its declared
change scope, changes error/exit semantics, or generic consumers require a
completion-specific policy branch.
