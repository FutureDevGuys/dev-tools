---
authority: canonical
owner: dev-tools
---

# ADR 0001: Ordering versus health dependencies

status: accepted
verification: verified

## Context

Some tasks need only sequencing, while others consume a capability produced by
their predecessor. Treating both relationships as health dependencies caused a
completed npm task with non-blocking findings to cancel the independent `skills`
updater. Visual report status is not a reliable capability signal.

## Decision

`after` is ordering-only: the successor waits until every referenced predecessor
is terminal, then may run regardless of outcome. `depends_on` is a capability
gate: task failure, cancellation, or an explicit `blocks_dependents` outcome may
cancel the successor. Unknown references and cycles are validated across the
combined graph. Cancellation evidence names the dependency and its actual
status.

## Invariants

- Ordering edges never cause dependency cancellation.
- Health edges block only on task failure, cancellation, or an explicit
  dependent-blocking outcome.
- Scheduling and cycle validation use the combined ordering graph.
- Report presentation does not implicitly define dependency health.

## Rejected alternatives

- Interpreting every predecessor issue as failure preserves the original false
  cancellation.
- Making `depends_on` ordering-only would allow consumers of failed capabilities
  to run.
- Special-casing npm or `skills` would leave the scheduler model ambiguous.

## Consequences and known limitations

Configurations must choose the relationship that matches capability semantics.
Existing `depends_on` configurations remain health-gated. The additive `after`
field is available to built-ins, external catalogs, and inline TOML. External
catalog tasks may use `after_selected = true` to generate ordering-only edges to
the selected run set; `after_selected_exclude` removes explicitly named task
IDs from that generated set.

## Verification

Named regression tests:

- `ordering_predecessor_failure_does_not_block_successor`
- `health_dependency_failure_reports_precise_blocking_detail`
- `health_dependency_completed_with_blocking_issues_is_named_accurately`
- `failed_dependencies_block_even_when_their_advisory_is_non_blocking`
- `mixed_ordering_and_health_dependency_cycle_is_rejected`
- `runtime_config_rejects_unknown_custom_updater_after_reference`
- `build_task_specs_expands_after_selected_as_ordering_only`
- `runtime_config_rejects_unknown_after_selected_exclusion`

## Runtime acceptance

Run two catalog tasks where the second declares only `after` on the first.
Acceptance requires the successor to start after the predecessor reaches a
terminal state, including when the predecessor has a non-blocking diagnostic.

## Supersession conditions

Supersede this record if dependency health becomes a typed capability contract,
the scheduler stops using terminal task outcomes, or configuration replaces
`after`/`depends_on` with another public relationship model.
