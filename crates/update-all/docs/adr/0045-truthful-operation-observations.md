---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0045: Truthful operation observations

status: proposed
verification: pending

## Context

Generic command reports rendered diagnostic severity as a package name and
invented emitted/captured state transitions. Wrapper failures named the executable
rather than the selected task. Successful JSON operations could produce no report
rows. Missing post-timeout inventory appeared blocked, while completed task state
made deferred operations green in the dashboard.

## Decision

Keep task lifecycle, ordering, capability health, command deadlines, and execution
ownership unchanged. Add report-only deferred and unconfirmed outcomes. Both
make selected work unresolved without adding a capability-health gate. Explicit
failed and blocked evidence retains its existing meaning under ADRs 0001 and 0040.
Issue counts include the new report outcomes in persisted artifacts and history.
New explicit deferred or unconfirmed evidence selects the existing incomplete-run
outcome and stops later admission with fail-fast. Without fail-fast, these report
values alone do not block ordering or health successors.

An explicitly configured operation_result parser reads bounded shared-v2 results
and legacy activation observations. It uses reported subject strings without
product-name branches. Absent or invalid required results fail the task. Failed
processes keep their lifecycle outcome and any valid observed effects. Installed
identity, available identity, and nullable reported change remain distinct.
Required-result validity is captured before arbitrary report sections are merged.
Section names cannot stand in for parser success. Shared-v2 product IDs,
operation names, outcomes, and exit codes retain their fixed protocol domains
while additive fields and legacy observations remain compatible.
The operation owns the scope of its change fact. The adapter presents declared
observations, not independent verification of the producer's claims.
A no-op never supplies a fabricated before-version or proof of currentness.
The existing UPDATE_ALL_RESULT v1 payload remains unchanged and contributes
visible operation rows from its declared outcomes.

Before-only inventory after failure is unconfirmed, with a null after-value.
Retain any explicit completion already observed. This decision adds no after-
failure probe, deadline extension, or replay authority. Diagnostic samples keep
their bounded artifact section but have null version fields and render outside
package change tables. Diagnostic severity stays independent of transaction
status. Failure fallback rows use the task label, not the wrapper executable.

TaskStateChanged carries optional typed presentation metadata. The dashboard
uses that metadata for unresolved labels and warning colors. Its lifecycle state,
terminal counters, and dependency-wait checks remain unchanged. The journal
retains the original state plus additive presentation metadata.

## Invariants

- Available versions never substitute for unobserved installed versions.
- Missing post-state does not prove a capability is blocked or unchanged.
- Diagnostic messages remain visible at every report verbosity without package counts.
- A successful process alone cannot satisfy an invalid declared result contract.
- Deferred work is not green success, and display metadata does not change scheduling.
- A failed process cannot become successful because it reported partial effects.

## Rejected alternatives

Changing TaskStatus would conflate lifecycle with observations and alter health
dependencies. Product-specific JSON branches would weaken the generic catalog
contract. Extra probes after timeout would change the execution boundary rather
than correct its report. Treating no-op as current would exceed its evidence.

## Consequences and known limitations

Report consumers must tolerate the additive deferred and unconfirmed row values.
The task lifecycle vocabulary is unchanged. The operation adapter bounds captured
input at 16 KiB and accepts trailing non-JSON process logs after its leading JSON
document. An additional parseable object or array at the start of a trailing line
is rejected. Ordinary bracketed progress is not another JSON document.
Other output shapes need a separately configured report adapter.
Native platform and signed installed-release acceptance remain separate gates.

## Verification

- `truthful_operation_reports_preserve_observed_versions_and_change_uncertainty`
- `truthful_operation_report_allows_progress_but_rejects_additional_documents`
- `truthful_operation_result_cannot_be_satisfied_by_a_named_report_pattern`
- `truthful_operation_result_rejects_invalid_required_v2_domains`
- `truthful_operation_final_rollup_pty_preserves_outcomes_and_observations`
- `truthful_declared_operation_result_rejects_missing_and_retains_failed_effects`
- `truthful_deferred_result_has_a_row_without_changing_dependency_health`
- `truthful_diagnostics_are_not_package_changes_or_version_observations`
- `truthful_wrapper_failure_names_the_task_not_the_executable`
- `failed_command_report_retains_pipx_before_inventory_without_claiming_refresh`
- `truthful_dashboard_presentation_does_not_turn_deferred_work_green`
- `truthful_task_presentation_survives_transport_and_keeps_journal_state`

## Runtime acceptance

Use the standalone candidate with disposable providers. Exercise success, no-op,
deferred, missing and malformed documents, changed-before-failure, and timeout
with partial progress. Compare plain output, dashboard labels and colors, JSON,
journal, and history. Verify ordering successors still proceed and explicit
health failures still block. Inspect complete diagnostic samples at normal
verbosity. Do not run real updates or alter native timeout policy for acceptance.

## Supersession conditions

Supersede when a stream-typed external result protocol replaces the bounded
adapter, when lifecycle outcomes change, or when typed capability results replace
the current explicit health evidence.
