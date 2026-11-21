---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0050: Structured item results

status: proposed
verification: pending

## Context

A task footer describes the aggregate outcome but cannot say which operations completed before a command failed, or identify the versions it observed for each item.

## Decision

A command can emit one `UPDATE_ALL_ITEM` JSON record per observed item before its existing `UPDATE_ALL_RESULT` v1 footer. Each item supplies a subject, a lowercase action identifier, an outcome, and optional observed before and after identities. The runner groups rows by action using its existing report sections. The same report data reaches task logs, final rollups, and persisted run artifacts.

Task logs and the final rollup show the action alongside each structured item. Color-capable displays use white for the subject, cyan for the action, and the existing outcome palette.

## Invariants

- The command owns observation and attribution. The runner has no producer-specific dispatch.
- The v1 summary remains valid without item records and retains its existing outcome and version fields.
- A failed process remains failed while valid item observations remain available.

## Rejected alternatives

Parsing each tool’s human output in the runner couples presentation text to the outcome. Adding fields to the strict v1 footer would cause installed readers to reject the footer.

## Consequences and known limitations

The runner considers up to 256 item lines per command, each within the structured text limit. It ignores malformed items, unrecognized outcomes, and item fields with control characters. Legacy readers continue to consume the original summary.

## Verification

- `truthful_operation_final_rollup_pty_preserves_outcomes_and_observations`
- `stylize_operation_items_colors_subject_action_and_outcome`
- `truthful_declared_operation_result_rejects_missing_and_retains_failed_effects`
- `truthful_item_observations_survive_a_failed_command_or_output_validation`

## Runtime acceptance

Use disposable provider commands with both engines. Verify distinct outcomes and before and after identities in artifacts and the final report. Return a nonzero process status after emitting valid observations and confirm the task stays failed and its item observations survive.

## Supersession conditions

Supersede this decision when the task protocol changes or when structured item results can carry a new scheduling authority.
