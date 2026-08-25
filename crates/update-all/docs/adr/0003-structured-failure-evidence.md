---
authority: canonical
owner: dev-tools
---

# ADR 0003: Structured failure evidence

status: accepted
verification: verified

## Context

Command failures can contain thousands of lines. Copying complete subprocess
output into every structured task and run field makes artifacts expensive to
inspect and duplicates the raw log that already exists.

## Decision

Task and run JSON contain bounded text, bounded collections, a concise primary
cause, and an explicit task-log filename. Human task logs retain complete command
output. This is an additive schema change and retains existing status values.

## Invariants

- Every structured text field has a fixed byte bound.
- Structured task collections have fixed entry bounds.
- Every task artifact identifies the corresponding complete task log.
- Truncation is explicit and points readers to the task log.
- Raw command output is not truncated by structured-artifact policy.

## Rejected alternatives

- Storing only raw logs makes summary and automation consumers parse prose.
- Copying raw output into JSON duplicates evidence and permits unbounded
  artifacts.
- Dropping command output loses the evidence needed for diagnosis.

## Consequences and known limitations

Automation should treat structured evidence as a classified summary and open the
named log for complete output. Large package reports are bounded; consumers that
need every raw line must use task logs.

## Verification

Named regression tests:

- `structured_failure_evidence_is_bounded_while_task_log_retains_full_output`

## Runtime acceptance

Run a controlled failing fixture with output larger than the structured field
limit. Acceptance requires bounded task and run JSON, an explicit log reference,
and the complete marker sequence in the corresponding task log.

## Supersession conditions

Supersede this record if artifacts move to external content-addressed evidence,
streaming structured events replace task logs, or compatibility requires a new
artifact schema with different evidence ownership.
