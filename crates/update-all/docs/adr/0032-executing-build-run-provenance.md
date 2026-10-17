---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0032: Executing-build run provenance

status: proposed
verification: pending

## Context

A retained failing run can outlive the executable that produced it. Reading the
currently installed version after an update does not identify that historical
run. The journal and final run artifact previously omitted the executing build,
so a later investigation could incorrectly attribute old failures to a successor.

## Decision

Capture the running image's common build-info document when its run log is
created. Persist it in the first `run_started` journal record and reuse the same
document as the additive `build_info` field in `run.json`, including final
rewrites after dashboard waiting. The explicit `build-info --json` command and
run capture use one product-owned constructor over compile-time values.

The new document contains only the common schema, product, package version,
source commit and state, build target, profile, and build timestamp. It excludes
runtime argv, command arguments, configuration contents or hashes, environment
values, executable paths, credentials, and installed-release observations.
Existing resolved run modes and selected task fields keep their current scope;
they do not represent a complete effective-configuration snapshot.

## Invariants

- Identity comes from the executing image, never the current installed alias,
  a subprocess, runtime environment, or repository discovery.
- The startup journal retains identity even when no terminal run artifact exists.
- Dashboard waiting and a concurrent installation change cannot replace it.
- Old artifacts lacking identity remain unknown; readers do not backfill them.
- Build self-description is diagnostic evidence, not release authentication or
  proof of the causes of a task failure.
- Task commands, outcomes, retries, privilege, and cancellation are unchanged.

## Rejected alternatives

Reading the installed executable afterward can name a different generation.
Persisting raw argv, environment or full configuration would expose unrelated
private values. A hash of secret-bearing configuration is not a safe substitute.
Per-attempt tracing and a new receipt system exceed this narrow provenance fix.

## Consequences and known limitations

This is additive under the existing observational artifact version and preserves
ADR 0003's bounded failure evidence. It cannot recover the source of older runs,
prove an executable's authenticity, identify external providers' versions, or
establish historical effective configuration. Native platform support and signed
release acceptance remain separate gates.

## Verification

- `persisted_runs_identify_the_executing_build_without_caller_values`
- `run_started_records_build_identity_before_any_task`
- `run_artifact_records_task_end_and_ui_wait_timing`

## Runtime acceptance

Run a standalone candidate with disposable successful and failing catalog tasks
in both synchronous and asynchronous engines. Compare startup and final identity
with that same candidate's common build-info document. Verify an unrelated runtime
identity variable cannot replace it, and that a later final-artifact rewrite
retains the startup identity and original task timing. Confirm old saved runs
remain readable without assigning them the candidate's identity. These checks
do not establish an installed-release or additional-platform guarantee.

## Supersession conditions

Supersede this record if a versioned run schema replaces the additive document,
authenticated execution receipts replace build self-description, or runtime
configuration capture acquires a separate privacy-reviewed contract.
