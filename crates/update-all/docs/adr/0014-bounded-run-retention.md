---
authority: canonical
owner: dev-tools
---

# ADR 0014: Bounded run retention

status: proposed
verification: pending

## Context

Update All already owns structured run metadata, an event journal, human logs, and task transcripts beneath one configured run root. Without a retention boundary, normal repeated operation grows that diagnostic root indefinitely. A separate cleanup service would split product ownership and add platform-specific maintenance.

## Decision

Update All enforces age, count, and aggregate-byte limits over its completed run directories after each terminal invocation and through an explicit `runs prune` command. Retention is diagnostic maintenance, not updater desired state. The current run is protected, and automatic cleanup recognizes only real directories containing parseable Update All metadata with a terminal status.

## Invariants

- Default retention is 30 days, 100 completed runs, and 128 MiB, with explicit `[logging]` overrides.
- Active, malformed, unowned, symlinked, and current run directories are never automatically deleted.
- Age is applied first, followed by oldest-first count and byte limits.
- `runs prune --dry-run` and the applying command compute the same ordered candidate set.
- Retention failure warns and does not change the updater task outcome.
- Run roots and files are owner-only on Unix; Windows relies on the user-local profile ACL.
- Retention contains no catalog, provider, plugin, completion, or task-specific behavior.

## Rejected alternatives

- Unbounded history eventually consumes material storage and makes run browsing slower.
- A cron job or system service duplicates Update All's run schema and creates another lifecycle to maintain.
- Deleting malformed or metadata-free directories risks claiming state the product cannot prove it owns.
- Counting the current run without protecting it can remove files still open by the active process.

## Consequences and known limitations

Diagnostic history is finite, and operators who require longer retention must raise the configured limits or export artifacts elsewhere. A crashed run remains non-terminal and is retained for manual inspection; this deliberately prefers leakage of bounded-by-operator stale evidence over unsafe automatic ownership guesses. Concurrent pruners may observe already-removed candidates and report a warning, but never broaden the deletion set.

## Verification

Named regression tests:

- `run_retention_prunes_age_count_and_bytes_without_touching_active_or_unowned`
- `run_retention_dry_run_reports_without_mutation_and_protects_current_run`
- `logging_retention_defaults_and_overrides_are_explicit`
- `runs_prune_is_a_public_dry_run_capable_command`
- `run_artifacts_are_owner_only_even_with_a_permissive_parent`
- `logging_initialization_failure_is_non_fatal`

## Runtime acceptance

Create several completed fixture runs around each configured boundary, compare the dry-run report with the applied deletion set, and verify the current, active, malformed, and metadata-free directories remain. Run a normal no-op updater invocation and confirm only diagnostic retention changes while package, catalog, completion, and task state remain untouched.

## Supersession conditions

Supersede this record if run artifacts move to an external store, a platform service becomes their authority, retention needs archival rather than deletion, or concurrency requires a shared cross-process index or lock.
