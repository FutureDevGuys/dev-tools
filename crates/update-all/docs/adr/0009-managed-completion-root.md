---
authority: canonical
owner: dev-tools
---

# ADR 0009: Managed completion publication root and snapshot health

status: proposed
verification: pending

## Context

Managed completion generation and shell startup ownership are separate authorities. Consumers need one stable product-owned data root that works across five shells without granting `update-all` authority to edit their startup files. Direct completion subcommands and the built-in completion task previously selected that root independently, and snapshot inspection could describe a manifest as available even when its referenced files were missing or changed.

## Decision

`update-all` resolves one absolute managed completion root for an invocation. The direct `completions sync` command gives an explicit `--managed-root` first precedence; all direct and task-backed completion paths otherwise use `UPDATE_ALL_COMPLETION_ROOT`, then the platform default. The initial defaults are `$XDG_DATA_HOME/update-all/completions` with the standard Unix fallback and `%LOCALAPPDATA%\update-all\completions` on Windows.

Publication stores content-addressed objects under `objects/`, immutable activation snapshots under `snapshots/<digest>/`, and the active snapshot name in `current`. A matching active digest is an unchanged no-op only after the manifest and every referenced view pass shared existence and digest validation. A matching but unhealthy active snapshot is rebuilt from the supplied payloads and reported as repaired without rewriting `current`. Both `completions status` and `completions init <shell>` use the same active-snapshot validation and fail closed on an unhealthy snapshot.

`update-all completion <shell>` remains the trusted self-completion emitter for Bash, Zsh, Fish, Elvish, and PowerShell. `update-all completions init <shell>` is the read-only startup contract, and shell configuration authorities decide where to evaluate or source its output. The `completions install` command and sync's `--apply` flag remain explicit one-release compatibility wiring for Zsh and PowerShell only.

## Invariants

- One invocation uses one resolved managed root across direct and task-backed publication.
- An unchanged outcome performs no managed-root mutation and is returned only for a healthy active snapshot.
- A repaired outcome means the active snapshot was unhealthy and was reconstructed from the current generated payloads without changing its content-derived identity.
- Status never advertises a shell whose active view is missing or fails its declared digest.
- Init and status share the active-snapshot health boundary.
- The managed root remains product-owned generic data and encodes no checkout, consumer, browser, or shell-startup authority.

## Rejected alternatives

Keeping task-backed publication on the platform default would make the environment override depend on the entry point. Treating a matching `current` string as sufficient health would preserve broken snapshots indefinitely. Reporting manifest keys without validating their views would make status disagree with init. Making startup edits the generic contract would couple public data publication to shell-specific ownership and exclude supported shells from a uniform onboarding path.

## Consequences and known limitations

Consumers can inspect and source the same validated immutable snapshot regardless of which update path refreshed it. Repair may replace a broken snapshot directory while readers are active; readers fail closed during that bounded repair window and succeed on retry. This record does not redesign provider discovery, native generator probing, managed payload overlays, or consumer-owned startup policy.

## Verification

Named regression tests:

- `completion_paths_resolve_the_managed_root_environment_override`
- `task_completion_sync_publishes_to_the_resolved_managed_root`
- `publish_is_idempotent_for_unchanged_snapshot`
- `publish_repairs_missing_active_snapshot_without_rewriting_current`
- `status_and_init_reject_an_active_snapshot_with_a_missing_view`
- `completion_sync_help_leads_with_public_init_and_labels_the_legacy_bridge`

## Runtime acceptance

Set `UPDATE_ALL_COMPLETION_ROOT` to a temporary absolute path, run an ordinary `update-all` invocation that selects the built-in completion task, and confirm `current` and `snapshots/` are created under that path. Without an explicit root, run `update-all completions status --json` and `update-all completions init` for all five shells and confirm they observe the same snapshot. Remove one active view, rerun sync with identical payloads, and confirm it reports repair, restores status/init health, and leaves the content-derived `current` value unchanged before marking this record accepted.

## Supersession conditions

Supersede this record if completion publication moves to another product authority, activation stops using content-derived immutable snapshots, startup ownership moves into `update-all`, or snapshot health gains a versioned public model that cannot preserve this fail-closed status/init contract.
