---
authority: canonical
owner: dev-tools
---

# ADR 0013: Five-shell immutable completion activation

status: proposed
verification: pending

## Context

ADRs 0009 through 0012 established the public root, candidate and binding identities, native-first generation, and conservative help-derived adapters, but provider activation still wrote Zsh payloads and overlay shims into an rc root while the public snapshot contained only Update All's own completion. That split made the public init contract incomplete, retained an implicit checkout-shaped authority, and prevented the five-shell planner from delivering provider bindings uniformly.

## Decision

An ordinary completion sync selects Bash, Zsh, Fish, Elvish, and PowerShell targets from repeatable command-line values, then configured defaults, then installed-shell detection including the current supported shell. `all` is exclusive with named shells, and the normalized deduplicated sorted set participates in candidate and binding identity.

One lock keyed to the absolute managed root covers provider inventory, candidate resolution and probing, memo changes, complete view construction, validation, and atomic activation. Generated candidate artifacts live under the product-owned managed-root cache. The default catalog and legacy audit-registry locations are also under that cache rather than `RC_ROOT`; a missing default catalog is a virtual empty catalog and is never materialized merely to run sync. Explicit catalog paths still fail closed when missing. A public immutable snapshot contains Update All's trusted self-completion plus every selected active provider binding for every selected shell, and `current` changes only after the complete snapshot validates. A healthy byte-identical activation is a no-op: it performs no generator probes, publication, pointer change, pruning, or persistent managed-root mutation. A changed strong identity producing identical canonical behavior changes only identity memoization.

The overall sync outcome is exactly one of `reused`, `probed_unchanged`, `published`, `retained_previous`, `unsupported`, `removed`, or `failed`. Snapshot manifests record active shell, command, provider, exact executable, and classification bindings. A separate change-aware issue memo records only current retained, unsupported, or failed states, so read-only status can explain degraded state without rewriting successful no-op attempts.

`completions init <shell>` and `completions status [--json]` remain strictly read-only and share fail-closed snapshot validation. Init emits only sourceable code and returns empty success when no snapshot or requested view exists. Startup files remain outside Update All's authority.

The one-release `--rc-root`, `install`, and `sync --apply` compatibility paths remain explicit. Public `--managed-root` and legacy `--rc-root` are mutually exclusive, legacy mode does not publish into the public root, and no implicit `.shellrc.d` path exists. Ordinary task-backed sync defaults to `refresh` and rejects the retired `refresh+audit` mode instead of loading a Zsh audit script from a checkout. A legacy audit accepts only an existing absolute executable through `--audit-command` and invokes it with direct argv.

Native output remains terminal authority. Help-derived IR now renders through the already-defined adapter for each selected shell only when native generation is unavailable or invalid; it never augments or replaces a valid native payload.

## Invariants

- Ordinary and task-backed sync never writes a shell rc root.
- Ordinary and task-backed sync never resolves or invokes an audit from `RC_ROOT`; auditing exists only in the explicitly parameterized legacy bridge.
- Default public sync neither reads nor creates a catalog or registry under a checkout or shell startup tree.
- All selected active bindings and all selected shell views activate together through one content-derived snapshot.
- An unchanged second sync runs zero candidate probes and leaves the managed root byte-for-byte and metadata-for-metadata unchanged after the transient sibling lock is released.
- Partial or failed inventory retains prior healthy bindings; only authoritative inventory or explicit configuration removes them.
- Status and init create, repair, prune, or rewrite nothing.
- No provider, checkout, syscfg, Shellrc, browser, or platform-specific behavior enters the completion engine.

## Rejected alternatives

Publishing only self-completion would leave the public loader incomplete. Writing per-shell files directly into consumer startup trees would create five ownership integrations and reintroduce checkout coupling. Dual-publishing public and legacy layouts would make no-op and retirement semantics ambiguous. Persisting every reused attempt would violate the no-op mutation contract. Shell command strings for audits would add interpolation authority unnecessary for an executable protocol.

## Consequences and known limitations

This record completes the provider-activation boundary reserved by ADRs 0011 and 0012 without changing their probe, trust, IR, query, or performance decisions. Explicit legacy users receive one release to move to public init. Snapshot content changes once because provider bindings and binding metadata become part of activation identity. The transient lock lives beside rather than inside the managed root so an unchanged sync does not alter managed-root directory metadata.

## Verification

Named regression tests include `public_sync_publishes_active_bindings_for_all_five_shells_then_is_probe_free`, `completion_shell_selection_normalizes_deduplicates_and_keeps_all_exclusive`, `ordinary_completion_mode_is_public_refresh_and_rejects_the_implicit_legacy_audit`, `fresh_public_completion_sync_uses_a_virtual_empty_catalog_and_then_reuses`, `public_and_legacy_completion_roots_are_mutually_exclusive_before_mutation`, `legacy_audit_requires_exact_executable_before_sync_mutation`, `legacy_audit_requires_an_exact_absolute_executable`, `legacy_powershell_audit_invokes_only_the_exact_executable_with_direct_argv`, `status_and_init_reject_an_active_snapshot_with_a_missing_view`, `identity_change_with_identical_artifact_updates_only_memo_then_reuses`, and the ADR 0011 and 0012 native-authority and five-adapter suites.

## Runtime acceptance

Run public sync for every installed supported shell twice against representative native and help-derived commands. Confirm the first snapshot contains active provider bindings, each real shell loads candidates and descriptions, the second invocation runs no candidate process and leaves the managed-root tree unchanged, status and repeated init on a read-only root perform no writes, and an explicit legacy invocation touches only its provided compatibility root before marking this record accepted.

## Supersession conditions

Supersede this record if completion activation moves to another authority, snapshots stop being immutable whole-set activations, startup ownership moves into Update All, the legacy bridge survives its stated release, or shell selection and outcome schemas require a backward-incompatible public contract.
