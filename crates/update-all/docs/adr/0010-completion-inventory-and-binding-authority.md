---
authority: canonical
owner: dev-tools
---

# ADR 0010: Completion inventory and binding authority

status: proposed
verification: pending

## Context

Completion generation previously treated a provider scan as an unqualified list of command names and keyed the active overlay by command alone. A transient or incomplete inventory could therefore look like an authoritative removal, while two installations exposing the same command could collide even though only one executable actually wins on the user's `PATH`. Reprobing an unchanged executable also made an idempotent second sync depend on generator behavior rather than artifact identity.

## Decision

Every provider inventory reports `complete`, `partial`, or `failed`. Only a complete inventory or an explicit configured removal may retire a previously known candidate; incomplete and failed inventories retain the last healthy candidate and binding. Candidate identity includes provider, installation, command entry point, exact executable, launch argv, and provider-native package or content identity. Binding identity is the requested shell plus the command name the user types.

Multiple providers may retain candidates for one binding. The exact executable resolved through `PATH` selects the active candidate unless a configured numeric priority selects another candidate; non-winning candidates remain cached and report `shadowed`. A healthy candidate with the same strong identity is reused without generator probes. The resolution fingerprint includes each provider-owned bundled artifact applicable to the binding shell, using the native planner's containment resolution and a fixed 4 MiB identity byte ceiling: missing and present are distinct states, and a present regular file contributes its byte length and full SHA-256 content digest. An unreadable, non-regular, or oversized configured artifact cannot take the unchanged fast path. When a changed identity produces the same canonical artifact, only identity memoization changes and the result is `probed_unchanged`; immutable snapshots, active views, and the `current` pointer remain unchanged.

## Invariants

- Partial, failed, timed-out, malformed, or budget-exhausted provider discovery cannot retire a healthy prior candidate.
- An explicit configured removal applies only to the named provider and command identity, or to all candidates of an explicitly disabled provider.
- Candidate and binding identities are separate, so provider caches cannot redefine what command name the shell completes.
- PATH selection uses the exact resolved executable; a priority override is declarative and the losing candidates remain non-errors.
- A strong unchanged identity performs no generator probe, and an unchanged second sync performs no completion-root or overlay mutation.
- A configured bundled artifact changing from missing to present or changing bytes at the same contained path invalidates reuse; an unchanged bounded digest preserves the fast path.
- Identity-only changes cannot create or activate a new immutable completion snapshot.
- Provider and identity logic remains public and product-neutral; it contains no checkout, syscfg, browser, Firejail, or shell-startup authority.

## Rejected alternatives

Treating every scan as complete would convert transient provider failures into destructive retirement. Rejecting duplicate command names would prevent accurate handling of ordinary PATH shadowing. Choosing the first provider would make activation depend on catalog ordering instead of the executable users invoke. Hashing only generated output would skip necessary reprobes when the executable or package identity changes, while probing on every run would violate idempotency and make an unchanged sync fragile.

## Consequences and known limitations

The managed root gains an atomic identity memo that records healthy candidates and active bindings separately from immutable publication snapshots. Provider-native identity quality is limited by each provider's authoritative inventory: exact executable content is always included, while richer package metadata is included when the provider exposes it. This decision does not add the five-shell native protocol planner, conservative help IR, trust tiers, or static/query renderer; those require later decisions and tests without weakening native completion authority.

## Verification

The regression contract is covered by `identity_change_with_identical_artifact_updates_only_memo_then_reuses`, `bundled_artifact_presence_and_content_change_invalidate_reuse_then_stabilize`, `bundled_artifact_identity_enforces_fixed_byte_bound`, `partial_inventory_retains_absent_binding_until_complete_inventory_retires_it`, `same_binding_uses_path_winner_and_reports_other_provider_shadowed`, `explicit_priority_overrides_path_without_treating_loser_as_error`, `second_unchanged_run_performs_zero_probes_and_zero_managed_root_mutation`, and `completion_binding_priority_survives_runtime_config_parsing`.

## Runtime acceptance

Publish a native completion from one provider, repeat the sync without modifying the executable, and confirm no generator process runs and no managed-root or overlay metadata changes. Then install a second provider candidate for the same command, verify that PATH and an explicit priority select the expected candidate while the other reports `shadowed`, and induce partial and failed inventory states to confirm the prior binding remains active before marking this record accepted.

## Supersession conditions

Supersede this record if completion candidates move to another inventory authority, binding selection no longer follows executable resolution, identity memoization is replaced by a versioned public state model, or a later trust architecture requires materially different retirement or shadowing semantics.
