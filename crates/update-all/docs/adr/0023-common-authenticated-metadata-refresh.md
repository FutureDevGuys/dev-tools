---
authority: canonical
owner: dev-tools
---

# ADR 0023: Common authenticated metadata refresh

status: proposed
verification: pending

## Context

The common status adapter needs original authenticated candidate evidence rather than legacy HTTP observations. Explicit check must supply it without activating an installation or silently completing the product-state cutover. Acceptance history must survive cache eviction and interruption between metadata publications.

## Decision

The Linux common adapter exposes `update-all update check [--json]` through the shared operation loop. It resolves stable release metadata through the existing admitted HTTPS transport and accepts only source-bound product-v2 metadata. It does not retrieve payloads, execute health checks, initialize installation state, retire legacy state or recover journals. An existing pending installation transition blocks check before network; mutation recovery remains a separate explicit boundary.

The product release lease spans authority admission, retrieval and publication. Before installation-v2 cutover, check preserves and advances the existing legacy acceptance fields without changing observational installed versions or automatic-check timestamps. After cutover, it uses only the initialized product authority document. Missing initialized authority cannot default to legacy history. Every update of that document retains its captured-source identity, the new exact accepted proof and all receipt-owned active/previous proofs, within the existing three-proof bound. Retained manifests are authenticated against the new accepted root before publication. A root rotation revoking a required retained signer blocks acceptance; this slice does not weaken retained authentication to make such a transition succeed.

The separate disposable document `cache/authenticated-candidate-v1.json` contains a strict schema, bounded original root and manifest strings, and the refresh operation's start time. Using the start time conservatively accounts for retrieval duration and keeps the shared loop's observation clock consistent. Each original metadata body retains the 512 KiB bound; the enclosing bound accounts for worst-case JSON escaping. This is not the legacy conditional HTTP cache, and common refresh does not import or rewrite those observations.

Check publishes durable acceptance before the candidate cache. Status reauthenticates original cached metadata under current online policy and requires an unchanged acceptance result against independently loaded history. It never advances or recreates history. Missing cache means absent evidence; expired or future-dated evidence cannot establish currentness. An interruption leaving superseded cache evidence produces an error until explicit check refreshes it, not a rollback of accepted history.

## Invariants

Candidate evidence never proves downloaded artifact custody. Metadata operations report no installation change. Cache removal cannot reset accepted history, and cache bytes cannot authorize restoration of a missing ledger. Unknown, malformed, oversized, linked or nonprivate cache documents fail without replacement. Admitted document identities are rechecked before publication; the existing shared atomic-document boundary supplies custody and durability, not hostile same-owner compare-and-swap.

## Rejected alternatives

Putting the acceptance ledger in disposable cache loses rollback protection on eviction. Promoting legacy check timestamps or HTTP bodies skips signed evidence. Initializing installation v2 during check would turn a metadata operation into an installation mutation. Accepting a revoked retained release merely to advance the ledger would weaken the recorded rollback authority.

## Consequences and known limitations

The adapter now supports common status and check on Linux; common install/apply/rollback, pending-state proof acquisition for explicit mutation, payload caching and legacy entrypoint cutover remain unfinished. Legacy self/product routes and automatic-update behavior are unchanged. No release identity, dependency version, platform support claim or conformance level changes. Native source-bound release acceptance, real interruption and retained root-rotation acceptance remain gates; source tests do not establish them.

## Verification

`common_status_reauthenticates_original_cache_against_separate_history` first observed missing available-version output before the cache reader existed; it now checks signed original evidence and rejection of lost history. `common_check_missing_home_emits_one_json_configuration_error` first failed on the absent public check command and now protects the matching v2 error document. `common_check_publishes_separate_history_and_bounded_cache_without_installation` covers real signed metadata, cache eviction, expiry, repeat acceptance and absent installation artifacts. `common_check_uses_initialized_authority_and_never_recovers_pending_state` protects initialized history, missing-authority rejection and pending-state preservation. `common_check_rejects_invalid_metadata_and_changed_history_without_cache_publication` and `common_cache_rejects_hostile_documents_and_serializes_refresh` cover publication identity, failed authentication, writer contention and hostile cache custody. The existing self-completion test resolves the nested check JSON option.

## Runtime acceptance

Qualify a clean source-bound standalone binary outside a checkout with traced metadata-only online check and network-free fresh/expired status, repeat checks, hostile cache and authority loss, pending cutover, initialized installations and interrupted publication. Complete the product-owned mutation adapter and retained rollback/root-rotation acceptance before claiming the full common update contract. Native non-Linux backends require separate acceptance.

## Supersession conditions

Supersede this record if check acquires installation mutation authority, freshness or cache acceptance changes, or retained root revocation receives a different supported transition. Preserve independent durable history, original signed evidence, bounded custody and explicit recovery.
