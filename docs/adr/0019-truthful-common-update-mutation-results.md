---
authority: canonical
owner: dev-tools
---

# ADR 0019: Truthful common update mutation results

status: proposed
verification: pending

## Context

The initial shared update loop converted every adapter error into `changed: false` and attached the pre-operation installation snapshot to successful mutations. A late error can follow activation, and a successful update changes the installed identity. The existing v1 boolean schema cannot express uncertain progress. Product adapters must not inherit these inaccurate observations.

## Decision

The additive `dev-tools-product::OperationResultV2` uses `dev-tools-operation-result-v2` and a required nullable boolean change field. For update operations its scope is durable managed installation state, including recovery records, not disposable caches or release-observation writes. A metadata-only check reports no installation change even if it refreshes accepted metadata or a cache. Products may separately report those writes without merging their authority with installed state.

Shared installation apply, repair and adoption reports include successful journal recovery in their change fact. Finalizing a committed journal or restoring prior receipt-owned pointers is not a clean no-op merely because the requested version is already active afterward. The same operation without a journal or further repair remains a no-op; conditional operations retain their explicit-recovery requirement. This accounting does not turn an error after entered recovery into evidence of no change.

Update All's legacy Unix release orchestration carries successful adoption, repair and recovery change facts through its already-current result and refreshes active/previous release-state fields from the resulting receipt. Correcting stale observational version fields alone does not establish installation change. Its regression exercises matching and stale state, missing aliases, committed-journal completion, uncommitted pointer restoration and unchanged repeats without artifact retrieval. This preserves the existing legacy activation schema; error-progress reporting, signed-proof authority, mixed-version exclusion and the v2 common adapter remain separate cutover work.

Shared install, apply and rollback errors default to unknown progress. A product adapter may provide an established true or false change fact through `UpdateError::with_changed`; error category alone never establishes that fact. Preflight and read-only failures report false because no installation mutation was entered. After any entered mutation, a fresh network-free, nonmutating observation supplies the installed identity. A failed observation never reuses the pre-mutation identity as current. After successful mutation it becomes the reported failure while preserving the established change fact; after a failed mutation the original error category and change fact remain primary. Observation does not prove that no intermediate journal or durable state changed, so matching versions alone never synthesizes a false change fact.

The existing v1 type, constants, schema and read-only doctor producers remain unchanged. Product foundation 0.1.1 adds v2; the shared update foundation advances to 0.2.0 because `execute` changes its public return type. Its only executable orchestration consumers are currently tests; Artifact Update uses its discovery types and does not silently change its existing operation-specific schemas. Frozen signed product 0.1.0 archives remain immutable and independently publishable. New update consumers require the new versioned foundation edge rather than replacing old bytes or pretending this return-type change is Rust-compatible.

The common conformance fixture and update-status gate target v2. Existing doctor v1 remains the bounded compatibility interface until its product-owned release consumers migrate; no current product is promoted from build-info to full conformance by this shared-crate change. Product-owned real-binary online, offline, installation, rollback and interruption acceptance remain required. This decision supersedes only the common update result portion of ADR 0002; metadata acquisition and artifact preparation remain separate unfinished adapter work.

## Verification and removal

Regression tests first reproduced false no-change after simulated activation failure and stale installed identity after success. Public adapter tests cover install, apply and rollback, unknown and explicit change facts, post-observation failure, interruption category preservation, preflight no-change and network-free rollback. Product-contract tests preserve v1 JSON and exercise all three v2 change values. The standalone conformance fixture checks the v1-doctor/v2-update transition. No v1 compatibility removal is authorized until migrated released readers and retained rollback consumers no longer require it; downgrade from unknown v2 progress to v1 false is never a valid translation.
