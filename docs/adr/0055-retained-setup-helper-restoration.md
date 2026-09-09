---
authority: canonical
owner: dev-auth
---

# ADR 0055: Retained setup helper restoration

status: proposed
verification: pending

## Decision

The Linux retained-generation owner supplies its approved, identity-checked prior setup-helper receipt to a fixed-leaf installation component. The component requires native root, helper-owning original and candidate releases, an admitted inactive installation receipt and inactive transparent paths. Full-generation restoration remains responsible for canonical layout, exclusive admission ownership, durable restoration direction, stopped broker and absent workloads. The public strong restoration operation remains gated while those components and their native acceptance are incomplete.

The component restores only `dev-auth-setup-helper` at ordinary root-owned 0755 and `setup-helper-v1.json` at root-owned 0644 in the held product data directory. Original helper bytes come from the retained immutable executable with exact ownership, mode, single-link custody and bounded release identity. The prior sidecar must semantically match the original release and native target, but restoration preserves its exact retained bytes, including serialization whitespace. Candidate sidecar bytes are derived from the approved candidate release using the existing product serializer. No credential, source configuration, legacy repair operation or external command is used.

Both current leaves are admitted before publication. Helper contents must equal the original or candidate executable; sidecar bytes must equal the retained original or derived candidate document. Either combination is admitted because an interrupted publication can leave a mixed pair. Missing leaves, unrelated contents, special permission bits, hard links and symbolic links fail without adoption or removal. Restoration durably publishes the helper before its sidecar through the existing descriptor-bound document boundary, then verifies exact original contents and custody. An unchanged retry synchronizes without republishing. Terminal verification is read-only and also requires exact retained sidecar bytes, not just semantic receipt equality.

This component supports restoration between two helper-owning releases. Original helper absence during a prior-installation upgrade remains unsupported; [ADR 0064](0064-initial-strong-generation-withdrawal.md) supplies candidate-only retirement when the entire original installation was absent. Shared binary/history restoration follows helper restoration, and the full installation verifier must still pass before a full-generation terminal state is acknowledged. No accepted 0.3.11 receipt schema or release bytes change.

## Evidence

The root user-namespace source fixture first failed at the absent helper-restoration operation. It now checks helper and exact sidecar restoration across both legacy-to-guarded and guarded-to-guarded fixture releases, unchanged repeat, either mixed publication state, unowned helper/sidecar preservation, missing leaves, wrong provenance, unsafe modes, hard/symbolic links, special-bit original sources and active-receipt rejection. The synthetic executable contents are not executed; this evidence does not establish signed release, process-death/power-loss, system-service or complete strong-generation acceptance.
