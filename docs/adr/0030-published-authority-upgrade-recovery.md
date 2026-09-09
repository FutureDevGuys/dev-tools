---
authority: canonical
owner: dev-tools
---

# ADR 0030: Published-authority upgrade recovery

status: proposed
verification: pending

## Decision

An interrupted installation-protocol upgrade whose product authority is already published can finish without candidate metadata. This bounded shared mechanism does not authorize fresh initialization, legacy adoption or reconstruction of missing authority. Product-owned admission and authenticated retained evidence remain prerequisites.

The additive Linux installation `resume_initialization` API requires an existing upgrade journal under the installation lock. Missing roots and missing journals fail without starting an upgrade, including an already-completed repeat. Unknown journals, changed receipts, invalid custody and callback rejection retain the existing failure semantics. Receipt publication and journal retirement share the existing initializer implementation, with its bounded local and idempotent product callback. Existing initialization APIs retain their contracts. This interface belongs to unpublished installation 0.2.1 and does not replace any frozen package identity.

The product callback owns authentication of its published authority and receipt-owned versions under the relevant writer lease. Missing unpublished authority needs a separate proof-dependent lane; malformed or mismatched authority must not become permission to initialize replacement state. The shared mechanism neither selects a release nor supplies candidate freshness.

Products define which explicit mutation operations may enter this boundary. Read-only observation does not implicitly recover a journal. Successful recovery requires fresh observation and preserves established change through later blocked or failed work. A completed empty installation remains empty and cannot acquire a retained version from recovery.

## Verification and remaining gates

Public installation tests cover no-upgrade admission, missing-root non-recreation, pre/post-receipt resumption, callback rejection and receipt preservation. Product-specific online/offline recovery integration and signed retained-artifact qualification are separate from these shared-mechanism tests.

Actual process death at product-authority and installation-receipt publication, clean signed successor acceptance, first-install interruption before authority publication, metadata-only acquisition for legacy upgrades lacking retained proof, legacy entrypoints and native non-Linux backends remain gates. No source test upgrades a release or platform support claim.
