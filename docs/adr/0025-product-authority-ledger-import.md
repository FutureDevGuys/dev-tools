---
authority: canonical
owner: dev-tools
---

# ADR 0025: Product-authority ledger import

status: proposed
verification: pending

## Context and decision

The shared manifest ledger initially required an Artifact Update configuration record. Built-in products own a release authority directly, including their GitHub release URL policy, and must preserve captured legacy acceptance history during protocol cutover. Constructing an artificial Artifact Update configuration would couple that migration to unrelated source and selector policy; copying ledger checks would create a second anti-rollback and retained-signature implementation.

The additive `ManifestLedger::import_release_state`, `from_bytes_with_authority`, `accept_release_metadata` and `verify_retained_with_authority` methods accept the existing typed `ReleaseAuthority` directly. The original record-based methods retain their public signatures and static-source admission. Both paths share the same acceptance and retained-metadata checks, ledger codec, strict decoding, state validation and authority identifier. No new document format, identifier encoding, dependency or product branch is introduced.

Import validates the complete supplied `ReleaseState` and the bounded serialized ledger, preserving all accepted generations, version and digests. Empty state is valid only as a representation of explicit first use; the constructor does not establish permission to reset history. Product and target names must be nonempty and contain no control characters, including the authority identifier's NUL separator. The pinned key is normalized through the existing public-key parser. Import does not authenticate the history or authorize replacement of an existing ledger. Products own source custody, exclusion of old writers, original-state capture, atomic publication and retry policy.

Every direct verification call reauthenticates original metadata under current caller-supplied policy and requires the same product/target/pinned-root stream. Stable-only acceptance remains mandatory. Retained metadata must use the exact accepted root, rechecking current signer revocation, and cannot exceed accepted generation/version or equivocate at their boundaries. It never advances online history. URL/schema/protocol policy remains caller-owned and is reapplied rather than included in the stable stream identifier. Signed metadata verification alone does not establish receipt ownership, installed bytes, historical acceptance, freshness or rollback permission.

## Compatibility and evidence

The existing static-manifest corpus passed before extraction. New tests compare initial and accepted bytes and authority IDs across both interfaces, load the same codec through direct authority, and verify unchanged acceptance. The import regression first showed that resetting the supplied history admitted an older release; preserving the complete validated state makes that counterexample fail as required. Negative coverage includes partial history, oversized representation, ambiguous stream names, mismatched authority, signatures, URL/schema/protocol changes, superseded roots, revoked signers, prereleases and future retained metadata. Rejected operations preserve ledger bytes. Existing Artifact Update integration remains required.

These interfaces are part of unpublished update 0.2.0 and require source-bound registry publication before external adoption. No product entrypoint migrates its live ledger in this slice. Product-owned captured-history import, signed-proof storage, mixed-version exclusion and source-bound install/offline/rollback/crash acceptance remain prerequisites for full common-adapter cutover. Supersede this record if durable stream identity, import authority or retained verification semantics change.
