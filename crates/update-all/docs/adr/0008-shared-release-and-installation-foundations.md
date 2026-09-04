---
authority: canonical
owner: dev-tools
---

# ADR 0008: Shared release and installation foundations

status: proposed
verification: pending

## Context

`update-all` introduced authenticated product releases, but its private implementation combines product orchestration with reusable trust and installation mechanics. Dev-auth requires the same root and manifest verification with a stronger source-commit binding, plus system installation and rollback. Copying either mechanism would create independent security authorities that can drift.

## Decision

The workspace provides two focused libraries. `dev-tools-release` owns product-neutral signed-root and signed-manifest verification, stable SemVer selection, artifact identity, anti-rollback and equivocation state, and explicit authenticated-cache handling. `dev-tools-installation` owns product-neutral nofollow filesystem admission, immutable version publication, receipt-owned aliases and pointers, rollback, uninstall, locking, and crash recovery.

Products supply their release authority, target identity, product-specific layout, service lifecycle, health verification, and user-facing result model. The libraries do not install third-party packages, manage services, interpret product policy, or enroll credentials. Manifest v1 and the Dev Auth-specific v2 remain readable for authenticated migration and rollback. Shared `dev-tools-product-v2` requires an exact source-commit binding and may contain multiple target artifacts; each verifier selects and authenticates one declared target without weakening the complete signed document.

`update-all` migrates behind behavior-parity tests. Its CLI, stable-channel selection, update-only absence behavior, external-manager collision behavior, health checks, retained rollback, and reporting remain product-owned and unchanged.

## Invariants

- A caller selects an accepted manifest schema and whether source-commit binding is mandatory; metadata cannot weaken that authority, and shared v2 always requires source binding.
- Online resolution failure never silently becomes evidence that cached metadata is current. Offline cache use is explicit and uses only previously authenticated bytes and persisted anti-rollback state.
- Installation replaces or removes only artifacts named by a valid receipt and matching their recorded identity.
- Shared libraries contain no dev-auth, update-all, service-manager, credential, policy, or package-manager behavior.
- Every mutable release-state transition is serialized and rejects generation rollback, version rollback, and same-generation equivocation.

## Rejected alternatives

Keeping the implementation private to `update-all` would force dev-auth either to shell through another product or to duplicate security-sensitive behavior. A single combined framework would couple network trust to filesystem mutation and make either primitive harder to reuse and audit. Product-specific branches in the shared crates would recreate the ownership split this decision removes.

## Consequences and known limitations

Release and installation defects have a wider product impact, so the shared crates require adversarial filesystem, signature, transport, state, and concurrency tests. Product integrations stay small and preserve their own acceptance gates. Platform-specific installation behavior remains behind explicit APIs and cannot be inferred from a successful build on another platform.

## Verification

The shared release suite covers manifest v1 and v2, source binding, revoked keys, incorrect URLs, artifact tampering, stable selection, rollback, and equivocation. The shared installation suite covers nofollow traversal, hardlinks, collisions, atomic publication, receipt integrity, serialized mutation, and owned-only uninstall. The migrated update-all behavior remains covered by `product_release_resolution_uses_latest_stable_matching_tag`, `authorized_manifest_signature_is_accepted`, `revoked_release_key_is_rejected`, `rollback_and_equivocation_are_rejected`, `artifact_integrity_requires_exact_length_and_hash`, and `candidate_health_requires_the_signed_version`.

## Runtime acceptance

Publish and install an existing v1 product through the migrated `update-all` path, then install a source-bound dev-auth candidate through the same release foundation. Verify anonymous download identity, a stable second pass, retained rollback, and behavior with source checkouts absent before marking this record accepted.

## Supersession conditions

Supersede this record if signed distribution moves to an external framework with equivalent source binding and anti-rollback properties, or if supported platform installation semantics cannot remain product-neutral without weakening an owner product's security boundary.
