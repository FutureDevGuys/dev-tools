---
authority: canonical
owner: dev-tools
---

# ADR 0006: Product-scoped authenticated releases

status: superseded
verification: pending
replacement: 0008-shared-release-and-installation-foundations.md

## Context

Dev Tools products release independently from one repository. GitHub exposes one repository-wide latest release, so a fixed latest-download URL cannot identify the latest release of each product. Separate product updaters would duplicate transport, signature, rollback, and activation policy.

## Decision

`update-all` is the shared authenticated release engine for `update-all`, `dev-cache`, `sync-configs`, and `skills-sync`. It resolves anonymous GitHub Releases metadata, selects the greatest stable semantic version whose tag matches `<product>/v<version>`, and rejects drafts, prereleases, invalid versions, and releases missing the product manifest or root document.

The selected root document authorizes release keys. The selected product manifest binds the product, generation, version, engine protocol, target artifact URL, byte length, and SHA-256 digest. Persistent per-product state rejects root rollback, manifest rollback, version rollback, and same-generation equivocation. Public commands activate only under product-owned state and bin roots. An existing command outside that root is externally managed and is never overwritten. `update-if-installed` is a clean no-op when the public command is absent.

Public built-in tasks invoke the same engine with data-only commands. Private policy remains in external catalogs and receives no product-specific Rust executor.

## Invariants

- Product release selection is independent of repository-wide latest-release state.
- Runtime discovery and updating require no checkout, Git, GitHub CLI, curl, wget, Python, or authentication.
- Every installed byte is authenticated by exact signed length and SHA-256 digest before health verification and activation.
- One engine owns transport, trust, rollback, retained versions, external-manager detection, and locked-binary deferral for every product.
- Absent products remain absent during update-only runs.
- A public command not activated from the product-owned root is never replaced.

## Rejected alternatives

- Repository-wide `/releases/latest/download` changes meaning whenever a different product releases.
- One updater per product duplicates security-sensitive code and reporting behavior.
- Desired-state version pins turn a stable-release policy into ongoing repository maintenance.
- Authenticated GitHub tooling makes unattended bootstrap depend on local login state.

## Consequences and known limitations

Anonymous GitHub API availability is required when a cached check is not usable. The initial protocol publishes one target artifact per product release; additional supported targets require a new manifest generation or release. Windows and WSL artifacts remain staging-only until native runtime acceptance passes. Root rotation uses sequential root documents signed by both the departing and successor offline roots so old and new trusted binaries can authenticate the transition.

## Verification

Named regression tests:

- `product_subcommands_share_the_release_engine`
- `product_release_resolution_uses_latest_stable_matching_tag`
- `authorized_manifest_signature_is_accepted`
- `revoked_release_key_is_rejected`
- `rollback_and_equivocation_are_rejected`
- `artifact_integrity_requires_exact_length_and_hash`
- `candidate_health_requires_the_signed_version`

The repository release gate also verifies deterministic signed recipe output with its Python release-contract suite.

## Runtime acceptance

Publish a clean Linux release for each product. Install through the shared engine outside every source checkout, compare the installed artifact digest and build metadata with the release and source commit, and rerun update-only convergence. Dev Cache additionally requires a fresh-shell `doctor --json` result with `routing_complete=true` and representative delegated-output preservation.

## Supersession conditions

Supersede this record if products move to independent repositories, release discovery moves to another signed distribution authority, or a stronger shared framework replaces this trust and activation protocol.

ADR [0008](0008-shared-release-and-installation-foundations.md) supersedes this proposal by moving the authenticated-release and receipt-owned installation mechanisms into product-neutral workspace crates. `update-all` retains its product orchestration and user-facing behavior.
