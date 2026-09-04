---
authority: canonical
owner: dev-tools
---

# ADR 0006: Public producer and private consumer direction

status: proposed
verification: pending

## Context

Public tools may be consumed by private workstation or organization repositories. If the public producer discovers or invokes a private consumer checkout, the public build and runtime become non-reproducible, private policy leaks into public architecture, and standalone use becomes impossible.

## Decision

Dependency direction is strictly from private consumer to public producer. A private consumer may invoke a documented public binary or depend on a published versioned crate. Dev Tools never reads, imports, invokes, discovers, tests against, or documents as required any private consumer repository, path, policy, manifest, state, credential, or helper.

Generic behavior needed by the public producer is implemented publicly with synthetic fixtures. Private inventory, host policy, orchestration, adapters, and cross-repository acceptance remain exclusively in the private consumer.

Downstream-facing shared crates are independently packageable for the declared public registry. Their workspace manifests pair a SemVer requirement with the local path used during same-repository development; packaged manifests retain the version requirement and remove local path authority. A downstream production lockfile resolves the registry package and records its checksum. Registry publication is not sufficient provenance by itself: production cutover also requires authenticated evidence binding the uploaded crate bytes to the reviewed source. Git revisions and neighboring paths are permitted only for non-production compatibility probes that cannot activate a caller migration.

## Invariants

- Dev Tools builds, tests, releases, installs, and runs when every private consumer checkout is absent.
- Public tests contain no private fixture or path authority.
- Neighboring-checkout path dependencies are prohibited across the boundary.
- Every downstream-facing shared crate declares an exact registry allowlist, and every shared workspace dependency declares a compatible SemVer requirement.
- A downstream production cutover waits until the selected package version and checksum exist in the public registry and authenticated source-to-package provenance verifies.
- A private consumer's failure or absence cannot change public product discovery or behavior.

## Verification

Repository scans reject known private checkout and helper coupling, Cargo metadata rejects cross-repository path edges, and the complete public gate runs in an isolated source tree with no private repository mounted. Package checks prove every downstream-facing crate has a declared registry and versioned internal edges. Registry acceptance additionally verifies the published checksum and authenticated source-to-package binding before a downstream cutover. Public fixtures use generic owner and task identities.

## Runtime acceptance

Build, release, install, update, roll back, and diagnose every public product on a clean host that has never contained a private consumer checkout.
