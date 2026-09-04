---
authority: canonical
owner: dev-tools
---

# ADR 0003: Native release administration and separated authority

status: proposed
verification: pending

## Context

The remaining release administration path uses repository-owned Python programs. Converting it to Rust removes an interpreter dependency and permits shared typed release contracts, but combining the workflow must not combine build, offline root, release-signing, publication, or privileged-installation authority.

## Decision

A native `release-admin` product owns deterministic build orchestration, manifest and root construction, offline verification, operation-only signer invocation, admitted publication, anonymous redownload verification, root rotation, and audit reporting. The command coordinates distinct authorities through typed inputs and never receives raw routine signing keys or ambient publication credentials.

New releases use one canonical `dev-tools-product-v2` manifest per product version. The manifest requires the exact source commit and may bind multiple target artifacts. Existing `dev-tools-product-v1` and `dev-auth-product-v2` documents remain readable only for explicitly bounded migration and receipt-owned rollback; new release metadata is never written in those forms. Product release authority switches to source-bound schemas at cutover and never resolves a later source-unbound release.

## Invariants

- Build, root, signing, publication, and privileged installation remain independently authorized.
- Every published artifact binds the exact product, source commit, target, length, digest, version, and generation.
- A selected target is verified as one projection of the complete signed target set; accepting one target never permits unsigned additions or substitutions.
- Remote metadata cannot select commands or privileged effects.
- Python release tooling remains authoritative until native parity and rollback acceptance pass, then is removed rather than retained as a second path.

## Verification

Rust integration tests replay the frozen release corpus, compare deterministic output byte-for-byte, reject authority confusion, target substitution, schema downgrade, and tampering, publish only exact reviewed identities through admitted operations, and anonymously re-download every asset for verification.

## Runtime acceptance

Produce two independent byte-identical release sets, sign them operation-only, publish one reviewed set, verify it anonymously, install it from outside the checkout, and prove an idempotent second pass and retained rollback before retiring Python release administration.
