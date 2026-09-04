---
authority: canonical
owner: dev-tools
---

# ADR 0002: Common product CLI and explicit network boundaries

status: proposed
verification: pending

## Context

Products currently expose different version, build, diagnostic, completion, and self-update shapes. A user downloading one product should not need to learn a different lifecycle or install a central updater, while scripts must not gain surprise network access.

## Decision

Every public product implements the common interface and result categories in the product standard. Update status is authenticated-cache-only, update check is the explicit network boundary, install and apply are explicit managed mutations, and rollback uses only authenticated retained state. Product-owned adapters preserve stronger setup and enrollment requirements.

## Invariants

- Ordinary commands, `--version`, `build-info`, `doctor`, status, and rollback are network-free.
- Expired or absent release evidence produces `unknown`, not `current`.
- An external installation is never overwritten implicitly.
- JSON output contains exactly one schema-versioned document and value-free failure kinds.

## Verification

The conformance suite verifies command grammar, help, version/build identity, completion generation, JSON schemas, exit categories, network isolation, cache expiry, external-manager preservation, offline behavior, and interruption.

## Runtime acceptance

Exercise status, check, install, apply, and rollback for each product from a standalone artifact. Confirm packet-free local operations, authenticated release selection, idempotent second passes, and retained rollback.
