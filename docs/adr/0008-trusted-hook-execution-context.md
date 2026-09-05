---
status: proposed
verification: pending
---

# Trusted hook execution context

## Decision

Expose a versioned, additive environment contract to trusted sync-configs pre/post hooks. Construct typed run context from resolved manifest, profiles, path context, and diagnostic run identity; overlay phase and entry metadata at invocation. Product-owned keys replace ambient values, and absent optional fields are removed. Preserve the existing runner's shell, working directory, bounded execution, authentication timing, failure policy, and dry-run/validation behavior.

This is a general product interface, not a consumer-specific integration. Consumers use their existing scripts; no templating language or second hook subsystem is introduced. Sudo receives an explicit key-preservation request rather than whole-environment preservation. Host sudo policy remains authoritative. Structured diagnostics do not gain environment values.

## Acceptance

The hook contract tests cover both privilege paths, selected profile order/deduplication, all metadata fields, optional-field absence, and both successful convergence states. Native integration tests cover ambient spoofing and profile delivery through the CLI. Existing dry-run, validation, failure, output-limit, timeout, and privilege tests remain required before release.
