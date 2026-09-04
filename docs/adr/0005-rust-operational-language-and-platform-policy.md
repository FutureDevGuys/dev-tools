---
authority: canonical
owner: dev-tools
---

# ADR 0005: Rust operational language and platform policy

status: proposed
verification: pending

## Context

Interpreter-backed wrappers and embedded foreign-language programs make standalone behavior depend on hidden runtimes, duplicate validation boundaries, and obscure the implementation actually being audited. Cross-compilation can also create an artifact that has never exercised native custody or process semantics.

## Decision

Repository-owned operational logic is Rust. Foreign-language material is limited to declarative documents, generated completions, explicit user hooks, minimal platform bootstrap launchers, protocol fixtures, and tests of those boundaries. Bootstrap launchers may locate and verify a pinned native binary but contain no policy or business logic. Platform support requires native acceptance.

## Invariants

- Rust is not a wrapper for an embedded Python, PowerShell, or shell implementation.
- Public product operation requires no interpreter.
- One audited Rust HTTP/TLS stack serves update functionality, and ordinary command paths do not initialize it.
- Cross-compilation is portability evidence, not runtime acceptance.

## Verification

Static checks reject hidden interpreter invocations and embedded operational scripts, dependency checks prevent duplicate network stacks, and native acceptance covers filesystem custody, process cleanup, update/install/rollback, privilege, and clean-device behavior.

## Runtime acceptance

Run every supported product and lifecycle operation on each advertised native platform without Python or command-line download and Git tooling. Measure startup, cached status, explicit check, update application, and artifact size against recorded baselines.
