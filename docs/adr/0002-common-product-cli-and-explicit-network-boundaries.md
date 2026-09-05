---
authority: canonical
owner: dev-tools
---

# ADR 0002: Common product CLI and explicit network boundaries

status: proposed
verification: pending

## Context

Standalone products need one predictable lifecycle without acquiring a runtime dependency on a central updater. The same update machinery also serves independently packaged programs whose implementation language and distribution format are irrelevant: native executables, AppImages, archives, plugins, extensions, JVM artifacts, Go binaries, Node packages, and other versioned assets. Local inspection remains fast and network-free, while explicit discovery handles heterogeneous release providers without granting remote metadata authority over commands, destinations, or privilege.

## Decision

Every public product implements the common interface and result categories in the product standard. Update status is authenticated-cache-only, update check is the explicit network boundary, install and apply are explicit managed mutations, and rollback uses only authenticated retained state. Products compile the shared `dev-tools-update` implementation and retain product-owned installation, health, setup, and enrollment adapters.

`artifact-update` exposes the same foundations as a standalone configuration-driven product for unrelated artifacts. Its local authority document names the provider, tag or version convention, platform and architecture selectors, ordered exact/glob/linear-time-regex asset rules, verification tier, and managed destination. Source adapters translate bounded remote metadata into inert candidates. Remote responses cannot contribute executable commands, shell text, destinations, selectors, or privilege.

The source layer admits GitHub, GitLab, Forgejo/Gitea, generic JSON, XML/Atom/RSS/Sparkle, Maven, npm, crates.io, static signed manifests, direct or final-redirect URLs, bounded HTML inventories, and AppImage/zsync through separate parsers behind one candidate contract. A source becomes install-capable only when signed first-party metadata, a pinned checksum/signature scheme, or another locally declared verifier authenticates the selected bytes. Unverifiable sources remain check-only.

One bounded Rust HTTP/TLS implementation owns HTTPS, allowed-host redirect policy, ETag and Last-Modified validation, 304 reuse, Retry-After and rate-limit handling, size limits, streaming downloads, timeouts, cancellation, and bounded global/per-host concurrency. A runtime replacement is accepted only through comparative startup, memory, binary-size, throughput, and p95 latency evidence; implementation fashion alone does not add a second network stack.

## Invariants

- Ordinary commands, `--version`, `build-info`, `doctor`, status, and rollback are network-free.
- Expired or absent release evidence produces `unknown`, not `current`.
- An external installation is never overwritten implicitly.
- Cache freshness defaults to 24 hours; a check is the only implicit metadata-network operation.
- Selectors compile once per accepted local configuration and ambiguity is terminal rather than guessed.
- Downloads stream with memory bounded independently of artifact size.
- Install and rollback replace only receipt-owned state and never infer authority from a filename or redirect.
- JSON output contains exactly one schema-versioned document and value-free failure kinds.

## Verification

The conformance suite verifies command grammar, help, version/build identity, completion generation, JSON schemas, exit categories, network isolation, cache expiry, external-manager preservation, offline behavior, interruption, source parsing, deterministic selection, redirect and size bounds, authenticity failures, crash recovery, and rollback ownership. Provider fixtures cover success, absence, ambiguity, malformed and oversized metadata, conditional requests, rate limits, and hostile archive inputs without depending on live services.

## Runtime acceptance

Exercise status, check, install, apply, and rollback for each product from a standalone artifact. Confirm packet-free local operations, authenticated release selection, idempotent second passes, retained rollback, and independent native platform behavior. Benchmark identical 1-, 32-, and 128-source discovery workloads before changing concurrency or the HTTP/TLS implementation.
