---
authority: canonical
owner: dev-tools
standard_version: 1
---

# Dev Tools product standard

This document is the normative current contract for public Dev Tools products. Architecture decision records explain why the contract exists; product documentation explains product-specific behavior; executable conformance tests enforce the common surface.

## Product classes

Public products are independently distributed end-user or maintainer commands. Internal helpers are narrowly scoped protocol executables, privileged helpers, broker workers, or test fixtures and do not inherit the general public-product CLI.

The public products are `update-all`, `artifact-update`, `dev-auth`, `dev-cache`, `sync-configs`, `skills-sync`, and `release-admin`. Adding or retiring a public product updates this list, the release product registry, and the executable conformance inventory in the same accepted change.

A public product must build, test, release, install, and operate without another Dev Tools product, a source checkout, an interpreter, Git, GitHub CLI, curl, wget, or a private downstream repository. A released binary contains the shared Rust implementation it uses. Operating-system facilities and explicitly documented product prerequisites are not sibling-product dependencies.

Private downstream consumers may invoke public product interfaces or consume published versioned crates. Dev Tools never reads, invokes, imports, discovers, tests against, or requires their code, policy, manifests, state, paths, credentials, or repository layout.

## Common public interface

Every public product provides the following canonical interface:

```text
<tool> --version
<tool> build-info --json
<tool> completion bash|zsh|fish|elvish|powershell
<tool> doctor [--json]
<tool> update status [--json]
<tool> update check [--json]
<tool> update install [--json] [--offline]
<tool> update apply [--json] [--offline]
<tool> update rollback [--json]
```

`--version` emits one stable `NAME MAJOR.MINOR.PATCH` line. `build-info --json` identifies the product, version, source commit, dirty state, build target, profile, and reproducible build timestamp. `doctor` is local, read-only, and network-free.

`update status` is local-only and evaluates authenticated cached release evidence. Evidence older than 24 hours produces `unknown`, never `current`. `update check` is the explicit network boundary and refreshes authenticated cache state. `update install` opts an explicitly downloaded product into its supported managed layout. `update apply` updates an existing managed installation. `update rollback` is network-free and activates only an authenticated receipt-owned retained version. `--offline` prohibits network access and accepts only authenticated cached artifacts.

An externally managed public command is reported as `external` and is never overwritten implicitly. A product whose first installation requires product-owned policy or enrollment may return `requires_setup`; the common update layer must not create policy, enroll credentials, or weaken the product's approval contract.

Ordinary product operations and `--version` never access the network. Remote release metadata may describe product identity and artifacts, but it may not provide executable commands, arbitrary destinations, shell programs, or privileged effects.

`artifact-update` is the standalone configuration-driven form of the shared update foundation. Its local `artifact-update-config-v1` authority selects providers, version conventions, artifact types, platform/architecture mappings, deterministic exact/glob/linear-time-regex selectors, verification requirements, and managed destinations for independently packaged applications. Unverifiable sources are check-only. Selection ambiguity is terminal, downloads are bounded and streaming, and install/rollback mutate only receipt-owned state.

New product releases use a canonical source-bound manifest that may contain multiple target artifacts for one product version and generation. Each target retains its own URL, length, and digest. A product verifies only its selected target after authenticating the complete manifest. Legacy manifest schemas remain readable only for explicitly bounded migration and receipt-owned rollback. Once shared v2 becomes authoritative for a product, its online release authority accepts only source-bound schemas; retained rollback never weakens online resolution.

## Common result contract

ADR 0003 defines verification and idempotent publication compatibility for the existing exact Dev Auth `0.3.11` source-bound Dev Auth v2 release. All manifest construction uses shared product v2; compatibility never authorizes another legacy-format release or reissuing accepted bytes.

Machine-readable common operations use `dev-tools-operation-result-v1`. The result identifies the product, operation, outcome, changed state, process exit category, fixed value-free error kind, managed or external installation state, cache freshness, and installed or available versions when applicable.

Common exit categories are `0` for completed or clean no-op, `1` for operational failure, `2` for invalid invocation or configuration, `3` for blocked, deferred, unsupported, or requires-setup outcomes, `4` for authenticity, integrity, or authority violations, and `130` for orderly interruption.

JSON mode emits exactly one document on stdout. Human diagnostics use stderr. Security diagnostics do not include secret values, captured subprocess output, or caller-controlled authority text. Authority-bearing documents deny unknown fields and declare an explicit schema. Observational result schemas may gain additive fields within a major schema version.

## Shared implementation

Identical reusable semantics belong in a focused Rust crate. A high-risk primitive may be shared before its second consumer when independent implementations would create conflicting security authorities. Product policy, service lifecycle, filesystem layout, presentation, and authorization remain product-owned and enter shared code through typed inputs.

Shared crates contain no product-name branches and do not form a broad `dev-tools-core`. Public products do not invoke sibling products for ordinary functionality. Cross-repository consumers use published versioned crates with exact lockfile and checksum authority rather than neighboring-checkout path dependencies.

| Foundation | Product-neutral responsibility |
| --- | --- |
| `dev-tools-product` | Product and build identity, common operation results, fixed error kinds, and exit categories. |
| `dev-tools-update` | Generic artifact source/selection contracts, signed release discovery, authenticated caching, freshness assessment, installation-adapter contracts, and rollback coordination. |
| `dev-tools-release` | Trust roots, signed manifests, source binding, anti-rollback checks, and artifact verification. |
| `dev-tools-installation` | Receipts, immutable versions, aliases, locks, journals, repair, rollback, and owned uninstall. |
| `dev-tools-command` | Bounded direct process execution and prepared-command execution. |
| `dev-tools-privilege` | One-shot typed privileged-operation authorization. |
| `dev-tools-privilege-session` (planned) | Workload-bound lease lifecycle, bounded authority delegation, expiry, revocation, and native containment contracts. |
| `dev-tools-secret` | Provider-neutral secret identifiers, operation capabilities, bounded cancellation contexts, zeroizing material, and value-free failures. |
| `dev-tools-reconcile-protocol` | Typed external reconciliation documents. |

`dev-tools-update` provides the executable product-neutral operation ordering and adapter contract. Persistent authenticated-cache transports and product adapters remain product-owned and are introduced incrementally behind that contract. A later privilege-session foundation remains separate from the mandatory one-shot authorization primitive. `release-admin` is a product, not a shared authority crate.

Rust is the operational implementation, not a wrapper around embedded Python, PowerShell, or shell programs. Non-Rust material is limited to declarative configuration and schemas, generated completions, explicit user-owned hooks, minimal platform bootstrap launchers, protocol fixtures, and tests whose subject is a foreign-language boundary. A bootstrap launcher may locate and verify a pinned native binary but contains no package, release, migration, or policy business logic.

## State, process, and security

Products use platform-native config, cache, data, state, and runtime roots and reject relative authority roots. Security-sensitive files and directories require owner-only Unix modes or an audited native ACL. Symlink and reparse boundaries fail closed where ownership or authority depends on path identity.

On Linux and other XDG systems, products use absolute `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, and `XDG_RUNTIME_DIR` values and otherwise fall back to the corresponding locations beneath the absolute home directory. On macOS, durable configuration, cache, application support, and logs use the applicable `~/Library` roots; runtime-only state uses a private temporary root. On Windows, configuration and durable application state use absolute roaming or local application-data roots according to whether the state should roam, while caches, logs, and runtime state use the local application-data root. A platform adapter must reject relative, device-namespace, alternate-data-stream, unsafe UNC, symlink, junction, mount-point, or other reparse authority where the operation's custody depends on a real directory or regular file. A fallback is accepted only when it has the same absolute-root and custody properties.

Managed mutation uses receipts, serialized locks, crash journals, atomic activation, explicit repair, retained rollback, and owned-only uninstall. Interruption leaves either the prior accepted state or a recoverable journaled transition.

Authority-bearing schemas deny unknown fields, identify their schema and capability requirements, and fail before mutation when a required capability is absent. Migrations are monotonic, journaled when they mutate authority, and preserve the last authenticated rollback candidate until the documented acceptance window ends. Compatibility code declares its owner, supported source versions, rollback window, and executable removal condition.

External processes use direct native argv, an explicit executable authority, controlled environment and working directory, closed or explicitly selected standard input, bounded output, timeout, cancellation, and owned-process cleanup. Shell interpretation is permitted only for an explicit user-owned hook, an acknowledged policy-permitted pinned-shell binding or administrator session under ADR 0004, or a shell-language output whose purpose is the shell itself.

Release authenticity does not grant privilege. Ordinary product helpers use typed operations and identity-validated helpers and expose no generic root command, arbitrary write, shell, password, or ambient `PATH` capability. ADR 0004 defines the separate explicitly approved Dev Auth administrator-session tiers, including a root/admin-equivalent unrestricted exception. That exception never widens ordinary setup, configuration reconciliation, update, or release authority. No tier stores passwords or refreshes global sudo timestamps.

## Dependencies, performance, and platform support

Workspace dependencies are intentionally narrow, licensed, locked, and audited. Update functionality uses one audited Rust HTTP/TLS stack and ordinary command paths do not initialize network machinery. Cargo features exclude unused network and platform implementations. Released binaries use dead-code elimination and link-time optimization when measurement supports it.

Every release records startup, cached-status, explicit-check, update-application, and binary-size baselines. An unexplained regression greater than 10 percent or 2 milliseconds absolute on a hot local command blocks release.

New dependencies require a license and provenance review, a feature audit, and evidence that an existing focused foundation cannot safely supply the behavior. A dependency that adds another HTTP client, TLS implementation, cryptographic authority, async runtime, command runner, archive implementation, or platform security layer requires an explicit ADR or an update to the record that owns that boundary. Release gates reject duplicate major network or TLS stacks unless a time-bounded exception names the owner and removal condition.

Cross-compilation proves only source portability. A platform is advertised as supported only after its native filesystem custody, process termination, update/install/rollback, privilege, and clean-device acceptance pass. Compatibility code has an owner, rollback window, and executable removal condition; it is not retained indefinitely.

## Conformance and exceptions

The repository conformance suite launches every public product and validates the common CLI, schemas, exit categories, local-only boundaries, standalone operation, dependency direction, release identity, and platform claims. Product tests retain product-specific behavior and security acceptance.

Migration is explicit in the conformance inventory: `inventory` means only that the public product is known, `build_info` means the common self-description contract is mandatory, and `full` means every common contract is mandatory. These stages describe unfinished rollout and do not weaken the target contract. A release may claim this standard only at `full`.

A product may add commands and stable result fields. A material exception to this standard requires a superseding ADR, executable coverage, a migration and rollback contract, and an update to this document after the replacement decision becomes authoritative.
