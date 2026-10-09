# Dev Cache

`dev-cache` routes positively known disposable tool caches to a machine-selected storage root. By default it preserves source trees, dependency trees, environments, installed tools, final binaries, documentation, and other deliverables in their normal locations. The optional Cargo final-output policy below routes Cargo-managed final artifacts into retained storage under the same selected root. Unknown, overridden, ambiguous, or unsafe state causes the affected adapter to abstain or fail closed.

If the operating system makes an otherwise selected cache root read-only before an intercepted tool starts, the intercept delegates once to the original tool without Dev Cache routing; compiler-name aliases bypass ccache. A read-only failure after the tool has run preserves its exit status without replay. This does not repair the filesystem or authorize fallback for a changed volume identity, unsafe ownership, missing root, permission failure or invalid configuration. `dev-cache doctor` remains the way to inspect the unhealthy cache root; native storage repair is external to Dev Cache. [ADR 0093](adr/0093-read-only-cache-root-intercept-fallback.md) owns this narrow failure behavior.

Configuration and state use standard platform `dev-cache` roots. POSIX intercepts live under `${XDG_DATA_HOME:-$HOME/.local/share}/dev-cache/intercepts`; Windows intercepts and generated completion live under `%LOCALAPPDATA%\dev-cache`.

`dev-cache build-info --json` emits the common checkout-independent `dev-tools-build-info-v1` document without initializing cache routing or maintenance state. Its product-owned `native_container_cache` field reports `disabled` in default builds or `experimental-unqualified` in explicit experimental builds; neither claims native acceptance. The hidden `--build-info` form remains for rollback to the pre-standard 0.1 line and is removed in the next minor release after one accepted release has shipped the standard subcommand.

Linux runtime acceptance covers Cargo and sccache, Go, npm, pnpm, uv and pip, ccache, Zig, Meson, Bun, and Yarn. Native Windows and WSL support is not claimed until their runtime acceptance harnesses pass.

## Retained Cargo final outputs (opt-in)

Enable `[cargo] final_outputs = true` in Dev Cache's machine configuration to route Cargo-managed final outputs beneath the configured root as well as disposable intermediates. For example, a root selected as `/storage/dev-cache` keeps these outputs on that storage volume; the product never hard-codes a mount point. This source feature requires separate native/release qualification before installed use.

Each actual Cargo workspace and observed toolchain gets a collision-resistant directory under `<runtime-domain>/outputs/cargo/<workspace-key>/<toolchain-key>`. Members share their workspace's directory; independent workspaces in one Git repository do not. Cargo retains its native target-triple and debug/release/named-profile layout. Existing repository-local target directories and running commands are left untouched. Re-run builds only after adopting a qualified version; this setting cannot relocate a process that is already running.

Supported canonical commands are build, check, test, bench, run, doc, rustc, rustdoc, clean, metadata and locate-project on Cargo 1.91+. Direct Cargo, recognized Rustup proxies and `rustup run TOOLCHAIN cargo ...` use the same routing. `dev-cache exec cargo cargo ...` supports it too; an arbitrary shell command cannot establish Cargo workspace identity and is rejected in opt-in mode. Aliases/external subcommands, install/package/publish, unknown/nightly scope options, explicit native output/CLI config settings and ambiguous compiler/configuration selectors abstain. User environment values, even empty ones, remain authoritative. Config is inspected from the invocation directory, including with a foreign `--manifest-path`. Failed native identity discovery on an eligible invocation stops before building rather than silently creating repository-local outputs.

Use `dev-cache path cargo --final-outputs --repo /path/to/workspace` to inspect the retained path without materializing it, or `cargo metadata --no-deps --format-version=1` to get Cargo's effective target directory. Set `RUSTUP_TOOLCHAIN` for a different toolchain query. Status includes the retained path or the reason it cannot be selected. Normal `path cargo` still reports intermediate storage.

Final output resources are cataloged, measured and activity-protected but never removed by Dev Cache GC, including stale/orphan/pressure passes. `retained_outputs_bytes` is included within `other_bytes`, so do not add it to the total again. Retained bytes can make storage targets unattainable. Native `cargo clean` still removes native outputs; retention is not backup, and an executable may still depend on disposable intermediate files. No automatic migration or deletion of old target trees is performed. Remove the enabled `final_outputs` config key before rolling back to an older binary; older readers will also report unfamiliar retained catalog records as issues without collecting them.

This is not a universal build-output redirect:

| Adapter | Final-output boundary |
|---|---|
| Cargo | The opt-in route covers Cargo's target tree; custom build scripts and explicit compiler/output arguments can emit elsewhere. |
| Go | Build/module/temp caches are routed; final `go build -o` output and installed `GOBIN` remain native. |
| ccache / sccache | Compiler caches are routed; emitted compiler/linker outputs remain caller-selected. |
| Zig | Global/local caches are routed; `zig-out`, installation prefixes and custom steps remain native. |
| Meson | Package cache is routed; setup/build-tree arguments remain native. |
| npm / pnpm / Yarn / Bun | Supported package/transpiler caches are routed; arbitrary scripts and Bun build output require tool/project-specific configuration. |
| uv / pip | Supported caches are routed; environments, wheels, sdists and download destinations remain native. |
| Temp | Temporary files only; no generic final-output setting. |

[ADR 0105](adr/0105-retained-cargo-final-outputs.md) defines identity, bounded discovery, retention, nested overrides and qualification limits.

## Explicit native container build cache

Default/stable builds omit `container-cache` from the CLI and completions and reject invocations before any provider contact. Only a source build with the default-off `experimental-container-cache` Cargo feature exposes `dev-cache container-cache docker --socket /absolute/path/docker.sock --json`. There is no runtime or environment opt-in. Applying experimental native cleanup requires positive local-daemon executable attestation, explicit cache IDs and matching engine ID, native storage root and rootful/rootless expectations. Unverified locality permits preview only, including some Docker-group rootful access. This separate command never routes or traverses engine storage and does not participate in filesystem GC or automatic maintenance. Podman is explicitly unsupported. Native Docker acceptance remains NOT RUN; see the [scope, accounting and disposable acceptance contract](dev-cache-native-cache.md), [ADR 0099](adr/0099-explicit-native-container-build-cache.md), and the [stable-build guard in ADR 0104](adr/0104-dev-cache-experimental-native-cache-gate.md).

## Automatic root-identity repair

Root preparation retains native filesystem identity separately from a transient Unix device number. After a reboot or device renumbering, matching retained filesystem evidence allows the device observation to refresh automatically without resetting the physical-root ID, runtime domains or cache contents. Linux uses supported native filesystem IDs, macOS uses the volume UUID, and Windows uses its native volume serial; neither a particular mount directory nor a workstation configuration is required. Unknown filesystem contracts retain strict checking rather than guessing that a replacement is the same storage.

Older v2 markers gain stable evidence automatically during ordinary routed use when their original device check still matches. If an old marker already has a mismatch and contains no stable evidence, Dev Cache cannot establish its previous filesystem identity from the new device number alone; that one-time case requires independent volume verification before repairing the marker. A missing root, an actual filesystem replacement, an unowned populated directory or a changed canonical path is never silently adopted. Diagnostic commands remain read-only: they can recognize matching stable evidence but do not rewrite the marker. [ADR 0091](adr/0091-dev-cache-stable-volume-repair.md) defines compatibility, native identity and qualification limits.

## Automatic maintenance

Normal routed commands maintain Dev Cache without a timer, daemon, repository hook, or per-project configuration. Compiler aliases and direct `ccache`/`sccache` intercepts are excluded from automatic maintenance: they execute once per compiler invocation and must not synchronously scan unrelated cache trees. They still route caches, publish resource records, hold activity leases and record completed use. Outer routed commands and explicit `dev-cache gc --apply` retain maintenance responsibility; a workload using only compiler intercepts needs explicit collection. See [ADR 0013](adr/0013-compiler-intercept-maintenance-boundary.md).

For other routed commands, a bounded collection pass runs before delegation when the selected root is under its configured space pressure; after delegation, a bounded routine pass runs when the maintenance interval is due. The default interval is 24 hours, data becomes stale after 120 days, collection starts below 50 GiB free, and pressure collection reclaims toward 100 GiB free. Pressure retries are limited to once per hour. Routed commands hold a root-wide shared lease only while publishing their resource records, then retain a resource-specific activity record for their remaining lifetime. Collection therefore proceeds for unrelated resources while explicitly abstaining from active resource IDs and containing workspaces. A crashed activity record is removed only after its process is proven absent on supported Linux runtimes; uncertain platforms fail closed. A failed or partial bounded pass remains incomplete so later passes continue draining eligible work; an unattainable free-space target on a smaller or externally occupied volume is reported as a shortfall without falsely classifying a successful collection pass as failed.

Every routed disposable resource has an authoritative catalog record outside the resource itself. The record binds its opaque identity to the physical root, runtime domain, adapter, exact domain-relative path, generation, last completed routed use, cleanup strategy, native executable context, and persistent safety hazards. Status and doctor discovery are read-only and never refresh usage timestamps; only an actual routed command does.

Status, doctor, report, path lookup, migration previews and explicit GC previews observe only an already initialized root and runtime layout. They report missing domains or directories without enrolling or recreating them and do not probe root writability. Ordinary routed operations retain root preparation. Writable preparation uses a unique no-clobber probe and leaves pre-existing probe-like files and symlinks untouched; interrupted residual probes are not automatically adopted or cleaned. [ADR 0015](adr/0015-dev-cache-read-only-root-observation.md) defines this boundary; a successful observation does not establish write access.

| Resource | Collection behavior |
|---|---|
| Cargo intermediate build directories, Go/ccache/generic temporary directories, pnpm metadata, uv managed-Python archives, Zig caches, Meson package downloads, Bun transpiler cache | Transactional rename into same-domain trash, then delete; default Cargo outputs, `zig-out`, Meson build trees, installed Python, and emitted artifacts are outside the catalog. |
| Opt-in Cargo final outputs | Retained, cataloged and measured; GC explicitly abstains under every policy. |
| sccache local data | Stop the recorded domain-specific server first, then use transactional owned deletion. Remote or foreign backends abstain. |
| Go build and module caches | Invoke the recorded real Go executable with `go clean -cache` or `go clean -modcache` and the exact managed native environment. |
| npm cache | Invoke npm's cache cleanup against the exact managed cache. |
| pnpm content-addressed store | Invoke the recorded pnpm or Corepack entrypoint's store pruning. External store servers and ambiguous linked state abstain. |
| uv and pip caches | Invoke their native prune or purge commands against the exact managed cache. uv symlink mode abstains. |
| ccache local data | Invoke ccache's own cleanup for the exact managed directory. Compiler outputs are never cataloged. |
| Bun install cache | Invoke Bun's package-cache cleanup. Global-store use or ambiguity abstains. |
| Yarn Classic cache | Invoke the recorded Yarn or Corepack entrypoint's cache cleanup. Berry project and Zero-Install state is never cataloged. |

Owned deletion uses an exclusive root lease, validates every path component against links and Windows reparse points, writes a transaction journal, atomically moves all members of a compound resource into same-domain trash, commits the journal, and then deletes. A later applied pass recovers committed trash after interruption. Artifact objects and metadata are one compound action. Invalid or tampered catalog and artifact records become visible abstentions and are never deletion candidates. Workspace identities from a proven earlier physical-root generation are reconciled to the current runtime-domain identity as bounded GC actions. Reconciliation atomically rehomes unique caches, updates catalog paths, merges only byte-identical file collisions, and abstains without mutation when content differs. An unknown-generation directory is removable only when it contains one structurally valid identity record, no payload files or links, and an independently validated current record describes the same workspace; empty cache-directory scaffolding is permitted.

`dev-cache gc` is a read-only plan. `dev-cache gc --apply` performs the plan and exits nonzero if an action failed, transactional trash remains, or a bounded pass has more eligible work. Free-space and cache-size shortfalls remain explicit report fields. Default `dev-cache status --json` reports current-workspace routing without scanning the cache catalog or other workspaces; `maintenance` is null and `maintenance_scope` is `not_observed`. Use `dev-cache status --full --json` for the live resource count, persistent hazards, catalog or workspace-ownership issues, trash backlog, and last automatic result (`maintenance_scope: full`). An unobserved result makes no maintenance-health claim. `dev-cache doctor --json` treats invalid ownership records, unrecovered trash, or a failed/incomplete automatic result as unhealthy.

GC previews hold a nonblocking shared observation lease on the existing coordination lock without creating it or removing stale activity records. They coexist with routed setup and active work; applied maintenance remains exclusive. A preview encountering exclusive maintenance defers or fails without waiting. Routed setup also fails immediately with a clear busy diagnostic rather than waiting silently for maintenance or delegating without its resource protections. Preview results are advisory observations across concurrent activity, not an atomic snapshot or authorization to delete later. See [ADR 0100](adr/0100-nonblocking-cache-observation-and-setup.md). If an older root has no coordination lock, explicitly run `dev-cache config init-root ROOT` for the configured root (retaining `--config PATH` when using a nondefault configuration) before previewing again. Initialization prepares coordination; a preview never does. Applied collection retains stale-record cleanup and recomputes its current plan rather than executing a previously printed list.

There is deliberately no separate refresh command: routing is reconciled on each recognized invocation, native cache metadata remains owned by its native tool, and garbage collection is event-triggered. Product binary updates are a separate responsibility of `update-all`; cache maintenance never updates compilers, runtimes, package managers, dependencies, or source trees.

Explicit native cache/output settings and `DEV_CACHE_MODE=off` remain authoritative. Unsupported versions, unparseable persistent configuration, external services, remote backends, symlink-sensitive modes, and linked-state ambiguity affect only the relevant resource; the original command delegates unchanged and the resource is not presented as routed or collectible.

If preparation leaves no managed resources, intercepts and explicit `exec` release the setup lease and delegate with the original environment and arguments, without publishing an empty activity record. Auxiliary settings such as an Sccache server port do not establish a routed resource. This also applies to Cargo versions older than 1.91 when their Sccache-only routing has no managed resource: Dev Cache injects neither its wrapper nor cache settings. Preparation failures still retain their existing error behavior, and any remaining routed resources keep their scoped activity protection.

Migration is always explicit and dry-run first. A successful applied migration fingerprints the source and destination, publishes only into a known adapter resource, writes a receipt, and registers the verified destination in the same authoritative catalog. Dev Cache does not implicitly discover or adopt existing product state.

## Space reporting and diagnostic cost

`dev-cache report` walks the current runtime domain once and measures ordinary-file apparent bytes. `bytes` is the sum of `repos_bytes` (workspaces), `shared_bytes` (cache), `artifacts_bytes` (artifact objects under `artifacts/blake3`) and `other_bytes` (including artifact metadata, control, migration and trash). Nested links/reparse entries are excluded and counted in `links_skipped`. Counts describe one live traversal, not an atomic snapshot or guaranteed reclaimable disk space.

A complete report has `complete: true`. Scan failure or interruption produces `complete: false`, a fixed `error_kind` and null size fields rather than partial totals; failure exits 1 and Ctrl-C cancellation exits 130. Progress goes to stderr, initially and at most once per second between filesystem operations. The scan limits directory handles to 32 and fails explicitly beyond depth 256. WalkDir may buffer directory entries within one iterator step, so memory and per-step cancellation latency are not strictly bounded. Kernel-blocked filesystem calls can delay progress and cancellation. Existing invalid-root errors occur before scanning.

Doctor remains exhaustive but shares its root, activation and maintenance observations with its embedded status. Default status avoids cache-size-dependent audit work; native tool/configuration probes, PATH discovery and executable hashing can still be slow. Full status/doctor and GC remain explicit expensive operations. The diagnostic correction does not add a persistent probe cache, serialize concurrent reports or alter deletion authority. [ADR 0102](adr/0102-dev-cache-scoped-status-and-single-pass-report.md) defines these boundaries.

GC admits candidate metadata first, then shares one payload-size traversal between the domain total and directory/file candidate estimates. Artifact record/companion accounting and zero-byte identity-rehome estimates are preserved. Existing candidates whose path spelling does not match any visited root are rejected rather than reported as zero; observed empty and proven-absent candidates remain valid. The index does not reconcile alternate casefold spellings. A preview has no post-operation size scan; applied collection retains one after actions. Failed size observations are errors, and applied recovery or actions may already have changed state before a later error. Catalog/identity validation, reconciliation content comparisons, configured automatic size-pressure checks and applied native cleanup remain additional work. The candidate index stores paths/counters, not every file, but WalkDir buffering is not a strict memory bound. Explicit CLI GC prints initial planning and rate-limited size-scan progress on stderr; library calls and automatic maintenance remain quiet. This adds no traversal or signal handler, and blocking filesystem operations can still delay interruption/progress. Exclusive applied-GC coordination and every mutation-authority check remain unchanged. [ADR 0103](adr/0103-dev-cache-indexed-gc-size-observation.md) defines this follow-up.

## Activation health

`dev-cache doctor --json` audits global routing rather than treating tool availability as activation. For every installed supported entrypoint, it verifies that the effective command is the owned canonical intercept, that the intercept resolves to a real executable without recursion, and that PATH contains no duplicate or stale Dev Cache intercept precedence.

The entrypoint matrix covers Cargo and Rustup; sccache; Go; npm and npx; pnpm, pnpx, and Corepack dispatch; uv and uvx; pip aliases and supported Python module dispatch; ccache and supported compiler commands; Zig; Meson; Bun and bunx; and Yarn, yarnpkg, and Corepack dispatch. Versioned pip and Python commands discovered on PATH are included.

Each entrypoint reports one of the following durable states:

- `routed`: the installed entrypoint is routed through an owned canonical intercept and resolves to its real executable.
- `absent`: the entrypoint is not installed and does not require routing.
- `intentional_abstention`: configuration disables the applicable adapter.
- `unsupported_version`: the installed tool cannot be routed safely by the supported adapter.
- `not_activated`, `shadowed`, `unowned_intercept`, `unresolved`, or `recursive`: mandatory activation is broken.
- `stale_intercept` or `stale_intercept_precedence`: an obsolete intercept remains and must be reconciled.
- `duplicate_intercept_path`: the canonical intercept directory occurs more than once in PATH.
- `invalid_override`: an explicit real-executable override is unusable.

Explicit overrides are reported separately from native discovery. `routed_adapters` contains an adapter only when its enabled, supported, installed entrypoints all pass activation without an explicit override; finding a real tool is not sufficient. `routing_complete` reports whether every mandatory installed entrypoint and the canonical PATH activation are healthy.

When the canonical intercept directory is missing from the current PATH, doctor reports `stale_current_shell` if a recognized persistent shell profile already contains activation and `persistent_configuration_missing` otherwise. This distinction is best-effort and never changes the mandatory entrypoint result. Any failed mandatory activation or maintenance check makes doctor exit nonzero.

## Workspace discovery

Workspace grouping uses local filesystem markers and never launches Git or its credential wrappers. The nearest `.git` file/directory takes precedence over nested language manifests; without one, the nearest supported language manifest or requested directory supplies the scope. Markers are cache grouping hints only. Git environment and configuration overrides do not change this scope. See [ADR 0086](adr/0086-local-cache-workspace-discovery.md).
