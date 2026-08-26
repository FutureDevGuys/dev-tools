# Dev Cache

`dev-cache` routes positively known disposable tool caches to a machine-selected storage root. It preserves source trees, dependency trees, environments, installed tools, final binaries, documentation, and other deliverables in their normal locations. Unknown, overridden, ambiguous, or unsafe state causes the affected adapter to abstain or fail closed.

Configuration and state use standard platform `dev-cache` roots. POSIX intercepts live under `${XDG_DATA_HOME:-$HOME/.local/share}/dev-cache/intercepts`; Windows intercepts and generated completion live under `%LOCALAPPDATA%\dev-cache`.

Linux runtime acceptance covers Cargo and sccache, Go, npm, pnpm, uv and pip, ccache, Zig, Meson, Bun, and Yarn. Native Windows and WSL support is not claimed until their runtime acceptance harnesses pass.

## Automatic maintenance

Normal routed commands maintain Dev Cache without a timer, daemon, repository hook, or per-project configuration. Before a command starts, a bounded collection pass runs when the selected root is under its configured space pressure. After the command finishes, a bounded routine pass runs when the maintenance interval is due. The default interval is 24 hours, data becomes stale after 120 days, collection starts below 50 GiB free, and pressure collection reclaims toward 100 GiB free. Pressure retries are limited to once per hour. Automatic collection defers normally when another routed command holds the shared root lease; an explicit manual collection still reports the busy root. A failed or partial bounded pass remains incomplete so later passes continue draining eligible work; an unattainable free-space target on a smaller or externally occupied volume is reported as a shortfall without falsely classifying a successful collection pass as failed.

Every routed disposable resource has an authoritative catalog record outside the resource itself. The record binds its opaque identity to the physical root, runtime domain, adapter, exact domain-relative path, generation, last completed routed use, cleanup strategy, native executable context, and persistent safety hazards. Status and doctor discovery are read-only and never refresh usage timestamps; only an actual routed command does.

| Resource | Collection behavior |
|---|---|
| Cargo intermediate build directories, Go/ccache/generic temporary directories, pnpm metadata, uv managed-Python archives, Zig caches, Meson package downloads, Bun transpiler cache | Transactional rename into same-domain trash, then delete; final Cargo outputs, `zig-out`, Meson build trees, installed Python, and emitted artifacts are outside the catalog. |
| sccache local data | Stop the recorded domain-specific server first, then use transactional owned deletion. Remote or foreign backends abstain. |
| Go build and module caches | Invoke the recorded real Go executable with `go clean -cache` or `go clean -modcache` and the exact managed native environment. |
| npm cache | Invoke npm's cache cleanup against the exact managed cache. |
| pnpm content-addressed store | Invoke the recorded pnpm or Corepack entrypoint's store pruning. External store servers and ambiguous linked state abstain. |
| uv and pip caches | Invoke their native prune or purge commands against the exact managed cache. uv symlink mode abstains. |
| ccache local data | Invoke ccache's own cleanup for the exact managed directory. Compiler outputs are never cataloged. |
| Bun install cache | Invoke Bun's package-cache cleanup. Global-store use or ambiguity abstains. |
| Yarn Classic cache | Invoke the recorded Yarn or Corepack entrypoint's cache cleanup. Berry project and Zero-Install state is never cataloged. |

Owned deletion uses an exclusive root lease, validates every path component against links and Windows reparse points, writes a transaction journal, atomically moves all members of a compound resource into same-domain trash, commits the journal, and then deletes. A later applied pass recovers committed trash after interruption. Artifact objects and metadata are one compound action. Invalid or tampered catalog and artifact records become visible abstentions and are never deletion candidates.

`dev-cache gc` is a read-only plan. `dev-cache gc --apply` performs the plan and exits nonzero if an action failed, transactional trash remains, or a bounded pass has more eligible work. Free-space and cache-size shortfalls remain explicit report fields. `dev-cache status --json` includes the resource count, persistent hazards, catalog or workspace-ownership issues, trash backlog, and last automatic result. `dev-cache doctor --json` treats invalid ownership records, unrecovered trash, or a failed/incomplete automatic result as unhealthy.

There is deliberately no separate refresh command: routing is reconciled on each recognized invocation, native cache metadata remains owned by its native tool, and garbage collection is event-triggered. Product binary updates are a separate responsibility of `update-all`; cache maintenance never updates compilers, runtimes, package managers, dependencies, or source trees.

Explicit native cache/output settings and `DEV_CACHE_MODE=off` remain authoritative. Unsupported versions, unparseable persistent configuration, external services, remote backends, symlink-sensitive modes, and linked-state ambiguity affect only the relevant resource; the original command delegates unchanged and the resource is not presented as routed or collectible.

Migration is always explicit and dry-run first. A successful applied migration fingerprints the source and destination, publishes only into a known adapter resource, writes a receipt, and registers the verified destination in the same authoritative catalog. Dev Cache does not implicitly discover or adopt existing product state.

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
