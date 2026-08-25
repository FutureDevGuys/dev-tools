# Dev Cache

`dev-cache` routes positively known disposable tool caches to a machine-selected storage root. It preserves source trees, dependency trees, environments, installed tools, final binaries, documentation, and other deliverables in their normal locations. Unknown, overridden, ambiguous, or unsafe state causes the affected adapter to abstain or fail closed.

Configuration and state use standard platform `dev-cache` roots. POSIX intercepts live under `${XDG_DATA_HOME:-$HOME/.local/share}/dev-cache/intercepts`; Windows intercepts and generated completion live under `%LOCALAPPDATA%\dev-cache`.

Linux runtime acceptance covers Cargo and sccache, Go, npm, pnpm, uv and pip, ccache, Zig, Meson, Bun, and Yarn. Native Windows and WSL support is not claimed until their runtime acceptance harnesses pass.

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

When the canonical intercept directory is missing from the current PATH, doctor reports `stale_current_shell` if a recognized persistent shell profile already contains activation and `persistent_configuration_missing` otherwise. This distinction is best-effort and never changes the mandatory entrypoint result. Any failed mandatory check makes doctor exit nonzero.
