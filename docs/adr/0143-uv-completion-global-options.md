---
authority: canonical
owner: dev-cache
---

# ADR 0143: UV completion after global options

status: proposed
verification: Linux completion acceptance passed; three unrelated environment-dependent tests blocked

## Context

UV accepts global options before its root command, including `uv --quiet generate-shell-completion zsh` and `uv --offline generate-shell-completion zsh`. ADR 0123 deliberately recognized only a leading completion command. Prefixed forms therefore still load Dev Cache configuration, prepare cache state and enter ordinary automatic maintenance. This decision extends that contract; it is not a regression in the first-argument-only contract.

## Decision

The product-owned dispatcher recognizes `generate-shell-completion` as UV's first command after these known global options:

- Switches: `--no-cache`, `--managed-python`, `--no-managed-python`, `--no-python-downloads`, `--quiet`, `--verbose`, `--system-certs`, `--native-tls`, `--offline`, `--no-progress`, `--no-config`, `--help`, and `--version`.
- Single-value options: `--cache-dir`, `--color`, `--allow-insecure-host`, `--directory`, `--project`, and `--config-file`, with a separate value or `--option=value`.
- Short switches `-n`, `-q`, `-v`, `-h`, and `-V`, including repeated and combined switches.

This inventory follows UV 0.13's public root options and preserves the earlier `--native-tls` spelling. Unknown and hidden option grammars remain routed rather than guessing their value arity. Support for a new UV option requires an explicit inventory and test update; no UV subprocess or configuration discovery is needed to classify an invocation.

The classifier consumes each recognized option value once without interpreting it. A value equal to `generate-shell-completion` is never itself the command. Native path values need not be Unicode. The first non-option token, `--`, an unknown option, or an unsupported short cluster ends classification. UV workloads such as `uv --quiet run generate-shell-completion` and `uv --offline tool run generate-shell-completion` retain ordinary routing. The existing leading-only `uvx --generate-shell-completion ...` rule is unchanged.

Recognized completion invocations use the existing direct delegation before Dev Cache configuration loading, root preparation, workspace discovery, leases, resource registration or maintenance. The original argv, environment and streams are retained, including options after the completion command. UV remains responsible for invalid option values, shell selectors and exit status. Recognizing `--help` or `--version` does not reinterpret their native precedence. This is a cache-work classification, not an authorization boundary.

Explicit `dev-cache exec`, ordinary UV routing and maintenance, and other tools' dispatch do not change. No dependencies, configuration keys, on-disk schemas, shell setup, releases or installed binaries change. Rolling back the source reverts prefixed completion to the previous routed behavior without state migration.

## Verification and acceptance

Linux verification used Rust/Cargo 1.99.1 and native UV 0.13.5. Baseline `f46e351` was built separately: prefixed completion failed with exit 10 under invalid Dev Cache configuration and exit 12 under an exclusive cache-root lock, while unprefixed completion and direct UV succeeded. The new test target failed four cases against that baseline and passed all five after the change. Independent source review found no actionable defects.

Native UV 0.13.5 grammar checks passed independently of Dev Cache: six prefixes (`--quiet`, `--offline`, `-qn`, separate `--directory`, attached `--config-file` and `--color=never`) produced identical stdout, stderr and status to unprefixed generation for Bash, Zsh, Fish, PowerShell, Elvish and Nushell. Missing and invalid shells retained native exit 2 and identical diagnostics; no native cache directory was created. These 38 comparisons do not test the Dev Cache intercept.

`completion_intercept.rs` covers recognized long options, separate/attached values, short clusters, mixed prefixes, non-Unicode paths, normalized executable names, and adjacent workload/unknown-grammar cases. Hermetic Unix executable tests use synthetic providers to check exact NUL-delimited argv, stdout, stderr and success/failure exit status under invalid configuration and a held exclusive root lease. Cache snapshots include directory modification times to catch temporary create/delete effects. Negative controls require ordinary workloads to encounter invalid configuration or the exclusive lease.

The built intercept passed 54 exact stdout/stderr/status comparisons with native UV across the six shells, invalid/missing shell selectors and the retained UVX form, under invalid Dev Cache configuration and an exclusively held root lock. Kernel inotify watches on the private configuration and every existing cache directory/file reported no open, access or mutation events during completion; complete cache snapshots were unchanged. Baseline controls generated events. This detects payload reads and directory scans, not metadata-only stat calls. Five adjacent workload/unknown-grammar controls still encountered the exclusive lock. After its release, a real offline `uv run` retained its managed cache environment, resource registration and automatic-maintenance record.

`cargo build -p dev-cache --locked -j 2`, `cargo fmt -p dev-cache -- --check` and `cargo clippy -p dev-cache --all-targets --locked -j 2 -- -D warnings` passed. The product suite passed 217 tests with three explicitly excluded environment-dependent checks and two pre-existing ignored tests. An unfiltered run is not a full pass: the environment prohibits ptrace for `compiler_probe_does_not_scan_unrelated_cache_tree_when_strace_is_available` and `interval_skipped_maintenance_without_size_cap_does_not_scan_cache_tree`, and Unix-domain socket binding for `stable_preview_and_apply_reject_before_any_provider_connection`. Those existing checks remain outstanding; no security setting was changed to enable them.

Signed release, managed installation and non-Linux runtime qualification remain separate and unperformed.
