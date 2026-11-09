---
authority: canonical
owner: dev-cache
---

# ADR 0123: Native completion intercept passthrough

status: proposed
verification: pending

## Context and decision

Shell startup may invoke native completion generators in the background. Treating these as ordinary routed workloads lets automatic maintenance run before or after completion output, acquire exclusive root coordination and delay unrelated routed work. Interval and action limits do not bound the preceding maintenance scans. The generator needs no managed cache resource.

The existing product-owned invocation dispatcher classifies the documented leading forms `uv generate-shell-completion ...` and `uvx --generate-shell-completion ...` as direct delegation. The existing passthrough resolves the original executable with its recursion checks and inherits native arguments, environment and streams without an output prefix. Dispatch precedes Dev Cache configuration loading, root preparation, repository discovery, resource registration, leases and automatic maintenance. Native argument validation and exit status remain the tool's responsibility, including an invalid or omitted shell selector.

Classification uses the existing normalized entrypoint inventory and the first native argument only. It does not search later arguments for completion-like words: `uv run generate-shell-completion`, `uvx generate-shell-completion`, and arguments after a tool name or `--` retain their existing dispatch. Other option placements and completion grammars are not claimed. Explicit `dev-cache exec` continues to request its selected adapter environment. This is a command-specific cache classification, not privilege authorization or an exemption from native tool safeguards.

[ADR 0143](0143-uv-completion-global-options.md) extends the UV root-command classification to recognized leading global options. It supersedes the first-argument-only restriction for `uv`, not the retained `uvx` grammar or any other boundary above.

Other workloads retain the existing pre/post automatic maintenance, activity and resource protections; explicit GC and compiler-intercept boundaries remain unchanged. No shell plugin, user configuration, private consumer, background supervisor, dependency or on-disk schema is introduced or changed. The common `dev-cache completion` renderer remains governed by ADR 0012.

The upstream native forms are documented in [UV's shell autocompletion instructions](https://docs.astral.sh/uv/getting-started/installation/#shell-autocompletion).

## Verification and acceptance

The original source-only change added both native forms, normalized executable spelling and adjacent workload arguments to the dispatch conformance case, without executing build, test, lint, CI or installed-binary acceptance at that time. Subsequent Linux build, test and native intercept evidence, including the original leading forms, is recorded in [ADR 0143](0143-uv-completion-global-options.md).

No signed release or managed installation is performed by this source change; the installed binary retains its previous behavior until qualified delivery. Native non-Linux qualification remains outstanding.
