# update-all catalogs

External catalogs extend `update-all` without recompilation. Embedded public tasks use the `builtin/` namespace; managed private catalogs should use an owner namespace; current-user catalogs should use `local/`. Fully qualified task IDs must be unique and no source overrides another.

Catalog origin does not create a dashboard section. Functional category controls presentation: System Packages, Developer Tools, Agent Tooling, Mobile & Reverse Engineering, Game Development, and Maintenance.

Catalog validation covers schema and namespaces, engine and adapter protocol compatibility, dependencies and ordering, resource locks, authority claims, elevation, interactivity, result protocol, and reporting.

## Neutral example

Reference the catalog from `config.toml`:

```toml
[updaters]
catalogs = ["catalogs/workspace.toml"]
```

Then define the task in `catalogs/workspace.toml`:

```toml
schema_version = 1
engine_api = 1
adapter_api = 1

[tasks."local/workspace-index"]
label = "Workspace Index"
command = "workspace-index"
args = ["refresh"]
detect_mode = "command_available"
category = "maintenance"
resource_locks = ["workspace-index"]
authority = "workspace-index-owner"
result_protocol = 1
requires_elevation = false
interactive = false
```

Catalog protocol fields default to version 1 when omitted; explicitly unsupported schema, engine, adapter, or result protocol versions fail before planning. Every immediate `catalog.d/<owner>/` directory defines its own lowercase ASCII owner namespace, and tasks discovered below it must use `<owner>/` task IDs. Explicit catalog paths may use another owner namespace, but duplicate fully qualified IDs and duplicate non-empty authority claims are always invalid.

`resource_locks` names mutable authorities that must not run concurrently. Locks affect scheduling without changing dashboard grouping. A task that declares `result_protocol = 1` must finish with one line of the form `UPDATE_ALL_RESULT {"outcome":"updated","detail":"...","current":"...","latest":"..."}`. The supported outcomes are `updated`, `no_op`, `not_applicable`, `deferred`, `failed`, `blocked`, and `cancelled`; answer values and secrets must not appear in the payload.

## Operation observations

`report_parser = "operation_result"` explicitly selects a JSON operation report.
It accepts the shared `dev-tools-operation-result-v2` document or the legacy
activation document with `product`, `version`, `changed`, `managed`, and `outcome`.
The subject is the reported product string. The parser has no product-specific
branches and does not inspect arbitrary JSON from tasks without this setting.

The parser accepts one leading JSON document and trailing non-JSON process logs,
including ordinary or bracketed progress from stderr. An additional parseable
JSON object or array at the start of a trailing line is rejected, including a
multiline document. Diagnostic extraction remains separate. Its captured input
limit is 16 KiB. Missing, malformed, unsupported, or multiple documents fail the
selected task. A failed process remains failed even when its document retains
observed effects. These are producer observations, not independent verification
of the producer's claims.

Required-result validity comes from the selected parser before report patterns
or state reports are merged. A pattern cannot satisfy that requirement merely
by naming its section `operation_results`. Shared-v2 product IDs, operation names,
outcomes, and exit codes must belong to the published protocol domains; additive
fields are allowed. Legacy subject strings and outcomes retain their compatibility.

The shared result's `installed_version` is a post-operation observation.
`available_version` remains an available target in notes, never an installed
after-version. `changed` distinguishes reported change, no reported change, and
unknown progress. The operation defines the change's scope. A clean `no_op` does not establish
that an installed version is current. The legacy `version` field supplies only
the reported installed identity. No before-version is inferred from it.

The existing `UPDATE_ALL_RESULT` v1 payload is unchanged. Its declared outcome
now contributes an operation row. A deferred result keeps its installed and
available versions distinct and does not claim a completed update.

Report patterns also accept `deferred` and `unconfirmed`. Both identify unresolved
selected work without changing task lifecycle or adding a dependency-health
gate. `blocked` and `failed` retain their existing health behavior. After a
timeout, known inventory entries without a post-operation observation are
unconfirmed. Update All does not run extra probes, increase the timeout, or
replay a command to fill that gap.

New explicit deferred or unconfirmed results select the existing incomplete-run
outcome and stop later admission with `--fail-fast`. Without fail-fast, these
report values do not block ordering or health successors by themselves.
