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
