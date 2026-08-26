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
[tasks."local/workspace-index"]
label = "Workspace Index"
command = "workspace-index"
args = ["refresh"]
detect_mode = "command_available"
category = "maintenance"
requires_elevation = false
interactive = false
```

The catalog contains only a top-level `tasks` table. Managed files discovered below `catalog.d/syscfg/` must use `syscfg/` task IDs, and files below `catalog.d/local/` must use `local/` task IDs. Explicit catalog paths may use another owner namespace, but duplicate fully qualified IDs are always invalid.
