# update-all

`update-all` discovers supported update authorities, validates one deterministic plan, and records task outcomes in an append-only run journal. Public built-ins cover broadly useful system and language managers. Private or machine-local behavior belongs in external catalogs.

The supported task selectors are `--only` and `--exclude`. Task presentation is grouped by function while logs and results retain each child task identity.

Outcome values are `updated`, `no_op`, `not_applicable`, `deferred`, `failed`, `blocked`, and `cancelled`. Exit status `0` means clean completion, `1` task failures, `2` deferrals only, `3` an invalid plan or cancelled required prompt, and `4` updater integrity failure.

Authenticated product operations share one interface:

```text
update-all product install dev-cache
update-all product status dev-cache --json
update-all product check dev-cache
update-all product update-if-installed dev-cache --json
update-all product rollback dev-cache
```

The supported product values are `update-all`, `dev-cache`, `sync-configs`, and `skills-sync`. The existing `update-all self ...` commands are the direct self-management surface for the updater itself.
