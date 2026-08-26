# update-all

`update-all` discovers supported update authorities, validates one deterministic plan, and records runtime events in an append-only `events.jsonl` journal before delivering them to the dashboard. Public built-ins cover broadly useful system and language managers. Private or machine-local behavior belongs in external catalogs.

The supported task selectors are `--only` and `--exclude`. Task presentation is grouped by function while logs and results retain each child task identity.

Prompt request, answer, and cancellation events are explicit journal records; answer text is never persisted. If the frontend disconnects, the engine records `frontend_detached` and continues with complete plain output. If the authoritative journal cannot be written, the engine cancels pending and running work and exits unsuccessfully.

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
