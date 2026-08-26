# update-all

`update-all` discovers supported update authorities, validates one deterministic plan, and records runtime events in an append-only `events.jsonl` journal before delivering them to the dashboard. Public built-ins cover broadly useful system and language managers. Private or machine-local behavior belongs in external catalogs.

The supported task selectors are `--only` and `--exclude`. Select a task by its exact qualified ID, such as `builtin/npm`, `managed/desktop-refresh`, or `local/workspace-index`, or select a functional category. Task presentation is grouped by function while logs and results retain each child task identity.

Prompt request, answer, and cancellation events are explicit journal records keyed by task and request generation; answer text is never persisted. One request generation accepts one answer, remains visibly submitted while the command processes it, and closes only when the command cancels it or emits the next generation. Interactive transcript, status, and wrapper filenames use the same flat safe encoding as other task artifacts, so qualified task IDs never create nested artifact paths. If the frontend disconnects, the engine records `frontend_detached` and continues with complete plain output. If the authoritative journal cannot be written, the engine cancels pending and running work and exits unsuccessfully.

Every task-scoped `log_line` record carries the task's exact qualified ID. Run-wide records have a null `task_id`, remain in the global pane and `run.log`, and never create a task-log artifact. The selected task pane replays all retained journal-delivered records for that ID, including records received before task registration.

Catalog relationships distinguish capability health from ordering. `depends_on`
and `depends_on_selected` require healthy predecessors. `after` and
`after_selected` wait only for terminal outcomes, so a final reconciliation task
can still run after an earlier failure. The corresponding `*_exclude` fields
remove exact task IDs only from generated selected-task relationships; explicit
relationships remain authoritative. Unknown IDs and cycles fail validation.

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
