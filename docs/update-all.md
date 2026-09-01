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

Managed completion publication is split from shell ownership. `update-all completion <shell>` emits the tool's trusted self-completion for Bash, Zsh, Fish, Elvish, or PowerShell. Both ordinary task-backed refreshes and `update-all completions sync` publish immutable managed completion snapshots under the same public root selected by `--managed-root` for the direct command, then `UPDATE_ALL_COMPLETION_ROOT`, then the platform default (`$XDG_DATA_HOME/update-all/completions` with the standard Unix fallback, or `%LOCALAPPDATA%\update-all\completions` on Windows). `update-all completions init <shell>` is read-only and prints shell code that sources a validated active snapshot for that shell, while `update-all completions status [--json]` inspects that same validated state and fails closed when a referenced view is missing or changed. A repeated sync is a mutation-free no-op only while the active snapshot remains healthy; otherwise it repairs the snapshot from the generated payloads and reports the repair. Shell startup files remain owned by the consumer. The `completions install` command and sync's `--apply` flag are explicit one-release compatibility wiring for Zsh and PowerShell only; they do not define the public startup contract.
