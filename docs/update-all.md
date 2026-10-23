# update-all

`update-all` discovers supported update authorities, validates one deterministic plan, and records runtime events in an append-only `events.jsonl` journal before delivering them to the dashboard. Public built-ins cover broadly useful system and language managers. Private or machine-local behavior belongs in external catalogs.

The supported task selectors are `--only` and `--exclude`. Select a task by its exact qualified ID, such as `builtin/npm`, `managed/desktop-refresh`, or `local/workspace-index`, or select a functional category. Task presentation is grouped by function while logs and results retain each child task identity.

Configuration reads select `--config PATH` first, then a nonempty
`UPDATE_ALL_CONFIG` path. An explicit path must identify a regular file; missing,
unreadable, malformed or invalid explicit configurations fail instead of falling
back to another configuration or runtime defaults. Symlinks to regular files and
paths relative to the invocation's working directory remain supported. Paths are
not trimmed: whitespace and native non-Unicode filenames remain literal paths.
Only an unset or exactly empty `UPDATE_ALL_CONFIG` enables ordinary discovery:
on Unix, `$XDG_CONFIG_HOME/update-all/config.toml`, then
`$HOME/.config/update-all/config.toml`; on Windows, the existing roaming
configuration root's `update-all/config.toml`. If discovery finds no file, runtime
defaults remain unchanged. A rejected task startup exits 3 before tasks, elevation
or run-log creation, so no run artifact is expected. Configuration-writing
commands such as `config init --path PATH` can still create an absent target.
See [ADR 0042](../crates/update-all/docs/adr/0042-explicit-configuration-read-selection.md).

Task policies are complete `[tasks.<key>]` tables, not field-by-field overrides.
A table replaces the fallback policy for that key, including built-in keys.
Omitted fields become `timeout_secs = 60`, `retries = 0`, and
`retry_backoff_secs = 0`. A table containing only `retries` therefore selects a
60-second timeout rather than retaining the built-in timeout.

For `pipx_upgrade`, the complete table takes precedence over
`UPDATE_ALL_PIPX_UPGRADE_TIMEOUT_SECS`. That environment variable supplies the
fallback only when the table is absent; the built-in fallback is 180 seconds.
This complete example retains that built-in timeout and disables configured
additional attempts. When editing an existing policy, retain its custom timeout
unless the timeout change is intentional.

```toml
[tasks.pipx_upgrade]
timeout_secs = 180
retries = 0
retry_backoff_secs = 0
```

`timeout_secs` bounds one command attempt. For `pipx upgrade-all`, the bound
covers the whole batch, not each package. `retries` allows additional attempts
only for eligible non-timeout failures. Update All never retries a command
timeout, even when `retries` is nonzero or partial output contains a network
error. [ADR 0026](../crates/update-all/docs/adr/0026-command-output-fidelity-and-bounded-diagnostics.md)
records the timeout and replay boundary. The
[configuration example](../crates/update-all/config.example.toml) lists complete
built-in policy tables.

Prompt request, answer, and cancellation events are explicit journal records keyed by task and request generation; answer text is never persisted. One request generation accepts one answer and cannot be submitted again. Other tasks' waiting prompts queue without replacing the active draft; after submission, the dashboard shows the next waiting request or a submitted notice while execution retains request authority. Help, rename and search keep input until visibly closed. Printable letters, including `g/G/k/K/q/Q`, are ordinary answer text; `Ctrl+C` requests cancel-all before or after submission. Interactive transcript, status, and wrapper filenames use the same flat safe encoding as other task artifacts, so qualified task IDs never create nested artifact paths. If the frontend disconnects, the engine records `frontend_detached` and continues with complete plain output. If the authoritative journal cannot be written, the engine cancels pending and running work and exits unsuccessfully.

Every task-scoped `log_line` record carries the task's exact qualified ID. Run-wide records have a null `task_id`, remain in the global pane and `run.log`, and never create a task-log artifact. The selected task pane replays all retained journal-delivered records for that ID, including records received before task registration.

Dashboard log retention is a display window: `logging.max_in_memory_lines` applies separately to each task and to the combined global pane. A global line can therefore be evicted while remaining in its task pane. Pane titles show older-line counts even while following the tail, and `m` opens the complete persisted log. Progress updates can be coalesced, but warning, error, and ordinary package messages remain distinct. Multiline messages retain individual logical lines in both the journal and dashboard.

The queued display backlog is also capped at `logging.max_in_memory_lines` records and 8 MiB. Under sustained output, older display records are omitted with per-task/global counts after their full evidence has been persisted. Current task/input/prompt state is coalesced by admitted task and generation; lifecycle and suspend/resume controls remain lossless. Each frame ingests at most `ui.max_events_per_frame` events, keeping rendering and cancellation responsive. Wrapped log scrolling and search use visual rows, not record counts. Search text/errors receive footer space before optional shortcuts, and help has its own arrow, page, Home/End and wheel scrolling. See [ADR 0035](../crates/update-all/docs/adr/0035-owned-dashboard-input-and-bounded-display.md).

Explicit warning and error syntax is classified consistently on stdout and stderr. Diagnostic summaries keep bounded samples, prioritize errors, and identify omitted occurrences with a complete-task-log reference. Messages remain visible at the default report verbosity, and later errors upgrade an existing warning advisory. Machine-readable npm and completion-provider observations read stdout independently of stderr. Planned npm updates verify installed versions, manifests and declared executable health before reporting success; isolated recovery exposes warnings without persisting script permissions. Script authorization requires a successful, unambiguous registry manifest for every observed closure member; unavailable, malformed, ambiguous and non-registry metadata stop that recovery. See [ADR 0026](../crates/update-all/docs/adr/0026-command-output-fidelity-and-bounded-diagnostics.md).

Task runs require a writable authoritative journal and a run-root task lock before requesting elevation or starting any task. If initialization fails, configure an explicit writable absolute `[logging].run_dir` or absolute `XDG_STATE_HOME`; Update All does not silently fall back to an unlogged run. The lock is shared by runs using the same configured root and is released only after tasks settle and task-result persistence is attempted, before a completed dashboard waits for dismissal. Different explicitly configured roots remain separate lock namespaces.

Controlled exits after journal creation, including invalid selections, invalid jobs, lock contention and failed privilege preparation, record terminal metadata, an artifact and one `run_completed` event whenever storage remains writable. `tasks_completed` identifies the earlier execution/dashboard-completion boundary. Finalization preserves completed task results, executing-build identity and task timing; rejected selections not started are listed separately. A terminal evidence write failure is non-clean and never means previously attempted tasks had no effects. An invalid-plan exit 3 is recorded as failure, not cancellation. Sync and async selections share dependency and fail-fast semantics; sync uses one worker and retains its own engine label.

Run artifacts are owner-only diagnostic state. After every terminal run, Update All retains completed runs for at most 30 days, 100 runs, and 128 MiB by default; `[logging]` keys `retention_max_age_days`, `retention_max_runs`, and `retention_max_bytes` override those limits. The current run, active runs, malformed directories, symlinks, and directories without Update All metadata are never automatically removed. `update-all runs prune --dry-run` reports the exact bounded deletion set as JSON, and `update-all runs prune` applies it. Retention failures warn and leave the updater outcome unchanged. This maintenance changes only diagnostics and is not a package, catalog, completion, or task-state mutation.

Each new run records the executing image's common build-info document in its first `run_started` journal record and in `run.json`. The identity is captured once and survives final artifact rewrites after dashboard waiting. This does not capture runtime arguments, environment values, configuration contents or hashes, or executable paths. Older runs without this field retain unknown build provenance; the currently installed version is not evidence of which image produced them. Build self-description does not authenticate a release. See [ADR 0032](../crates/update-all/docs/adr/0032-executing-build-run-provenance.md).

`update-all build-info --json` emits the common checkout-independent `dev-tools-build-info-v1` document without loading configuration, release state, task catalogs, or network machinery. The hidden `--build-info` form remains for rollback to the pre-standard 0.1 line and is removed in the next minor release after one accepted release has shipped the standard subcommand.

Catalog relationships distinguish capability health from ordering. `depends_on`
and `depends_on_selected` require healthy predecessors. `after` and
`after_selected` wait only for terminal outcomes, so a final reconciliation task
can still run after an earlier failure. The corresponding `*_exclude` fields
remove exact task IDs only from generated selected-task relationships; explicit
relationships remain authoritative. Unknown IDs and cycles fail validation.

In the unreleased runner correction, a command's configured timeout covers its
direct-child wait and owned output/input settlement. A child that exits while a
descendant retains captured pipes cannot extend that deadline indefinitely.
Timeout cleanup keeps partial output, settles the owned process group, and then
releases task resources; it does not authorize replay or classify the underlying
cause as a network failure. See [ADR 0026](../crates/update-all/docs/adr/0026-command-output-fidelity-and-bounded-diagnostics.md).

Privilege admission is configured by `[updaters].privilege_mode`; the default remains `prompt_tty`. Existing aliases remain valid:

- `prompt_tty` / `prompt`: native prompting in interactive terminals, with existing startup preflight, keepalive and task-terminal authentication. Noninteractive runs require usable cached sudo authority.
- `skip` / `best_effort_skip` / `never`: deliberately exclude elevated tasks without discovering or invoking sudo, while leaving user-scope work enabled. These exclusions alone keep the clean-skip exit convention. Health dependents cannot consume the missing capability.
- `fail` / `fail_run`: refuse elevated tasks unconditionally, preserving the existing task-failure policy. This is not `required`.
- `auto`: explicitly opt into already-authorized, noninteractive Linux elevation. Each direct elevated launch uses native `sudo -n --` with exact argv. A bounded `sudo -n -v` admission checks available authority; missing sudo, unavailable authority or pre-launch expiry defers affected tasks and their health dependents while independent and ordering-only work continues. Failed admission is latched for the run, with no password fallback, repeated authentication requests, background keepalive or protected-command replay. Tasks declaring `needs_sudo_session` defer as unsupported because the runner cannot guarantee a nested manager will not prompt. Non-Linux auto elevation also defers rather than inferring platform authority from Unix sudo discovery.
- `required`: when a selected task needs elevation, usable elevation is a run prerequisite before any task starts. Interactive runs use native authentication; noninteractive runs use bounded noninteractive admission and fail instead of prompting. A selection containing only user-scope work requires no sudo. Unsupported platform admission fails explicitly. Successful preflight does not guarantee authority in a later task terminal. A failed direct protected invocation remains failed without launch-time interactive refresh or automatic replay.

Auto deferral is a skipped, unstarted task with an explicit blocking advisory and fixed privilege reason code in persisted artifacts. Deferrals produce task-run exit 2 unless failure or cancellation takes precedence. An elevated invocation that has already begun retains its actual failure, timeout or execution-owned cancellation, including failure after partial effects; it is never reclassified as a harmless deferral or automatically replayed. No mode installs sudo, changes sudoers or credential policy, or grants authority. The new modes are source-level behavior pending native qualification; synthetic sudo fixtures do not establish native policy support. See [ADR 0034](../crates/update-all/docs/adr/0034-compatible-privilege-fallback-modes.md).

Outcome values are `updated`, `no_op`, `not_applicable`, `deferred`, `failed`, `blocked`, and `cancelled`. Exit status `0` means clean completion, `1` task failures, `2` deferrals only, `3` an invalid plan or cancelled required prompt, and `4` updater integrity failure.

Authenticated product operations share one interface:

```text
update-all product install dev-cache
update-all product status dev-cache --json
update-all product check dev-cache
update-all product update-if-installed dev-cache --json
update-all product rollback dev-cache
update-all product retain dev-cache --root-document /absolute/current-root.json --manifest /absolute/historical-manifest.json --artifact /absolute/dev-cache --json
```

The unreleased `product retain` operation is always offline. It explicitly owns
an authenticated historical executable without activation, ledger/trust/cache
changes or new rollback eligibility. Its current accepted root, strict custody,
durable recovery and normal-cleanup protection contract is documented in
[offline bundles](update-all-offline-bundles.md#retain-a-historical-artifact-without-activation).

If GitHub's release list temporarily omits the root or manifest assets for the newest stable product tag while the canonical downloads exist, Update All uses only those fixed canonical URLs and still authenticates the downloaded bytes before reporting a release or changing an installation. Duplicate named assets and missing downloads remain failures; it never silently selects an older version. [ADR 0024](../crates/update-all/docs/adr/0024-canonical-release-assets-after-incomplete-index.md) owns this bounded discovery fallback.

The supported product values are `update-all`, `dev-cache`, `sync-configs`, and `skills-sync`. The existing `update-all self ...` commands are the direct self-management surface for the updater itself.

The unreleased common-interface migration supplies `update-all update status`, `check`, `install [--offline]`, `apply [--offline]` and `rollback`, each with optional `--json`, on Linux. Status is local-only; check refreshes source-bound signed metadata without downloading payloads, initializing or repairing installations. Pending recovery remains unknown to observation and blocks check. Explicit mutation authenticates original retained proofs before recovery and uses the existing journaled v2 installation authority. Online payload preparation occurs only when a newer authenticated artifact is needed; offline requests use local authenticated evidence and bytes only. A version-satisfied no-op needs no retained payload. Rollback is network-free and selects only the receipt-owned previous version.

Common commands emit `dev-tools-operation-result-v2` with matching common exits, nullable durable change and a fresh read-only post-mutation installed identity. Cache evidence older than 24 hours or dated in the future cannot report current. Independent accepted history cannot be reset by cache loss, and initialized authority cannot be recreated from installed bytes. Legacy self/product commands for Update All share this transaction while preserving their established completed-result surface. Ordinary startup has no hidden release check or activation; the old `install.auto_update` field remains readable but both `true` and `false` are inert. Native acceptance and non-Linux mutation remain pending; this source is not a full-conformance claim. See [ADR 0030](../crates/update-all/docs/adr/0030-common-managed-update-lifecycle.md).

An ordinary task run can still update managed products through four visible catalog tasks: `builtin/dev-tools-update-all`, `builtin/dev-tools-dev-cache`, `builtin/dev-tools-sync-configs`, and `builtin/dev-tools-skills-sync`. They are detected when `update-all` is on PATH and, when selected, invoke `update-all product update-if-installed <product> --json`. These commands can check releases and activate updates for installed managed products; absent products remain absent and externally managed commands are not overwritten. They are controlled by `--only`, `--exclude`, and `[updaters]` selection, not by `install.auto_update`. For example, `--exclude builtin/dev-tools-update-all,builtin/dev-tools-dev-cache,builtin/dev-tools-sync-configs,builtin/dev-tools-skills-sync` omits all four; `run_all_detected = false` omits automatic selection but still permits explicit includes and `--only`. With none selected there is no separate startup updater. Direct `update`, `self`, and `product` subcommands remain available independently of the ordinary task plan.

Use Update All 0.1.8 or later as the source-bound release seed. The published 0.1.6 binary still has a v1-only online reader and cannot install shared-v2 releases; 0.1.7 corrects that reader but does not create private product-root ancestors during a fresh install under the default `022` umask. Their published bytes are immutable. The successor creates new state-directory ancestors privately, authenticates shared-v2 metadata on its actual download path, preserves source identity and rejects online schema downgrade for Update All, Dev Cache and Sync Configs. Exact Skills Sync 0.1.4 generation 5 remains a bounded online migration exception until that product's source-bound successor ships. This reader policy does not alter receipt-owned rollback or permit an accepted version to acquire different bytes.

Managed completion publication is split from shell ownership. `update-all completion <shell>` emits the tool's trusted self-completion for Bash, Zsh, Fish, Elvish, or PowerShell. Explicit `update-all completions sync` publishes one immutable snapshot containing Update All and every active provider binding for the selected shells under the public root selected by `--managed-root`, then `UPDATE_ALL_COMPLETION_ROOT`, then the platform default (`$XDG_DATA_HOME/update-all/completions` with the standard Unix fallback, or `%LOCALAPPDATA%\update-all\completions` on Windows). Ordinary task runs do not implicitly publish completions: the built-in catalog currently has no task that reaches the completion executor. A user-owned custom task can explicitly invoke sync. The default provider catalog and legacy audit registry live under the public root's cache, never under `RC_ROOT`; the absent default catalog behaves as a virtual empty catalog so a fresh machine can publish Update All's own completion without creating placeholder configuration. Repeat `--shell`, configure `completions.shells`, use `all` alone, or omit both to detect installed supported shells including the current shell. `update-all completions init <shell>` is strictly read-only and prints shell code that sources a validated active snapshot for that shell, while `update-all completions status [--json]` reports that snapshot's bindings, concise health and size metadata for prior snapshots, and any retained, unsupported, or failed candidate state. Provider inventories report complete, partial, or failed; only a complete inventory or explicit configured removal may retire a prior candidate. When multiple providers expose the same command, activation follows the exact executable resolved through PATH unless `completions.tools[].priority` explicitly overrides it, and non-winning candidates remain cached as `shadowed`. One managed-root lock covers inventory through activation. A repeated sync reuses an unchanged strong candidate identity without probing and is a mutation-free no-op while the active snapshot remains healthy; a changed identity with identical canonical behavior updates only identity memoization and reports `probed_unchanged`. Overall sync outcomes are `reused`, `probed_unchanged`, `published`, `retained_previous`, `unsupported`, `removed`, or `failed`.

Completion history is bounded without a daemon or separate cleanup authority. By default Update All protects the current snapshot, the three most recently activated prior snapshots, and every prior snapshot activated less than 24 hours ago; `[completions]` keys `retention_prior_snapshots` and `retention_min_age_hours` configure those floors. A dedicated activation-recency sidecar changes only when `current` changes, including when an old immutable snapshot becomes active again; a no-op never touches it, and stores created before this metadata use snapshot modification time until each snapshot is reactivated. Pruning runs only after a behavior-changing publication backed by complete, non-degraded provider inventories. It never runs for an unchanged or repaired snapshot, an identity-only `probed_unchanged` result, retained state, unsupported or failed generation, or incomplete inventory. Before deletion, Update All proves the exact owned snapshot shape, activation-recency records, and content-addressed object identities; malformed state defers the whole cleanup pass without mutation. A successful pass removes eligible old snapshots and unreferenced objects while retaining every object referenced by the current or protected history.

Native generation is authoritative and native-first for Bash, Zsh, Fish, Elvish, and PowerShell. The bounded planner tries provider-owned static artifacts, a remembered successful recipe for the same candidate and shell, declarative catalog recipes, versioned safe stdout protocols, help-evidenced protocols, and standard Click or Typer environment-source generation in that order. A valid registered native artifact ends probing; help is not run afterward to augment or replace it. Process recipes use the exact resolved executable and direct argv with closed stdin, controlled environment, output limits, per-probe timeout, total deadline, and an attempt budget. Catalog recipes cannot name install-completion mutation forms. Accepted bytes preserve shell-specific content except for UTF-8 BOM removal, line-ending normalization, and one terminal newline, and are recorded as static or dynamic. Provider-managed and explicit catalog sources may publish dynamic output; ambient dynamic output requires `completions.tools[].trust_dynamic = true`, and a rejection is a hard policy result rather than permission to silently use the help fallback.

Explicit sync also emits one final `UPDATE_ALL_RESULT` v1 footer after its requested sync, legacy installation and audit succeed. A custom task can declare `result_protocol = 1` to require it. The footer reports `updated`, `no_op`, `deferred`, or `failed` observations, with snapshot publication separate from candidate-shell refresh/unchanged counts and inventory coverage. Publishing the tool's own snapshot does not claim provider completions refreshed. Configured-only coverage and preservation of unrequested cached candidates are intentional scope, not deferral; genuinely incomplete requested inventory or retained requested work is deferred even when a snapshot was published. Failures take precedence. The footer contains no software-version fields, paths or raw diagnostics and stays within 512 bytes. Errors or observed cancellation suppress it; existing process exit behavior is unchanged. Other completion subcommands do not emit this footer.

Shell startup files remain owned by the consumer. The ordinary-run `--completions` and `--completion-provider` flags and corresponding environment settings remain parsed compatibility controls for the dormant task executor; the retained `refresh` default does not schedule publication. Use `update-all completions sync` for refresh. The old task-backed `refresh+audit` mode is still rejected because it depended on a Zsh script under `RC_ROOT`. The `completions install` command and sync's `--apply` flag are explicit one-release compatibility wiring for Zsh and PowerShell only; they require an explicit legacy root, never dual-publish to the public root, and do not define the public startup contract. Auditing through that bridge requires an exact absolute `--audit-command`; Update All never interprets an audit command string through a shell. There is no implicit `.shellrc.d` output path.
