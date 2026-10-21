---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0033: Mandatory task-run evidence and shared scheduling

status: proposed
verification: pending

## Context

A default run could continue after journal creation failed and thereby also omit its task-run lock. Selector, plan, lock, and privilege preparation failures could leave a controlled exit recorded as running. The synchronous plain engine had a separate execution loop that bypassed health dependency and fail-fast semantics.

## Decision

Task execution requires a writable authoritative journal and the existing per-run-root task lock before privilege preparation or task execution. The configured logging root remains the lock namespace; distinct explicit roots remain distinct namespaces. Journal admission failure is terminal and directs the operator to an explicit writable logging root, not an implicit fallback.

One lifecycle owner finalizes every controlled return after log creation, preserving observed task results, executing-build identity and task timing. The execution boundary is recorded as tasks_completed; the final invocation boundary is recorded once as run_completed. Metadata remains nonterminal while a completed dashboard still owns its files, preventing another invocation from pruning it. Frontend shutdown does not depend on a working journal. Terminal process outcome is explicit: invalid-plan exit 3 is failure, not user cancellation. Full evidence persistence failure makes the invocation non-clean, without erasing task effects or authorizing replay. Retention runs after controlled terminalization and retains uncertain historical runs.

Both engine selections use the dependency-aware scheduler. Sync selects one active task and retains its reported engine identity and plain output. This restores ADR 0001's distinction between ordering and health; skipped tasks honor explicit blocking evidence while harmless nonapplicable skips remain healthy.

This decision replaces only ADR 0014's non-fatal logging-initialization contract. Its retention limits, protected directories, ownership, nonfatal pruning and treatment of crashed records remain in force. ADRs 0003, 0026, 0027, 0028 and 0032 retain their evidence, no-replay, cancellation and provenance contracts.

## Invariants

- A failed journal admission cannot launch tasks or request elevation.
- No public task-run entry point can omit journal and lock admission.
- The lock is retained until owned execution settles and terminal task evidence is attempted, not while a completed dashboard waits indefinitely.
- Every controlled exit has explicit terminal status, exit code and bounded reason when storage permits; unstarted selections remain identifiable.
- Persistence failure never claims that a protected effect did not happen.
- Sync and async share dependency and fail-fast behavior; engine labels remain truthful.
- Retention does not relabel uncertain or crashed records or infer ownership from a PID.

## Rejected alternatives

Continuing without logs loses both diagnosis and exclusion. Moving the lock to an implicit host-wide path changes configured-root compatibility. A second synchronous scheduler duplicates the semantics that already diverged. An empty fallback artifact must not replace completed task evidence.

## Consequences and known limitations

Previously tolerated unwritable log roots now require configuration repair. This is deliberate fail-closed admission, not permission to change host filesystem policy. Controlled finalization cannot guarantee evidence after SIGKILL, power loss, or storage failure. Synthetic fixtures and ordinary tests do not establish native platform support or installed-release acceptance.

## Verification

- `task_run_requires_writable_journal_before_any_effect`
- `sync_and_async_share_health_dependencies_and_fail_fast`
- `invalid_selector_and_jobs_terminalize_created_run_once`
- `task_run_lock_uses_shared_run_root_and_releases_on_drop`
- `run_artifact_records_task_end_and_ui_wait_timing`
- `structured_failure_evidence_is_bounded_while_task_log_retains_full_output`
- `two_processes_share_mandatory_task_lock_until_owned_execution_settles`
- `sync_cancellation_settles_tasks_finalizes_evidence_and_releases_lock`
- `final_artifact_failure_returns_error_without_losing_observed_task_result`
- `finalization_retains_failure_facts_when_run_is_canceled`
- `finalizing_run_is_protected_from_another_runs_retention`
- `dashboard_transport_shutdown_wakes_frontend_after_journal_failure`
- `completion_progress_write_failure_latches_evidence_admission_failure`
- `persistence_failure_latches_without_producer_terminal_output`
- `general_enospc_stops_admission_settles_processes_and_restores_terminal`

## Runtime acceptance

Use disposable catalogs, state roots and harmless marker commands. Confirm no effects or elevation after journal admission failure, mutual exclusion in two concurrent processes, dependency and fail-fast parity in sync/plain and async/plain with one and multiple workers, and terminal metadata/artifact/journal agreement after invalid selectors, invalid jobs, lock contention, failed privilege preparation, success, failure and cancellation. Inject mid-run journal and final-artifact failures and preserve observed effects without replay. Retain active, crashed, malformed and unowned history. The original default cloud and desktop baseline invocations remain separate evidence and are not repeated.

## Supersession conditions

Supersede this decision if lock namespaces, lifecycle ownership, task-run outcome conventions or the shared scheduler contract materially change.
