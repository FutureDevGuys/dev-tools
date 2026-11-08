---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0048: Unattended restart after finalized task outcomes

status: proposed
verification: pending

## Context

An explicit post-update restart is intended to finish unattended. ADR 0036 withheld restart after task failures, deferrals, warnings, and skipped tasks, and required manual dashboard dismissal. A single unrelated updater failure or unanswered dashboard therefore prevented the operator's requested restart after all task processes had settled.

## Decision

Supersede ADR 0036's clean-run and dashboard-dismissal requirements. The explicit `--restart-after` flag and its `--reboot` alias request one non-forced OS restart after the scheduler settles its work, the frontend restores the terminal, and run evidence is durably finalized. Task failures, deferrals, warnings, and intentional skips do not veto restart. A nonempty all-skipped task run is eligible. The dashboard closes automatically for this invocation without changing the operator's persistent dashboard preference.

The restart request does not turn failed or deferred updates into successful updates: saved task/run results and the task-run process exit category remain intact when the OS accepts the request. A denied or uncertain restart request is an invocation failure and remains separately recorded in `restart.json`.

Explicit global or per-task cancellation controls still veto restart. Task results marked canceled by dependency failure or fail-fast are settled outcomes and do not veto restart; the admitted operator cancellation events retain that distinction independently of task-result counts. Empty selections, invalid plans, startup failures before task execution, failed evidence publication, and failed evidence sync do not request restart. Restart must reacquire the shared run-root task admission lock and retain it through the OS request and receipt writes. A concurrent updater is neither canceled nor restarted out from under its work.

Retain ADR 0036's native OS adapters, no-prompt authority boundary, inhibitor checks, no-force arguments, no automatic retries, separate receipt, and compile-time harmless test backend. Restart remains opt-in per invocation, unavailable to maintenance subcommands, and independent of persistent configuration. Native system policy may still deny a request. This change neither acquires new restart privilege nor guarantees the OS completes a reboot.

## Invariants

- Finalized failed, deferred, warning-bearing, and all-skipped task runs can request restart exactly once.
- Update failure and deferral remain visible after an accepted restart request.
- No human dashboard dismissal is required when restart is selected.
- Cancellation, startup failure, empty selection, and evidence failure prevent restart.
- Every task process settles and the terminal is restored before the request.
- The same-root admission lock excludes other task runs through the request.
- OS permission, inhibitor, no-force, no-retry, and no-replay boundaries remain unchanged.
- Automated tests cannot issue native restart requests.

## Rejected alternatives

Adding another flag for restart after failure would leave the ordinary unattended restart flag unable to complete its purpose. Suppressing update errors after an accepted restart would hide partial updates. Requiring dashboard dismissal would retain a human dependency after work finishes. Restarting after an explicit cancellation would ignore the operator's stop request. Force, policy changes, and automatic authorization are unnecessary to correct task-outcome gating.

## Consequences and known limitations

An operator selecting restart must save work before invocation, even when an updater is expected to fail or defer. Interactive updater commands may still need input during their tasks; this change removes the end-of-run dashboard wait and does not invent answers to vendor prompts. Existing OS policy and application inhibitors may refuse restart. Native adapter acceptance remains pending; harmless lifecycle qualification does not establish a completed physical reboot.

## Verification

- `restart_eligibility_requires_finalized_uncanceled_task_evidence`
- `restart_eligibility_preserves_explicit_operator_cancellation`
- `restart_after_requests_once_only_after_successful_persisted_terminalization`
- `restart_after_preserves_failed_deferred_and_warning_task_outcomes`
- `restart_after_requests_after_dependency_and_fail_fast_cancellations`
- `restart_after_closes_dashboard_without_input_and_restores_terminal`
- `restart_after_requests_after_all_skipped_tasks`
- `restart_after_suppresses_canceled_subprocess_runs`
- `restart_after_suppresses_failed_startup_authentication`
- `restart_after_suppresses_failed_evidence_persistence`
- `restart_after_suppresses_failed_pre_request_evidence_sync`
- `restart_refuses_when_another_task_run_owns_admission`

## Runtime acceptance

Run the real CLI against disposable catalogs and private state with the compile-time harmless restart backend in both scheduler modes. Cover failed, deferred, warning-bearing, all-skipped, canceled, empty, invalid, and persistence-failure runs. Inspect exactly one marker after finalized task/run evidence, preserving original exit categories. Use real PTYs without sending dismissal input to verify dashboard auto-exit and terminal restoration before the marker. Keep native OS restart acceptance separate on an explicitly authorized disposable machine; no native reboot is performed for this change.

## Supersession conditions

Supersede if restart gains new privilege authority, automatic retry, forced closure, configuration-based activation, additional OS adapters, or different cancellation semantics.
