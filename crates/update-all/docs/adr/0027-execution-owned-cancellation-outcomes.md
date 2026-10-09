---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0027: Execution-owned cancellation outcomes

status: proposed
verification: pending

## Context

Ordinary command tasks converted typed cancellation into failure text before the scheduler could record the canceled outcome. Independently, normal UI cancellation directly signaled registered processes while the execution owner waited for their exit. The resulting signal exit could win the wait race and be mistaken for an ordinary command failure.

## Decision

Normal task and cancel-all controls publish cancellation requests. A request pending before a command attempt prevents that attempt from spawning, including after retry backoff. The execution owner observes the request, terminates and reaps its owned child or process group through the existing cleanup path, and returns typed cancellation. If an exit is already observable when cancellation is checked, preserve that status instead. Never infer cancellation solely from diagnostic wording, a nonzero status, or a later request flag.

The primary command, pre-command, sudo-refresh execution retry and transient lock/busy execution retry preserve typed cancellation before failure formatting and recovery selection. The scheduler retains its existing mapping to canceled task state. Cancel-all or a global cancellation selects run exit code 3; cancel-one preserves the existing overall run-exit rules. Completed sibling successes and genuine failures retain their outcomes.

After the direct child exits, ordinary pipe capture remains cancellation-aware while draining descendant output. A cancellation request still cleans the owned group but does not replace the already-observed direct-child status. The registration remains held until draining ends. Forced shutdown after the existing grace period retains its explicit direct-termination operation and existing outcome policy. Log messages distinguish a request from proven termination.

Completion presentation carries explicit cancellation and genuine-failure facts from the engine alongside the existing success flag. A canceled run has a yellow canceled header unless genuine task or journal failures require the failed header. Cancel-one keeps the existing overall completion presentation. The synthesized canceled-task attention row is a warning with a rerun suggestion; explicit error advisories and failed report rows keep their original severity. Exit codes and task outcomes are unchanged.

## Invariants

- The execution owner, not a competing normal UI signal, attributes ordinary command cancellation.
- An already-observed exit status remains authoritative.
- A cancellation request does not authorize signaling unrelated process groups or change process custody.
- Cancel-one remains responsive when an owned descendant retains output pipes after the direct child exits.
- Pager Ctrl-C dismissal remains separate from task cancellation.

## Rejected alternatives

Treating every nonzero exit after a request as canceled can hide genuine failures. Matching the word `cancelled` trusts arbitrary command output. Adding process-generation cancellation receipts is unnecessary when the existing execution owner can perform normal cleanup.

## Consequences and known limitations

Normal cancellation can take the existing wait polling interval to reach the execution owner. This does not redesign optional report-probe cancellation, authentication error caching, package-specific recovery, or transcript replay failure precedence. It does not add authority to terminate descendants outside an owned process group. Native non-Linux process and terminal acceptance remains separate.

## Verification

- `command_task_preserves_typed_cancellation_from_primary_and_pre_command`
- `command_task_does_not_infer_cancellation_from_failure_text`
- `command_task_preserves_typed_cancellation_from_transient_retry`
- `normal_cancellation_notifies_owner_and_forced_cleanup_still_terminates`
- `command_policy_pending_cancellation_does_not_spawn_new_work`
- `cancellation_does_not_replace_an_observed_process_exit`
- `cancellation_drain_keeps_exited_status_and_releases_descendant_pipes`
- `controlled_capture_cancel_terminates_descendants`
- `run_completion_header_preserves_cancellation_and_real_failures`
- `attention_required_distinguishes_cancellation_from_real_errors`
- `completion_event_retains_cancellation_and_failure_facts_in_journal`

## Runtime acceptance

Use a standalone source candidate and disposable catalogs. Verify cancel-all and cancel-one using the actual dashboard, without a pager and after returning from one. Task/run JSON, journal and dashboard must agree on canceled outcomes. Check pre-command and transient-retry cancellation; do not launch later work. Keep already-finished success and genuine failure outcomes in mixed runs. Exercise an active TERM-resistant descendant and a direct child that exits while a descendant retains its output pipes; cancel-one must finish cleanup without losing the direct child's actual outcome. Verify the existing forced-grace path. Inspect the actual final header and Needs Attention rows for a canceled-only run and a canceled run with genuine failures; journal completion facts, displayed labels and counters must agree without changing exit codes. Source checks do not establish signed-release or installed-successor acceptance.

## Supersession conditions

Supersede this record if process ownership is delegated to a supervisor with typed cancellation receipts, the task outcome model changes, or recovery/report stages acquire distinct cancellation outcomes.
