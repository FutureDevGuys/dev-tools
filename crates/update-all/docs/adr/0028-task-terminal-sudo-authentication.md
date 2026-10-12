---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0028: Task-terminal sudo authentication

status: proposed
verification: pending

## Context

An interactive elevated task authenticated with a separate `sudo -v` inside a
captured terminal, then replaced its shell with `sudo -n`. Terminal-scoped
credentials from startup preflight need not apply to that terminal, and replacing
the shell changes the parent identity used by parent-scoped timestamp policies.
After a password timeout, refreshing on the foreground terminal and replaying in
a new captured terminal repeated the same unanswered authentication request.

## Decision

Interactive Unix elevation uses one native `sudo -- command args` invocation in
the existing task execution path. That process owns authentication and protected
command launch. Noninteractive elevation retains `sudo -n -- command args`.
Privilege-mode admission, startup preflight, keepalive, task input routing, log
capture and process ownership retain their existing contracts.

Sudo authentication diagnostics receive no automatic command-policy retry.
Password-read timeout is authentication failure, not transient network failure.
Interactive elevated commands do not automatically replay after any failure,
including a runner timeout or output-capture guard. They also bypass post-failure
package recovery/reconciliation that could rerun the protected command. A failed
child may already have made changes; the user reviews the log before explicitly
retrying the task and answering the task-terminal prompt.

## Invariants

- No shell authentication wrapper or second sudo process transfers authority.
- Run preflight does not promise authorization in every task terminal.
- No password, sudoers or timestamp policy is changed or persisted.
- Authentication failure remains failure; it cannot become success or cancellation.
- A sudo diagnostic or timeout after earlier command effects does not authorize replay.
- Existing argv boundaries, logs and typed cancellation remain intact.
- After prompt submission, existing cancel-one, cancel-all and quit controls
  remain available without submitting the answer again. Before submission,
  those characters remain ordinary masked input.

## Rejected alternatives

Refreshing the original terminal again cannot authorize a new terminal reliably.
Changing sudo timestamp policy widens authority. Moving the command to the real
foreground terminal requires separate exclusive terminal ownership, output
capture and privileged descendant cleanup acceptance, beyond this correction.

## Consequences and known limitations

An interactive task can still require its own password prompt despite successful
startup preflight. The dashboard's existing masked input and owned PTY remain in
use. Existing preflight and keepalive failure policy is unchanged. Explicit
noninteractive cached-session recovery remains separate. Diagnostic matching
limits retries; it does not prove which process emitted a message or whether a
protected command already ran. Native sudo policy and platform qualification is
still required.

## Verification

- `interactive_elevated_command_uses_one_sudo_process_without_auth_replay`
- `interactive_sudo_transcript_wrappers_do_not_replay_protected_effects`
- `sudo_session_tasks_launch_with_noninteractive_sudo_after_preflight`
- `sudo_authentication_failures_never_receive_automatic_retry_budget`
- `submitted_prompt_preserves_cancel_and_quit_controls_without_resubmission`
- `unsubmitted_prompt_keeps_cancel_control_characters_as_input`

## Runtime acceptance

The immediate Linux delivery sequence is superseded by [ADR 0029](0029-implementation-first-linux-sudo-delivery.md). The four-policy matrix below remains explicitly tracked follow-on coverage; no unrun lane is claimed as passed. The implementation and safety invariants in this record are unchanged.

Use an isolated catalog and controlled sudo executable to verify exact argv,
one authentication/launch attempt, task-terminal input, success and failure logs,
and no replay after a side-effecting command emits a sudo diagnostic. Exercise
password timeout with a nonzero configured retry budget and verify prompt/run
artifacts agree. Verify typed cancellation and owned-child cleanup during input
and command execution. Then qualify real sudo with a disposable harmless command
under terminal-scoped, parent-scoped, no-cache and NOPASSWD policies on each native
platform. Do not change the user's sudo policy or run system updates for testing.

## Supersession conditions

Supersede this record when a typed privilege executor replaces sudo or a separately
qualified native terminal owner changes authentication and command execution.
