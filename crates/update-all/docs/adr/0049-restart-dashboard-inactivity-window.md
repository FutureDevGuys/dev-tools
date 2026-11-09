---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0049: Restart dashboard inactivity review window

status: proposed
verification: pending

## Context

Immediate dashboard closure in restart mode removed the operator's opportunity to review task results. The user requested a timed close that resets with user activity, suggesting three minutes. The countdown must remain unattended while allowing active review without a race against an older task-completion timestamp.

## Decision

Supersede ADR 0048's immediate dashboard closure with a 180-second inactivity review window, starting when the frontend receives task completion. Configure a positive integer `[ui].restart_idle_secs` or override it with `--restart-idle-secs SECONDS`, which requires `--restart-after` (including its `--reboot` alias). The window applies only to completed dashboards in restart mode. Plain output retains immediate post-finalization requests, and ordinary dashboards retain their existing persistence policy.

Keyboard presses and repeats, paste, and mouse interaction in the dashboard restart its countdown. Output, resize events, and passive focus changes do not count as activity. A compact countdown identifies the pending restart. `q` dismisses early and proceeds; `Ctrl+C` cancels restart, including when received as the frontend closes. Canceled task runs do not wait through a misleading restart countdown. Preserve ordinary dashboard configuration rather than persisting the invocation's restart review policy.

Retain task-outcome-independent restart, explicit cancellation vetoes, task settlement, terminal teardown, durable evidence, exclusive restart admission, and the native no-force/no-retry restart boundary. The idle window does not acquire privileges, answer vendor prompts, track desktop-wide activity, or create a background restart schedule.

## Invariants

- No countdown elapses while tasks are running.
- Dashboard activity grants a fresh complete review interval.
- Output and terminal resize cannot keep an unattended dashboard open forever.
- Task failures and deferrals retain their original outcomes and do not veto countdown completion.
- Cancellation received during review prevents any OS request.
- Ordinary dashboard and plain-output behavior remain as specified above.
- Automated verification cannot issue a native restart.

## Rejected alternatives

An absolute three-minute deadline can close the dashboard while the operator is reading or navigating. Counting logs as activity can prevent unattended completion. Desktop-wide input observation introduces an unrelated global integration and privacy surface. Persistently disabling dashboard review for restart runs changes ordinary invocations. A new background timer would outlive the task and complicate cancellation and evidence ownership.

## Consequences and known limitations

An idle completed dashboard delays restart by three minutes by default, even when ordinary persistence is disabled. Active dashboard review may delay it indefinitely. Activity in another application is outside this terminal's input stream. Plain-mode automation still requests restart immediately after finalized tasks. OS policy and inhibitors may still refuse restart. Native restart acceptance remains separate from harmless lifecycle verification.

## Verification

- `restart_after_closes_dashboard_without_input_and_restores_terminal`
- `restart_after_is_opt_in_and_read_only_surfaces_never_request_it`
- `restart_idle_window_resets_for_keyboard_mouse_and_literal_paste`
- `restart_idle_review_honors_early_quit_and_cancellation`
- `ordinary_dashboard_ignores_restart_timeout_configuration`
- `restart_idle_cli_and_config_validate_before_task_effects`
- `restart_review_resets_only_for_dashboard_activity`
- `restart_review_paste_preserves_editors_without_submitting_controls`
- `restart_review_timeout_defaults_to_three_minutes_and_rejects_zero`
- `restart_review_config_and_cli_override_preserve_user_preferences`
- `restart_review_does_not_reset_for_resize`
- `restart_review_canceled_task_exits_without_misleading_countdown`
- `restart_review_pauses_for_log_viewer_and_resumes_with_full_interval`
- `restart_review_preserves_deferred_task_outcome`

## Runtime acceptance

Drive the real CLI with the compile-time harmless restart backend in real PTYs. Verify a configured short idle window, reset on keyboard/mouse/paste input, no reset on resize, late completion starting a fresh window, explicit cancellation during review, and unchanged ordinary dashboard persistence. Verify default and overridden positive timeouts and invalid zero values through public CLI/configuration boundaries. Confirm exactly one harmless marker after terminal teardown and durable results. No physical restart is authorized for this change.

## Supersession conditions

Supersede if timer activation, activity sources, default duration, cancellation semantics, restart authority, or background execution changes.
