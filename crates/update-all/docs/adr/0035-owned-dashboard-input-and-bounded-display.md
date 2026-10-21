---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0035: Owned dashboard input and bounded display

status: proposed
verification: pending

## Context

A prompt's request-generation authority already belongs to execution, but the
dashboard could overwrite another task's draft, route keys into a hidden prompt,
or interpret printable answer characters as navigation. Display history limits
also did not bound queued output between journal writers and the frontend.
Wrapped navigation discarded offsets within a record and modal help could not
reach its final entries on ordinary terminal sizes.

## Decision

Keep one visible modal owner for rendering, keys and mouse input. Preserve the
active task/generation draft while queuing other tasks' prompt requests; advance
to waiting input after an answer or explicit cancellation. Ignore stale request
and cancellation generations. Plain printable answer characters remain text;
Ctrl+C is the explicit cancel-all chord, including while editing or waiting after
submission. Submission remains one-shot and does not change execution authority.

Persist command evidence before admitting it to the display transport. Bound
queued display output in both records and bytes, separately from lossless
lifecycle, prompt and suspend/resume controls. Eviction is presentation-only,
reported with omission counts and full-log pager access. Bound each frame's
receiver ingestion; no unbounded second pending-log queue is permitted.

Use the same visual-row geometry for wrapped rendering, scrolling and search,
including Unicode width, timestamps, badges and omission banners. Reserve visible
footer rows for the search editor and its error ahead of optional shortcuts.
Help owns its scroll position, and its input cannot move underlying panes.
Shortcut labels wrap between complete key/meaning groups at ordinary terminal
widths rather than clipping commands or splitting cancellation instructions.
The plain frontend acknowledges suspend/resume controls as terminal-mode no-ops,
so harmless foreground work does not report nonexistent dashboard timeouts.

Own terminal cleanup from the first successful mode change. On setup, resume or
restoration failure, attempt every applicable restoration operation while
preserving the primary failure. No retained terminal mode is evidence that an
operation succeeded.

## Invariants

- No prompt text or answer gains execution authority outside the existing typed
  task/generation input path; stale answers cannot be replayed.
- Masked input and the existing no-secret journal contract remain intact.
- UI eviction never truncates authoritative task logs or journals.
- Output cannot postpone control delivery indefinitely or block producer threads
  waiting for frontend capacity.
- Cancellation remains an execution-owned request and outcome under ADR 0027.
- No privilege, retry, installation or release behavior changes in this decision.

## Rejected alternatives

A larger unbounded queue only postpones exhaustion. Blocking all sends couples
execution settlement and suspend acknowledgments to rendering. Letting invisible
prompts capture input loses the user's visible context. Converting every key into
a shortcut corrupts legitimate answers. Keeping only record-level offsets cannot
scroll within long wrapped output.

## Consequences and known limitations

The live dashboard may omit display output under sustained load; full persisted
evidence remains available through the existing pager. Control events are
lossless and arise from bounded selected-task execution rather than line volume.
Native terminal acceptance and synthetic state/rendering tests are distinct;
neither establishes real sudo qualification, another platform's terminal
behavior, a signed release or an installed fix.

## Verification

- `prompt_editor_preserves_all_printable_navigation_characters`
- `control_c_cancels_without_editing_or_submitting_prompt`
- `concurrent_prompt_requests_preserve_active_draft_and_advance_once`
- `hidden_prompt_never_receives_modal_editor_keystrokes`
- `actual_log_viewports_scroll_within_one_ten_row_record`
- `actual_log_viewports_share_unicode_badge_banner_and_resize_geometry`
- `wrapped_search_renders_match_behind_newer_output_and_restores_position`
- `dashboard_search_editor_and_error_are_visible_at_small_and_large_sizes`
- `help_end_reaches_final_entry_without_moving_underlying_panes`
- `wrapped_log_keyboard_pages_and_home_use_the_visible_row_range`
- `dashboard_transport_bounds_flood_and_accounts_for_every_omitted_record`
- `dashboard_transport_coalesces_prompt_flood_without_losing_current_generation`
- `dashboard_transport_journals_full_ordered_output_before_eviction`
- `dashboard_transport_shutdown_wakes_frontend_after_journal_failure`
- `terminal_setup_faults_restore_native_terminal_flags`
- `native_e2e_footer_keeps_complete_shortcuts_at_standard_terminal_sizes`
- `native_e2e_prompt_hints_keep_cancellation_words_together`
- `native_e2e_plain_frontend_acknowledges_foreground_handoffs`
- `general_enospc_stops_admission_settles_processes_and_restores_terminal`

## Runtime acceptance

Run the exact candidate under disposable Linux PTYs at 80x24 and a larger size,
with isolated configuration, state and harmless custom tasks. Exercise ordinary
and masked synthetic answers, Ctrl+C before/after submission and Escape,
concurrent requests, help/search/rename ownership, wrapped search and navigation,
flooded output, full-log pager return and normal completion. Compare actual
terminal flags before and after injected partial setup/resume failures. Compare
received answers, task results, ordered persisted markers and UI completion;
never capture genuine credentials. Keep failed, passed and NOT RUN lanes explicit.

## Supersession conditions

Supersede this record if frontend ownership, authoritative prompt routing,
display eviction or terminal lifecycle moves to a different architecture.
