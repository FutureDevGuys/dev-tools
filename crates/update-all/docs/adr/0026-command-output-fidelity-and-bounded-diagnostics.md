---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0026: Command output fidelity and bounded diagnostics

status: proposed
verification: pending

## Context

Appending diagnostic stderr to machine-readable stdout can invalidate a successful inventory query. Dashboard severity previously depended on the stream, multiline messages lost their line boundaries, and warning samples could crowd a later error out of the summary. The diagnostic collector searched an unbounded list even though only five samples were rendered. Quiet npm configuration could suppress the lifecycle warning that triggered executable health verification.

## Decision

Machine-readable capture returns stdout alone while failed commands preserve both streams as evidence. Streaming logs retain stream identity and classify explicit diagnostic syntax independently of the stream. Multiline messages become individual logical records. Diagnostic collection keeps fixed sample budgets per severity, renders errors first, and reports omitted occurrences with a complete-task-log reference. Diagnostic severity remains independent of package transaction status. ADR 0003's bounded JSON and full-log authority remain in force.

Before reporting a planned npm root as updated, verify its installed version, manifest and declared executable health even when npm printed no lifecycle warning. Share version and root observations across the planned batch. An isolated recovery invocation requests warning output without changing persistent npm configuration; lifecycle authorization continues to follow ADR 0002.

Each closure member's complete registry manifest must be observed successfully and decoded as one unambiguous manifest before authorizing its scripts. The manifest name and version must exactly match the requested closure member. JSON objects and npm 12's singleton-array response are accepted; empty and multiple-result arrays are rejected. Unavailable or malformed registry metadata, invalid dependency shapes and non-registry sources stop recovery before the script-authorized retry. Existing observational parsing does not grant that authority.

## Invariants

- Successful stderr cannot become an npm path or completion-provider JSON document; failure context retains both streams.
- Every logical message line reaches the dashboard and journal with its task identity.
- Collector state stays bounded independently of distinct input count; fixed sample budgets make processing linear in input bytes.
- Late errors remain eligible, omitted occurrences are explicit, and diagnostic messages remain visible at default report verbosity.
- Warning and error colors agree across raw logs and diagnostic reports without marking a package transaction failed solely because it emitted a diagnostic.
- Diagnostic samples do not inflate package item counts; a concise failed-command summary prefers explicit error evidence over preceding progress or warnings.
- Dashboard eviction counts remain visible at the tail; full persisted logs remain accessible.
- Progress coalescing preserves warnings, errors and ordinary package messages.
- A broken declared executable cannot be reported as updated solely because npm returned success.

## Rejected alternatives

Increasing line and sample limits postpones omission while increasing memory. Product-specific exceptions make generic collection and health checks brittle. Unconditionally authorizing npm scripts discards the existing isolated registry-closure authority.

## Consequences and known limitations

Each task and the combined dashboard pane still retain separate bounded windows. Explicit diagnostic syntax does not establish the severity of arbitrary prose. Executable probes add bounded work for planned npm updates; other native platforms remain unqualified. The scaling benchmark measures the collector, not end-to-end updater performance.

Crossterm remains a required dependency for terminal colors and width discovery in plain reports. The optional `tui` feature controls Ratatui dashboard rendering; disabling it must leave the plain reporting build functional.

The foreground log viewer uses `less +F -K -R -S`. Less's documented interrupt exit status 2 means the user dismissed that viewer with Ctrl-C, so it resumes the dashboard without a failure advisory. This status convention applies only to Less; launch errors, other nonzero statuses and signal termination remain failures. The existing signal-cancellation suppression during log viewing is unchanged, and updater cancellation outside the viewer remains independent.

## Verification

- `output_diagnostic_levels_agree_across_streams_and_reports`
- `command_diagnostics_preserve_late_errors_and_explain_omissions`
- `diagnostic_footer_preserves_messages_and_severity_at_default_verbosity`
- `multiline_task_logs_retain_every_logical_line_in_dashboard_and_journal`
- `successful_capture_keeps_unterminated_stdout_separate_from_stderr`
- `stdout_capture_failure_keeps_both_streams_in_error_context`
- `npm_global_path_ignores_stderr_diagnostics`
- `npm_silent_install_does_not_report_a_broken_executable_as_updated`
- `does_not_coalesce_diagnostics_or_package_messages_containing_byte_counts`
- `dashboard_shows_evicted_log_counts_while_following_the_tail`
- `raw_diagnostic_badges_follow_severity_independently_of_stream`
- `raw_diagnostic_badges_render_in_focused_and_global_logs`
- `raw_diagnostic_badges_leave_neutral_and_report_display_kinds_unchanged`
- `raw_diagnostic_badges_preserve_prompt_precedence`
- `raw_diagnostic_badges_preserve_search_highlighting`
- `raw_diagnostic_badge_width_matches_wrapped_rendering`
- `diagnostic_report_warning_cells_use_warning_colors`
- `diagnostic_marker_colors_do_not_highlight_identifier_substrings`
- `task_failure_summary_prefers_a_late_error_over_earlier_warnings`
- `diagnostic_samples_are_not_counted_as_package_transaction_items`
- `controlled_catalog_keeps_late_errors_in_full_logs_and_bounded_summary`
- `later_command_errors_upgrade_the_existing_diagnostic_advisory`
- `detailed_task_changes_keep_diagnostic_row_severity`
- `npm_silent_install_recovers_the_observed_registry_script_closure`
- `npm_silent_install_never_authorizes_scripts_without_verified_registry_metadata`
- `pipx_inventory_reads_json_independently_of_stderr_diagnostics`

- `streaming_pipe_preserves_blank_records_and_line_boundaries`
- `streaming_pipe_partial_prompt_terminators_do_not_create_blank_records`
- `pty_reader_preserves_blank_records_and_split_crlf`
- `streaming_readers_do_not_emit_after_capture_guard`
- `stream_callback_keeps_subprocess_blanks_in_raw_log_only`
- `diagnostic_rollup_preserves_complete_notes_at_every_verbosity`
- `diagnostic_rollup_colors_do_not_change_transaction_status`
- `log_pager_accepts_only_less_interrupt_status`

## Runtime acceptance

Run a controlled catalog fixture with stdout and stderr diagnostics, more unique warnings than the sample budget, a late error and multiline result text. Verify complete disk logs, journal line boundaries, diagnostic severity and the omitted-sample notice. Check dashboard tail eviction counts. Repeat the npm lane against a disposable user-owned installation with a manifest-current but broken launcher and verify bounded recovery without persisted lifecycle trust. Native Windows and WSL acceptance and installed-release activation remain separate gates.

In a real terminal, open active and completed task/run logs with the actual Less executable, dismiss with Ctrl-C, reopen, and verify dashboard recovery without a viewer-failure advisory or cancelled tasks. Separately verify that a genuine viewer error still emits the failure advisory and that the dashboard's cancel-all control still cancels its tasks after returning. A source-binary check is not signed-release acceptance.

## Supersession conditions

Supersede this record if structured provider diagnostics replace text classification, log persistence changes authority, or a versioned npm protocol replaces manifest and executable health verification.
