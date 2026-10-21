---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0040: Truthful blocked run outcomes

status: proposed
verification: pending

## Context

A task can finish its own reconciliation and retain rich Completed results while
selected packages or capabilities remain explicitly blocked. Run aggregation
looked only for Failed tasks and explicit privilege deferrals, so a run with NPM
permission-denied rows and a blocking advisory could return clean success. The
same omission let fail-fast admit later work. Some NPM rows also presented the
requested target as the installed after-version despite no successful observation.

## Decision

Keep ADR 0001's rich task statuses and ordering-versus-health dependency contract.
For run aggregation, Completed or Skipped tasks with existing explicit blocking
rows or non-info dependent-blocking advisories are unresolved selected work.
Explicit deferred advisories count independently of severity. The intentional
privilege-disabled advisory on a Skipped task is exempt by itself, not a blanket
exemption for other blocking findings on that task. Missing/nonapplicable tasks
and other ordinary skips are not reclassified.

Use the existing task-run exit categories: global cancellation selects 3,
genuine Failed task or journal failure selects 1, otherwise unresolved selected
work selects 2, and clean completion or intentional exclusion selects 0. A
Completed rich task containing a Failed package row therefore selects 2, not 1;
this change does not introduce a comprehensive package-failure taxonomy or
rewrite task statuses. Ordinary nonblocking warnings and errors alone remain
nonfatal. These are task-run categories, not the separate common-update API.

Fail-fast stops later admission on a Failed task or unresolved selected work;
already running owned tasks settle normally. Settle blocked health dependents
before admitting newly ready tasks so a deliberate prerequisite exclusion cannot
hide the unresolved requested dependent. Ordering-only work otherwise continues.
Attempted-command and pre-command elevation denials carry explicit deferred
blocking evidence rather than being indistinguishable from intentional skips.
They authorize no automatic replay and make no no-effect claim.

Run and task presentation describes blocked/deferred work generically, without
implying that sudo can resolve every blocked capability. The existing machine
status schema remains unchanged. Writer issue counts use the persisted bounded
findings, including warning/error, explicit deferred or blocked/failed evidence
on Skipped tasks, consistent with read-only history. Older info-only deferrals
are counted on read without changing saved files. An issue count is not an
exit-code policy.

NPM's unattempted or failed installation and unverified lifecycle-diagnostic rows
keep the requested target in notes, not in the observed after field. The after
field is null when no trustworthy post-install observation exists. Verified
successes and observed unhealthy installed versions retain their evidence.

## Invariants

- A selected explicit blocking capability cannot yield clean run success.
- Nonblocking warnings do not become failed capabilities.
- Intentional privilege exclusion alone remains exit 0; an unsatisfied selected
  health dependent is unresolved work.
- Cancellation, genuine-failure precedence, dependency health and rich task
  statuses remain intact.
- Fail-fast never cancels or replays already running work.
- Requested versions never stand in for unverified installed versions.
- Process, journal, run artifact and read-only history agree on run outcome and
  persisted issue counts without broadening the serialized status vocabulary.

## Rejected alternatives

Treating all issues as failure would repeat ADR 0001's false capability blocking.
Changing every Completed task with blocked findings into Failed would discard
rich outcomes and alter dependency policy. Exempting all Skipped tasks, or an
entire task that also has privilege-disabled, would hide unrelated blocked work.
Assuming a failed install left the previous version intact would also invent
poststate when partial mutation is possible.

## Consequences and known limitations

Automation previously relying on a false exit 0 now observes exit 2. A run may
have a nonzero issue count but exit 0 for harmless warnings or deliberate skips.
Explicit structured info-only deferral counts as an unresolved issue without
coercing its severity or changing ordinary information-only findings.
NPM's existing configured retry policy is not changed by this decision. Native
platform, real package-manager, sudo, dashboard-terminal and installed-release
acceptance remain separate from disposable executable fixture evidence.

## Verification

- `blocked_npm_cli_is_incomplete_and_never_invents_poststate`
- `successful_and_nonblocking_warning_cli_runs_stay_successful`
- `deferred_privilege_and_intentional_skip_counts_match_history`
- `blocked_fail_fast_stops_later_admission_not_running_work`
- `genuine_failure_precedes_blocked_work_without_losing_success`
- `attempted_elevation_denial_is_not_an_intentional_skip`
- `deferred_health_gate_stops_fail_fast_before_newly_ready_admission`
- `failed_or_unattempted_npm_install_never_claims_target_as_poststate`
- `explicit_blocking_evidence_controls_incomplete_runs_not_display_severity`
- `skipped_issue_counts_follow_bounded_persisted_evidence`
- `npm_lifecycle_diagnostics_do_not_invent_an_installed_version`
- `explicit_info_deferral_counts_as_an_unresolved_issue`
- `explicit_info_deferral_is_counted_in_existing_run_history`
- `async_outcome_prefers_canceled_over_failed`
- `run_completion_header_preserves_cancellation_and_real_failures`

## Runtime acceptance

Use the exact standalone candidate with disposable Rust providers in sync/plain
and async/plain with one and multiple workers. Exercise authority rejection,
preflight rejection, ordinary and mixed failures, verified success, nonblocking
warnings, intentional exclusion, explicit privilege deferral and both attempted
elevation-denial paths without real elevation. Compare process exit, final
journal, metadata, task/run JSON, history JSON/plain counts, package observations
and effects. With fail-fast, require pending work not to start and in-flight
independent work to finish. Retain cancellation precedence under mixed outcomes.
Then separately inspect native dashboard headers and native supported-platform
behavior, with secure user-operated elevation if needed. No native support or
release/installation claim follows from synthetic providers.

## Supersession conditions

Supersede this record if typed capability outcomes replace explicit report and
advisory blocking, task-run exit codes change, intentional exclusions acquire a
separate status, or package-failure aggregation replaces the rich task model.
