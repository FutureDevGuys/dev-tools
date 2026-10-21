---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0034: Compatible privilege fallback modes

status: proposed
verification: pending

## Context

Some hosts cannot provide sudo or interactive authentication. Aborting every
independent updater task makes that limitation a run-wide failure, while silently
attempting unprivileged work or retrying a started protected command is unsafe.
Operators need explicit policy without changing existing configuration meanings.

## Decision

Extend the existing privilege_mode setting with auto, never and required. The
default remains prompt_tty. Skip and best_effort_skip retain intentional exclusion;
never is their alias. Fail and fail_run still refuse elevated tasks, not demand
run-wide prerequisite authentication.

Auto admits only already-authorized noninteractive Linux elevation. Before a
direct elevated command, bounded native sudo admission checks authority and the
launch uses sudo -n with exact argv. Missing executable, unavailable authority,
known pre-launch expiry and unsupported noninteractive paths are typed deferrals.
Unavailability is latched; no background keepalive, interactive refresh, fallback
password prompt or repeated admission after denial occurs. Independent work and
ordering-only successors continue. Health dependents remain blocked. Commands
requiring a nested sudo session defer unless a qualified no-prompt path exists;
this decision adds no manager-specific path. Non-Linux auto admission defers.

Required makes usable elevation a run prerequisite only when a selected task needs
it. Interactive Unix admission uses existing native authentication; noninteractive
admission is bounded and cannot fall back to a prompt. No task begins after an
unsuccessful prerequisite. Unsupported platform prerequisites fail explicitly.
A failed direct protected invocation cannot trigger launch-time interactive
refresh or automatic protected replay in required mode. A catalog interactive
flag cannot enable sudo prompts when the caller lacks an interactive terminal;
the task launch still uses sudo -n even when capture creates a task PTY.

This supersedes only ADR 0028's unchanged privilege-admission, preflight and
keepalive promise for the new explicitly selected modes, and its interactive
sudo invocation rule when auto requires noninteractive launch. Legacy prompt_tty
behavior and ADR 0028/0029's authentication, exact argv, no-replay and execution
ownership protections remain intact. No new credential authority is created.

## Invariants

- Default and every legacy spelling preserve their admission meanings.
- Auto and never cannot request interactive privilege authentication.
- No selected elevated task means no prerequisite sudo request.
- A preflight does not guarantee authority in another terminal or later launch.
- Auto deferral carries explicit dependent-blocking evidence and fixed reason codes.
- Auto deferrals produce exit 2 unless real failure or cancellation takes precedence.
- Intentional exclusions alone retain clean-skip behavior; health gates never pass
  solely because an unestablished capability has a skipped display status.
- After a protected invocation begins, failure, timeout, uncertain capture and
  cancellation remain execution-owned outcomes, never no-effect claims or replay authority.
- No installation, sudoers/timestamp policy change or credential persistence occurs.

## Rejected alternatives

Changing the default would silently alter existing configuration. Mapping fail to
required would change an explicit refusal into an elevation attempt. An outer
cached-authority check cannot guarantee a nested manager will not ask for a
password. Matching a launched command's stderr cannot prove no protected effects.

## Consequences and known limitations

Auto may defer work that prompt_tty could complete after native authentication.
Fixed generic authority-unavailable reasons do not claim to distinguish policy
denial from absent credentials. Structured fields are additive under the existing
bounded artifact schema. Linux native acceptance is still required; synthetic
executables and cross-platform compilation establish no native support guarantee.

## Verification

- `privilege_modes_preserve_legacy_aliases_and_add_explicit_fallback_modes`
- `privilege_configuration_preserves_default_and_validates_new_modes`
- `auto_privilege_defers_missing_sudo_without_starting_the_command`
- `never_privilege_skips_without_sudo_or_command_invocation`
- `auto_privilege_uses_exact_noninteractive_argv_and_never_replays_started_work`
- `auto_privilege_denial_is_latched_and_independent_work_continues`
- `auto_privilege_expiry_defers_new_work_without_refresh_or_replay`
- `auto_privilege_defers_nested_and_unsupported_platforms_without_sudo`
- `auto_privilege_interactive_task_invocation_still_forbids_password_prompts`
- `auto_privilege_admission_timeout_is_bounded_and_latched`
- `required_privilege_noninteractive_preflight_never_falls_back_to_prompting`
- `required_privilege_launch_failure_never_prompts_or_replays`
- `required_privilege_interactive_catalog_task_cannot_create_password_permission`

- `auto_privilege_cancellation_preserves_execution_ownership_and_one_effect`
- `auto_privilege_precommand_failure_is_not_replayed_or_reclassified`
- `auto_privilege_cli_defers_health_gates_and_continues_independent_work`
- `required_privilege_cli_is_a_prerequisite_only_for_selected_elevated_work`
- `never_privilege_cli_keeps_clean_exclusions_but_reports_blocked_health_dependents`

## Runtime acceptance

Use isolated homes, configuration, catalogs and harmless marker commands. Across
sync/plain and async/plain jobs=1 and jobs>1, verify absent and denied sudo,
noninteractive success, pre-launch expiry, nested-manager deferral, required
prerequisite failure and selections with no elevation. Compare process exits,
journal, task/run artifacts and dashboard completion. Verify health blocking,
independent continuation, no password prompt and exactly one protected effect on
failure or timeout. Exercise cancellation with owned-child cleanup.

Then repeat the existing exact-source harmless native current-policy journey
without changing sudoers, timestamps or credentials. Native credential entry
stays in the user's secure prompt, never chat or captured fixtures. Record unrun
policy/platform lanes as NOT RUN. Publication and installation remain separate.

## Supersession conditions

Supersede this record if a typed executor replaces sudo, additional platforms or
nested-manager no-prompt paths acquire qualified support, or an operator-visible
mode changes its prompting, prerequisite or deferral meaning.
