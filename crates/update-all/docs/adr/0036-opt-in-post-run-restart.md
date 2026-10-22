---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0036: Opt-in post-run restart requests

status: proposed
verification: pending

## Context

An operator may want a host restart after updates, but a successful task-process
exit alone does not prove a clean run, durable evidence, or terminal restoration.
Forced restart commands can discard unsaved work. Cross-platform restart APIs
have different permission, inhibitor and confirmation semantics.

## Decision

The ordinary task-run CLI accepts --restart-after (alias --reboot), disabled by
default and never enabled by configuration or the environment. Print a save-work
warning before tasks start. Read-only and explicit maintenance subcommands do not
use this option. A restart is requested only after the shared scheduler and
frontend return, terminal artifacts are finalized, and file buffers are synced.
A run must have at least one completed task, no failed or canceled tasks, no
reported task issues, no pending global cancellation, and successful finalization.
The dashboard must be dismissed first. An empty or entirely skipped run cannot
restart the machine. An unsatisfied explicit restart request exits nonzero.

After dashboard dismissal, restart must reacquire the same run-root task admission
used by the scheduler and retain it through the OS request and its evidence writes.
If another run owns admission, withhold restart without canceling that run or
relabeling already-completed task evidence. Completed dashboards may still remain
open while another run executes; dashboard ownership is not restart authority.

Linux uses /usr/bin/systemctl with --no-ask-password --check-inhibitors=yes reboot,
only on a native systemd host. Detected containers and WSL are rejected. Windows
resolves shutdown.exe through GetSystemDirectoryW and passes /r /t 0, never /f;
a positive timeout implicitly forces application closure. macOS uses the native
Apple Event restart dialog (kAEShowRestartDialog), with user-consent prompting
disabled, rather than shutdown or immediate kAERestart. The operator must confirm
that dialog. Native OS permission denial, inhibitors, missing facilities and
unsupported runtimes do not trigger elevation, policy changes, alternative
commands, forced restart, or replay. Existing updater privilege policy is not
widened: restart uses only the caller's existing OS authority.

A separate restart.json records request_pending before the one request, then
request_accepted or request_failed_or_uncertain when observable. The run.json
continues to describe the completed update tasks. Acceptance is not proof of a
reboot, and an interrupted pending request never authorizes automatic retry.
Command-based requests have a 30-second execution bound and owned cancellation.

The explicit restart-test-backend build feature completely substitutes a
harmless JSON marker backend; it cannot fall through to a native reboot, even
when its marker environment variable is absent. Those builds are not distributable
release artifacts. Normal binaries have no runtime command injection seam.

## Invariants

- No restart follows failed, deferred, canceled, empty, all-skipped or unpersisted work.
- A success exit does not override canceled-task evidence.
- No request precedes terminal teardown and durable final run evidence.
- No request occurs while a different same-root Update All run owns task admission.
- No implicit sudo, credential refresh, permission change or force option exists.
- No retry follows a denied, timed out or uncertain request.
- OS acceptance is distinguished from actual reboot completion.
- No real machine restart is performed by the automated test suite.

## Rejected alternatives

Unconditional shutdown after a zero process exit misses cancel-one and evidence
failure. Unix shutdown commands can kill applications rather than respect vetoes.
Windows shutdown's default timeout implicitly forces closure. A runtime arbitrary
command override would broaden authority solely to make tests easier. Immediate
macOS restart bypasses the recommended safe confirmation dialog.

## Consequences and known limitations

Linux requires systemd's explicit inhibitor-checking option (systemd 248 or newer).
Containers, WSL and other init systems need manual restart. Existing host policy
may deny any backend; no restart guarantee is made. Native macOS and Windows
acceptance remains pending, including ABI, signing and local permission behavior.
There is an unavoidable boundary after OS acceptance beyond which update-all
cannot cancel the restart. Power loss can leave a pending receipt. Persistence
errors after a request do not imply the request had no effect.
The admission guard coordinates only Update All runs using the same run root. It
does not fence manual package-manager commands, other state roots, or new writers
after the asynchronous OS request is accepted and the guard is released.

## Verification

- `restart_adapters_never_force_or_prompt_for_elevation`
- `restart_eligibility_requires_clean_completed_task_evidence`
- `restart_after_requests_once_only_after_successful_persisted_terminalization`
- `restart_after_is_opt_in_and_read_only_surfaces_never_request_it`
- `restart_after_waits_for_dashboard_exit_and_restores_terminal`
- `restart_after_refuses_when_second_run_started_during_dashboard_review`
- `restart_after_suppresses_failed_pre_request_evidence_sync`

## Runtime acceptance

Run harmless real-CLI lifecycle tests in both engines for success, task failure,
SIGINT, invalid selectors, empty/all-skipped selection, journal/artifact failure,
ENOSPC, backend denial and missing test-marker admission. Inspect the marker's
snapshots of terminal run evidence and its count of finalization events. Use a
real PTY to prove no request while the dashboard owns the terminal, followed by
restoration before request. Separately qualify each native OS adapter on a user-
authorized disposable machine, including OS refusal and unsaved application
work. Such real restarts are NOT RUN by this change's cloud tests.

## Supersession conditions

Supersede if restart gains new privilege authority, automatic retry, forced
closure, configuration-based activation, additional OS backends or an automatic
macOS restart rather than its confirmation dialog.
