---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0047: Reuse startup sudo authority on the original terminal

status: accepted
verification: verified

## Context

Startup authenticates with native sudo on the invoking terminal. A later interactive task previously received a new controlling PTY, so terminal-scoped sudo authority did not apply there. Custom tasks declaring either direct elevation or a nested sudo session need the same execution contract as built-in tasks.

## Decision

On Linux, an interactive task declaring requires_elevation or needs_sudo_session uses the startup controlling terminal for native input and /dev/tty. Update All remains the direct parent of direct sudo invocations. A shared terminal lease serializes these handoffs across concurrent tasks. The dashboard must acknowledge suspension before launch; missing acknowledgment prevents the command from starting.

The product-neutral ForegroundTerminal mechanism in dev-tools-command gives an owned child group the foreground, then restores the original foreground group, terminal attributes, and calling-thread signal mask on every exit path. Update All owns deadlines, cancellation, output drainage, and the terminal lease. Stdout and stderr remain bounded captured streams and are mirrored live while the dashboard is suspended, preserving custom result footers and report parsers. Native terminal input is never read by the dashboard or written to run artifacts.

Direct Linux elevation uses sudo -n after startup admission. A launch-time denial remains failure without password fallback, refresh, or replay. Nested commands retain native sudo policy. An explicitly configured external_window retains its separate-terminal authentication semantics. Other platforms and ordinary dashboard-managed tasks keep their existing execution paths.

This supersedes ADR 0028's task-terminal authentication rule and ADR 0034's legacy prompt_tty execution rule for this Linux path. Their admission modes, no-replay protection, and unsupported-platform limits remain. ADR 0029's exact-source native acceptance, authenticated release, and managed activation requirements remain mandatory.

## Invariants

- Public catalogs, built-in tasks, and user custom tasks use the same declared privilege fields. No consumer paths, package choices, or private policy enter this mechanism.
- Sudo credentials remain native. Update All changes no sudoers, timestamp policy, authentication provider, or persistent privilege authority.
- No shell wrapper changes the parent of a direct sudo invocation.
- The native terminal has one foreground task owner. Cancellation while waiting for ownership starts no command.
- Captured result footers, stderr, task identity, and exact argv survive the handoff.
- Ctrl+C on the foreground command requests run cancellation. Stopped commands fail and their owned group is settled rather than replayed.
- An unstarted task and a failed command with possible partial effects remain distinct.

## Rejected alternatives

Keeping a background task attached to the startup controlling terminal while routing its input through another PTY breaks /dev/tty readers and can stop them on SIGTTIN. Detecting that stop does not restore their native interaction. A persistent terminal broker or privileged daemon adds another authority and process protocol. Discarding captured output breaks custom result_protocol and report_parser contracts. Changing sudo timestamp policy would widen authority outside the updater's task.

## Consequences and known limitations

Typical terminal-scoped policy reuses the single startup authentication, including nested managers. Parent-scoped policy supports direct sudo children but cannot authorize arbitrary nested parents. No-cache policies can deny later direct launches; the updater never promises to override native policy. Explicit external windows may authenticate separately. Captured stdout and stderr are pipes; callers requiring terminal output semantics can explicitly select direct_tty, with its existing reduced output evidence. Programs that deliberately leave their owned process group remain outside process-group containment.

## Verification

- `custom_privileged_tasks_reuse_startup_terminal_and_preserve_captured_results`
- `native_terminal_failure_and_cancellation_never_replay_protected_effects`
- `foreground_sudo_refuses_launch_without_dashboard_terminal_release`
- `interactive_elevated_command_uses_one_sudo_process_without_auth_replay`
- `npm_registry_tilde_ranges_are_not_local_dependency_paths`

## Runtime acceptance

Disposable native PTYs exercise the public executable in plain and dashboard modes with sync and async scheduling, concurrent custom tasks, controlled sudo, native terminal input, exact argv and parent/session/terminal identity, captured results, failure, cancellation, and job-control stop. These controlled sudo fixtures do not establish host sudo policy support. The shared terminal mechanism separately checks foreground and terminal restoration through explicit completion, Drop, panic, spawn failure, background refusal, and absent terminals.

Before accepting this decision or activating a release, run the exact candidate with real sudo through a user-visible terminal and a harmless isolated catalog. The user enters any credential directly into native sudo. Verify one startup authentication, subsequent direct and nested launches, exact argv, captured result agreement, no protected replay, and cancellation cleanup. Native non-Linux acceptance remains unrun. Signed publication and receipt-owned installation are separate milestones.

## Linux qualification evidence

The signed Linux x86-64 0.1.17 artifact from source `74ce7f9a157b88297952073f4ff0e38ab2e8eada` passed native direct and nested sudo launches under the host's current configuration. The intentional exit-7 task emitted its protected effect once and remained failed despite a configured retry budget. Cancellation returned exit 3 with a saved canceled task. The two independently constructed release sets were byte-identical, authenticated publication verified the public downloads, and managed activation retained 0.1.16 for rollback. The installed executable matches the native-qualified artifact SHA-256 `76e84de6b03110b9fe2c7c426b82bef6b6d5d0edc907fb2ff1fddc03c28f1b1f`. The published manifest generation is 18. Native policy-matrix and non-Linux lanes remain unrun.

## Supersession conditions

Supersede this record if terminal ownership, captured result evidence, platform qualification, nested-manager authority, or startup authentication policy changes.
