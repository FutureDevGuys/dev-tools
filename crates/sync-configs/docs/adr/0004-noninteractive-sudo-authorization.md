# ADR 0004: Non-prompting sudo authorization before a foreground-only prompt

status: proposed
verification: source fixtures pass; native sudo acceptance pending

## Context

`sudo -v` validates only the sudo timestamp. Policy that authorizes commands without a timestamp, such as a sudoers `NOPASSWD` rule or a plugin-managed grant, leaves `sudo -n -v` failing while `sudo -n -- COMMAND` succeeds. Without a command check, a session authorized that way still prompts.

The interactive `sudo -v` reads its reply from the controlling terminal. A process outside the terminal's foreground process group stops on that read with `SIGTTIN`, so its prompt shows, the typed reply echoes unread, and sudo eventually times out. A wrapper that launches `sync-configs` in its own process group produces that state.

## Decision

Authorization stops at the first step that succeeds:

1. `sudo -n -v` exits 0.
2. `sudo -n -- TRUE` exits 0, where `TRUE` is the first `true` that passes the session's executable authority, which is trusted-executable validation outside test-only injected sessions. Candidates are the absolute entries of the captured `PATH` in order, then `/usr/bin`, `/bin` and `/usr/local/bin`, the order sudo discovery uses. Without a candidate, this step is skipped. The check uses the same argument form, captured environment and bounded runner as privileged work, with closed stdin, captured output, a 30-second deadline and a 64 KiB capture bound. Cancellation propagates as interruption. Any other outcome moves to the next step.
3. The interactive `sudo -v` runs with inherited streams only when standard input is a terminal, `/dev/tty` opens with `O_NOCTTY`, and that terminal's foreground process group is the caller's process group. Otherwise authorization returns `PromptUnavailable` before prompting. Its message names the remedy: run `sync-configs` directly in a terminal, or authenticate first in a user-visible terminal and verify with `sudo -n -v`. Fatal diagnostics add the value-free `authentication_prompt_unavailable` kind to the [closed projection](../../../../docs/adr/0128-sync-configs-fatal-run-diagnostics.md).

Interruption checks separate the steps. No step reads, proxies or stores a credential, and sudo remains the sole credential cache and authorization boundary. Platforms without Unix sudo keep returning `Unsupported`. A policy narrow enough to admit `true` but not a later command authorizes the session, and that later command then fails as an ordinary privileged-command failure.

## Verification

Source fixtures drive a fake sudo that models timestamp and grant policy through the public session API: a cached timestamp, a grant that admits `sudo -n --` while `sudo -n -v` fails, and a pseudo-terminal fixture that authenticates with no controlling terminal, from a background process group, and from the foreground process group. Probe fixtures inject the session `PATH`: one whose only `true` lives in a private directory, and one with no usable `true`, which falls through to the prompt decision. Native acceptance against real sudo with a `NOPASSWD` rule, a plugin-managed grant and a wrapper-launched background run remains pending.
