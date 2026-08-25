---
authority: canonical
owner: update-all
---

# update-all Incident Note: Interactive Sudo + Dashboard (February 26, 2026)

## Scope

This incident and fix apply to the Rust `update-all` binary in this directory.
It does not depend on shell wrapper behavior. The installed command path (`~/.local/bin/update-all`) is a compiled binary installed from this source tree.

## Symptoms Observed

- Password prompts appeared inside/under the dashboard at awkward times.
- On cancel/exit, delayed `[sudo] password for ...` prompts could appear after dashboard shutdown.
- In some runs, prompt handling appeared to stall until manual interrupt (`Ctrl-C`).
- The dashboard "Input Prompt" overlay could show false positives from non-interactive `yay` output lines like `==> Retrieving sources...`.

## Root Causes

1. Interactive/sudo lifecycle was not fully centralized at run start.
2. Capture-mode cancellation could miss helper descendants when process-group handling was not consistently managed.
3. `yay --sudoloop` introduced an additional sudo lifecycle independent of `update-all`.
4. Prompt overlay detection in TUI was too broad and treated generic `==> ...` lines as prompts.

## Final Fix Implemented

### 1) Pre-auth before dashboard startup

- `update-all` now checks selected tasks for sudo session requirements before launching dashboard task execution.
- It performs preflight authentication using `sudo -v` before dashboard flow when needed.
- This moves password entry to a predictable phase and avoids prompt/render contention.

### 2) Managed sudo session keepalive

- Added a binary-owned keepalive loop (`sudo -n -v`) while async run is active.
- Keepalive failure triggers fail-fast cancel-all.
- Keepalive is explicitly stopped and joined before final teardown is reported.

### 3) Remove updater-owned sudo loop for `yay`

- Builtin `yay` invocation dropped `--sudoloop`.
- Sudo lifecycle is now owned by `update-all`, not duplicated by updater arguments.

### 4) Stronger cancellation/teardown semantics

- Interactive capture-mode process execution uses managed process groups where required.
- Cancel/timeout paths terminate process groups so helper subprocesses do not survive run teardown.

### 5) Prompt overlay false-positive fix

- TUI prompt heuristics now only match explicit interactive prompt patterns.
- Generic status lines (for example `==> Retrieving sources...`) are excluded.
- Overlay only shows when the prompt line is still the latest log for that same task, preventing stale prompts from persisting.

## Relevant Runtime Signals in `run.log`

Look for these markers to validate expected behavior:

- `Preparing elevated session (sudo authentication required)...`
- `sudo session keepalive started`
- `sudo session keepalive failed; canceling all tasks` (only on failure path)
- `sudo session keepalive stopped`
- `cancel-all teardown complete`

## Operator Validation Checklist

1. Start `update-all`.
2. Confirm password prompt (if needed) happens in pre-auth phase before dashboard workload proceeds.
3. Let async tasks run and observe no spurious prompt overlay during normal `yay` build/download logs.
4. Exit/cancel dashboard (`q`/`Esc`) and verify no delayed shell-level sudo prompt appears after process exit.

## Config/Model Additions

- Custom updater tasks now support:
  - `needs_sudo_session = true|false`
- This is separate from `requires_elevation`:
  - `requires_elevation` controls command wrapping with `sudo -n -- ...`
  - `needs_sudo_session` requests pre-auth + keepalive session ownership for task flows that rely on ambient sudo credentials.
