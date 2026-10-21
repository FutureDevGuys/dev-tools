# update-all

`update-all` runs detected system and developer-tool updates through a catalog-driven engine with compact dashboard and plain-output frontends.

Public built-ins cover broadly applicable package and language managers. Additional organizations and users can add namespaced TOML catalogs under the platform configuration directory without rebuilding the binary.

The command updates itself only from authenticated stable-release manifests. Runtime release checks use native HTTPS and do not require Git, GitHub CLI, curl, wget, Python, authentication, or a source checkout.

See the repository [README](../../README.md) and [update-all documentation](../../docs/update-all.md) for installation, catalog authoring, result semantics, and the release trust model.

Configuration reads honor `--config` before nonempty `UPDATE_ALL_CONFIG`.
An absent or invalid explicitly selected file fails before tasks start; it never
falls back to an unrelated configuration. Unset or exactly empty environment
selection preserves ordinary discovery. Explicit inputs must be regular files
(including symlinks to regular files); relative and literal whitespace paths
remain supported. This does not change configuration-file creation commands.

## Blocked or deferred updates

Task runs return 0 for clean completion or intentional exclusions, 1 for an
operational task or journal failure, 2 when selected work remains explicitly
blocked or deferred, and 3 for global cancellation. Cancellation takes precedence,
then operational failure. These task-run codes are separate from the common
managed-update command API.

A task may retain its rich `completed` status while individual packages are
blocked; that is no longer a clean run. Ordinary nonblocking warnings alone still
allow exit 0. `--fail-fast` stops later admission on failures or blocked/deferred
work, but lets already running tasks settle. An intentional privilege exclusion
alone stays a clean skip; a selected health dependent without its capability does
not. NPM reports an unknown after-version when installation was not observed,
keeping a requested target in notes rather than presenting it as installed.

## Restart after updates

Run `update-all --restart-after` (alias `--reboot`) to request a non-forced restart
only after a clean task run, dashboard dismissal, and durable run-log finalization.
Save your work first. Failure, cancellation, reported task issues, empty/all-skipped
plans, and evidence-write failures prevent the restart. Help/version and maintenance
subcommands never restart the host. Restart is off by default and has no persistent
configuration setting.

Linux requires a native systemd host with inhibitor checking (systemd 248+); WSL,
containers and other init systems are unsupported. Windows requests an immediate
non-forced restart. macOS requests the native restart confirmation dialog, which you
must confirm. Existing OS policy and application vetoes still apply. The command
does not acquire privileges, force applications closed or retry a failed request.
`restart.json` beside the run logs records the request outcome; acceptance is not
proof that the computer restarted. If denied or uncertain, check the OS and restart
manually. Native macOS/Windows acceptance is pending, not established by Linux tests.

Developers can run harmless executable lifecycle tests with
`cargo test -p update-all --features restart-test-backend --test restart_after`.
This test feature disables native restart entirely; do not distribute such builds.

## If storage fills during a run

Required log or artifact write failures stop new task admissions and make the run
fail. Already-running commands remain owned and are settled through the existing
execution lifecycle; the dashboard is restored before the final diagnostic is
printed. Available evidence preserves observed outcomes, but completely full or
failed storage may prevent final records from being written at all.

JSON artifact replacements are staged before publication, preserving the last
complete snapshot if a later write fails. That snapshot can record completed
tasks and exit zero while metadata remains `finalizing`; it does not establish
successful invocation finalization or authorize replay. This replacement
guarantee is not power-loss durability.

A failed or missing record is not proof that a package update did nothing.
Package managers may have partially changed their installations before failure
or cancellation. Free space, inspect the affected manager's state, and follow its
recovery procedure before retrying; do not infer success from a downloaded version
or automatically rerun every updater. This behavior applies with or without the
restart flag, and incomplete evidence always prevents an automatic restart.

### Inspect damaged run evidence

Use `update-all runs inspect [QUERY] --json` to inspect local run metadata and
final artifacts without repairs, package commands, network access, or replay.
QUERY is an exact recorded UUID/display name or observed directory name. The
`update-all-run-inspection-v1` result distinguishes missing, malformed,
unreadable, unsafe, oversized and unsupported evidence. Unknown facts are null.
`evidence_status: available` means the two artifacts are readable and supported,
not that the run completed or packages are healthy; journal consistency is not
checked. Human inspection shows the recorded metadata status, escapes directory
names and uses `?` for unknown counts.

`restore` and `resume` also use null task/issue counts (rather than misleading
zero) for unavailable final evidence. Healthy legacy results remain equivalent.
A malformed metadata neighbor no longer hides healthy history. Scan limits are
4096 root entries, 256 KiB per metadata file, 8 MiB per run artifact and 64 MiB of
initially observed eligible files. No scan silently returns a truncated result.

Exact directory-name inspection reads only that child, even when unrelated
history exceeds the aggregate scan bounds. Observation is not a coherent live
filesystem snapshot or protection against adversarial parent-directory races.

Reported storage exhaustion (ENOSPC, EDQUOT or explicit supported disk/quota messages) stops automatic command retries and further NPM recovery. Partial package changes may remain: inspect the affected prefix/cache/temp filesystem and package state before explicitly retrying. This is reported-error handling, not a free-space guarantee or automatic cleanup.

Update All no longer deletes hidden NPM directories just because their names resemble temporary staging. They may contain retained package data, even when a canonical package also exists. A bounded advisory reports observed entries without claiming they are stale or recoverable; review conflicts explicitly. NPM's own authorized update behavior is unchanged, and Update All does not automatically restore retained copies.
