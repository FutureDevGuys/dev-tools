# update-all

`update-all` runs detected system and developer-tool updates through a catalog-driven engine with compact dashboard and plain-output frontends.

Public built-ins cover broadly applicable package and language managers. Additional organizations and users can add namespaced TOML catalogs under the platform configuration directory without rebuilding the binary.

The command updates itself only from authenticated stable-release manifests. Runtime release checks use native HTTPS and do not require Git, GitHub CLI, curl, wget, Python, authentication, or a source checkout.

See the repository [README](../../README.md) and [update-all documentation](../../docs/update-all.md) for installation, catalog authoring, result semantics, and the release trust model.

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

A failed or missing record is not proof that a package update did nothing.
Package managers may have partially changed their installations before failure
or cancellation. Free space, inspect the affected manager's state, and follow its
recovery procedure before retrying; do not infer success from a downloaded version
or automatically rerun every updater. This behavior applies with or without the
restart flag, and incomplete evidence always prevents an automatic restart.
