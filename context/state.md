# Active work

- After live strong-mode cutover, use dev-auth's broker-backed manifest-signing operation to publish the prepared Update All 0.1.6 at generation 7 and sync-configs 0.1.13 at the next manifest generation; do not export the release key through a file or ambient environment.
- Complete live Linux acceptance for the released standalone dev-auth v0.3.6 setup, receipt-owned installation and rollback, global native-passthrough plus workload-private Git/gh routing, sandbox adapters, and thin Syscfg/sync-configs clients; preserve installed v0.2.7 as the rollback line until cutover acceptance closes.
- Prove Linux strong-mode admission and transparent human passthrough across CLI, desktop, subagents, fresh shells, editors, signals, sandbox adapters, cache expiry, revocation, and no-human-fallback before changing normal launcher resolution.
- Prove the transient systemd workload boundary end to end, including private environment handoff, supervisor death, descendant cleanup, broker pidfd invalidation, and terminal/exit propagation.
- Run native macOS, Windows, and WSL acceptance before advertising those platforms as supported; their backends remain interface-only until native evidence exists.
