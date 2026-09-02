# Active work

- Publish the prepared Update All 0.1.6 artifact at manifest generation 7 and prepare sync-configs 0.1.13 at the next manifest generation after the generic dev-auth/1Password release-key projection is available; do not export the release key through an ad hoc file or ambient environment workaround.
- Complete dev-auth v0.3 as a standalone transparent Linux workload-identity broker, including authenticated setup-plan v3, receipt-owned installation and rollback, strong workload admission, sandbox adapters, standalone clean-device acceptance, and thin Syscfg/sync-configs clients; preserve v0.2.8 as the rollback line until cutover acceptance closes.
- Prove Linux strong-mode admission and transparent human passthrough across CLI, desktop, subagents, fresh shells, editors, signals, sandbox adapters, cache expiry, revocation, and no-human-fallback before changing normal launcher resolution.
- Prove the transient systemd workload boundary end to end, including private environment handoff, supervisor death, descendant cleanup, broker pidfd invalidation, and terminal/exit propagation.
- Run native macOS, Windows, and WSL acceptance before advertising those platforms as supported; their backends remain interface-only until native evidence exists.
