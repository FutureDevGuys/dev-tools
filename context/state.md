# Active work

- After live strong-mode cutover, use dev-auth's broker-backed manifest-signing operation to publish the prepared Update All 0.1.6 at generation 7 and sync-configs 0.1.13 at the next manifest generation; do not export the release key through a file or ambient environment.
- Publish and install dev-auth v0.3.7 with order-independent systemd socket activation, receipt-bound service-asset upgrades, bounded broker-readiness retry, and lock-free receipt validation on every unprivileged runtime path; v0.3.6 remains the live rollback line until the corrected release is accepted.
- Prove Linux strong-mode admission and transparent human passthrough across CLI, desktop, subagents, fresh shells, editors, signals, sandbox adapters, cache expiry, revocation, and no-human-fallback before changing normal launcher resolution.
- Prove the transient systemd workload boundary end to end, including private environment handoff, supervisor death, descendant cleanup, broker pidfd invalidation, and terminal/exit propagation.
- Run native macOS, Windows, and WSL acceptance before advertising those platforms as supported; their backends remain interface-only until native evidence exists.
