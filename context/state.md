# Active work

- Finish dev-auth v0.3 standalone release and clean-device acceptance, then perform a reversible one-workload-at-a-time rollout. Keep the installed stable release reversible until rollback acceptance passes.
- Prove Linux strong-mode admission and transparent human passthrough across CLI, desktop, subagents, fresh shells, editors, signals, sandbox adapters, cache expiry, revocation, and no-human-fallback before changing normal launcher resolution.
- Prove the root-owned transient systemd workload boundary end to end, including private environment handoff, supervisor SIGKILL, descendant cleanup through `KillMode=control-group`, broker pidfd invalidation, and terminal/exit propagation, before strong-mode acceptance.
- Run native macOS, Windows, and WSL acceptance before advertising those platforms as supported; their backends remain interface-only until native evidence exists.
