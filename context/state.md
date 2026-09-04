# Active work

- Use the admitted operation-only release path to rebuild, publish, install, and accept Update All 0.1.6 generation 7 and native sync-configs 0.2.0 generation 14 from the final merged source; the earlier `acd45e4` artifacts are superseded and must not be published.
- Run the current Syscfg manifest through installed native sync-configs twice and require the second pass to perform no configuration mutations or unnecessary authentication.
- Prove Linux strong-mode admission and transparent human passthrough across CLI, desktop, subagents, fresh shells, editors, signals, sandbox adapters, cache expiry, revocation, and no-human-fallback before making the full support claim.
- Run native macOS, Windows, and WSL acceptance before advertising those platforms as supported; their Dev Auth backends and native sync-configs targets remain unclaimed until native evidence exists.
- Decide separately whether Dev Auth should offer capability-scoped bounded privilege leases with hard and idle expiry, explicit revocation, workload binding, and native per-OS brokers; never implement this as global sudo-timestamp refresh, password handling, or an arbitrary root-command service.
