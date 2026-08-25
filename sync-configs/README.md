# sync-configs

`sync-configs` converges an explicitly selected trusted configuration manifest. It handles copied and linked files, recursive entries and filters, permissions, JSON and TOML overlays, ownership receipts, removed-key reconciliation, trusted hooks, profiles, external profile maps, validation, dry-run, and structured value-free reporting.

```sh
sync-configs --config ./manifest.yaml --profile desktop --dry-run
sync-configs --config ./manifest.yaml --profile desktop
```

Dry-run performs no writes and runs no hooks. `sync-configs` installs no packages, applications, public tools, or copies of itself. Personal manifests, host policy, generated configurations, hooks, and desired paths belong in the configuration repository that invokes it.

See the workspace [sync-configs documentation](../docs/sync-configs.md) for the supported interface and trust boundary.
