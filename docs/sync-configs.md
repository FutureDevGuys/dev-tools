# sync-configs

`sync-configs` is a config-only convergence engine. It consumes an explicit trusted manifest and supports symlink and copy realization, recursive expansion and filters, permissions, JSON and TOML overlays, ownership receipts, removed-key reconciliation, trusted hooks, profiles, external profile maps, dry-run, validation, and structured value-free output.

Dry-run writes nothing and executes no hooks. The command never installs packages, applications, Dev Tools products, or itself.

The release artifact is a platform-neutral Python zip application containing its hash-locked Python dependency and third-party license. It requires Python 3.11 or newer, but does not resolve or install packages on the target host. Release builds normalize archive metadata and validate the artifact under `python -S` so globally installed packages cannot satisfy its imports.
