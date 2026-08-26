# Dev Tools

Reliable, inspectable tools for keeping a developer workstation current, fast, and reproducible across supported platforms.

Dev Tools is a product workspace, not a package manager and not a workstation configuration repository. Each command is independently installable and independently released.

![Update All dashboard showing six compact functional groups](docs/assets/update-all-dashboard.png)

| Product | Use it for |
|---|---|
| [`update-all`](docs/update-all.md) | Run supported package and tool updaters through one dependable plan and dashboard. |
| [`dev-cache`](docs/dev-cache.md) | Route known disposable build caches to storage you select without moving source or deliverables. |
| [`sync-configs`](docs/sync-configs.md) | Converge explicitly selected files, directories, and structured overlays from a trusted manifest. |
| [`skills-sync`](docs/skills-sync.md) | Reconcile installed agent skills and their links from an explicit lock and provider selection. |

## Installation

Verified release artifacts are the supported installation path. Every product uses its own nested release tag, such as `update-all/v1.2.3`. The Rust products require no Git, GitHub CLI, Python, curl, or wget on the target host. The platform-neutral `sync-configs` artifact bundles its Python dependencies and requires Python 3.11 or newer. Release publication remains gated while the signing and Linux acceptance workflow is established; until the first verified release exists, build from this private staging checkout with the development commands below.

| Platform | Status | Notes |
|---|---|---|
| Linux | Staging | Source validation is supported; signed binary releases are not published yet. |
| Windows | Acceptance pending | Artifacts may be built, but runtime support is not claimed until native Windows acceptance passes. |
| WSL | Acceptance pending | Runtime support is not claimed until the WSL acceptance harness passes. |
| macOS | Unclaimed | Some updater definitions are portable, but product runtime acceptance is not complete. |

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
python -m pytest sync-configs/tests
python sync-configs/scripts/build_zipapp.py
```

See the [documentation index](docs/README.md), [security policy](SECURITY.md), [contribution guide](CONTRIBUTING.md), and [license terms](LICENSE-MIT) ([Apache-2.0](LICENSE-APACHE)).

## Non-goals

- Dev Tools does not choose personal packages, applications, host profiles, desktop policy, or private updater tasks.
- It does not synchronize credentials, browser state, sessions, tunnels, or complete environment snapshots.
- It does not install timers, daemons, watchers, scheduled tasks, or a background updater.
- It does not silently adopt old product names, paths, or configuration.
