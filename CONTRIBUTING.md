# Contributing

Changes should preserve product independence, deterministic behavior, fail-closed boundaries, value-free logs, and the documented platform support claims. Add tests for changed behavior, update the relevant product documentation, and run the validation commands in [docs/development.md](docs/development.md).

Public built-in updater tasks must solve a broadly applicable problem through a supported upstream interface, be reliably detectable, require no private paths or helpers, and have safe unattended or explicit prompted behavior.
