---
authority: canonical
owner: dev-auth
---

# ADR 0133: Native-account workstation configuration authority

status: proposed
verification: pending

## Decision

Dev Auth's credential-bearing workstation `config.toml` is a product-specific exception to the general XDG configuration-root selection in the Dev Tools product standard. On Linux and WSL it is selected from the effective native account record at `.config/dev-auth/config.toml`; on macOS it is selected at `Library/Application Support/dev-auth/config.toml` under that account record. Caller `HOME` and `XDG_CONFIG_HOME` cannot redirect this particular authority. Windows continues to use its current-user Roaming AppData known-folder authority. Runtime and cache locations remain subject to the platform's separately validated private-directory rules; this decision does not disable XDG for unrelated products or for non-authority cache placement.

The product opens one private, no-follow configuration snapshot and checks ownership, mode and filesystem custody before credential use. The native-account locator is shared with managed Git workspace-home resolution so path expansion and configuration do not disagree about the operating-system user. No environment override, hidden test path, or fallback to a caller-selected configuration is accepted.

## Migration and rollback

The default Linux and macOS locations are unchanged for users who did not set an alternate XDG/HOME root. An older installation that deliberately kept Dev Auth configuration only under an alternate environment-selected directory is not silently copied or imported: that path is caller-controlled and may contain a different authority. The operator must intentionally publish the reviewed configuration at the fixed native-account destination with the product's private-file custody, then run local validation before using credentials. The prior file is left untouched. Rolling back to an older binary restores that binary's former locator behavior; this candidate does not mutate or erase either configuration location. This exception remains until a separately approved versioned configuration migration supersedes it.

## Verification and remaining gates

The checks described below are retained source fixtures and historical topic evidence. They have not been rerun against this integrated source; native and signed acceptance remain pending.

Source tests assert the account-record destination. A Linux public CLI fixture runs under a disposable native-account record with conflicting `HOME` and `XDG_CONFIG_HOME`: `workspace-status` classifies its native-home workspace using only the native-home configuration, then refuses a valid alternate-environment configuration when the native-home file is absent. A separate unsigned installed-binary fixture in a rootful disposable systemd image repeats that same positive and negative selection against a real container account after full setup. Both are credential-free, and neither establishes a signed host installation. Native WSL and macOS checks must prove the fixed locator, independent credential store and private runtime without Windows or caller-environment fallback before platform support is claimed. Existing user-only public CLI fixtures that relied on `HOME` to simulate another native account must run under their disposable native-account boundary or use explicitly supplied source documents; changing a test environment variable is not native identity.
