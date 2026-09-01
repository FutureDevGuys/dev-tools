# sync-configs

`sync-configs` converges an explicitly selected trusted configuration manifest. It handles copied and linked files, recursive entries and filters, permissions, JSON and TOML overlays, ownership receipts, removed-key reconciliation, trusted hooks, bounded native-sudo hooks and regular-file targets, profiles, external profile maps, validation, dry-run, and structured value-free reporting.

```sh
sync-configs --config ./manifest.yaml --profile desktop --dry-run
sync-configs --config ./manifest.yaml --profile desktop
```

Dry-run performs no writes and runs no hooks. `sync-configs` installs no packages, applications, public tools, or copies of itself. Personal manifests, host policy, generated configurations, hooks, and desired paths belong in the configuration repository that invokes it.

An entry may set `pre_script_privilege: sudo` or `post_script_privilege: sudo`. When any selected, non-dry-run entry requests that privilege, `sync-configs` authenticates the native sudo timestamp once, then invokes every declared privileged script through `sudo -n --`; selected user scripts remain unprivileged. No enabled privileged script means no sudo probe or prompt. The trusted manifest owns the command and privilege decision, while sudo remains the credential-cache and authorization authority.

On POSIX, a trusted manifest may also set `target_privilege: sudo` for one literal regular-file `copy` to an absolute target. The entry must explicitly declare `target_owner`, `target_group`, `target_parent_mode`, and `permissions.file`. `sync-configs` validates every selected privileged entry and compares content, ownership, group, and modes before authentication. A disabled, dry-run, blocked, or already-current target never probes sudo. A differing target reuses the run's single sudo session, is revalidated immediately before mutation, is staged beside the destination, atomically replaced, and verified exactly. Privileged target sources and target path components may not be symbolic links, and the resulting file and parent must remain readable and traversable by the invoking user so future no-op checks do not require elevation.

Grouped results remain buffered so summaries are deterministic. Informational records have their own group, and captured hook output uses the same colored, aligned group/name columns as entry results. On an interactive terminal, `sync-configs` prints one value-free progress line in those same colored, aligned columns before each selected pre- or post-script, identifying only its phase and declared entry labels; hook commands and captured output remain in the final grouped result. Noninteractive and JSON consumers receive no progress noise, and JSON stdout contains exactly one JSON document.

TOML overlays preserve intentional commented target keys by default, report their dotted paths without values, and support explicit `activate` or `error` policies. Generic mutually exclusive sibling groups prevent stale alternatives from surviving beside the selected source key. Root manifests may declare read-only JSON state preconditions so an owning configuration system can require its current layout generation before local overlays run.

See the workspace [sync-configs documentation](../docs/sync-configs.md) for the supported interface and trust boundary.
