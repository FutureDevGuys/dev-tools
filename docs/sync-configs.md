# sync-configs

`sync-configs` is a config-only convergence engine. It consumes an explicit trusted manifest and supports symlink and copy realization, recursive expansion and filters, permissions, JSON and TOML overlays, ownership receipts, removed-key reconciliation, trusted hooks, bounded native-sudo hooks and regular-file targets, profiles, external profile maps, dry-run, validation, and structured value-free output.

Results remain buffered into deterministic status groups. Informational records join their own group instead of appearing before the report, and captured hook output uses the same colored, aligned group/name columns as entry results. An interactive terminal receives one immediate value-free line in those same colored, aligned columns before each selected pre- or post-script so a long native or network hook cannot look frozen; the line contains only the phase and declared entry labels. Noninteractive and JSON consumers remain quiet until their normal result, and JSON stdout contains exactly one JSON document.

Dry-run writes nothing and executes no hooks. The command never installs packages, applications, Dev Tools products, or itself.

The release artifact is a platform-neutral Python zip application containing its hash-locked Python dependency and third-party license. It requires Python 3.11 or newer, but does not resolve or install packages on the target host. Release builds normalize archive metadata and validate the artifact under `python -S` so globally installed packages cannot satisfy its imports.

## Comment-aware TOML overlays

TOML overlays default to `commented_target_policy: respect`. When the target already contains a recognizable commented assignment, or a commented table header covering a source assignment, that source path stays inactive. The final plain report lists only dotted paths under `Suppressed by comments`; it never includes their values. Leading whitespace before `#` is supported. Use `activate` only when comments are documentation rather than an intentional disabled state, or `error` when any suppression must block the run.

```yaml
entries:
  - name: provider-config
    source: ./provider.toml
    target: ~/.config/example/config.toml
    mode: toml_overlay
    commented_target_policy: respect
    mutually_exclusive_sibling_keys:
      - under: providers.*
        keys: [auth, env_key]
```

`mutually_exclusive_sibling_keys` is a generic semantic constraint. Each `under` path may contain `*` for one table level. If the effective source activates one listed key, the overlay removes target-only active siblings from that group while preserving unrelated target-only keys. More than one active source key in a group fails before writing. A source key suppressed by a respected target comment is not active and therefore does not displace another live sibling.

JSON has no standard comment syntax, so JSON overlays do not implement comment suppression. Another comment-capable format may adopt the same `respect|activate|error` contract when its parser can identify comments without guessing.

## Declarative state preconditions

Callers may require a non-secret JSON state contract before any entry is processed:

```yaml
state_preconditions:
  - type: json_fields
    path: ~/.local/state/example/state.json
    fields:
      current_version: 2
      pending: null
    remediation: Run the owner's full convergence command.
```

The check is read-only in normal and dry-run modes. Missing, invalid, or mismatched state stops before hooks or writes and reports only the path, mismatched field names, and caller-authored remediation. The owning system—not `sync-configs`—must create or advance the state.

## Privileged regular-file targets

On POSIX, a trusted manifest may request one bounded elevated realization with `target_privilege: sudo`. The initial contract admits only a literal regular-file source, `mode: copy`, and a literal absolute target. The entry must explicitly declare the target owner, group, parent-directory mode, and file mode:

```yaml
entries:
  - name: system-policy
    source: ./system/example.conf
    target: /etc/example/example.conf
    mode: copy
    target_privilege: sudo
    target_owner: root
    target_group: root
    target_parent_mode: "0755"
    permissions:
      file: "0644"
    reconcile_existing: true
```

`target_privilege` accepts `user` (the default) or `sudo`. The `target_owner`, `target_group`, and `target_parent_mode` fields are valid only with `sudo`; `permissions.file` remains the target file-mode declaration. Privileged targets reject relative targets, globs, directories, filters, overlays, source permission changes, per-entry scripts, symbolic-link sources, symbolic-link targets, and symbolic-link target parents. The declared owner and group must exist. The resulting parent must remain traversable and the file readable by the invoking user, because planning and no-op verification deliberately occur without elevation. `target_parent_mode` governs the parent directory mode only; existing parent ownership is preserved rather than inferred from the file target.

All selected privileged entries are validated before authentication. The planner compares source content with target content and checks the target's user, group, and mode plus the parent directory's user, group, and mode. Disabled profiles, dry-run, existing-content conflicts, and exact postconditions execute no sudo command. Differing existing content follows the ordinary copy authority boundary: set `reconcile_existing: true` or deliberately select the takeover managed-path policy to replace it.

When mutation is required, `sync-configs` acquires or reuses one native sudo timestamp for the entire run. It revalidates source, target, and parent identities immediately before mutation, applies parent metadata only when needed, installs the candidate into a same-directory temporary regular file, verifies its digest and metadata, and atomically replaces the target. It then verifies the complete postcondition. A failed staged install leaves the prior target untouched; drift, unsafe paths, malformed state, and failed verification stop closed. `sync-configs` never runs its whole process as root, and the public engine contains no caller-specific destinations or policy.

## Privileged hooks

Trusted entries may independently set `pre_script_privilege: sudo` or `post_script_privilege: sudo`; the default is `user`. After profile selection, a normal run requests one native sudo timestamp only when at least one enabled script needs it, then runs each privileged script through `sudo -n --`. Existing cached authorization is reused, dry-run and disabled profiles never authenticate, and an unavailable or rejected sudo session stops before hooks or file convergence. The manifest remains the sole authority for which command is elevated, and sudo remains the sole credential cache and authorization boundary.

```yaml
entries:
  - name: native-consumer-hooks
    source: ./hook-reconciler
    target: ~/.local/libexec/example/hook-reconciler
    mode: copy
    pre_script: python ./hook-reconciler apply --scope system
    pre_script_privilege: sudo
    post_script: ~/.local/libexec/example/hook-reconciler apply --scope user
    post_script_privilege: user
```
