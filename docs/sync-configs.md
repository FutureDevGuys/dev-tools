# sync-configs

`sync-configs` is a config-only convergence engine. It consumes an explicit trusted manifest and supports symlink and copy realization, recursive expansion and filters, permissions, JSON and TOML overlays, ownership receipts, removed-key reconciliation, trusted hooks, optional native-sudo hook execution, profiles, external profile maps, dry-run, validation, and structured value-free output.

Results remain buffered into deterministic status groups. Informational records join their own group instead of appearing before the report, and captured hook output uses the same colored, aligned group/name columns as entry results. An interactive terminal receives one immediate value-free line in those same colored, aligned columns before each selected pre- or post-script so a long native or network hook cannot look frozen; the line contains only the phase and declared entry labels. Noninteractive and JSON consumers remain quiet until their normal result, and JSON stdout contains exactly one JSON document.

Dry-run writes nothing and executes no hooks. The command never installs packages, applications, Dev Tools products, or itself.

## Typed external reconcilers

The fixed `dev-tools-reconcile-v1` protocol lets an owner tool reconcile its own user configuration without turning `sync-configs` into an orchestration language. A reconciler entry declares one absolute executable, one desired-state source, a user or system scope, user or sudo privilege, and the fixed protocol identifier. Arbitrary commands, flags, shell strings, and templates are rejected.

```yaml
reconcilers:
  - name: dev-auth-user-config
    group: Identity
    subgroup: Dev Auth
    executable: /usr/local/bin/dev-auth
    source: ./dev-auth/config-v2.toml
    scope: user
    privilege: sudo
    protocol: dev-tools-reconcile-v1
```

For each selected entry, `sync-configs` runs only `reconcile plan --source PATH --output PLAN --format json`, `reconcile apply --plan PLAN --sha256 HEX --format json`, and `reconcile verify --source PATH --format json`. Plans stay in a private temporary directory and are removed after the terminal result. The owner tool must publish a nonempty, single-link, mode-`0600` regular plan owned by the native caller even when planning runs through sudo; `sync-configs` nofollow-opens and identity-stabilizes that plan before approving its digest. Subprocesses have fixed time and output bounds; their result must use the value-free `dev-tools-reconcile-result-v1` schema. Human output uses the existing group, color, and summary presentation. JSON output includes structured reconciler results and never includes captured owner-tool output. Dry-run executes planning only. A sudo reconciler shares the same one-time native sudo session used by privileged legacy hooks.

The owner tool remains solely responsible for domain validation, action planning, mutation, receipts, and verification. In particular, the dev-auth reconciler manages only the current user configuration; it cannot install dev-auth, alter administrator policy, manage services, activate same-name launchers, or enroll credentials.

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
