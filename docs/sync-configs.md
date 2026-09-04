# sync-configs

`sync-configs` is a config-only convergence engine. It consumes an explicit trusted manifest and supports symlink and copy realization, recursive expansion and filters, permissions, JSON and TOML overlays, ownership receipts, removed-key reconciliation, trusted hooks, bounded native-sudo hooks and regular-file targets, profiles, external profile maps, dry-run, validation, and structured value-free output.

Results remain buffered into deterministic status groups. Informational records join their own group instead of appearing before the report, and captured hook output uses the same colored, aligned group/name columns as entry results. An interactive terminal receives one immediate value-free line in those same colored, aligned columns before each selected pre- or post-script so a long native or network hook cannot look frozen; the line contains only the phase and declared entry labels. Noninteractive and JSON consumers remain quiet until their normal result, and JSON stdout contains exactly one JSON document.

Dry-run performs no desired-state writes and executes no hooks; unless logging is disabled, it still records its diagnostic run. The command never installs packages, applications, Dev Tools products, or itself.

Normal convergence and validation return `0` when the selected operation completes, `1` for a validated convergence/check failure, and `2` for CLI parsing or invalid invocation. Ctrl-C requests orderly cancellation and returns `130` after owned hook/reconciler processes and temporary state are settled; repeated interrupts coalesce during cleanup, and an interrupt arriving after terminal finalization begins does not rewrite the published outcome. JSON convergence output uses one value-free document with `schema_version`, `outcome`, `exit_code`, `dry_run`, `profiles`, and, when present, structured reconciler results; an interrupted JSON run reports `outcome: interrupted` and `error_kind: interrupted`. Schema additions are additive within a major product line.

## Bounded diagnostics

Normal convergence creates one owner-only run directory beneath `$XDG_STATE_HOME/sync-configs/runs` on accepted Unix runtimes. Root precedence is `--log-root`, `SYNC_CONFIGS_LOG_ROOT`, then the platform default; an explicit root must be absolute. `run.json` records lifecycle, selected logging policy, outcome, and value-free counts. The default `events` style also writes `events.jsonl`; `transcript` writes `console.log`; and `both` writes both payloads. `off` creates nothing. Windows reserves `%LOCALAPPDATA%\sync-configs\runs` as its future root, but recording and log-management commands currently fail closed before storage access because inherited ACLs are not proof of owner-only custody; normal convergence degrades that diagnostic failure to a value-free warning. Windows logging remains disabled until an audited native DACL boundary and runtime acceptance exist.

Orchestrators may set `SYNC_CONFIGS_PARENT_RUN_ID` to another canonical run identifier to correlate child diagnostics. Invalid or free-form values are ignored rather than persisted.

Structured events deliberately contain no manifest path or value, environment value, credential, hook command, hook output, or arbitrary exception text. Entry labels are represented only by a short SHA-256 correlation identifier. `debug`, `info`, `warning`, `error`, and `critical` select the minimum event severity, with `info` as the default. A transcript is an explicit operator choice because it preserves the console text and may therefore contain sensitive hook output.

Events stop at 8 MiB and transcripts stop at 16 MiB. Finalization retains completed, failed, and interrupted runs for at most 30 days, 100 runs, and 128 MiB in aggregate; live or malformed run directories are not automatically deleted. `sync-configs logs list [--json]`, `sync-configs logs show RUN_ID`, and `sync-configs logs prune [--dry-run]` provide bounded inspection and explicit maintenance. Logging is diagnostic unmanaged state rather than a convergence postcondition: failure to create, append, finalize, or prune a run warns on stderr and does not convert a successful configuration run into failure.

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

For each selected entry, `sync-configs` runs only `reconcile plan --source PATH --output PLAN --format json`, `reconcile apply --plan PLAN --sha256 HEX --format json`, and `reconcile verify --source PATH --format json`. Plans stay in a private temporary directory and are removed after the terminal result. The owner tool must publish a nonempty, single-link, mode-`0600` regular plan owned by the native caller even when planning runs through sudo; `sync-configs` nofollow-opens and identity-stabilizes that plan before approving its digest. Subprocesses have fixed time and output bounds; their result must use the value-free `dev-tools-reconcile-result-v1` schema. Human output uses the existing group, color, and summary presentation. JSON output includes structured reconciler results and never includes captured owner-tool output. Dry-run executes planning for user-privileged reconcilers and never applies; a sudo reconciler is reported as deferred because dry-run never authenticates. A sudo reconciler shares the same one-time native sudo session used by privileged hooks.

The owner tool remains solely responsible for domain validation, action planning, mutation, receipts, and verification. In particular, the dev-auth reconciler manages only the current user configuration; it cannot install dev-auth, alter administrator policy, manage services, activate same-name launchers, or enroll credentials.

The release candidate is the native `sync-configs` executable built from the workspace crate with `cargo build --release --locked --bin sync-configs`; target hosts do not need Python or a package resolver. Release-set construction reads the product version from Cargo metadata and signs one exact target-specific artifact under the independent `sync-configs/vX.Y.Z` tag. Windows artifacts use the `sync-configs.exe` executable name. Linux x86-64 is the only target admitted to the current cutover, but its public support claim remains pending until the signed generation completes installation, rollback, and native runtime acceptance. The release builder, signer, publisher, and installer reject every other `sync-configs` runtime meanwhile.

Fresh installations and native steady state have no Python dependency. During a managed upgrade from the retained Python `sync-configs 0.1.13` artifact, keep that interpreter available through adoption and the rollback window: Update All health-checks the prior artifact before replacing it and again before rolling back to it. A command installed outside Update All's product root (for example through pip or pipx) remains externally managed and is reported rather than overwritten; migrate that installation deliberately before expecting authenticated native activation.

## Native one-shot operations

The same native executable exposes focused operations for trusted callers that do not need a manifest: `sync-configs json-overlay SOURCE TARGET`, `sync-configs toml-overlay SOURCE TARGET`, and `sync-configs managed-path-policy SOURCE TARGET`. Overlay commands retain `--dry-run` and `--check`; check exits `1` when a write would be required. JSON supports repeatable `--replace-json-pointer` plus receipt-backed removed-key reconciliation. TOML supports source- or target-wins conflicts, comment policy, receipt-backed removed-key reconciliation, and `--remove` for exact source-owned keys. The classifier supports safe, strict, and takeover policies plus an optional recognized skeleton and human or JSON output. These are native subcommands, not Python module entrypoints or compatibility shims.

`sync-configs completion bash|zsh|fish|elvish|powershell` emits a first-party completion definition for the complete native CLI.

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

When mutation is required, `sync-configs` acquires or reuses one native sudo timestamp for the entire run. It revalidates the complete active privileged-target batch before authentication, then revalidates source, target, and parent identities immediately before each mutation, applies parent metadata only when needed, installs the candidate into a same-directory temporary regular file, verifies its digest and metadata, and atomically replaces the target. It then verifies the complete postcondition. A failed or interrupted staged install settles its adjacent temporary candidate before returning; drift, unsafe paths, malformed state, and failed verification stop closed. `sync-configs` never runs its whole process as root, and the public engine contains no caller-specific destinations or policy.

## Privileged hooks

Trusted entries may independently set `pre_script_privilege: sudo` or `post_script_privilege: sudo`; the default is `user`. After profile selection, a normal run requests one native sudo timestamp immediately before the first eligible privileged phase: before a privileged pre-hook, before target/reconciler mutation that needs sudo, or before a privileged post-hook only when that entry actually converged successfully. Existing cached authorization is reused; dry-run, disabled profiles, ineligible post-hooks, blocked/no-op targets, and unselected reconcilers never authenticate. An unavailable or rejected session stops before the affected mutation boundary. The manifest remains the sole authority for which command is elevated, and sudo remains the sole credential cache and authorization boundary. The selected sudo binary, elevated shell, privileged-target helpers, and sudo reconciler executable must resolve through root-owned, non-group/world-writable files and ancestor paths; user-writable aliases are rejected during preflight and before authentication.

Each user hook receives closed stdin, the environment captured when the run was planned, a five-minute timeout, and independent 16 MiB stdout/stderr result bounds. A privileged hook launches `sudo` from that captured environment, but the environment visible after elevation remains governed by the host's sudo policy; `sync-configs` does not bypass `env_reset` or forward arbitrary variables as command-line values. A hook timeout or limit failure is value-free in structured status. On Unix the shared command runner owns the hook process group and terminalizes it before returning; platforms without an accepted descendant-containment primitive must not claim equivalent process-tree cleanup from compilation alone.

```yaml
entries:
  - name: native-consumer-hooks
    source: ./hook-reconciler
    target: ~/.local/libexec/example/hook-reconciler
    mode: copy
    pre_script: /usr/local/libexec/example-hook-reconciler apply --scope system
    pre_script_privilege: sudo
    post_script: ~/.local/libexec/example-hook-reconciler apply --scope user
    post_script_privilege: user
```
