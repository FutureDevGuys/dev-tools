# Reusable bounded maintenance authority

The execution follow-on provides direct `privilege inspect|exec|delegate|leave` aliases using the same administrator grammar. Maintenance request/status/revoke keep their meaning; administrator equivalents stay explicitly under `privilege grant`. Planned execution may select integer `output_limit_bytes` from 1 to 16777216, bound into its exact plan digest. Capped plans require graph selection; native Sudo argv cannot bypass capture. Counts aggregate externally forwarded stdout/stderr/PTY output and exclude internal pipes and terminal input. Overflow, failed transport or bounded drain/cleanup failure stops only the owned job and cannot publish success.

Ordinary strong workload launch can explicitly request fresh administrator approval with `--privilege-scope user|workload --privilege-duration DURATION`. Noninteractive use returns approval-required before starting anything. A pending grant is unusable until native target exec is proved and activation succeeds; the target remains kernel-stopped until release. Workload authority and hard deadlines remain independent. See [ADR 0119](adr/0119-bounded-grant-output-and-native-launch-activation.md); source integration does not qualify installed support.

The separate administrator source family is `dev-auth privilege grant request|status|inspect|exec|delegate|revoke|leave`. Its policy is `dev-auth-administrator-grant-policy-v1` at `/etc/dev-auth/administrator-grants-v1.json`; its runtime is `/run/dev-auth-grants`. These inputs preserve the maintenance policy and runtime described below. Generate the default deny-all input with `dev-auth setup template administrator-grant-policy`, then select privilege-only or combined full setup explicitly. An absent embedded source-matched sudo bridge blocks component activation. See [ADR 0115](adr/0115-native-administrator-grants-with-maintenance-compatibility.md) and [ADR 0116](adr/0116-retained-grant-setup-and-explicit-empty-native-files.md) for scope, approval, migration and pending native gates.

Candidate administrator plans also define optional per-command `run_as`, `stdin`, `stdout` and `stderr` fields. `run_as` contains numeric `uid`, `gid` and required `supplementary_groups`; an empty group list clears inherited groups. Streams select `"inherit"` or `"null"`. Omission or JSON null preserves the existing canonical plan and defaults, while every explicit selection changes the approval digest and requires graph execution. A pipe producer's stdout and consumer's stdin must be omitted so approved stream choices cannot be overwritten. Null streams use a retained host null-device descriptor. Direct argv and native Sudo cannot reinterpret selected plan effects. See [ADR 0122](adr/0122-exact-plan-node-identity-and-streams.md).

A terminal-selected graph runs each ready pipe component in one foreground process group, preserves binary pipes and dependency order, and relays stop/resume while retaining the original grant deadline. The independent grant owner remains responsible for expiry while the worker is stopped. Nonterminal execution retains its existing graph schedule. These terminal and identity/stream changes have source fixtures; compilation, focused behavior tests and approved native execution remain pending. See [ADR 0121](adr/0121-terminal-command-graph-custody.md).

The 0.5 candidate source implements the request/execute lifecycle for reusable typed/exact-plan maintenance sessions. The finite receipt-install production adapter is implemented in source; native qualification remains pending, so this is not a released administrator-session capability. The installed 0.4 credential workload grant still runs its payload as the native user.

A root policy declares exact operation variants and their resource audience. Arbitrary helper labels are rejected. Ordinary builds admit only the closed [receipt-install adapter](dev-tools-receipt-install-v1.md); the disposable fixture protocol is available only in the explicit native-test build. A request can narrow that policy. One native administrator approval starts a new non-root controller; its descendants may execute the approved operations repeatedly within the shared/per-operation budgets and fixed lifetime. Ordinary processes outside that controller cannot execute by copying its session ID.

```text
dev-auth privilege plan --request /absolute/private/request.json --output /absolute/private/approval.json --json
dev-auth privilege request --plan /absolute/private/approval.json --sha256 APPROVED_DIGEST --authorize polkit -- /absolute/native/controller ARGUMENTS...
dev-auth privilege execute-plan --session SESSION --operation OPERATION --plan-id PLAN
dev-auth privilege execute --session SESSION --operation OPERATION --request /absolute/private/operation.json
dev-auth privilege status --session SESSION --json
dev-auth privilege revoke --session SESSION --json
```

Inside the admitted controller, omitting `--session` uses the routing selector in `DEV_AUTH_PRIVILEGE_SESSION`. The receiver still verifies kernel identity and cgroup membership. The initial typed request shape is `{"schema":"dev-auth-privilege-operation-v1","plan":"PLAN"}`; it cannot insert new argv, input or resource authority. The request's idle/hard caps and total/per-operation uses are explicit. The current hard cap remains eight hours. One in-flight operation is supported; later calls reuse the grant without new approval.

Policy is separate from credentials and defaults to absent/deny. An empty `capabilities` map is an explicit deny-all document. Installing or changing it is a root-only, digest-bound setup operation; `update-privilege-policy` also requires the exact current digest. Helper installation is not a grant.

```text
dev-auth setup install-privilege-policy --source /absolute/root-owned/policy.json --sha256 APPROVED_DIGEST
dev-auth setup update-privilege-policy --source /absolute/root-owned/policy.json --sha256 APPROVED_DIGEST --current-sha256 CURRENT_DIGEST
```

The privileged execution profile retains the kernel-owned core pattern and rejects socket collectors (`@`, including `@@`) and unsupported/ambiguous patterns. Absolute pipe collectors are supported by the process-local Linux recursion guard: soft and hard RLIMIT_CORE are exactly1 before native exec, and inherited argument-aware seccomp rules deny every subsequent core-limit write, including lowering to0, truncated resource arguments and nonnull high-only pointers. Read-only queries remain allowed. Trusted bootstrap/coordinator/wrapper startup uses inherited/systemd limit1 and early DUMPABLE0. The non-root caller's hard CORE limit must permit1; a hard0 fails readiness rather than falling back.

This preserves the host's existing crash collector. No sysctl or ordinary credential-workload setting changes. Socket collectors have no equivalent guard and remain unsupported. Native support requires the [collector-negative matrix](../crates/dev-auth/tests/support/CORE-NATIVE.md), including live positive controls, descendant exec and trusted infrastructure crashes. Source checks alone do not qualify pipe support. See the official [Linux v6.17 coredump implementation](https://github.com/torvalds/linux/blob/v6.17/fs/coredump.c) and [Unix socket collector routing](https://github.com/torvalds/linux/blob/v6.16/net/unix/af_unix.c).

The privileged execution profile is deliberately bounded. It uses approved held filesystem resources, private namespaces, restricted capabilities and syscall rules. It does not provide an unrestricted host-root shell, service manager, container manager or network client. Exact argv alone is not effect containment. Verify the real helper's resource and execution requirements before adopting it, and never disguise an incompatible broad command as a reviewed operation.

Expiry and revocation cannot undo completed effects. Successful cleanup requires positive kernel evidence for all retained domains; an incomplete/failed observation remains unsuccessful. Terminal observation files contain no reusable grant. Restart never restores a lease.

## Native acceptance harness

Build the opt-in non-installed subjects with `--features native-privilege-fixture`. Ordinary source testing can run `kernel_boot_deadline_kills_even_a_stopped_coordinator_process`; it starts only an unprivileged child and tests the independent kernel timer.

`public_reusable_session_approval_execution_and_terminal_cleanup` is ignored by default. It requires an explicitly prepared disposable systemd/cgroup-v2 fixture, an installed candidate with receipt-owned maintenance assets, a native non-root observer and real administrator approval. It does not install policy, create accounts, alter polkit approval or create an unattended grant itself.

Provide `DEV_AUTH_NATIVE_PRIVILEGE_FIXTURE=disposable` and a caller-owned mode-0600 `DEV_AUTH_NATIVE_PRIVILEGE_INPUT` document with schema `dev-auth-privilege-native-input-v1`, absolute `dev_auth`, `fixture_binary`, `fixture_root`, `approval_plan`, approved digest and `case`. The fixture root is a fresh caller-owned mode-0700 `/var/tmp/dev-auth-privilege-native-*` directory. All approved resources must be within it. The helper executable must be the separately verified compiled fixture binary.

Use one fresh grant/root for each finite case in `crates/dev-auth/tests/support/PRIVILEGE-NATIVE.md`. The opt-in `dev-auth-native-fixture-v1` protocol admits only `dev-auth-privilege-native-fixture`, fixed helper verbs, one `/var/tmp/dev-auth-privilege-native-*/scope` resource and a single target leaf. It cannot be used to bless another executable or a host execution-hook resource. Root policy remains separately installed and each grant still requires real administrator approval.

The runnable matrix includes reuse, expiry, revocation, identity/custody faults, death paths, replay/busy/exhaustion, blocked streams, cleanup uncertainty and signal fidelity. Signed setup upgrade/restore fixtures are in `setup_v3/recovery_native/signed.rs`. A source-only pass does not execute those ignored native cases. Actual suspend/resume and real maintenance compatibility remain separate recorded acceptance gates; test-feature synthetic helpers do not qualify the production adapter.

## Production maintenance adapter

The optional [standalone receipt-install contract](dev-tools-receipt-install-v1.md) covers exact root-owned tool status, install/replacement, journal-bound resume and explicitly approved reverse replacement in a dedicated system target. It reuses the existing receipt/journal installer. A separately approved root executor record and independent candidate/predecessor evidence are prerequisites; the source build neither deploys nor grants them. The real-artifact native matrix is [RECEIPT-NATIVE.md](../crates/dev-auth/tests/support/RECEIPT-NATIVE.md), separate from the synthetic27-case matrix.

Public Update All offline product installation uses the invoking account's HOME/XDG_STATE_HOME layout. Changing its UID would change custody and remains unsupported. Dev Auth cannot modify its own helper/policy/setup generation while its reusable grant holds shared exclusion; self-upgrade uses the existing signed setup route after cleanup. The dedicated receipt installer's journal lock is independent of this exclusion. Native qualification and a real approved root deployment remain required before claiming installed maintenance support.
