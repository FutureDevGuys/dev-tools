# Reusable bounded maintenance authority

The 0.5.2 release provides direct `privilege inspect|exec|delegate|leave` aliases using the same administrator grammar. Maintenance request/status/revoke keep their meaning; administrator equivalents stay explicitly under `privilege grant`. Planned execution may select integer `output_limit_bytes` from 1 to 16777216, bound into its exact plan digest. Capped plans require graph selection; native Sudo argv cannot bypass capture. Counts aggregate externally forwarded stdout/stderr/PTY output and exclude internal pipes and terminal input. Overflow, failed transport or bounded drain/cleanup failure stops only the owned job and cannot publish success.

Ordinary strong workload launch can explicitly request fresh administrator approval with `--privilege-scope user|workload --privilege-duration DURATION`. Noninteractive use returns approval-required before starting anything. A pending grant is unusable until native target exec is proved and activation succeeds; the target remains kernel-stopped until release. Workload authority and hard deadlines remain independent. See [ADR 0119](adr/0119-bounded-grant-output-and-native-launch-activation.md); source integration does not qualify installed support.

The separate administrator source family is `dev-auth privilege grant request|status|inspect|exec|delegate|revoke|leave`. Its policy is `dev-auth-administrator-grant-policy-v1` at `/etc/dev-auth/administrator-grants-v1.json`; its runtime is `/run/dev-auth-grants`. These inputs preserve the maintenance policy and runtime described below. Generate the default deny-all input with `dev-auth setup template administrator-grant-policy`, or authorize one account as in [authorizing an account for administrator grants](#authorizing-an-account-for-administrator-grants), then select privilege-only or combined full setup explicitly. An absent embedded source-matched sudo bridge blocks component activation. See [ADR 0115](adr/0115-native-administrator-grants-with-maintenance-compatibility.md) and [ADR 0116](adr/0116-retained-grant-setup-and-explicit-empty-native-files.md) for scope, approval, migration and pending native gates.

Administrator plans in the 0.5.2 release also define optional per-command `run_as`, `stdin`, `stdout` and `stderr` fields. `run_as` contains numeric `uid`, `gid` and required `supplementary_groups`; an empty group list clears inherited groups. Streams select `"inherit"` or `"null"`. Omission or JSON null preserves the existing canonical plan and defaults, while every explicit selection changes the approval digest and requires graph execution. A pipe producer's stdout and consumer's stdin must be omitted so approved stream choices cannot be overwritten. Null streams use a retained host null-device descriptor. Direct argv and native Sudo cannot reinterpret selected plan effects. See [ADR 0122](adr/0122-exact-plan-node-identity-and-streams.md).

A terminal-selected graph runs each ready pipe component in one foreground process group, preserves binary pipes and dependency order, and relays stop/resume while retaining the original grant deadline. The independent grant owner remains responsible for expiry while the worker is stopped. Nonterminal execution retains its existing graph schedule. The `run_as` and stream selections have focused behavior tests; approved native execution of these terminal and identity/stream changes remains pending. See [ADR 0121](adr/0121-terminal-command-graph-custody.md).

The 0.5.2 release implements the request/execute lifecycle for reusable typed/exact-plan maintenance sessions and includes the finite receipt-install production adapter. Native qualification remains pending, so the release does not claim a supported administrator-session capability. A credential workload grant still runs its payload as the native user.

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

## Authorizing an account for administrator grants

`dev-auth setup template administrator-grant-policy --user NAME --maximum-duration DURATION` prints the deny-all policy with exactly one subject: the named existing non-root account, resolved to its numeric uid through the native account database. By default that account may request `user` and `workload` scopes with `administrator` authority for at most the maximum duration, and cannot delegate. Repeat `--scope` to choose scopes explicitly and add `--allow-delegation` to permit narrowed delegation. The command prints nothing and fails for a missing or root account, a zero or malformed duration, or any subject that the policy's own validation refuses. The document keeps the schema's `/usr/bin/sudo`, the only sudo program setup accepts. Outside Linux the options are unsupported. The 0.5.2 release prints only the deny-all template; these options are in its successor source. The policy document itself does not depend on the binary that wrote it.

Review the document, then install it where only root can change it. Setup reads only a regular, singly linked source that is not group- or world-writable.

```text
dev-auth setup template administrator-grant-policy --user account-name --maximum-duration 12h > /absolute/private/administrator-grants-v1.json
sudo install -d -m 0755 /etc/dev-auth/source
sudo install -m 0644 /absolute/private/administrator-grants-v1.json /etc/dev-auth/source/administrator-grants-v1.json
```

Privilege-only planning runs as root from the exact signed release executable it selects. The [standalone setup guide](dev-auth-v0.3.md) shows how to plan with a downloaded release, including the offline bundle form. Apply the `sha256` digest that planning prints. The grant coordinator runs only with `--activation transparent`; `inactive` installs the component stopped. A first strong installation applies as root, which also installs the receipt-owned setup helper.

```text
sudo dev-auth setup plan --purpose privilege-only --mode strong --channel stable --activation transparent --grant-policy /etc/dev-auth/source/administrator-grants-v1.json --output /run/dev-auth-setup-plan.json --format json
sudo dev-auth setup apply --plan /run/dev-auth-setup-plan.json --sha256 APPROVED_DIGEST --format json
```

To add grants to an existing credential installation, plan from its deployment document with `--grant-policy`. Writing `grant_policy` into the document instead also requires the `dev-auth-deployment-v2` schema, as `dev-auth setup template credential-grant-deployment` shows. Setup preserves the credential purpose, accounts and credential actions. The document's `activation` controls the grant coordinator and the credential `git` and `gh` launchers together, so the coordinator runs only when it is `transparent`.

```text
sudo dev-auth setup plan --deployment /absolute/source/deployment.toml --grant-policy /etc/dev-auth/source/administrator-grants-v1.json --output /run/dev-auth-setup-plan.json --format json
sudo dev-auth setup apply --plan /run/dev-auth-setup-plan.json --sha256 APPROVED_DIGEST --format json
```

Once the installed setup helper comes from the 0.5.2 release or later, the native account can apply either plan without running as root by replacing `sudo` with `--authorize polkit` or `--authorize sudo`. An older helper cannot read these plans, so apply as root. PolicyKit authorization also needs a root-owned `/usr/bin/pkexec` and accepts credential files but not `--credential-stdin`.

```text
dev-auth setup apply --plan /run/dev-auth-setup-plan.json --sha256 APPROVED_DIGEST --authorize polkit
```

The authorized account then requests a grant. Each request needs fresh native administrator approval, and its duration cannot exceed the policy maximum.

```text
dev-auth privilege grant request --scope user --authority administrator --duration 12h
dev-auth privilege grant status
dev-auth privilege grant revoke GRANT_ID
dev-auth privilege grant leave
```

`status` observes only the caller's grants. `revoke` ends one grant and terminates its privileged descendants. `leave` ends the selected grant, and with no selected grant it changes nothing. Managed sudo routing ends with its grant, however the grant ends, and sudo then has its native behavior. A user grant ends at logout only when logind reports that the account has no interactive session. A command that native sudo started keeps running if sudo exits or its completion channel closes, until the command exits or its grant ends. See [ADR 0136](adr/0136-grant-lifetime-sudo-routing-and-job-survival.md). When the sudo plugin refuses an invocation, it prints one line with the reason and the step that restores native sudo. A failure that belongs to one grant never stops the coordinator. If the coordinator itself exits, every grant ends and the service manager stops every managed job. See [ADR 0137](adr/0137-coordinator-fault-containment-and-sudo-refusal-reasons.md). If the grant policy or the sudo program changes, the coordinator admits nothing new, keeps `status`, `revoke` and `leave` working, and lets running jobs finish under their grants. It then exits, and the service manager starts a coordinator that binds the new state. A look at native state that fails is retried and never ends a grant. When the coordinator accepts a sudo connection but does not answer, an account that it does not route has native sudo. See [ADR 0138](adr/0138-trust-change-drain-and-observed-supervision.md). Native grant, sudo, guardian and signed setup acceptance remain pending under ADR 0115 and ADR 0116, so this path is not an installed-support claim.

## Native acceptance harness

Build the opt-in non-installed subjects with `--features native-privilege-fixture`. Ordinary source testing can run `kernel_boot_deadline_kills_even_a_stopped_coordinator_process`; it starts only an unprivileged child and tests the independent kernel timer.

`public_reusable_session_approval_execution_and_terminal_cleanup` is ignored by default. It requires an explicitly prepared disposable systemd/cgroup-v2 fixture, an installed candidate with receipt-owned maintenance assets, a native non-root observer and real administrator approval. It does not install policy, create accounts, alter polkit approval or create an unattended grant itself.

Provide `DEV_AUTH_NATIVE_PRIVILEGE_FIXTURE=disposable` and a caller-owned mode-0600 `DEV_AUTH_NATIVE_PRIVILEGE_INPUT` document with schema `dev-auth-privilege-native-input-v1`, absolute `dev_auth`, `fixture_binary`, `fixture_root`, `approval_plan`, approved digest and `case`. The fixture root is a fresh caller-owned mode-0700 `/var/tmp/dev-auth-privilege-native-*` directory. All approved resources must be within it. The helper executable must be the separately verified compiled fixture binary.

Use one fresh grant/root for each finite case in `crates/dev-auth/tests/support/PRIVILEGE-NATIVE.md`. The opt-in `dev-auth-native-fixture-v1` protocol admits only `dev-auth-privilege-native-fixture`, fixed helper verbs, one `/var/tmp/dev-auth-privilege-native-*/scope` resource and a single target leaf. It cannot be used to bless another executable or a host execution-hook resource. Root policy remains separately installed and each grant still requires real administrator approval.

The runnable matrix includes reuse, expiry, revocation, identity/custody faults, death paths, replay/busy/exhaustion, blocked streams, cleanup uncertainty and signal fidelity. Signed setup upgrade/restore fixtures are in `setup_v3/recovery_native/signed.rs`. A source-only pass does not execute those ignored native cases. Actual suspend/resume and real maintenance compatibility remain separate recorded acceptance gates; test-feature synthetic helpers do not qualify the production adapter.

## Production maintenance adapter

The optional [standalone receipt-install contract](dev-tools-receipt-install-v1.md) covers exact root-owned tool status, install/replacement, journal-bound resume and explicitly approved reverse replacement in a dedicated system target. It reuses the existing receipt/journal installer. A separately approved root executor record and independent candidate/predecessor evidence are prerequisites; the source build neither deploys nor grants them. The real-artifact native matrix is [RECEIPT-NATIVE.md](../crates/dev-auth/tests/support/RECEIPT-NATIVE.md), separate from the synthetic27-case matrix.

Public Update All offline product installation uses the invoking account's HOME/XDG_STATE_HOME layout. Changing its UID would change custody and remains unsupported. Dev Auth cannot modify its own helper/policy/setup generation while its reusable grant holds shared exclusion; self-upgrade uses the existing signed setup route after cleanup. The dedicated receipt installer's journal lock is independent of this exclusion. Native qualification and a real approved root deployment remain required before claiming installed maintenance support.
