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

`dev-auth setup template administrator-grant-policy --user NAME --maximum-duration DURATION` prints the deny-all policy with exactly one subject: the named existing non-root account, resolved to its numeric uid through the native account database. By default that account may request `user` and `workload` scopes with `administrator` authority for at most the maximum duration, and cannot delegate. Repeat `--scope` to choose scopes explicitly and add `--allow-delegation` to permit narrowed delegation. Only `--scope command` lets the account use [`privilege run`](#running-one-program-under-its-own-grant). The default leaves it out. A subject that lists `command` cannot set an idle cutoff or a use budget. The command prints nothing and fails for a missing or root account, a zero or malformed duration, or any subject that the policy's own validation refuses. The document keeps the schema's `/usr/bin/sudo`, the only sudo program setup accepts. Outside Linux the options are unsupported. The 0.5.2 release prints only the deny-all template; these options are in its successor source. The policy document itself does not depend on the binary that wrote it.

Review the document, then install it where only root can change it. Setup reads only a regular, singly linked source that is not group- or world-writable.

```text
dev-auth setup template administrator-grant-policy --user account-name --maximum-duration 12h > /absolute/private/administrator-grants-v1.json
dev-auth setup template administrator-grant-policy --user account-name --maximum-duration 4h --scope command > /absolute/private/administrator-grants-v1.json
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

## Running one program under its own grant

`privilege run` gives root to one program's process tree and to nothing else. It asks for one fresh approval, runs the program as you, routes sudo from that program and its descendants through the new grant, and ends the grant when the program exits. The subject's policy must list the `command` scope, without an idle cutoff or a use budget. `privilege grant run` is the same command.

```text
dev-auth privilege run --duration 2h -- just converge
dev-auth privilege run --duration 2h --preserve-env SSH_AUTH_SOCK --format json --result-file /absolute/private/run.json -- /usr/bin/bash ./converge.sh
```

`--duration` must be within the policy maximum, and `run` refuses a longer one before it prompts. `--authority` accepts only `administrator`, its default. The exit status is the program's own, and a program ended by a signal ends `run` with that signal. A failure of `run` itself exits 2 for an invalid request, 3 when approval is required or the coordinator is absent or busy, 4 when approval is denied or the policy refuses, and 1 when the program could not start or its cleanup failed. Use `--result-file` to tell those apart from the program's own status. With `--format json`, `--result-file` receives the result, because the program keeps your terminal and streams. The result names the operation `run`, carries `child_exit_code` or `child_signal`, and carries the final `grant` with its `stop_reason`. `--non-interactive` returns `approval_required` and starts nothing. An interrupt while the approval is pending cancels the request.

`run` resolves the program through your `PATH` and opens it read-only as you, so you need read and execute access to it. The program must be a native ELF executable on a filesystem that is neither FUSE nor mounted `noexec`. To run a script, name its interpreter, as in the second example. The program gets only `PATH`, `HOME`, `SHELL`, `USER`, `LOGNAME`, `TERM` and `LANG` from your environment, and each variable you name with `--preserve-env`. The approval names the program's canonical path, its SHA-256 digest, its device, inode and owner, every argument, the working directory, every environment variable and the duration. It also says that the authority is unrestricted root for that process tree. The coordinator executes the exact file it digested. `run` refuses a caller that runs with no-new-privileges, under a seccomp filter, or in another user, network, PID, IPC, UTS, cgroup or time namespace, because the program would run outside that confinement.

The program runs inside a cgroup that the grant coordinator owns, with your uid, groups, umask, working directory and streams, in a session of its own with a new, empty session keyring. Only processes in that cgroup can use the grant. Another process of your account cannot join the cgroup, and naming the grant ID from outside is refused. A process that the program starts through another service manager, such as `systemd-run --user`, runs outside the tree, and its sudo is not routed. The coordinator unit's `TasksMax=4096` and `LimitNOFILE=8192` apply to the whole tree. The program has no logind session of its own, so PolicyKit actions that an active session may take without authentication ask for authentication inside `run`.

The grant ends when the program exits, at its hard deadline, on revocation, at an observed logout, or when the coordinator stops. When the grant ends, everything in its cgroup stops, the program included, so `privilege leave` from inside the tree ends the program. At the hard deadline the whole tree stops, and the result reports the signal and a `stop_reason` of `HardExpired`. Choose a duration that covers the whole run, because nothing extends a grant. If the program upgrades the sudo program or edits the grant policy, the coordinator refuses every later sudo in the run and restarts after the program exits (ADR 0138).

Another process of your account can still reach the tree in a few ways. When `kernel.yama.ptrace_scope` is 0, it can attach to the program with `ptrace`, so set it to 1 or higher. It can write into the program's standard input through `/proc`, and it can drive your terminal, for example through a terminal multiplexer. It can also change scripts, configuration and preserved variables that the program reads. See [ADR 0139](adr/0139-command-scoped-grants-and-remaining-time-checks.md) for the security analysis.

## Checking the remaining time of a grant

Work that runs under an existing grant can check, before a long privileged step, that its grant lasts long enough:

```text
dev-auth privilege grant status --require-remaining 30m --format json
dev-auth privilege grant status --require-remaining 30m --scope user --format json
```

Without `--scope`, the check applies to the grant that sudo routing selects for the calling process: the grant of the job, workload or command that the process runs in, and otherwise the account's user grant. With `--scope user`, `--scope workload` or `--scope command`, it applies to the caller's routable grant of that scope, which need not be the grant that sudo uses. The check uses the hard deadline. An idle cutoff that the policy sets on a user or workload grant can end that grant sooner.

| Outcome | `error_kind` | Exit |
| --- | --- | --- |
| The covering grant is active and has at least the duration left | `null` | 0 |
| No routable grant covers the caller | `no_grant` | 3 |
| The covering grant ends sooner | `insufficient_remaining` | 3 |
| No coordinator runs | `requires_setup` | 3 |
| The duration or scope is invalid | `invalid_request` | 2 |

Every `status` document has `schema` `dev-auth-administrator-grant-result-v1`, `operation` `status`, `changed` `false` and `error_kind`. `grants` lists each of the caller's grants and is absent when there are none. With `--require-remaining`, `grant` is the covering grant whenever one exists. Each grant has these fields:

| Field | Value |
| --- | --- |
| `id` | 32 lowercase hexadecimal digits |
| `scope` | `user`, `workload` or `command` |
| `authority` | `{"kind":"administrator"}`, `{"kind":"exact-plan","sha256":...}` or `{"kind":"typed","operations":[...]}` |
| `state` | `pending`, `active`, `stopping` or `terminated` |
| `duration_seconds` | the approved duration |
| `remaining_milliseconds` | time until the hard deadline, 0 once it passes |
| `idle_seconds` | the idle cutoff, or `null` |
| `remaining_uses` | the use budget left, or `null` |
| `stop_reason` | `null` while active, otherwise the reason, such as `HardExpired`, `Revoked`, `Logout` or `WorkloadEnded` |
| `cleanup_failed` | whether cleanup of the grant's processes failed |

## Native acceptance harness

Build the opt-in non-installed subjects with `--features native-privilege-fixture`. Ordinary source testing can run `kernel_boot_deadline_kills_even_a_stopped_coordinator_process`; it starts only an unprivileged child and tests the independent kernel timer.

`public_reusable_session_approval_execution_and_terminal_cleanup` is ignored by default. It requires an explicitly prepared disposable systemd/cgroup-v2 fixture, an installed candidate with receipt-owned maintenance assets, a native non-root observer and real administrator approval. It does not install policy, create accounts, alter polkit approval or create an unattended grant itself.

Provide `DEV_AUTH_NATIVE_PRIVILEGE_FIXTURE=disposable` and a caller-owned mode-0600 `DEV_AUTH_NATIVE_PRIVILEGE_INPUT` document with schema `dev-auth-privilege-native-input-v1`, absolute `dev_auth`, `fixture_binary`, `fixture_root`, `approval_plan`, approved digest and `case`. The fixture root is a fresh caller-owned mode-0700 `/var/tmp/dev-auth-privilege-native-*` directory. All approved resources must be within it. The helper executable must be the separately verified compiled fixture binary.

Use one fresh grant/root for each finite case in `crates/dev-auth/tests/support/PRIVILEGE-NATIVE.md`. The opt-in `dev-auth-native-fixture-v1` protocol admits only `dev-auth-privilege-native-fixture`, fixed helper verbs, one `/var/tmp/dev-auth-privilege-native-*/scope` resource and a single target leaf. It cannot be used to bless another executable or a host execution-hook resource. Root policy remains separately installed and each grant still requires real administrator approval.

The runnable matrix includes reuse, expiry, revocation, identity/custody faults, death paths, replay/busy/exhaustion, blocked streams, cleanup uncertainty and signal fidelity. Signed setup upgrade/restore fixtures are in `setup_v3/recovery_native/signed.rs`. A source-only pass does not execute those ignored native cases. Actual suspend/resume and real maintenance compatibility remain separate recorded acceptance gates; test-feature synthetic helpers do not qualify the production adapter.

## Production maintenance adapter

The optional [standalone receipt-install contract](dev-tools-receipt-install-v1.md) covers exact root-owned tool status, install/replacement, journal-bound resume and explicitly approved reverse replacement in a dedicated system target. It reuses the existing receipt/journal installer. A separately approved root executor record and independent candidate/predecessor evidence are prerequisites; the source build neither deploys nor grants them. The real-artifact native matrix is [RECEIPT-NATIVE.md](../crates/dev-auth/tests/support/RECEIPT-NATIVE.md), separate from the synthetic27-case matrix.

Public Update All offline product installation uses the invoking account's HOME/XDG_STATE_HOME layout. Changing its UID would change custody and remains unsupported. Dev Auth cannot modify its own helper/policy/setup generation while its reusable grant holds shared exclusion; self-upgrade uses the existing signed setup route after cleanup. The dedicated receipt installer's journal lock is independent of this exclusion. Native qualification and a real approved root deployment remain required before claiming installed maintenance support.
