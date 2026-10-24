---
authority: canonical
owner: dev-auth
---

# ADR 0139: Command-scoped administrator grants and remaining-time checks

status: proposed
verification: hermetic source tests pass; native acceptance pending

## Context

Unattended automation needs root for some of its steps, and it should not hand root to anything else. The two grant scopes in [ADR 0115](0115-native-administrator-grants-with-maintenance-compatibility.md) do not fit that need.

- A user-scope grant routes sudo for every process of the account until its deadline, its revocation or an observed logout. Any code that runs as the account can use it, including code that has nothing to do with the automation.
- A workload-scope grant limits root to one Dev Auth workload's cgroup. A workload is a credential workload. It must be declared in advance with a launcher in the credential policy's root-owned `trusted_launchers`, so a tool cannot run its own program under a grant scoped to that program. Consumers work around this by wrapping themselves in an interpreter launcher.

Grants cannot be extended, and work that still runs at the deadline is stopped. A consumer that is about to start a long privileged step can learn how much time its grant has left only by parsing every grant in `privilege grant status --format json` and guessing which one sudo routing would use.

## Decision

### `privilege run` requests a grant for one program and runs it

```text
dev-auth privilege run --duration DURATION [--authority administrator] [--preserve-env NAME]... [--result-file PATH] [--format human|json] [--non-interactive] -- PROGRAM [ARGUMENTS...]
dev-auth privilege grant run ...
```

`run` asks for one fresh administrator approval of a grant whose only scope is the process tree of `PROGRAM`. After approval it runs `PROGRAM` as the calling user, routes sudo from that process tree through the grant, ends the grant when `PROGRAM` exits, and returns `PROGRAM`'s exit status. `--authority` accepts only `administrator`, its default. The other options mean what they mean for `exec`: `--format json` needs `--result-file`, which receives the value-free result while `PROGRAM` keeps the caller's streams. `--non-interactive` returns `approval_required` before anything connects or starts.

The name follows the existing grammar. `request` creates a grant and runs nothing. `exec` runs a command as root inside a grant that already exists. `run` does both for one program and runs it as the caller. No bounded maintenance command is named `run`, so `privilege run` is a direct alias of `privilege grant run` under the rule in [ADR 0119](0119-bounded-grant-output-and-native-launch-activation.md), and both share one Clap leaf.

### The command scope

Grant scopes gain a third value, `command`. A command-scoped grant routes sudo only for processes in the cgroup that the coordinator created for its program. `run` is the only way to obtain one. `grant request`, `delegate` and `workload launch --privilege-scope` reject it, because none of them creates the program's boundary.

The administrator grant policy opts a subject in by listing `command` in that subject's `scopes`. A policy that does not list it denies `run`, so every existing policy grants nothing new. Policy validation accepts one to three distinct scopes. A subject that lists `command` cannot also set `idle_timeout_seconds` or `maximum_uses`, because a command grant lasts while its program runs, and an idle cutoff or a use budget would stop or starve that program partway. An older Dev Auth refuses a policy that lists `command`, because the policy schema denies unknown values. `setup template administrator-grant-policy --user NAME --maximum-duration DURATION --scope command` emits the opt-in. The template's default scopes stay `user` and `workload`.

`run` holds no credential resource. It does not read the credential policy, does not use `trusted_launchers`, and does not create a credential workload. Credential workloads keep their launcher rules unchanged.

### The program runs inside a boundary the coordinator owns

After approval the coordinator creates the grant's boundary and, inside it, one job boundary for the program. Both are root-owned, nondelegated cgroups under the coordinator's unit, with the guardians and admission gates of ADR 0115. The coordinator starts the program in the job boundary through the same spawn path as `exec`. The program gets the caller's uid, gid, supplementary groups, umask, working directory, mount namespace and standard streams, and the environment described below. As a login does for a user's first process, it gets a session, a process group and a session keyring of its own, and no descriptor of the coordinator. It therefore shares no session, keyring or open file with the root jobs the coordinator runs. A terminal caller gets the relayed terminal of `exec`. That terminal stays root-owned, so other processes of the account cannot open it. The program never holds root and has no capabilities.

The program runs unconfined in the host namespaces, apart from the caller's mount namespace. `run` therefore refuses a caller that runs with no-new-privileges, under a seccomp filter, or in a user, network, PID, IPC, UTS, cgroup or time namespace other than the coordinator's. Such a caller would leave its confinement through the program.

Routing uses the mechanism that already serves every managed job. The coordinator receives each sudo invocation over its socket and reads the sudo process's cgroup from kernel peer evidence. It compares that cgroup directory's device and inode with each held job boundary. A match routes the invocation through that job's grant, and the grant's scope must contain the job's scope. The coordinator publishes no routing marker for a command scope, because no marker selects it. The sudo jobs that the program starts run in their own job boundaries inside the same grant and route through it the same way. When the coordinator accepts a sudo connection from the tree and does not answer, the plugin refuses the invocation, because it runs beneath the coordinator's cgroup (ADR 0138). The coordinator cannot be absent while the tree runs, because the tree runs in the coordinator's unit.

The unit's `TasksMax=4096` and `LimitNOFILE=8192` therefore apply to the whole process tree, and stopping `dev-auth-grants.service` stops the tree with every other managed job (ADR 0137).

### The approval names exactly what it authorizes

The client resolves `PROGRAM` through its own `PATH`, as a shell would, and canonicalizes the result. It opens that file read-only as the caller and passes the open descriptor to the coordinator. The kernel therefore applies the caller's own permissions to the lookup. The coordinator opens the canonical path only as an `O_PATH` handle inside the caller's root, with `RESOLVE_IN_ROOT` and no symlink, to confirm that it names the same device and inode as the descriptor. The coordinator requires all of the following before it prompts:

- the descriptor is open read-only, so it cannot change the bytes after approval;
- the file is a regular ELF file of at most 1 GiB;
- the caller's uid, gid and groups may execute it under its mode bits;
- its mount is not `noexec`, and its filesystem is not FUSE, whose daemon chooses both the attributes and the bytes it serves;
- the path is spelled canonically, with no `.`, `..`, repeated or trailing slash.

The coordinator then digests the descriptor's bytes with SHA-256.

The client passes the program only the variables a login sets, `PATH`, `HOME`, `SHELL`, `USER`, `LOGNAME`, `TERM` and `LANG`, and the ones named with `--preserve-env NAME`. The coordinator discloses every variable it receives, whatever client sent the request. A variable that changes what the program loads or runs, such as `LD_PRELOAD`, therefore appears in the prompt, or the program never sees it.

The PolicyKit message discloses all of the following:

- that the authority is unrestricted root authority, and that every process in the tree can run any command as root through sudo;
- that no other process can use the grant, and that the grant ends when the program exits;
- the requesting user and the requesting process's PID;
- the duration;
- the canonical program path, its SHA-256 digest, its device and inode, and its owner;
- the complete argument vector, including the first argument;
- the working directory;
- the complete environment.

Each path, argument and value appears in double quotes. Every quote, backslash and byte outside printable ASCII in it is escaped, and so are `&`, `<` and `>`, which some PolicyKit agents read as markup. A caller's argument therefore cannot start a line, forge text or hide part of the message. The disclosed command is limited to 4096 bytes. A longer one fails with `invalid_request`, because an approval cannot authorize what it cannot show. The PolicyKit details also carry the scope, the duration, the path and the digest. They identify the request and do not fix its arguments or environment.

After approval the coordinator checks that the descriptor's stamp is unchanged, then executes that descriptor. A path that changes after approval cannot select other bytes. A script is not a native program. To run one, name its interpreter, as in `-- /usr/bin/bash ./converge.sh`. The approval then names the interpreter, and the arguments name the script.

The client cancels a pending request when it receives a signal that would end it, such as an interrupt from the terminal. Approval then fails, and the signal never reaches a program that starts after the caller gave up.

### Lifetime

The grant ends at the first of these events:

- the program exits;
- the hard deadline passes, when the guardian stops the whole tree even if the coordinator is stopped;
- the grant is revoked, including through `leave` inside the tree;
- logind reports that the account has no interactive session (ADR 0136);
- the coordinator shuts down.

When the grant ends, the coordinator stops everything in its boundary, the program included. A grant that outlived its program would give root to leftover processes that nothing waits for, and a program that outlived its grant would run on in the coordinator's unit with nothing to bound it. `leave` from inside the tree therefore ends the program. A grant ends early but never late. Its hard deadline is fixed at approval, and nothing extends it.

A change to a watched trust input drains the coordinator as in ADR 0138. A running program continues until it exits, but the coordinator refuses every sudo it starts after the change, as it does for every other grant, and no new `run` starts. A program that upgrades the sudo program or edits the grant policy partway therefore loses sudo for the rest of its run. The coordinator exits once the program has exited.

`run` validates the request against the policy before it prompts. A duration above the subject's maximum, a subject that does not list `command`, a confined caller, a program that fails the checks above, or a missing login fails without a prompt.

### What happens when the work needs more time than it has

A command-scoped grant is sized to the whole program at approval. When the deadline passes, the guardian stops the whole tree at once, including any sudo job. Nothing in the tree continues without root, and nothing is left half-privileged. The result reports the program's signal and the grant's `stop_reason` of `HardExpired`. Choose a duration that covers the whole run. The policy maximum bounds the choice.

Work that runs under a user or workload grant can check its remaining time before it starts a privileged step:

```text
dev-auth privilege grant status --require-remaining DURATION [--scope user|workload|command] [--format json]
```

Without `--scope`, the check applies to the grant that sudo routing selects for the caller now: the caller's job, workload or command grant, then the account's user grant (ADR 0136). With `--scope`, it applies to the caller's routable grant of that scope, which need not be the grant that sudo uses. The check succeeds when that grant is active and its hard deadline is at least `DURATION` away. It reports that grant in `grant`.

| Outcome | `error_kind` | Exit |
| --- | --- | --- |
| A covering grant has enough time left | `null` | 0 |
| No routable grant covers the caller | `no_grant` | 3 |
| A covering grant ends sooner than `DURATION` | `insufficient_remaining`, and `grant` shows it | 3 |

An idle cutoff that the policy sets on a user or workload grant can end that grant before its hard deadline, so the check applies to the hard deadline only. Every status document lists each of the caller's grants, omitting the list when there are none, with `id`, `scope`, `authority`, `state`, `duration_seconds`, `remaining_milliseconds`, `idle_seconds`, `remaining_uses`, `stop_reason` and `cleanup_failed`.

## Security analysis

### Compared with user scope

| Question | User scope | Command scope |
| --- | --- | --- |
| Which processes can sudo through the grant | every process of the account, in any session | processes in the one cgroup that the coordinator created for the program |
| How another process gains that ability | it runs as the account | it cannot join the cgroup; it can only subvert a process already inside |
| Ends when | deadline, revocation, logout, shutdown | the same events and also program exit |
| Approval discloses | scope and duration | scope, duration, program path, digest, file identity, arguments, working directory and environment |
| Pre-declared launcher | none | none |

User scope gives root to the account. Command scope gives root to one process tree that the approver identified.

### Hijack resistance

A process outside the tree cannot obtain the authority:

- **Joining the tree.** Moving a process into a cgroup needs write access to that cgroup's `cgroup.procs` and to the common ancestor's. Both are root-owned, so the kernel refuses every non-root process.
- **Copying a selector.** Routing for a command scope reads only the kernel identity of the sudo process's cgroup. A grant ID, a PID, an environment variable or a marker file selects nothing.
- **Naming the grant.** `exec --grant ID` and `delegate ID` reach the registry, which requires the grant's scope to contain the caller's. A caller outside the tree has its user or workload scope, so the registry refuses it with `authority_denied`.
- **Swapping the program.** The coordinator executes the read-only descriptor it digested and confirms its stamp after approval.
- **Forging the prompt.** Any process of the account can ask for a `run`. The prompt names the requesting PID, the exact program, its digest, every argument, the working directory and every environment variable, so a forged request must show exactly what it runs. While one request from an account waits for approval, another from the same account fails with `busy`, so two prompts for one account never appear at once.
- **Leaving confinement.** A caller under no-new-privileges, seccomp or another namespace cannot use `run` to start an unconfined program.
- **Outliving the program.** The grant stops when the program exits and kills what remains in the tree. The guardian enforces the hard deadline without the coordinator. A coordinator exit stops the tree.
- **Leaving the tree.** A process in the tree cannot move out of its cgroup. Work it starts through another service manager, such as `systemd-run --user` or `cron`, runs outside the tree, and sudo does not route that work.

Some paths stay open, and the approver accepts them by approving:

- A process of the same account can attach to a member with `ptrace` when Yama's `kernel.yama.ptrace_scope` is 0 or Yama is absent. With `ptrace_scope` 1 or higher, only an ancestor can attach, and every ancestor of the tree is the root coordinator or a member of the tree. Workload scope has the same exposure.
- A process of the same account can open the program's standard streams through `/proc/PID/fd`, because the caller's pipes and files belong to the account. It can write commands into a program that reads its standard input. It can also drive the caller's own terminal, for example through a terminal multiplexer's socket, and type into an interactive program.
- The tree runs code and reads data that the account can change. That includes scripts it runs, its configuration, its preserved environment and sockets owned by the account. A process of the same account that changes them can steer what the tree does with root.
- A program file that the account can write, including through group permissions or an access control list, can change in place between the coordinator's last check and its execution. The digest then names the bytes at approval. The disclosed owner shows only whether the account owns the file.
- Root can do anything, including handing out root. The prompt says that the authority is unrestricted.

Each open path needs an attacker that already runs as the account and acts on this one tree. Under user scope, the same attacker runs sudo directly.

### What the program does not inherit

The program has no logind session of its own, so PolicyKit treats it as inactive for actions that an active session may take without authentication. Its audit login ID and security context are the coordinator's. Its session keyring is new and empty, so credentials kept in the caller's login session keyring are absent. Its resource limits are the coordinator unit's, not the caller's. A program that needs any of these must obtain them itself.

### Properties that do not change

Every grant still needs its own fresh approval. Nothing extends a grant. Routing decisions use kernel identity, never selectors. The guardian enforces the hard deadline. Delegation still needs `allow_delegation`, and a delegated grant cannot widen its parent's scope. Credential workloads, `trusted_launchers`, bounded maintenance and existing grant scopes keep their behavior.

## Verification

Hermetic tests need no root, sudo, PolicyKit, systemd or D-Bus. They use temporary directories for held cgroups and caller roots, the coordinator's routing state without native boundaries, forked children that run no program, and the built CLI with no coordinator. They cover these cases:

- a policy without `command` denies `run`, the opt-in permits it within the maximum duration, and `command` with an idle cutoff or a use budget fails validation;
- the template emits the opt-in only when asked;
- the wire requests reject `command` for `request` and `delegate`, reject unknown fields, and a `run` carries exactly five descriptors;
- the approval message discloses the path, digest, file identity, arguments, working directory, environment and duration, and escapes control bytes and markup;
- the client passes only the login environment and the preserved variables;
- the coordinator accepts only a read-only, executable, canonically named regular ELF descriptor and digests its bytes;
- a caller under no-new-privileges or seccomp counts as confined;
- a child that enters a user session gets the requested umask, its own session and keyring, and none of its parent's descriptors;
- a program exit ends its grant;
- a process in the program's boundary routes through the grant, and a sibling process of the same account does not, even when it names the grant;
- the remaining-time check succeeds, fails with `insufficient_remaining`, or fails with `no_grant`;
- the status document carries `scope`, `state` and `remaining_milliseconds`;
- `run` admits new work, so a draining coordinator refuses it;
- the CLI refuses a noninteractive `run`, a missing program and a script before it connects.

Starting the program in its boundary, routing its sudo, the confinement and namespace checks against a live caller, the signal cancellation of a pending approval, and stopping the tree need an owned cgroup boundary or a coordinator, so they have no hermetic test. Native acceptance remains pending. It needs a real approval of `run`, sudo from the program and from a grandchild, a sibling process's sudo during the run, a program that exits while a background child runs, expiry during a sudo job, `leave` from inside the tree, logout during a run, an interrupt during approval, a confined caller, a trust change during a run, and `status --require-remaining` inside and outside the tree.
