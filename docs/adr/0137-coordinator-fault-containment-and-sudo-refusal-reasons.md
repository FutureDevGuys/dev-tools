---
authority: canonical
owner: dev-auth
---

# ADR 0137: Coordinator fault containment and sudo refusal reasons

status: proposed
verification: hermetic source tests pass; native acceptance pending

## Context

ADR 0136 keeps an attached managed job running when sudo or its completion channel is lost, and it ends user grants only at an observed logout. Three paths still let a transient fault stop in-flight privileged work or hide why sudo refused.

- Any error from a reaping pass ended the coordinator process. The unit's `KillMode=control-group` then stopped every managed job. A failed withdrawal of one abandoned pending launch was such an error.
- Startup confirmed the unit through the service manager in a single three-second attempt. A service manager that re-executes itself during an upgrade, or a system bus that reloads, can leave that call unanswered, and the coordinator then exited.
- Sudo answers a failed audit open with only `error initializing audit plugin dev_auth_sudo_audit`. The plugin's error string never reaches the terminal, so the user never learned the reason or the remedy.

## Decision

### Reaping ends the coordinator only on an integrity failure

A reaping pass ends the coordinator only when the coordinator can no longer trust its own clock or grant records. That means the boot clock is unreadable, or the grant registry and the native metadata disagree about a grant. The coordinator writes one journal line that names the failure and exits. `reap` returns a type that only these failures can build, so a failure that belongs to one grant cannot end the pass.

A failure that belongs to one grant stays with that grant, and the next pass retries it:

- a failed withdrawal of an abandoned pending launch, whose grant has already stopped and admits nothing;
- a failed removal of an ended grant's routing marker (ADR 0136);
- a failed stop or population read of a stopped grant's boundary, which keeps that grant's cleanup pending or failed;
- an unreadable workload population, which [ADR 0138](0138-trust-change-drain-and-observed-supervision.md) retries without ending the grant;
- a dead or failed job leader, which affects only that job.

A control request sweeps abandoned launches too, and it no longer fails because one launch could not be withdrawn.

A panic in a connection task or in the login observer is a defect in the coordinator. It stops every grant through the ordinary shutdown. [ADR 0138](0138-trust-change-drain-and-observed-supervision.md) replaces the rule that a changed or unobservable grant policy or sudo program ends every grant. A change drains the coordinator, and a look that could not be taken is retried.

### A coordinator exit stops every managed job

The unit keeps `KillMode=control-group`, `SendSIGKILL=yes` and `TimeoutStopSec=5s`. When the coordinator exits, the service manager stops every process in the unit, including managed jobs and their deadline guardians. The coordinator does not leave running jobs to their guardians, for these reasons:

- A guardian enforces only the hard deadline. Revocation, logout and policy changes need the coordinator, so an orphaned administrator job would run unsupervised until a deadline that can be hours away.
- No grant survives a restart (ADR 0115). A restarted coordinator kills and removes every remaining grant cgroup before it admits anything, so jobs left running would stop anyway once the unit restarts.
- The guardians run in the unit's own cgroup, and startup refuses a unit with any other kill mode.

The coordinator therefore exits only when its own state is lost.

[ADR 0141](0141-graceful-ends-and-drained-stops-for-managed-work.md) replaces `KillMode=control-group` and the 5-second stop timeout with `KillMode=mixed` and `TimeoutStopSec=90s`, so that an orderly stop drains, and keeps the rule that a coordinator exit stops every managed job.

### Startup retries an unanswered service manager

Startup confirms the unit's crash-cleanup contract before it creates any listener, so admission stays closed while the unit is unverified. Each attempt waits up to three seconds for an answer. An attempt is unanswered when it times out, when the system bus cannot be reached, or when the bus replies that the service manager has no name owner, cannot be started or did not reply. An unanswered attempt is retried after 250 milliseconds, then after a delay that doubles up to five seconds. After 60 seconds without an answer the coordinator exits, and `Restart=on-failure` starts it again two seconds later. Any other reply fails at once, including an error from the service manager and an answer that shows the unit breaks the contract. Each retry writes one journal line.

The coordinator removes routing markers before verification (ADR 0136), so sudo has its native behavior while the coordinator retries.

### The sudo plugin prints why it refused

When the plugin refuses an audit open, it sends one error message through sudo's conversation function before it returns. The message is one line of at most 160 bytes. It names no grant, account, path or credential. The plugin reads no input and keeps no conversation pointer.

| Refusal | When | Remedy in the message |
| --- | --- | --- |
| Unreachable | Routing selects a grant, but `sudo.sock` is absent or the connection to it fails. | Start `dev-auth-grants.service`. A starting coordinator removes stale routing. |
| Unanswered | The coordinator accepted the connection, then closed, exited, stalled or garbled its greeting or preflight answer. | Retry, or restart `dev-auth-grants.service`, which ends every grant. |
| Denied | Every other refusal. | Inspect the grant with `dev-auth privilege grant status`, or run `dev-auth privilege leave`. |

`leave` needs a running coordinator, so the unreachable message names the service instead. [ADR 0138](0138-trust-change-drain-and-observed-supervision.md) gives native sudo to an unanswered invocation that the coordinator does not own. Every other refusal is unchanged from ADR 0136. A refusal at final admission gets no conversation function from sudo, so it still reports only the error string.

## Verification

Hermetic tests use an injected unit verifier, socketpairs and a fake sudo conversation, with no root, sudo, systemd or D-Bus. They cover retries after an unreachable or a silent attempt, an immediate failure on a contract mismatch, the end of the retry budget, which bus errors count as unanswered, each refusal classification, a coordinator that closes before it answers, and the message that a refused audit open prints. The unit asset test pins `KillMode=control-group` and `Restart=on-failure`. `just accept-sudo-abi` compares the conversation message and reply layouts with the installed `sudo_plugin.h`.

Containing a failed launch withdrawal has no hermetic test, because failing it on demand needs an owned cgroup boundary. Native acceptance remains pending. It needs a failed launch withdrawal beside a running job, every job stopping when the coordinator exits, startup during a service manager re-execution, and each refusal message through native sudo.
