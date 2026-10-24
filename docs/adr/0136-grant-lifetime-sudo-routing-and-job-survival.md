---
authority: canonical
owner: dev-auth
---

# ADR 0136: Grant-lifetime sudo routing and managed job survival

status: proposed
verification: hermetic source tests pass; native acceptance pending

## Context

A managed native sudo job can run a package manager, a boot loader or a filesystem tool. Stopping its domain partway through such a command leaves damage that outlasts the fault, such as a half-applied upgrade, a stale package lock or missing kernel images. ADR0115 stops managed work when a grant ends, and that rule stays. Three coordinator paths also stopped managed work while the grant had not ended.

- A completion channel that closed, or reset, before sudo reported completion failed the wait as a protocol violation, and the bridge stopped the job.
- Reaping stopped any job whose sudo process exited before completion.
- A login query that failed or took longer than two seconds ended every user-scope grant of the account as a logout, which stopped all of their jobs. A service manager that re-executes itself during a system upgrade is one event that can make that query fail.

Routing markers also outlived their grants. A marker stayed after expiry, revocation, logout or cleanup until an explicit `leave`, and a restarted coordinator loaded old markers as denial state. Once the grant retired, the plugin saw the marker, the coordinator found no grant, and every sudo for the account failed. That included sudo with a valid native ticket.

## Decision

### An attached job runs until its grant stops it

Completion is accounting, not authority. After native sudo attaches an invocation, its command keeps running until it exits or its grant stops it. The grant stops it at the hard deadline, on revocation, on an observed logout and at coordinator shutdown. A changed grant policy or sudo program no longer stops it ([ADR 0138](0138-trust-change-drain-and-observed-supervision.md)).

If sudo's end of the completion channel closes, or resets with a coordinator frame unread, the bridge logs the invocation as abandoned and stops reading. The bridge does not stop the job's domain. If the sudo process exits before completion, reaping leaves the job's domain running. Reaping retires an abandoned job once its cgroup is empty, and grant cleanup still waits for that job. An abandoned invocation admits nothing, extends nothing and refunds no use.

These failures still stop the job:

- a completion frame from any process other than the admitted sudo;
- a malformed frame or an unexpected request from a connected sudo;
- a failed identity check after completion;
- the hard deadline.

A sudo process that exits before attachment never started its command, so reaping still stops its domain.

The bridge reads with `MSG_DONTWAIT` after epoll readiness. `recvmsg` therefore never sleeps and cannot return `EINTR`. Spurious readiness returns `EAGAIN`, which the bridge retries.

### Only an observed logout ends user scope

A user-scope grant ends at final interactive logout when logind answers that the account has no interactive session. A login query that fails, is denied or exceeds its two-second limit is logged and retried on the next pass. That query does not end the grant. If logout cannot be observed, the hard deadline bounds the grant.

### Routing lives exactly as long as its grant

A routing marker routes sudo only while its grant is active. Selection ignores a marker whose grant has stopped or retired, so the bridge answers native for that scope at once. Every reaping pass removes the marker file of each ended grant and retries a failed removal. This holds for every way a grant ends, including expiry, revocation, logout, shutdown and retirement. A starting coordinator removes every marker after it takes the daemon lock and before it reads policy, because no grant survives a restart. `leave` with no selected grant succeeds and reports no change.

A workload whose own grant ended routes through its account's selected user-scope grant while that grant is active. The workload had that routing before its own grant existed.

The plugin follows the coordinator's native answer even when it saw a marker before it connected. A marker still makes sudo deny when the coordinator cannot be reached. A denial by an active grant still denies.

### Relationship to ADR0115

ADR0115 says that denied managed Sudo never falls back to a cached native authorization or a broader grant. That rule still governs every invocation that an active grant routes. An admission that the grant denies never continues natively and never consults another grant. The rule no longer holds the account in managed routing after the grant ends.

After a grant ends, sudo for the account has its native behavior. A native ticket that was valid when the grant started, and has not expired when the grant ends, can therefore authorize sudo again. Managed routing does not refresh native tickets while a grant is active. To deny native sudo after every grant, configure native sudo without cached credentials, for example with `timestamp_timeout=0`.

[ADR 0137](0137-coordinator-fault-containment-and-sudo-refusal-reasons.md) keeps a reaping failure that belongs to one grant from ending the coordinator, and it records that a coordinator exit stops every managed job. It also makes the sudo plugin print the reason for each refusal. [ADR 0138](0138-trust-change-drain-and-observed-supervision.md) drains the coordinator when the grant policy or sudo program changes instead of stopping every grant, acts only on observed state, and gives native sudo to an unanswered invocation that the coordinator does not own.

### Diagnostics

The coordinator writes one journal line for each of these events:

- an abandoned completion, with the grant, the job, the sudo PID, the kernel error and the grant's lease state, because a stopping grant also closes the channel when its cleanup kills sudo;
- a failed completion, with the grant, the job, the sudo PID and the receive outcome;
- a routing withdrawal, with the grant and its lease state, which names the stop reason;
- a grant reaching its terminal state, with its lease state;
- a failed login observation, with the UID and the failure.

## Verification

Hermetic tests use socketpairs and temporary directories, with no root, sudo or systemd. They cover end of stream, reset and malformed frames at the packet layer. They cover abandonment of a closed or reset completion channel, denial of completion from another process and acceptance of completion from the admitted sudo. They cover routing after each way a grant ends, a workload returning to its account's grant, marker removal when a grant ends and at startup, the plugin's preflight decision and the logout decision. The reaping change for a sudo process that exits after attachment has no hermetic test, because it needs an owned cgroup boundary.

Native acceptance remains pending. It needs a long managed command that survives a SIGKILL of its sudo process and finishes, a login service restart during a user grant, a coordinator restart with published markers, and the revocation and expiry phases of `tests/native_privilege/user.sh`.
