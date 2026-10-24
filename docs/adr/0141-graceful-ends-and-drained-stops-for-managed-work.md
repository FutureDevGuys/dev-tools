---
authority: canonical
owner: dev-auth
---

# ADR 0141: Managed work ends with a fixed grace, an orderly stop drains, and attached work is never idle

status: proposed
verification: hermetic source tests pass; native acceptance pending

## Context

ADR 0136, ADR 0137 and ADR 0138 keep transient faults from stopping managed work. Events that a running job cannot control still cut it off partway, and ending managed work when that is intended gave it no chance to reach a consistent state.

- Stopping or restarting `dev-auth-grants.service` stopped every job. Under `KillMode=control-group` the service manager sends SIGTERM to every process in the unit, jobs included, before the coordinator can act, and SIGKILL five seconds later. The coordinator stopped every grant and then cancelled its connection tasks, which could drop the final result of an `exec` whose job had just ended. Setup restarts the unit when it applies, recovers, restores, repairs or uninstalls, so a self-upgrade did the same to every running job.
- A grant's end stopped its work with `cgroup.kill`, an immediate SIGKILL. That held for the hard deadline, revocation, an observed logout, `leave` and coordinator shutdown. The deadline guardian also wrote `cgroup.kill` at the deadline, and at once whenever the coordinator closed a boundary's admission gate.
- Idle expiry counted from the last admission only. A long command under a grant with an idle cutoff was stopped at the cutoff while it still ran.
- The unit set no `OOMPolicy`, so the service manager's default `stop` applied. One kernel OOM kill of any process in any managed tree stopped the unit, and with it the coordinator and every grant.
- A root `exec` job without a terminal shared the coordinator's session and process group. A `kill 0` in that job, a common cleanup idiom, signalled the coordinator, which stopped every grant and exited with status 0, so the service manager did not restart it.
- A sudo upgrade inside managed work, such as a package transaction in a `privilege run` convergence, drained the coordinator (ADR 0138). The coordinator then refused every later sudo and `exec`, so the rest of the run had no root, and the sudo plugin told the user to restart the service, which would end the run.

## Decision

### Ending managed work: SIGTERM, then SIGKILL after a fixed grace

Every intended end of managed work sends SIGTERM first and SIGKILL after a fixed grace of 10 seconds. That covers the hard deadline, revocation, an observed logout, `leave`, the leftovers of a `privilege run` program that exited, a job whose client left, a failed sudo completion check (ADR 0136) and coordinator shutdown. No caller, request or policy chooses the grace.

When a boundary stops, the coordinator closes its admission gate at once, so nothing new enters the boundary. It then sends SIGTERM and SIGCONT to every member, so a stopped member also sees the request. SIGKILL follows when the grace ends, unless the boundary is empty by then. The grace starts when the stop starts or at the hard deadline, whichever comes first.

Each member receives one SIGTERM. Every managed process runs in a job boundary, and grant boundaries, delegated ones included, hold only job boundaries. A stopping grant closes its gate and kills what remains when its grace ends, but sends no signal, and each of its jobs sends its own members their one request. A program that reads a second request as an order to quit at once therefore still gets its grace. SIGTERM is a request and the kill is the guarantee, so a member that the walk misses, for example while processes come and go, is still killed when the grace ends. A child that the coordinator has forked but that has not yet started its program has the default action for SIGTERM, SIGINT, SIGHUP and SIGQUIT, so a request that reaches it then ends it.

The hard deadline still ends the grant. Admission and sudo close at the deadline, the work receives SIGTERM, and whatever still runs 10 seconds later is killed. The deadline guardian enforces this without the coordinator. At the deadline it closes the admission gate itself and arms its timer for the deadline plus the grace. When the coordinator closes the gate first, the guardian arms its timer for the grace from that moment. The guardian writes `cgroup.kill` when its timer fires and exits as soon as the boundary is empty. A coordinator that cannot act therefore cannot keep any work past its hard deadline plus 10 seconds. A wedged coordinator sends no SIGTERM, so its work receives only the guardian's SIGKILL.

The grace extends how long processes that already run may finish, never the grant. Nothing is admitted after the deadline, and nothing moves the deadline. The approval states the duration, and this record states the grace.

Two stops still kill at once. The output relay of a capped plan kills its job when the output contract fails, because the relay that carries the job's streams is gone (ADR 0119). A boundary dropped without a stop, which happens only when the coordinator fails or exits, is killed at once.

Revocation, `leave` and the end of `privilege run` wait up to 15 seconds, the grace plus 5 seconds, for the stopped work to end before they report a cleanup failure. So do the cleanup waits of a captured `exec` and of a failed plan graph. Clients wait longer than the coordinator: `revoke`, `leave` and `status` wait 25 seconds for their answer, and `exec`, `run-plan` and `run` wait for their result until 30 seconds after the hard deadline, the grace, the cleanup wait and 5 seconds to deliver it.

### An orderly stop drains

The unit uses `KillMode=mixed`. The service manager then sends SIGTERM to the coordinator alone, and SIGKILL to every process left in the unit once the coordinator exits or `TimeoutStopSec` passes.

On SIGTERM or SIGINT the coordinator drains:

- it closes admission as a trust-change drain does (ADR 0138), so no new grant, launch, delegation, execution, managed sudo or sudo relay starts;
- it keeps every grant and job, and answers `status`, `inspect`, `revoke` and `leave`;
- it waits until no managed job remains, for at most 60 seconds;
- it stops every grant, so remaining work receives SIGTERM and, 10 seconds later, SIGKILL;
- it waits up to 15 seconds for every grant to end, then up to 5 seconds for its connections to deliver their results, and exits.

An `exec` whose job ends during the stop therefore still receives its result. The stop takes at most 80 seconds, and the unit's `TimeoutStopSec=90s` covers it. Startup refuses a unit whose kill mode is not `mixed`, whose `SendSIGKILL` is off, or whose stop timeout is shorter than 80 seconds. A stop during a trust-change drain turns it into this bounded drain. A coordinator that drained for a stop exits with status 0. One that drained for a trust change still exits with a failure status, so that `Restart=on-failure` starts a coordinator that binds the new state.

A panic in a connection task or the login observer still skips the drain and stops every grant at once (ADR 0137), with the grace above.

### A routed sudo during a drain is told to rerun

During any drain the coordinator answers each sudo connection instead of closing it. An invocation that no grant routes gets native sudo. An invocation that a grant routes, and that the drain refuses, gets the new `draining` answer. The plugin then prints one line that says the coordinator admits no new sudo while its running commands finish, and that the step should be rerun after `dev-auth-grants.service` restarts. The line names no grant, account or path, and fits the 160-byte limit of ADR 0137.

### Setup does not restart over managed work

Before setup changes anything, while it holds the exclusive setup lock, it refuses when any boundary inside `dev-auth-grants.service` is populated, that is when any managed job runs. When it stops the coordinator, it waits up to 100 seconds, longer than the unit's stop timeout, for the stop to finish. The refusal applies to every setup operation that can restart the coordinator. Its message says that setup would end the running work, and that the user can let the work finish or revoke its grant, and must run setup outside any grant. While setup holds the lock, the coordinator admits no new job, so no job can start between the check and the restart. Setup that runs inside managed work, for example under `privilege run`, is refused the same way, because restarting the coordinator would end setup itself.

### A crash stays unrecoverable

A coordinator that crashes, panics outside its tasks, or is chosen by the OOM killer exits. Under `KillMode=mixed` the service manager then kills every process left in the unit at once, without SIGTERM, and the restarted coordinator removes every leftover boundary before it admits anything (ADR 0137). No grant survives a restart (ADR 0115). Work that must survive a coordinator crash does not belong under a grant.

### Attached work is not idle

A grant with a running job is not idle, whatever its idle cutoff. The idle cutoff counts from the later of the last admission and the moment the grant's last job ended. A running job of a delegated grant keeps each ancestor from idling as well. The hard deadline still applies to a busy grant. The grant accounting holds a count of attached jobs for each grant, and the coordinator changes it in the same step that adds a job to or removes a job from its records.

The idle cutoff therefore limits how long a grant admits new work without approval only while nothing runs under it. A job lasts until its boundary is empty, so a process that a job leaves behind, such as a daemon started with `sudo cmd &`, or a sudo that waits before it attaches, keeps its grant from idling until it ends or the hard deadline passes. Ending running work at an idle cutoff would cut a task off partway, which this record rules out. An approver who needs a shorter bound on unattended admission chooses a shorter duration.

### OOM containment

The unit sets `OOMPolicy=continue`, so a kernel OOM kill of one process is logged and nothing else stops. It sets `OOMScoreAdjust=-900`, so the kernel prefers almost any other process over the coordinator and its guardians. Every process that the coordinator starts in a boundary resets its own OOM score adjustment to 0 before it runs. Managed work therefore keeps the kernel's ordinary ranking and never inherits the coordinator's protection. An OOM kill in one job affects only the process that the kernel chose.

A per-job `memory.oom.group` would kill a whole job together. It needs the memory controller enabled below the unit's cgroup. The coordinator and its guardians live in that cgroup, so the cgroup v2 rule against internal processes forbids it. Moving them into a leaf would need `Delegate=yes`, which ADR 0115 rules out, so this record does not use it.

### Every job leads its own session

Every process that the coordinator starts in a boundary calls `setsid` before it runs, so it leads a session and a process group of its own, as systemd gives each service. A terminal job then takes its relayed terminal as before. A signal that a job sends to its own process group, such as `kill 0`, reaches only that job.

### Admitted grants keep working across a sudo-program change

A change to the sudo program still drains the coordinator (ADR 0138), so no new grant, launch, delegation or `run` starts until the restarted coordinator binds the new program. New work under a grant that is already active continues: managed sudo, sudo relays, `exec` and `run-plan`. Only managed sudo and the relay use the sudo program. For each sudo connection the coordinator selects the program it admits through:

- the program bound at startup, while a look finds it unchanged;
- after an observed change, the file that the policy's path names now, opened and checked by the same function that startup uses: root-owned ancestors and file, no group or world write, a regular file and no symlink in the final component;
- nothing, when the look could not be taken or the new file fails those checks, which refuses that connection.

The connecting process must run the selected program, and the sudo relay executes it. Completion is verified against the image that the invocation was admitted with. Each connection selects afresh, so after a second replacement only the newest file is admitted. The policy must also be observed unchanged.

This keeps admission fail-closed. Every admission still needs a positive look, and a look that fails refuses. It adds no second trust path, because startup's only validation of the sudo program is the function that the drain reuses, and only root can place a file that passes it.

Because active grants keep their use, this drain ends only once no grant is active, no managed job runs and no connection is open. A task that runs separate sudo steps under a user or workload grant therefore keeps its grant between steps. The drain is bounded by the latest hard deadline among the active grants, and revoking them or running `leave` lets it end sooner. Until it ends, no new grant starts for any account, and the restarted coordinator then binds the new program through startup.

A change to the grant policy is different. Every active grant was approved under the old policy, so after a policy change the coordinator refuses new work under every grant, and answers a routed sudo with `draining` as above. A policy change during a sudo-program drain turns it into a policy drain, which ends once no job or connection remains. An orderly stop refuses the same work.

### Diagnostics

The coordinator writes one journal line for each of these events:

- a stop request, with the number of running jobs and the drain bound;
- the end of a stop drain, with the number of grants it stops and the number of jobs still running;
- a managed sudo admission through a replaced sudo program, with the grant.

### Relationship to ADR 0115, ADR 0136, ADR 0137, ADR 0138 and ADR 0139

ADR 0115 stops managed work when a grant ends, and this record adds the fixed grace before SIGKILL without moving the hard deadline. ADR 0136 lists the events that stop an attached job, and each now sends SIGTERM before SIGKILL. ADR 0137 kept `KillMode=control-group` and a 5-second stop timeout; this record replaces both with `KillMode=mixed` and `TimeoutStopSec=90s`, and keeps the rule that a coordinator exit stops every managed job. ADR 0138 drains on a trust change; this record keeps that drain, keeps new work under admitted grants across a sudo-program change, and answers routed sudo during any drain. ADR 0139 stops the whole tree at once at the deadline and refuses sudo for the rest of a run after a sudo upgrade; this record replaces both rules.

## Verification

Hermetic tests need no root, sudo, systemd, D-Bus or PolicyKit. They use temporary files that stand in for `cgroup.kill` and `cgroup.events`, an eventfd gate, forked children, socketpairs and in-process task sets. They cover these cases:

- a stopped boundary is sent SIGTERM first and SIGKILL only once the grace passes, and a late stop is killed at the deadline plus the grace;
- a forked child that has not started its program has the default action for SIGTERM instead of its owner's handler;
- a client waits for the result of work stopped at its deadline through the grace and the cleanup wait;
- the deadline guardian waits out the grace after the gate closes, exits early once the boundary is empty, and at the deadline closes the gate itself and kills after the grace;
- an orderly stop closes admission, waits for running jobs within its bound and ends once none runs, and a stop during a trust drain becomes the bounded drain;
- the shutdown lets a connection that is finishing deliver its result, and cancels one that never finishes at its bound;
- the startup unit contract accepts `KillMode=mixed` with a covering stop timeout and refuses `control-group`, a short stop timeout and `SendSIGKILL=no`, and the shipped unit satisfies it;
- the unit asset pins `KillMode=mixed`, `TimeoutStopSec=90s`, `OOMPolicy=continue` and `OOMScoreAdjust=-900`, and setup observes both this contract and the previous one, so it can stop an installed coordinator before it replaces the unit;
- setup refuses while a grant boundary is populated or cannot be read;
- a grant with an attached job does not idle, only its hard deadline can end it, its idle cutoff counts from the job's end, an attached job of a delegated grant keeps its parent from idling, and the hard deadline still applies;
- a sudo-program drain waits for active grants, a policy drain does not, and a policy change during a sudo-program drain becomes a policy drain;
- setup waits longer for the coordinator's stop than the unit's stop timeout;
- a started job leads its own session and process group and resets its OOM score adjustment to 0;
- the sudo program selection keeps the bound program while it is unchanged, uses the startup validation after a change, and refuses an unobservable look or a failed validation;
- new work under an active grant continues through a sudo-program drain and is refused on a policy change, a stop drain or an unobservable policy, while a new grant or delegation still waits for the restart;
- a routed invocation during a drain gets `draining`, an unrouted one gets native sudo, and the plugin prints the rerun message for `draining`.

The reaping, bridge, spawn and setup call sites have no hermetic test, because they need owned cgroup boundaries, a root sudo peer or kernel cgroup evidence. Neither do one SIGTERM per member across nested boundaries, the walk that tolerates processes that come and go, the guardian's early exit when a populated boundary empties, which needs kernel `cgroup.events` notifications, and the call from the sudo program selection to the startup validation, which needs root-owned files. The root-only native boundary acceptance now allows the grace before it expects a hard expiry to kill.

Native acceptance remains pending. It needs a `systemctl stop` and a `systemctl restart` during a long `exec` that ends within the drain and one that outlasts it, a setup apply refused while a job runs, a revocation and an expiry of a job that handles SIGTERM and of one that ignores it, a long command under an idle cutoff, an OOM kill inside one job, a root `kill 0` inside an `exec`, and a `privilege run` that upgrades the sudo program and then uses sudo again.
