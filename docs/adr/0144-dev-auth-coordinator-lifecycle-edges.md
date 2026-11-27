---
authority: canonical
owner: dev-auth
---

# ADR 0144: The grant coordinator survives a PolicyKit restart, restarts after any unordered exit and starts under the previous unit

status: proposed
verification: hermetic source tests pass; native acceptance pending

## Context

ADR 0136 through ADR 0141 keep events outside a job's control from ending managed work. Five lifecycle edges of `dev-auth-grants.service` remained (issue #105).

- The unit required `polkit.service`, so a PolicyKit restart, for example in a package upgrade, stopped the coordinator, which stopped every grant.
- The unit used `Restart=on-failure`. A coordinator that exits with status 0 is not restarted. A root `kill -TERM -1` reaches the coordinator, which drains and exits with status 0, and a panicked connection task ended the process with status 0 as well.
- The coordinator refused every unit but the one this release publishes. Setup replaces the executable and the unit in separate steps, and setup observes both the published unit and the one it replaces. An executable that replaced the installed one without setup, or a rollback that left the previous unit beside it, kept the coordinator down after a crash or a boot until setup rewrote the unit.
- `TasksMax=4096` is shared by every job and by the coordinator, and `systemd-oomd` kills the whole cgroup it selects, which can be the coordinator's own.
- `exec`, `run-plan`, a new request and a delegation refused during a drain failed with `authority_denied`, which says nothing about rerunning, while the sudo plugin prints rerun guidance for the same drain (ADR 0141).

## Decision

### PolicyKit is wanted, not required

The unit has `Wants=polkit.service` and `After=polkit.service systemd-logind.service`, and no `Requires=`, `Requisite=`, `BindsTo=`, `PartOf=`, `StopPropagatedFrom=` or `Conflicts=` on another unit. A stop or restart of PolicyKit then leaves the coordinator and every grant alone.

Approval is checked when a request is made. A call to PolicyKit that goes unanswered fails the request with `native_unavailable`, exit 3, so a retry after PolicyKit returns succeeds, instead of `approval_denied`, which reads as a refusal. A call is unanswered when the bus could not deliver it, its destination had no owner or could not be started, or the destination left before it replied. Any other reply, including `AccessDenied`, and a timeout of the approval itself, stay `approval_denied`. Unit verification at startup (ADR 0137) and approval use one classification of bus errors, and it counts the bus's `Spawn.*` replies as unanswered.

### The service manager restarts any exit it did not order

The unit has `Restart=always` with `RestartSec=2s`. A stop that the service manager orders, including `systemctl stop`, setup's stop and a shutdown, never restarts a unit, so this restarts only an exit that no stop job ordered, whatever its status. That covers a drain that a root `kill -TERM -1` triggered, which exits with status 0, and the exit for a trust change (ADR 0138), which no longer depends on its failure status.

A panicked or cancelled coordinator task also ends the process with a failure status, the runtime-failure status, instead of 0. Only an orderly stop exits with success. The service manager's start rate limit still ends a restart loop, as it did for `Restart=on-failure`.

### Startup accepts the previous unit

Startup still requires that the coordinator is the unit's main process in the unit's own cgroup, that the service manager kills every process left once the coordinator exits (`SendSIGKILL=yes`), `ExitType=main`, `RemainAfterExit=no` and `Delegate=no`. These keep ADR 0137's crash cleanup. For the stop contract it accepts either:

- `KillMode=mixed` with a stop timeout of at least the orderly stop's bound, which is the unit this release publishes and the only one under which a stop drains (ADR 0141); or
- `KillMode=control-group`, the unit that setup replaces. A stop sends SIGTERM to every process at once, so jobs end without a drain, but the coordinator's exit still stops every job.

It refuses `process`, `none` and `mixed` with a shorter stop timeout. Under `control-group` the coordinator writes one journal line that a stop cannot drain and that product setup publishes the current unit.

This relaxes ADR 0141's rule that startup refuses any unit that does not let the coordinator drain. A coordinator that is down gives no managed sudo and no grants, which is worse than a coordinator that cannot drain a stop, and the previous unit is one that setup itself still observes and stops. Setup's observation and the coordinator's startup compile in one list of the kill modes and stop timeouts they accept (`TEARDOWNS`), and a test requires each listed unit to satisfy startup.

The binary and the unit move together in these paths, and the order matters only where a start could fall between them:

- Apply writes the unit only while the coordinator is stopped and empty, reloads, and only then starts it, so the start sees the unit it wrote. Recovery stops the coordinator before it completes binary activation (ADR 0116).
- Restoration stops and disables the coordinator, restores the unit, then the executable, and ends with the coordinator inactive (ADR 0048).
- An executable replaced outside setup is the case this section covers.

An older release's executable still refuses the unit that this release publishes, because it requires `KillMode=control-group`. Only an executable replaced outside setup can sit beside a newer unit, and product setup then restores the matching unit. This record cannot change a published executable.

### oomd exempts the coordinator's cgroup

The unit has `ManagedOOMPreference=omit`, so `systemd-oomd` does not select the coordinator's own cgroup, whose kill would end every grant. The service manager does not apply the preference to the cgroups below the unit's, so the job boundaries are ordinary candidates, and an out-of-memory kill of one job's cgroup leaves the coordinator and every other job running.

### The task limit stays shared

A task limit for one job needs `pids.max` in the job's cgroup, which needs the pids controller enabled in the unit's `cgroup.subtree_control`. The coordinator and its deadline guardians run in the unit's own cgroup, and cgroup v2 forbids enabling controllers below a cgroup that holds processes. Moving them into a leaf needs `Delegate=yes`, which ADR 0115 rules out and ADR 0141 rejected for `memory.oom.group` for the same reason. `RLIMIT_NPROC` counts a user's processes system-wide, so it cannot bound one job either. `TasksMax=4096` therefore stays one limit for the whole tree, and the privilege documentation says that one program that forks without bound can exhaust it for every job.

### Refused work during a drain is told to rerun

A new failure kind, `draining`, replaces `authority_denied` for work that a drain refuses: `exec`, `run-plan`, a managed sudo relay, a new request, a delegation and a launch. That covers a policy change, a stop and a policy change not yet reaped. Its exit status is 3, like the other failures that a retry resolves, and its message says that the coordinator is draining and admits no new work, that running commands continue, and that the step should be rerun once `dev-auth-grants.service` restarts. The text mirrors the sudo plugin's line and names no grant, account or path.

A coordinator that is shutting down after the drain (the stopping phase) still answers `busy`. A look at the policy that fails still answers `native_unavailable`. A request that the registry refuses keeps `authority_denied`.

An older client cannot decode the new kind and reports a protocol failure instead of printing it, so a client and its coordinator should be upgraded together, which setup does.

## Verification

Hermetic tests need no root, systemd, D-Bus or PolicyKit. They cover these cases, with expected values taken from issue #105 and the unit and cgroup rules above:

- the unit asset has no `Requires=`, `Requisite=`, `BindsTo=`, `PartOf=`, `StopPropagatedFrom=` or `Conflicts=`, wants and follows `polkit.service`, sets `Restart=always` without `RestartPreventExitStatus=`, and sets `ManagedOOMPreference=omit`;
- an unanswered approval call is `native_unavailable` with exit 3 and an answered one is `approval_denied`;
- a panicked task ends the process with a failure status, only an orderly stop exits with success, and a task that finished normally ends nothing;
- startup accepts the published unit and the previous one, each listed unit that setup observes satisfies startup, and a unit that stops only the coordinator, stops nothing or keeps `SendSIGKILL=no` is refused;
- each kind of work that a drain refuses fails with `draining`, exit 3 and the rerun message, work under an active grant continues through a sudo-program drain, and `status` and `leave` still answer.

Native acceptance remains pending. It needs a PolicyKit restart while a grant is active and a request made while PolicyKit is stopped, a `kill -TERM -1` and a panic injected into the coordinator followed by the restart, an executable replaced beside the previous unit and a crash, `systemd-oomd` under memory pressure, and `exec` during a policy drain on an installed system.
