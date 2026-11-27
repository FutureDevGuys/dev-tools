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

Two consequences are accepted. `systemctl kill` of the coordinator now restarts it, because no stop job ordered the exit. Setup observes the unit before it changes anything and treats `activating` with the `auto-restart` sub-state as a nonterminal transition, so a setup that starts during the two seconds before a restart fails closed and is rerun.

### Startup accepts the previous unit

Startup still requires that the coordinator is the unit's main process in the unit's own cgroup, that the service manager kills every process left once the coordinator exits (`SendSIGKILL=yes`), `ExitType=main`, `RemainAfterExit=no` and `Delegate=no`. For the stop contract it accepts either:

- `KillMode=mixed` with a stop timeout of at least the orderly stop's bound of 80 seconds, which is the unit this release publishes and the only one under which a stop drains (ADR 0141); or
- `KillMode=control-group` with a stop timeout of at most 5 seconds, which is the unit that setup replaces. A stop sends SIGTERM to every process at once, so jobs end without a drain.

It refuses `process`, `none`, `mixed` with a shorter stop timeout, and `control-group` with a longer one. The 5 second bound is the one the released 0.5.5 coordinator enforced. Under `control-group` the service manager sends only SIGTERM to the processes left when the coordinator exits, and SIGKILL once the stop timeout passes, so the timeout bounds how long a job that ignores SIGTERM outlives the coordinator. With the previous unit that is up to 5 seconds, and a longer or infinite timeout, for example from a drop-in, would let such a job outlive its grant without bound. A coordinator exit therefore stops every job at once only under the published unit, and this record claims no more than that bound for the previous one.

Under `control-group` the coordinator writes one journal line that says the unit predates this release: a stop cannot drain, one OOM kill of any process stops the unit, it still requires `polkit.service` and it restarts only after a failure. It says to rerun product setup.

This relaxes ADR 0141's rule that startup refuses any unit that does not let the coordinator drain. A coordinator that is down gives no managed sudo and no grants, which is worse than a coordinator that cannot drain a stop, and the previous unit is one that setup itself still observes and stops. The units that setup observes and that startup accepts are listed once (`TEARDOWNS`). Setup compares the exact pairs, startup uses the published pair as a lower bound and the previous pair as an upper bound, and tests require both to hold and refuse a longer `control-group` timeout and an infinite one.

The binary and the unit move together in these paths, and the order matters only where a start could fall between them:

- Apply writes the unit only while the coordinator is stopped and empty, reloads, and only then starts it, so the start sees the unit it wrote. Recovery stops the coordinator before it completes binary activation (ADR 0116).
- Restoration stops and disables the coordinator, restores the unit, then the executable, and ends with the coordinator inactive (ADR 0048).
- An executable replaced outside setup is the case this section covers.

An older release's executable still refuses the unit that this release publishes, because it requires `KillMode=control-group`. Only an executable replaced outside setup can sit beside a newer unit, and product setup then restores the matching unit. This record cannot change a published executable.

### oomd exempts the coordinator's cgroup

The unit has `ManagedOOMPreference=omit`, so `systemd-oomd` does not select the coordinator's own cgroup, whose kill would end every grant. The service manager does not apply the preference to the cgroups below the unit's. Whether `systemd-oomd` can rank or select one job's cgroup is not established: the memory controller cannot be enabled below the unit (ADR 0141), so a job cgroup may have no memory accounting for it to read. This record therefore claims only the exemption of the unit's cgroup, and per-job oomd containment is unverified until native acceptance.

### The task limit stays shared

A task limit for one job needs `pids.max` in the job's cgroup, which needs the pids controller enabled in the unit's `cgroup.subtree_control`. The coordinator and its deadline guardians run in the unit's own cgroup, and cgroup v2 forbids enabling controllers below a cgroup that holds processes. Moving them into a leaf needs `Delegate=yes`, which ADR 0115 rules out and ADR 0141 rejected for `memory.oom.group` for the same reason. `RLIMIT_NPROC` counts a user's processes system-wide, so it cannot bound one job either. `TasksMax=4096` therefore stays one limit for the whole tree, and the privilege documentation says that one program that forks without bound can exhaust it for every job.

### Refused work during a drain is told to rerun

A new failure kind, `draining`, replaces `authority_denied`, `busy` and `native_unavailable` for work that a drain or a stop refuses: `exec`, `run-plan`, a managed sudo relay, a new request, `run`, a delegation and a launch. That covers a policy change, a sudo-program change for work that needs the new state, a stop, the final stop that follows it and a change not yet reaped. Its exit status is 3, like the other failures that a retry resolves, and its message says that the coordinator is draining and admits no new work, that running commands continue, and that the step should be rerun once `dev-auth-grants.service` restarts. The text is the sudo plugin's line with sudo replaced by work and the unit named, and a test compares the whole message with the plugin's line.

Every admission check answers `draining`, not only the first. A request that needs approval is checked before the approval and again after it, and so are the launch activation and commit, the delegation and an `exec` that takes its job slot. A drain that begins while the PolicyKit dialog is open therefore refuses the approved grant with the same guidance, not with a denial. All of these checks use one admission function. Only a caller, launch owner or program that changed during the approval is still `authority_denied`, and the drain is reported before it. `busy` now means only that a request or job limit was reached. A look at the policy or a trust input that could not be taken answers `native_unavailable`, which is retryable. A request that the registry refuses keeps `authority_denied`.

`draining` is an additive value of `error_kind` under the same `dev-auth-administrator-grant-result-v1` schema, as `insufficient_remaining` was in ADR 0139. A new schema name would make an older client reject every result, so the schema stays. An older client cannot decode the new kind and reports a protocol failure, with no `changed` value, instead of printing it, so a client and its coordinator should be upgraded together, which setup does. A conformance test pins the name, the exit status, the message and the schema.

## Verification

Hermetic tests need no root, systemd, D-Bus or PolicyKit. They cover these cases, with expected values taken from issue #105 and the unit and cgroup rules above:

- the unit asset has no `Requires=`, `Requisite=`, `BindsTo=`, `PartOf=`, `StopPropagatedFrom=` or `Conflicts=`, wants and follows `polkit.service`, sets `Restart=always` without `RestartPreventExitStatus=`, and sets `ManagedOOMPreference=omit`;
- an unanswered approval call is `native_unavailable` with exit 3 and an answered one is `approval_denied`;
- a panicked task ends the process with a failure status, only an orderly stop exits with success, and a task that finished normally ends nothing;
- startup accepts the published unit and the previous one, each listed unit that setup observes satisfies startup, and a unit that stops only the coordinator, stops nothing, keeps `SendSIGKILL=no`, has `control-group` with a timeout above 5 seconds or an infinite one, or has `mixed` below 80 seconds is refused;
- each kind of work that a drain refuses fails with `draining`, exit 3 and the sudo plugin's guidance, work under an active grant continues through a sudo-program drain, and `status` and `leave` still answer;
- the decision after an approval answers `draining` in every drain and stop, and `authority_denied` only for a caller that changed;
- the result document for `draining` has the documented schema, kind and exit status.

The post-approval checks of delegation, launch activation and an `exec` taking its job slot call the same admission function, but need a live coordinator, caller and approval to run, so only the function itself is covered hermetically.

Native acceptance remains pending. It needs a PolicyKit restart while a grant is active and a request made while PolicyKit is stopped, a `kill -TERM -1` and a panic injected into the coordinator followed by the restart, an executable replaced beside the previous unit and a crash, `systemd-oomd` under memory pressure, and `exec` during a policy drain on an installed system.
