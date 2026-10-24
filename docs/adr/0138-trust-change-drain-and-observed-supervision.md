---
authority: canonical
owner: dev-auth
---

# ADR 0138: Trust changes drain the grant coordinator, and supervision acts only on observed state

status: proposed
verification: hermetic source tests pass; native acceptance pending

## Context

The grant coordinator binds two trust inputs at startup: the grant policy file and the sudo program that the policy names. It holds each file open and records its stamp, which is the device, inode, size, modification time and change time. Every reaping pass, control request and sudo connection compared both inputs again. Three faults followed.

- Any change to a trust input stopped every grant, and with it every managed job. Replacing the sudo program changes its stamp, so a package transaction that upgrades sudo inside a managed job killed that transaction partway through.
- The coordinator kept the stamps it bound at startup. After a change it refused every later sudo connection and every control request, `leave` included, until it restarted. The sudo plugin then refused every non-root account, because it refused whenever a coordinator accepted its connection and closed it, even for an account with no routing marker.
- A look that could not be taken counted as a finding. An unreadable policy file ended every grant, and an unreadable workload cgroup ended that workload's grant. A failed read about a pending launch owner or an execution client counted as that process being gone, and stopped its work.

## Decision

### Watched trust inputs

The coordinator watches the grant policy and the sudo program. For each input it holds the file it bound and that file's stamp. One look at an input compares two stamps with the bound stamp. One is the stamp of the held descriptor. The other is the stamp of the file that the path names now, opened with the custody checks that startup uses: root-owned ancestors and file, no group or world write, the expected file type and no symlink in the final component.

- The input changed when either stamp differs, when the path names a file that breaks custody, or when its final component is a symlink or the wrong file type.
- The look could not be taken when the path or the descriptor cannot be opened or inspected now. That includes a path that is absent while it is being replaced.
- An observed change wins over a look that failed.

A change to any watched input has the same effect, whichever input changed and whatever work is running.

### A change drains the coordinator

The first pass that sees a change closes admission for good. From then on the coordinator:

- admits no new grant, launch, delegation, execution, managed sudo or sudo relay under the old trust, even if a later look finds the inputs as they were;
- keeps every grant and every running job, and a job ends as before: at its grant's hard deadline, on revocation, on an observed logout, when its workload ends or when its command exits;
- keeps routing markers while their grants are active, so a routed account keeps denying instead of falling back to native sudo (ADR 0115);
- answers `status`, `inspect`, `revoke` and `leave`;
- exits once no managed job remains and no connection is open, so the client of a finished execution still receives its result.

At the exit it writes one journal line that names the changed input and exits with a failure status. `Restart=on-failure` then starts a coordinator that binds the new state.

The coordinator exits instead of rebinding in place. Startup is the only path that establishes trust. It takes the daemon lock, removes every routing marker, and validates the policy and the sudo program with the custody checks above. It then confirms the unit and recovers cgroups before any listener exists (ADR 0136, ADR 0137). A restarted coordinator therefore validates a replaced sudo program exactly as the first coordinator did. Admission stays closed from the change until that validation passes. If the new state fails validation, the coordinator never listens. No managed admission exists then, and sudo has its native behavior for every account.

Rebinding in place would add a second trust path that must match startup. It would swap trust under connections that still hold the old inputs, and it would fail the completion check of a sudo that still runs the old image. Its only benefit is to keep grants that have no running job across a change. That benefit does not apply to a policy change, because those grants were approved under the old policy.

The exit waits for running jobs, so `KillMode=control-group` finds no managed job to stop. Grants without a running job end at the exit, and their accounts have native sudo after the restart. A drain lasts at most until the latest hard deadline among the grants that still run a job.

[ADR 0141](0141-graceful-ends-and-drained-stops-for-managed-work.md) keeps new work under active grants admitted across a sudo-program change, answers a routed sudo with `draining` during any drain, and adds a bounded drain for an orderly stop.

### Supervision acts only on an observed answer

Reaping and supervision end a grant or stop a job only on an observed answer. A look that could not be taken changes nothing and is retried on the next pass. Admission still needs a positive look: a trust input, caller, launch owner or sudo peer that could not be observed refuses that one admission. Each observation is classified as follows.

| Observation | Observed answer that acts | Look that could not be taken |
| --- | --- | --- |
| Watched trust inputs | A changed stamp, a custody break, a symlink or the wrong file type drains the coordinator. | Any open or inspection failure, including an absent path. The admission that needed it is refused. |
| Workload population, from the held cgroup's `cgroup.events` | `populated 0` ends the workload's grant. So do absent control files, because a cgroup can be removed only once it is empty. | A read failure, oversized content or malformed content. |
| Pending launch owner: pidfd, `/proc/PID/cgroup` and `/proc/PID/exe` | An exited process, `ENOENT` or `ESRCH`, another cgroup or another image revokes the launch. | Any other read failure. The owner is unavailable for admission meanwhile. |
| Execution client: pidfd, and the namespaces, directory, identity and cgroup under `/proc/PID` | An exited process or any observed difference stops the job. | Any other read failure. |
| Execution client connection and captured-output connection | Readiness on a zero-timeout poll stops the job. | A poll that fails. |
| Execution signal channel | End of stream, a reset or a malformed frame stops the job. | `EAGAIN`, `EINTR` and `ENOMEM`. |
| Native sudo job leader, by pidfd | An exit marks the leader done. Only an invocation that never attached is stopped (ADR 0136). | A poll that fails. |
| Sender of a completion frame | A different sender, or a sudo that exited, stops the job (ADR 0136). | A liveness poll that fails abandons the invocation, and the job continues under its grant. |
| Identity after completion: `/proc/PID/exe`, cgroup and pidfd | Another image, a cgroup outside the job, or a sudo that exited stops the job (ADR 0136). | Any other read failure abandons the invocation, and the job continues under its grant. |
| Population of a stopping grant's boundary | An empty boundary is removed, and its cleanup is reported. | A read failure keeps cleanup pending instead of reporting it failed. |
| Population of an execution boundary during its cleanup wait | An empty boundary ends the wait. | A read failure keeps waiting within the existing five-second bound. |
| Liveness of a pending sudo relay | An exit drops the relay. | A failed poll also drops it, which refuses an admission that has not started. |
| Child wait, `waitpid` | Unchanged: an error other than `EINTR` means lost custody and stops the job. | Unchanged: `EINTR` is retried. |
| Boot clock | Unchanged: an unreadable `CLOCK_BOOTTIME` is an integrity fault (ADR 0137). It fails only with errors that never clear. | Not applicable. |
| Login, from logind | Unchanged from ADR 0136. | Unchanged from ADR 0136. |

### The sudo plugin falls back when the coordinator owns nothing here

The coordinator can accept a connection and then close it, exit, stall or garble its greeting or preflight answer. The plugin then decides by ownership. The coordinator owns an invocation when a routing marker selects its account or workload (ADR 0136), or when the invocation runs beneath the coordinator's own cgroup. Every managed job runs there, and a process inside a job routes through that job's grant without a marker.

- An invocation that the coordinator owns gets the `Unanswered` refusal of ADR 0137.
- Any other invocation has native sudo, as when no coordinator runs.
- Ownership that cannot be read denies. That includes a coordinator outside the plugin's PID namespace.
- An answer from the coordinator still decides, including a native answer for a selected account.

The plugin finds the coordinator's cgroup through the PID of the listening socket's owner. It confirms with the coordinator's pidfd that the PID was not reused before it compares the paths.

### Diagnostics

The coordinator writes one journal line for each of these events:

- a change that closes admission, with the input and the number of running jobs;
- the exit of a drained coordinator, with the input;
- the first failed look at a subject, and the first look that succeeds after it. The subjects are the trust inputs, a workload, a launch owner, a stopping grant's boundary and an execution client. A lasting fault does not write a line on every pass;
- an invocation abandoned because its completion could not be verified, with the grant, the job, the sudo PID and the error.

### Relationship to ADR 0115, ADR 0136 and ADR 0137

ADR 0115 ends grants on relevant policy loss. A change still ends them, at the drained exit instead of at once. ADR 0136 stopped a job on a policy change, and this record replaces that rule. ADR 0137 ended every grant on a changed or unobservable policy or sudo program, and ended a workload's grant on an unreadable population. This record replaces both rules. The refusal reasons of ADR 0137 are unchanged. This record narrows when the `Unanswered` refusal applies.

## Verification

Hermetic tests use injected stamps and looks, a temporary directory that stands in for a held cgroup, socketpairs that stand in for held connections, and a socketpair coordinator. They need no root, sudo, systemd or D-Bus. They cover these cases:

- a changed sudo program or policy keeps grants and routing and closes admission;
- the drain exit decision, with and without a running job;
- control requests that never wait for trust;
- a trust look that could not be taken, and the open-error classification;
- a removed, unreadable or malformed workload population;
- launch owner and execution client looks that could not be taken;
- the `/proc` exit classification and held-descriptor readiness;
- an unanswered invocation with and without ownership, an answering coordinator, and cgroup containment.

The reaping, bridge and supervision call sites have no hermetic test, because they need owned cgroup boundaries and a root sudo peer.

Native acceptance remains pending. It needs a long managed command that replaces the sudo program and then finishes, a policy edit during a managed job, `status` and `leave` during a drain, the drained exit and restart, sudo for an unselected account during a drain, and a policy file that is absent for one pass.
