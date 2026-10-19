---
authority: canonical
owner: dev-auth
---

# ADR 0096: Prove configured launcher startup before handing off a new grant

status: proposed
verification: pending

## Context

The disposable installed-grant run authenticated native login and completed both administrator scopes, but a deliberately broken launcher left its newly approved user-wide grant active. The strong supervisor had cleared its pending revocation owner immediately after writing the one-byte admission gate. That write proves only that the child may proceed; the child can still fail broker validation or `execve` of the configured launcher. A child exit status cannot distinguish a failed `execve` from a launched program's own exit status.

## Candidate decision

For a new strong-mode grant, the supervisor retains a private pipe writer across the internal `supervisor-child` exec. After validating its registered broker boundary, the final Dev Auth child starts the configured launcher with native `Command::spawn`; the platform spawn boundary returns an error if the target or its script interpreter cannot execute. Only after spawn succeeds does that child send a success byte, close its writer, and wait for the launched process. The parent commits the pending grant only after that exact proof. A failed spawn reports a failure byte; missing, malformed or timed-out proof revokes the new grant before ending the workload session. The pipe is not an authorization input from the caller; the existing cgroup, pidfd, policy and identity checks remain required.

The internal child remains as the launched process's monitor, retaining the registered pidfd and the native workload cgroup while the actual target runs as its descendant. It returns the target status and the outer service still owns domain teardown. The spawned target also receives a Linux parent-death signal if that monitor dies after reporting startup; the service-owned workload domain remains the definitive descendant cleanup boundary. This replaces the earlier candidate's close-on-exec plus `/proc/PID/exe` observation, which could not prove a successful target that exited before observation. A policy-selected sandbox adapter may carry the same inherited proof descriptor to its verified `sandbox-child`; that child checks native pipe custody and sends success only after its own final spawn. An adapter that closes or substitutes the descriptor cannot claim launch success, and the pending grant is revoked. Ordinary workloads without a new grant retain their direct exec path. A successful user-wide grant still follows its approved scope and deadline after the workload exits.

## Remaining gate

The local pipe fixture covers a running target, immediate successful and nonzero exits, explicit spawn failure including a missing interpreter, missing announcement, interruption before spawn and termination of a proved target after monitor death. Source tests cover the sandbox adapter's exact descriptor argument shape, and an opt-in unprivileged Bubblewrap namespace carried the private pipe to the final child. That transport probe is not a broker, grant, cgroup or terminal acceptance. The isolated installed development fixture passed both ordinary scopes and broken-interpreter cleanup on the preceding candidate, not yet on this revised monitor topology. Native replay must prove both scopes, fast exits, cleanup, coordinator loss, interruption, terminal behavior and the complete configured sandbox admission boundary. No signed Dev Auth release or host installation follows from the source correction.
