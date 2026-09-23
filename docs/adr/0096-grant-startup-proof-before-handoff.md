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

For a new strong-mode grant without a sandbox adapter, the supervisor retains a private pipe writer across the internal `supervisor-child` exec. The child validates its registered broker boundary, arms close-on-exec on that writer, announces the final configured-launcher exec attempt, and reports a failed exec explicitly. The parent commits the pending grant only after the announcement, writer closure, and observation that the retained child is still running under an executable other than the installed supervisor. Missing, malformed, failed, timed-out, or ambiguous proof revokes the new grant before ending the workload session. The pipe is not an authorization input from the caller; the existing cgroup, pidfd, policy and identity checks remain required.

This proof is deliberately conservative. An executable that ends before the parent can observe the changed native image may have run, but cannot retain a newly issued grant on that ambiguous evidence. A configured launcher that resolves to the supervisor executable is likewise not proven. Grant-bearing launches through a sandbox adapter remain blocked until the adapter can preserve an equivalent final-exec proof across its own process boundary. Ordinary workloads without a new grant retain their existing launch path. A successful user-wide grant still follows its approved scope and deadline after the workload exits.

## Remaining gate

The local pipe fixture covers successful final exec, explicit exec failure, missing announcement and a signal between announcement and exec. The isolated installed development fixture has repeated both ordinary scopes and the broken-interpreter startup case with no active user grant remaining. Additional native checks must cover immediate exit, sandboxed launch, coordinator loss, interruption, and terminal behavior before this candidate is called fully accepted. The fixture did not install or release signed Dev Auth bytes on the host.
