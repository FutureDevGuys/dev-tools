---
authority: canonical
owner: dev-auth
---

# ADR 0088: Approved command graphs in owned execution

status: proposed
verification: pending

`privilege exec --plan-sha256 DIGEST` and `privilege exec --operation NAME` select a complete administrator-configured execution plan. They cannot be combined with a caller-supplied command. The coordinator proves that the selected grant contains that exact plan or named operation, admits one use for the whole graph, and preserves the existing scope, deadline, signal and revocation boundaries. Arbitrary root execution remains the separately approved administrator tier.

The product-neutral command foundation owns bounded native pipe wiring and direct-child lifecycles: at most 64 nodes and 63 topologically ordered one-to-one stdin/stdout pipes. Each process keeps caller-configured unconnected streams; graph roots and sinks inherit the invocation's streams. Concurrent unconnected nodes may interleave those streams. Every unused parent pipe endpoint closes before waiting. Failure or cancellation stops every admitted direct child before bounded reaping, and callers remain responsible for detached-descendant containment.

Linux creates each graph pipe with atomic close-on-exec flags. Darwin lacks the `pipe2(CLOEXEC)` primitive used by that implementation; setting `FD_CLOEXEC` after `pipe()` leaves a concurrent-spawn descriptor leak window. The Apple source branch therefore rejects a piped graph before spawning any node until an equally strong native descriptor backend is implemented and qualified. Unconnected graph nodes retain their ordinary direct-child behavior. This is explicit fail-closed source compatibility, not a macOS administrator-execution support claim.

Dev Auth supplies that containment through one root-owned execution cgroup. A private same-product worker receives the validated policy plan through a sealed anonymous descriptor, not argv, environment or a named file. Its real/effective root identity is required before descriptor intake; setid invocation still enters only the existing enrolled dispatcher. The coordinator executes the retained product ELF and retains each inherited descriptor at its existing number, clearing close-on-exec only in the child. Keeping the owned handles live prevents collision with the held executable or spawn-internal descriptors; there is no fixed descriptor target or remapping. The worker cannot authorize, refresh, delegate or widen the grant.

The worker starts configured native argv, environment and cwd in the retained caller mount context, wires binary pipes, and waits for the direct nodes. `last` selects the last declared node's result, `all` the first nonzero result, and `pipefail` the last nonzero result; all-success results are zero. Signal outcomes use the native shell-style `128 + signal` aggregate. Internal worker failures use exit 125. On unsuccessful graph completion, the coordinator terminates remaining owned descendants and requires emptiness before returning; failed cleanup remains a failure. Successful detached descendants remain under the grant's existing expiry/revocation controls.

Verification includes isolated command-crate compilation, lossless binary pipes and EOF, partial-spawn cleanup, pre-cancellation, invalid graphs, exit aggregation, narrower authority selection, sealed plan custody, noninteractive CLI behavior, and native execution under both grant scopes. The root cgroup fixture additionally tests separate real/effective identity and preservation of an inherited descriptor alongside the held image. Source checks do not establish signed installation or complete platform acceptance.
