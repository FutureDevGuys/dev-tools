---
authority: canonical
owner: dev-tools
---

# ADR 0118: Consumed native command graphs

status: proposed
verification: pending

## Decision

The focused command foundation adds `CommandGraphNode`, `GraphDependencies`,
`GraphExitPolicy`, `CommandGraphOutput`, dependency validation, and
`run_prepared_command_graph`. Each prepared command is consumed and retains any
held-executable borrow. Product policy, approval, run-as selection, environment,
input and output custody, output limits, and hostile-descendant containment stay
with the calling product. No product names or policy enter the foundation.

At most 64 nodes form a directed acyclic graph. Each stdout has at most one pipe
consumer and each stdin has at most one pipe producer. Pipes are native binary
streams and join their nodes into a concurrent component. Completion dependencies
wait for every member of the predecessor's pipe component, including cleanup,
regardless of success status. A dependency within its own pipe component is a
cycle and fails before spawning. Declaration order determines the `last`, `all`
and `pipefail` aggregate status independently of completion order.

The Linux backend reuses ADR 0088's process-group custody and bounded cleanup.
Auto-reaping SIGCHLD dispositions fail before spawning. Each leader stays
waitable through all real group signals; leader exit alone is insufficient
settlement. Partial spawn, cancellation and error paths close unused parent pipe
endpoints and signal every reserved running group before bounded individual
reaping. Cleanup failures remain visible. The caller supplies a bounded
nonblocking continuation callback and owns the overall deadline. Panic fallback
retains bounded cleanup. Escape from a process group still requires the caller's
native outer containment.

Unconnected streams retain caller-prepared descriptors. Captured `Stdio::piped()`
streams fail because the runner has no capture consumer. This mode does not
provide terminal foreground routing. The typed graph and
validation surface is portable. Other platforms return an explicit unsupported
execution error until a native backend is qualified; this source increment does
not establish Windows or another platform's runtime support.

The graph retains each selected native `ExitStatus`. A numeric exit such as 143
remains distinguishable from SIGTERM, allowing a caller to propagate a signal
after its product-owned cleanup. Exact plan bytes and dependency declarations
remain product-owned approval input; no old accepted plan digest grants a
changed graph.

## Verification

Focused source fixtures cover binary pipe preservation and EOF, completion after
failure, whole-pipe-component dependencies, invalid cycles and duplicate pipe
consumers, declared-order exit aggregation, native signals versus numeric exits,
held executable ownership, pre-cancellation and bounded partial spawn cleanup.
All eight graph fixtures passed on native Linux. The existing inherited custody
fixture passed its 21 isolated cases; nine public-file output fixtures passed,
with the existing Node.js acceptance fixture unrun. Warnings-denied all-target
Clippy passed for the command package. These results qualify this source slice;
they do not qualify a product installation or another operating system.

Compilation, source behavior checks and the owning product's stopped-coordinator,
run-as, stream bounds and terminal acceptance are recorded separately. This ADR
remains proposed with verification pending until its required native and installed
acceptance is established.
