---
authority: canonical
owner: dev-tools
---

# ADR 0121: Foreground terminal command graph custody

status: proposed
verification: pending

## Context

ADR0004 requires typed and exact plans to retain native terminal streams and job
control. ADR0118's existing graph mode explicitly excludes foreground routing and
assigns a separate process group to every node. Feeding that runner a PTY does
not establish the terminal plan contract. ADR0119's independent output and job
owner remains responsible for enforcing an approved deadline while a worker is
stopped; a shared command runner must not acquire that product policy.

## Decision

The focused command foundation adds `run_prepared_terminal_command_graph` with
consumed `CommandGraphNode` values, `GraphExitPolicy`, an explicit
`TerminalGraphSignalMask` choice, and a bounded nonblocking continuation callback.
The existing ordinary graph and inherited command public APIs remain intact.
No product identity, approval, run-as policy, descriptor adapter, output cap,
cgroup authority or external controller enters this shared interface.

The Linux backend requires a current controlling terminal and the launcher's
foreground ownership before any spawn. The same bounded DAG validation, native
binary pipes, completion dependencies and declaration-order status aggregation
apply. Ready pipe-connected components run one at a time, chosen by their first
declared node; this explicit terminal schedule permits one foreground group per
active component on the terminal. Every component member joins its first owned
child's group. Each native spawn is checked against that group. Caller-selected
unconnected streams and held executable/descriptor callbacks survive unchanged;
undrained capture pipes fail with owned cleanup.

The first direct child remains unreaped through every real group signal, including
stop, continue, partial-spawn failure and normal completion cleanup. Each direct
member has separate wait custody. Exit observations use WNOWAIT; stop/continue
consumption never consumes an exit. If a child exits between the initial state
observation and a stop/continue-only consuming wait, Linux may return ECHILD to
the latter query. Only a fresh successful WEXITED|WNOHANG|WNOWAIT observation
proving that exact retained child's exit accepts this race; lost custody and
non-exit failures remain errors. Followers are reaped before the reserved
leader, after all cleanup signals, and a failed follower reap retains that leader
for bounded fallback. Signal-zero group extinction after reaping is conservative:
PID reuse may fail cleanup but cannot authorize a real signal or false success.
A lost wait/group owner fails closed; the runner never signals a recycled hint.
Descendants which deliberately leave a group still require caller-owned native
containment.

A focused private terminal/signal custody module is shared with ADR0088's inherited
runner. Its existing inherited mask selection, forwarding, foreground restoration
and public behavior remain in force. The new terminal graph additionally observes
job-control signals, consumes at most64 pending signals per cycle, and waits on a
held nonblocking signalfd with a bounded poll interval. It changes only the calling
thread's mask, never global signal handlers or dispositions. The caller must own
all child reaping, prevent SIGCHLD disposition changes, and use a single-threaded
launcher or explicit process-wide routing. Automatic child reaping is rejected
before admission.

`RestoreEntry` appends an async-signal-safe child callback restoring the API-entry
thread mask, matching inherited execution. `PreservePrepared` appends no child
mask callback: the caller explicitly owns each prepared payload's mask. This
prevents a worker's intentionally blocked helper signals from overriding a
product-prepared restoration of the payload's captured outer mask. The prepared
callbacks execute in their original order and retain their complete commands.

A stopped member stops its entire owned component. Native non-reaping observations
must establish every direct member stopped or exited before foreground restoration
and the owner's self-stop. On external resume, the same continuation callback is
checked immediately before returning foreground ownership and continuing payloads;
no deadline is reset. An independently running native owner is necessary to enforce
expiry while the launcher itself is stopped. This requirement stays explicit in
product integration and is not approximated by an in-process timer. Partial spawn,
cancellation, operation errors and panic fallback close remaining command owners,
retain bounded native cleanup and restore terminal ownership before releasing the
signal mask. Uncertain process, terminal or mask finalization cannot return success.

The public typed surface is portable. Platforms without this backend return an
explicit unsupported result; cross-compilation does not establish native support.
This additive API extends ADR0118 for terminal callers without changing its ordinary
concurrent mode, and preserves ADR0004/ADR0119 approval and independent ownership.

## Verification

Source fixtures extend the existing isolated single-threaded inherited-command
harness. They define shared foreground PGID and binary pipe/EOF behavior, held
executable custody, component dependency completion, all three exit policies,
foreground restoration, whole-component stop/resume, externally expired suspended
work that cannot continue, real PTY-generated SIGINT, kernel-handshake partial
spawn failure, admitted cancellation, prepared payload masks, absent terminals and
background refusal. Existing auto-reaping and pre-cancellation fixtures also cover
the new API. The existing outer driver accepts `--fixture NAME` only for one
explicitly declared fixture name, retaining the same fresh private child directory,
PTY/session setup, stop/resume ownership and finite watchdog. Unknown or malformed
selectors fail before child admission. Its own try_wait/stop-only observation race
also requires a fresh retained exit proof before the normal owned reap. This
selector permits bounded focused qualification without replaying unrelated cases.
Ordering uses native pipe/read and waitid evidence rather than a sleep-based
admission claim. No new test framework or dependency is introduced.

Only source preparation, parser/format checks and exact before/after inventory are
claimed here. Compilation, strict owning lint, focused native fixtures and actual
product terminal/run-as/cap/deadline acceptance remain unrun under the global
compiler hold. Independent review and the owning qualification gates must pass
before publication or any installed-platform support claim.
