---
authority: canonical
owner: dev-tools
---

# ADR 0030: Consumed inherited-command supervision

status: proposed
verification: pending

## Decision

Expose an additive inherited-stream runner through the focused command crate.
Its prepared command is consumed, retaining held-executable borrows and preventing
child-only signal-mask callbacks from accumulating across reuse. Native argv,
working directory, environment, and explicitly selected streams remain caller-owned.
No shell, credential authority, product policy, or external controller is introduced.
Held executables also expose a borrowed descriptor and additive per-component
validation callback. The shared ownership/type/mode baseline always runs first;
product callbacks can tighten it but never approve a rejected component.
Linux supplies the first backend; other targets return an explicit unsupported error.

The caller provides a bounded nonblocking continuation callback and owns the total
operation deadline. Pre-cancellation prevents spawn. Signal forwarding requires a
single-threaded launcher or a caller-owned process-wide signal-routing arrangement;
changing the calling thread's mask cannot control unrelated threads. The caller
must exclusively own child reaping and prevent disposition changes during the
invocation. Auto-reaping SIGCHLD dispositions fail before spawn; each real group
signal first requires a retained direct-child WNOWAIT observation. Each observation
cycle consumes at most64 pending signals so cancellation is not starved by a flood.
The existing terminal foreground contract is restored on exit and stop/resume.

The existing process-domain supervisor owns teardown, reserves the unreaped leader
identity while issuing group signals, and requires a group-extinction observation.
Leader exit alone is not successful cleanup. The shared Unix reaping phase uses
bounded try_wait polling after all real signals, avoiding process-global SIGCHLD
handler installation and remaining effective while SIGCHLD is blocked. Errors retain finalization failures;
panic fallback performs bounded cleanup. Descendants intentionally leaving the
owned process group require caller-owned outer containment and are not claimed
contained. A retained zombie may conservatively make cleanup fail rather than pass.

## Verification

A harness-free integration binary runs each signal case in a separate genuinely
single-threaded process, under an external driver deadline. Qualify ordinary exit,
held execution, pre-cancel, spawn failure, callback panic, direct interrupt signals,
stop/resume, terminal restoration and descendant settlement. Existing bounded and
public-file output tests remain required after sharing consumed-command ownership.
Target-native acceptance and release evidence remain required before advertising
installed-platform completion; source tests alone do not accept a product release.
