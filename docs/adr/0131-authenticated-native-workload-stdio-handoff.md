---
authority: canonical
owner: dev-auth
---

# ADR 0131: Authenticated native workload standard-stream handoff

status: proposed
verification: pending

## Context

Under enforcing SELinux, the signed 0.5.4 captured-output native fixture failed
before the workload boundary was accepted. A fixture-only descriptor snapshot
uniquely bound PID1's denial to the caller-origin stdout FIFO; stderr was a
different FIFO. The existing `systemd-run --pipe --pty` auto mode delegated those
captured descriptors through PID1. The result does not indicate a credential or
approval failure and does not justify a security-policy exception.

## Decision

Keep the existing all-terminal native PTY route. The dispatcher duplicates only
its inherited descriptors 0, 1 and 2 into owned close-on-exec slots above 2. If all
three refer to terminals, the service arguments retain `--pipe --pty`. Otherwise
the service starts with null standard streams and without either flag, so PID1
does not receive the caller-origin captured descriptors.

The dispatcher sends the retained streams over the existing StrongBoundary Unix
socket only after authenticating the receiving native UID, GID, retained peer
identity and exact workload cgroup. The service authenticates the root dispatcher
before receiving. This is stream transport, not enrollment, policy, approval,
credential, arbitrary descriptor-selection or filesystem-open authority. No
caller-provided descriptor number, path or environment marker selects a stream.

The private `DAIO1` frame precedes the existing shell-source and environment
frames. Its fixed six-byte body selects either the inherited terminal route, or
captured stdin/stdout/stderr in that exact order with a three-bit presence mask.
A closed inherited channel remains closed. No more than three rights are accepted;
unknown versions, roles, missing or excess rights, unexpected ancillary data,
truncation, EOF and deadline failure reject the launch. Every delivered descriptor
has close-on-exec and an RAII owner, including rejected rights. The handoff has a
fixed ten-second bound and cannot extend the existing caller, service or workload
hard deadline. Rights are never resent after a partial send.

Before any agent, credential or payload worker starts, the fresh service installs
the authenticated descriptors onto 0..2. Normalization above 2 prevents source/
destination aliasing. The same open-file descriptions, binary bytes, independent
channels and offsets are retained; output is not merged, buffered into a new
product log, or redirected to a caller-selected path. A partial installation
failure exits this fresh service before activation. Infrastructure diagnostics
before a captured-stream handoff use the existing value-free dispatcher stage
and failed native status; the service's initial null streams cannot emit payload
or credential output. Mixed-terminal approval continues on the dispatcher's
existing foreground TTY agent. Native service/cgroup ownership, namespace mapping,
admission, argv/environment, credential lifetime and termination receipts remain
authoritative. SELinux enforcement and policy remain unchanged.

Both peers must come from the same receipt-verified candidate. An old peer fails
the new frame rather than interpreting stream data as shell-source authority.
There is no silent legacy fallback, new public CLI selector, installed migration
or setup mutation. Retained older installed releases keep their immutable bytes.

## Verification

Focused ordinary tests cover the denied routing choice, unchanged terminal route,
actual terminal versus mixed-stream detection, binary stdin and separate stdout/
stderr through child installation, closed channels, exact descriptor identity,
shared regular-file offset, close-on-exec, fragmented frames, timeout, peer closure
without SIGPIPE, and leak-free rejection of malformed, excess and truncated rights.
The existing transient-service builder also pins captured service properties and
literal payload argv. These checks do not prove SELinux acceptance.

Native qualification must use a newly built matching core and test harness in a
fresh owned enforcing systemd guest. First run the existing public strong enrolled
workload/recovery fixture, with its explicit synthetic retained provenance and
synthetic provider. It must establish the real protected dispatcher, credential
read/stdin projection without secret stdout, whole-domain expiry/revocation/death
cleanup, and restoration. It is source behavior, not signed release acceptance.
The unchanged signed fresh-install/workload/restoration fixture requires a newly
authenticated bundle for the corrected source; old signed 0.5.4 bytes and their
failure cannot qualify this correction. Terminal streams, native grant approval,
mixed streams and lifecycle acceptance remain required before a platform or
release claim. A receiving-domain SELinux denial remains a genuine failed result;
no relabeling, allow rule, permissive mode or credential substitution is permitted.
