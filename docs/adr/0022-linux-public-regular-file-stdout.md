---
authority: canonical
owner: dev-tools
---

# ADR 0022: Linux public regular-file stdout

status: proposed
verification: pending

## Decision

`dev-tools-command` 0.1.2 adds an explicit Linux regular-file stdout mode for admitted public-output observers. Some upstream programs explicitly exit before asynchronous pipe writes finish; a successful status then accompanies incomplete output. The public synthetic Node fixture captures that failure without importing consumer policy. Default pipe capture and the frozen 0.1.1 package remain unchanged.

The new prepared-command functions consume either a native `Command` or a `HeldCommand` through `OwnedPreparedCommand`, which retains the held executable borrow. Consumption prevents child setup from persisting into a later operation. Native argv, environment, working directory and admitted child setup remain attached to the command. Stdin is closed and stderr is still a bounded pipe. The existing Unix supervisor remains the sole authority for cancellation, timeout, process-group cleanup and primary/secondary errors; this mode adds no shell, secondary controller or product policy.

Stdout uses a close-on-exec anonymous Linux memory file with owner-only permissions and sealing enabled. Before execution, a child-only callback lowers both soft and hard file-size limits to the minimum of the inherited limits and the requested output bound plus one overflow-detection byte. Kernel enforcement bounds ordinary stdout extension independently of polling speed. The limit also restricts extension of other regular files, including incidental cache files. Callers must admit only operations compatible with that child-wide restriction. This is not containment for privileged or deliberately escaping workloads, a total-memory limit, or a filesystem-allocation sandbox. The callback uses fallible libc resource-limit operations; the already-locked MIT/Apache-2.0 libc dependency supplies the platform ABI without introducing another runtime or security framework.

The GNU C Library documents `getrlimit` and `setrlimit` as async-signal-safe in its [resource-limit interface](https://sourceware.org/glibc/manual/latest/html_node/Limits-on-Resources.html). The callback uses initialized stack values and errno conversion without allocation or locks. Native qualification here is Linux x86-64 GNU; another libc or native target still requires its own process acceptance.

All stdout work must finish by command-leader completion. The supervisor observes file size but does not read mutable output while the command runs. After leader exit and stderr completion it terminalizes the owned process group, seals stdout against writes, growth and shrinkage, then reads immutable bytes at explicit offsets. A retained writer cannot alter accepted bytes or move the reader's shared offset. Sealing failure is a terminal capture error. The mode does not wait for regular-file EOF and does not extend the existing guarantee to detached process groups. Public capture storage never uses a named temporary path or `TMPDIR`; it is not secret custody and does not promise secure erasure.

## Verification and publication

The public crate suite covers regular stdout and piped stderr, exact bounds and overflow, native arguments/environment/cwd/status, closed stdin, pre-cancellation, held execution, unchanged parent limits, stricter inherited limits, timeout, spawn failure, running cancellation and successful-leader descendant cleanup. A kernel-bound test runs the production child setup without a supervisor. Finalization tests retain a competing file handle and prove offset independence and write/resize denial. The explicit Node acceptance test checks the complete upstream-style early-exit JSON document.

Source tests do not establish downstream CLI compatibility, registry availability or another native platform's acceptance. Publication requires a clean signed source, reproduced package bytes, authenticated source-to-package binding, registry checksum verification and the consumer's own real-CLI gate. No production consumer cutover is authorized by a neighboring source checkout or the frozen 0.1.1 archive.
