# Native pipe-collector exclusion proof

Status: source/runnable harness only; native collector tests NOT RUN. This is the release/deployment qualification for process-local pipe support. It is not a runtime attestation subsystem and does not authorize changing an existing host's crash handling.

## Exact supported mechanism

The dedicated root maintenance bootstrap inherits soft=hard RLIMIT_CORE1 through the native approval child's pre-exec hook. systemd creates its coordinator with LimitCORE1 before ELF startup. Private maintenance entries set DUMPABLE0 and set/read back limit1 early. The operation wrapper establishes this before forks, capability dropping and payload exec. Payload/seccomp descendants cannot change CORE via setrlimit or prlimit64, even to0; read-only queries work. Resource numbers are compared after the kernel's32-bit truncation and new-limit pointers are checked across all64 bits. Alternate syscall ABIs reject first.

Linux's exact limit1 recursion check runs before starting a pipe handler. Limit0 does not do this. Socket collectors (`@`/`@@`) remain rejected. A native caller with inherited hard CORE0 cannot raise it to1 in the approval child and fails the read-only readiness check. This source does not change the user's shell limit or host sysctl.

The ordinary source test `core_limit_filter_survives_native_child_exec_and_rejects_writes` runs only an unprivileged disposable child with the actual filter, makes native mutation/query syscalls and reexecutes another child. It never triggers a core or collector. Pure BPF conformance checks cover full-width pointers, truncated resource values and alternate architectures/ABI. These source checks are useful but cannot replace the native cases below.

## Preconfigured isolated kernel fixture

Use a separately authorized disposable VM/kernel, or an already appropriate isolated native test machine. A normal container shares its host kernel core_pattern; it is not permission to change that host setting. Nothing in this harness writes any sysctl, installs a collector, changes policy or creates a grant.

The fixture must already run systemd with the other native matrix prerequisites and `/run/.containerenv` explicitly marking the disposable fixture. The reviewed root-owned0755 `dev-auth-privilege-native-fixture` executable is the collector/controller/fault observer. Its exact kernel core pattern must already be:

```text
|/ABSOLUTE/VERIFIED/dev-auth-privilege-native-fixture core-collector %P
```

`%P` is the initial-namespace host PID. Require the exact kernel release and profile bytes in the test evidence. Provision `/run/dev-auth-core-fixture` as root0700, `events` as an empty root0600 single-link regular file, and `configuration.json` as root0600 with exactly:

```json
{"schema":"dev-auth-native-core-collector-v1","kernel_release":"EXACT_NATIVE_RELEASE","collector":"/ABSOLUTE/VERIFIED/dev-auth-privilege-native-fixture","collector_sha256":"INDEPENDENT_64_HEX_ARTIFACT_DIGEST"}
```

The collector image, fixed directory, configuration and event inode are retained/revalidated. Each kernel invocation appends and fsyncs one bounded event, then waits for a root observer acknowledgement so that its exact native image/argv and pidfd can be retained before exit. It never reads or stores core contents. A missing acknowledgement fails after five seconds. Prepare fresh empty event/ack state for every case; do not erase a failed run's evidence.

## Three finite cases in the existing native matrix

Use the ordinary `prepare`, public plan, `write-input`, explicit root `fault-driver` and non-root integration command documented in `PRIVILEGE-NATIVE.md`, with one fresh grant/scope for each:

- `core-collector`: the actual privileged helper checks immutable limit1, attempts lowering, raising, idempotent writes, high-bit resource and high-only pointer bypasses, and verifies read-only queries. It forks/executes a descendant that repeats them and crashes with SIGSEGV. After its native join and no-core status, the direct helper repeats checks and crashes. The trusted wrapper re-raises that same native signal. The root observer resolves the unique host PIDs using exact executable inode/argv and the retained operation cgroup; payload-provided namespace PIDs are never authority. It retains all operation PIDs, including wrapper/init, before releasing each crash checkpoint
- `core-coordinator-death`: reuse the established detached-root-work/coordinator-death seam, but signal the exact retained coordinator pidfd with SIGSEGV. Check its native CORE1 limit before injection and require whole-domain cleanup, stopped descendant writes and released setup exclusion
- `core-bootstrap-death`: reuse the pinned approval/argv/bootstrap-death seam with SIGSEGV on the exact retained bootstrap pidfd. Require the same cleanup and exclusion proof

Every case performs a positive root control before approval and after all retained negative subjects die. That control sets CORE0, makes itself dumpable and crashes; the configured collector must actually append/fsync the matching host-PID event, be authenticated by its inode/argv, acknowledge and finish. Both positive controls and collectors are joined before final event comparison. The exact event inventory must contain only those two positive PIDs. Any event for a payload, descendant, wrapper, coordinator or bootstrap fails. A declined approval, missed identity/checkpoint, unavailable observation or collector failure fails; silence alone is never a pass.

The root observer starts first and publishes readiness only after the first acknowledged positive control. It accepts only the closed disposable input, and no arbitrary signal target or command tail. The normal native observer independently proves terminal cgroup emptiness/removal and socket cleanup. The fixture changes no system/core settings while it runs.

Retain exact candidate/collector hashes, kernel release, core profile, independently approved plan/digest, protected event bytes and complete test/stdout/stderr/terminal observations. Pass these three cases and the real-adapter matrix before claiming this candidate works with pipe collectors. The full containment matrix now has27 finite cases; the four real receipt-installer cases remain separate.
