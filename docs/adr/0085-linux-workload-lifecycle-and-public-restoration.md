---
authority: canonical
owner: dev-auth
---

# ADR 0085: Linux workload lifecycle and public restoration

status: proposed
verification: pending

The Linux supervisor retains the authenticated dispatcher's peer pidfd through workload execution. Dispatcher death fails supervision, and failed supervision returns before synchronous broker cleanup so the native service can terminate remaining descendants. The broker independently retains its session lease and retryable credential cleanup. Active sessions renew every five seconds to observe revoked authority without extending their approved hard deadline. Pruning expired pending admissions returns their identifiers for broker cleanup, just as pruning active admissions does.

The strong service's full identity mapping is a semantic property, not a requirement for one textual map row. UID and GID maps must describe an exact, contiguous identity mapping across the complete supported identifier range. Bounded partitioned and reordered mappings are accepted; gaps, overlap, remapping, zero-length and overflow ranges are rejected. This preserves the native identity requirement when systemd emits more than one identity range.

`setup restore --mode strong` now enters the existing native-root, exclusive-lease, retained-generation restoration composition. This supersedes the public strong-mode gate in ADRs 0049 and 0064; their custody, direction, inactive-state, exact-candidate and credential-preservation requirements remain unchanged. The command cannot obtain privilege itself or accept a new plan or credential. Retry output retains the selected mode and immutable candidate path. Non-Linux restoration remains unsupported.

The optimized public-binary disposable-systemd fixture uses synthetic encrypted enrollment and a bounded fake provider. It completes strong setup recovery, real set-ID dispatch, non-root broker admission, provider validation, logical read and stdin projection without secret stdout. Separate expiry, revocation, dispatcher-death and broker-death cases require both the worker and its detached TERM-ignoring descendant to terminate within twenty seconds, followed by unit cleanup and released setup exclusion. The same fixture then restores initial absence through the public command, preserves encrypted enrollment and requires an unchanged retry. A separate fresh-container fixture restores a retained prior strong generation and verifies a public unchanged retry.

The pre-fix native matrix failed revocation and dispatcher-death containment; both pass with the supervisor changes. Pending-expiry and partitioned-identity regressions also failed before their focused fixes. The public owner test previously returned an unconditional strong-mode gate and now rejects a non-root caller through the installation-owner authority check without mutation. Normal root-host test execution never invokes the mutating public restore operation.

These fixtures use synthetic retained release provenance and no live provider credentials. They establish native source behavior, not signed intake, real-provider scope, power-loss durability, non-Linux support or unrestricted administrator-session implementation. Signed fresh install, upgrade and restoration remain release gates. General-purpose workload scope and native argument handling are unchanged.
