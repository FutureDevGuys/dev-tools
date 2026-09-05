---
authority: canonical
owner: dev-tools
---

# ADR 0004: One-shot authorization and bounded administrator sessions

status: proposed
verification: pending

## Context

Standalone products need bounded privileged effects, while an operator may deliberately authorize a wider workload. Reusing ambient sudo timestamps confuses these authorities and does not translate safely across operating systems. The distinction between an exact invocation and a restriction on that invocation's effects must remain visible.

## Decision

`dev-tools-privilege` authorizes one typed operation against one absolute identity-validated helper. `dev-tools-privilege-session` owns the separate product-neutral lease lifecycle; products compile the shared implementation and own their policy and narrow helpers. Neither primitive requires a sibling product at runtime. Dev Auth exposes explicit administrator sessions for user-selected work, not an expansion of ordinary setup or update authority.

A lease binds native caller and retained workload identity, product and operation audiences, helper and plan identities, resource scope, use limits, and idle and hard expiry. The tiers are `typed`, `exact-plan`, and `unrestricted`. Typed authority admits only product-defined operations. Exact-plan authority admits only the approved executable graph and streams; its approval discloses broad-effect executables and interpreters rather than implying that fixed argv constrains all resulting effects. Unrestricted authority requires separate administrator-policy permission and visible native approval and is explicitly root/admin-equivalent.

Default lifetime is 30 minutes idle and two hours hard. Administrative policy may lower either value or explicitly raise the hard limit to at most eight hours. Time accounting is monotonic and includes suspension where the native contract requires it. Only accepted useful activity resets idle time. Polling, heartbeats, and delegation never extend hard expiry. Leases are memory-only and broker restart invalidates them.

Expiry and revocation deny new admissions, recursively invalidate descendant authority, cancel managed commands, permit bounded cleanup, and then force termination and join through the retained native boundary. Failure to prove cleanup is a failure outcome, not successful revocation. A delegated lease can only narrow authority, lifetime, and the parent's conserved use budget. Attaching authority to an arbitrary existing PID is prohibited.

Executable plans use a bounded DAG with exact native argv, environment and working-directory policy, run-as identity, binary-safe pipes, explicit stdin/output modes, PTY or ConPTY, output limits, cancellation, and `last`, `all`, or `pipefail` exit aggregation. Shell interpretation exists only for explicitly approved pinned-shell or unrestricted work. An optional same-name sudo binding preserves native passthrough outside an eligible lease; it does not implement sudo grammar or turn a typed lease into arbitrary administrator authority.

## Invariants

- Ordinary product helpers expose no arbitrary root command, write, shell, or filesystem capability. The separately approved unrestricted Dev Auth tier is the explicit exception, never an implicit fallback.
- No tier handles passwords, refreshes global sudo timestamps, trusts environment variables as authority, or exposes an unauthenticated root endpoint.
- Release authenticity and privilege authorization are independent.
- Each product owns a narrow receipt-bound helper and can operate without a separate broker product.
- Logout, authority loss, helper replacement, revocation, or policy change invalidates the affected lease and starts cleanup.
- Revocation cannot undo completed privileged effects or guarantee containment against a malicious administrator who disables enforcement. This limitation is disclosed before unrestricted approval.

## Verification

Contract tests cover all tiers, exact-plan admission, replay, audience confusion, identity replacement, idle/hard expiry, suspension, use exhaustion, delegated-budget conservation, recursive revocation, binary pipelines, terminal streams, interruption, broker crashes, cleanup failure, and value-free audit output. Each platform backend additionally proves native caller identity, helper custody, and retained process containment before exposing session operations.

## Runtime acceptance

Linux, macOS, Windows, and WSL2 are accepted separately through their native approval, IPC, process, and filesystem boundaries. Linux uses retained pidfds and directly managed cgroup v2; systemd, OpenRC, runit, and s6 are service adapters rather than identity authority. WSL admission does not grant Windows authority. Native host access, signing identities, and required entitlements are acceptance prerequisites. No platform claim follows from another platform's tests or a cross-compiled binary.
