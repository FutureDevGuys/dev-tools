---
authority: canonical
owner: dev-auth
---

# ADR 0094: Explicit binding code trust

status: proposed
verification: pending

## Decision

The pre-activation binding plan and receipt foundations move to v3 and include an explicit `code_trust` field in each binding intent. `pinned` is the drafting default; `mutable` requires a deliberate `workload bind plan --code-trust mutable` choice. Code trust is separate from native workload containment and credential policy. A change from pinned to mutable is a rebind with a new digest-bound plan and retained prior generation, never an automatic refresh or silent downgrade.

The v2 draft plan and foundation receipt encodings are rejected under v3. No active binding proxy or installed binding receipt used v2, so the cutover does not migrate an installed launcher, credential, setup generation or release. An existing draft must be regenerated from current target identity. The target-specific resolution and snapshot mechanisms from [ADR 0017](0017-binding-target-specific-resolution.md) remain unchanged.

## Remaining gate

This schema change does not activate a proxy or make pinned/mutable execution safe. Activation must bind the selected workload launcher to the approved target, preserve native argv/cwd/streams and identity, keep an immutable pinned-byte view when selected, allow later edits only for explicit mutable mode, journal receipt/proxy publication through setup, and verify rollback/removal. Until those gates pass, the public binding command remains discovery and planning only. Tests cover default pinned plans, deliberate mutable plans, legacy-schema rejection and explicit trust downgrade classification.
