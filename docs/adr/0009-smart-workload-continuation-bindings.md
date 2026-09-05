---
authority: canonical
owner: dev-auth
---

# ADR 0009: Smart workload continuation bindings

status: proposed
verification: pending

## Context

Users launch agents through vendor commands, wrappers, desktop entries, aliases, and shell functions. Bypassing or replacing those programs loses behavior and creates machine-specific deployment debt. A same-name proxy needs one desired-state authority and reversible ownership, not a second configuration mechanism.

## Decision

Dev Auth installs receipt-owned proxies ahead of approved downstream targets without moving or overwriting the original program. A continuation preserves the currently visible executable or wrapper. A structured binding declares an exact executable, fixed argv, caller insertion position, public environment policy, and working-directory behavior. A pinned-shell binding retains an explicitly submitted bounded shell definition and exact shell identity and requires separate permission and acknowledgement of shell-language authority.

Setup excludes its owned proxy layers during discovery and records the native resolution order, visible and canonical target identity, continuation path, and current receipt preconditions in the common setup plan. CLI binding management and deployment documents normalize into the same desired-state model. An externally managed source is not edited implicitly; the CLI emits the normalized proposed source change. User-only reconciliation never activates proxies or modifies services, administrator policy, or enrollment.

An admitted launch retains the approved executable identity once. Runtime Git/gh operations do not rediscover or hash the binding. New downstream bytes require a new digest-bound plan, whether classified as a refresh of an existing binding or an intentional rebind. Root ownership alone does not authorize silently accepting replacement bytes. Same intent and identity produce zero changes, and discovery excludes existing proxies to prevent stacking.

Activation is journaled: deactivate affected proxies, validate the candidate and policy, atomically publish the new immutable binding generation, verify integration, and activate last. Receipts bind owned paths and the exact prior generation. Rollback restores that generation only when its downstream identity still verifies; it does not reinstall or substitute an unowned third-party program. Removal deletes only receipt-owned artifacts so the untouched original becomes visible again.

## Invariants

- Preserve native argv, cwd, streams, terminal behavior, signals, and exit semantics within the explicitly declared environment and continuation behavior.
- Reject unsafe custody, altered receipts, unowned collisions, ambiguity, known binding cycles, and recursive admission. Do not claim static interpretation or proof of arbitrary wrapper programs.
- Pinned-shell source enters through stdin, contains no credentials, is privately stored and digest-bound, and reaches the retained shell through a private descriptor or handle rather than argv or environment.
- Discovery recipes contain product-specific suggestions; authorization remains generic. CLI and desktop identities are distinct. An editor is never admitted merely because it hosts an agent extension.
- Desktop integration is either a reversible owned override or a separate entry; an unowned user override is never replaced.
- Native containment carries descendant authority. Task IDs, copied variables, paths, and socket names do not grant admission; independent tasks must launch through an admitted binding.

## Verification

Tests cover wrapper and symlink preservation, structured argument insertion, bounded shell source, path ordering, proxy exclusion, recursion, target replacement, explicit rebind, interrupted activation, receipt tampering, rollback, owned removal, no-op convergence, desktop collisions, exact streams and signal behavior, and externally managed configuration. Native acceptance exercises CLI and desktop agents, editor subprocesses, nested shells, subagents, concurrent workloads, and denied-session no-fallback behavior.
