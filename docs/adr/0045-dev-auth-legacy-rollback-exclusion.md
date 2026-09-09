---
authority: canonical
owner: dev-auth
---

# ADR 0045: Legacy installation maintenance exclusion during full-generation migration

status: proposed
verification: pending

## Decision

The public Linux `setup repair`, `setup rollback` and `setup uninstall` commands resolve their installation and stable setup lock from the effective native account and explicit installation mode, not ambient home or path variables. Strong mode requires root and user-only mode requires a non-root native owner. Each obtains the same nonblocking exclusive lease used by full setup before inspecting or changing installation state and retains it through nested helper and receipt recovery. An admitted workload or another setup operation therefore blocks maintenance promptly. User-only legacy-session absence remains required because older executables did not hold admission leases. Native coordination on other platforms remains unavailable rather than falling back to uncoordinated mutation.

Binary-only rollback cannot restore the policy and integration generation retained by full setup. The low-level receipt rollback rejects any existing full-setup transition before helper recovery, launcher deactivation or receipt mutation. This applies to both pending and accepted generations. Malformed state, unsafe state or missing retained bytes never authorize a binary-only swap. The public command checks this while holding its lease, excluding concurrent publication by participating full-setup writers. A transition must not be deleted to bypass this boundary.

Public legacy repair and uninstall likewise reject a retained full-setup generation while holding their lease. Binary repair cannot establish configuration-aware recovery, and binary uninstall must not orphan the generation's remaining policy and integration authority. The existing transaction-aware `setup recover` route remains available for supported installed-candidate recovery. Deactivation and credential revocation are not indiscriminately routed through this exclusive maintenance boundary: reducing exposure must not depend on all admitted workloads first releasing their leases.

The low-level `repair_at`, `rollback_at` and `uninstall_at` library seams remain available for isolated installation fixtures and internal callers that own external serialization; they are not the public CLI's native admission boundary. Keeping them separate avoids reacquiring an already-held full-setup lease during nested recovery. No new CLI arguments, release selection, credential handling or privilege acquisition are introduced. Legacy installations without a full-generation transition retain repair, binary rollback and owned uninstall. Configuration-aware full maintenance remains a separate implementation requirement, not an outcome of this guard.

## Evidence and remaining gates

Receipt-level tests require pending and accepted full-setup markers to reject rollback while preserving exact receipt bytes and launcher targets. The disposable native-user installed CLI fixture requires a held shared admission lease to reject all three maintenance commands, then requires an accepted generation to reject after that lease is released. A separate installed native legacy fixture requires repair to reconstruct an owned alias, followed by successful rollback and uninstall preserving native programs. Both parents assert that the named child test actually ran. Separate legacy tests retain receipt-owned release switching; full setup retains explicit dispatcher deactivation without claiming generation restoration.

This evidence is source-binary Linux coverage. Signed strong-mode acceptance, old nonparticipating writer coordination, other lower-level mutation routes, whole-domain teardown and native non-Linux coordination remain required before production migration acceptance.
