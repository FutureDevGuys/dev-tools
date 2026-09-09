---
authority: canonical
owner: dev-auth
---

# ADR 0073: Initial staged-binary forward recovery

status: proposed
verification: pending

## Decision

[ADR 0077](0077-unstaged-initial-user-installation-recovery.md) additionally permits retained initial absence before the binary layout exists, using the exact approved running candidate and conditional absent installation.

[ADR 0075](0075-staged-user-upgrade-forward-recovery.md) extends the same staged-candidate mechanism to an exact retained user-only prior installation, preserving its product receipt's separate replacement authority.

Linux setup recovery can finish an approved initial user-only binary installation whose versioned executable is already staged but whose shared receipt is absent. This extends ADRs 0044, 0069 and 0072 only for paired prior receipt absence, a missing current product receipt and the exact retained pending candidate. Upgrades, incomplete strong installations, absent candidate bytes and new release selection remain outside this path.

Admission revalidates the retained plan and candidate documents, native caller and running candidate identity, setup exclusion and forward direction before mutation. The prospective product receipt comes from the existing pure constructor. An exact shared-transition observation must establish either the approved uncommitted initial journal or prior receipt absence without a journal. Product-owned directory checks and the shared bounded artifact reader verify the retained versioned executable. With a journal, existing binary pointers may only name that exact candidate; without one, they must be absent. Unknown product aliases and previous pointers reject before recovery. This binary operation does not select transparent launcher publication or acquire ownership of independent same-name tools.

Exact shared recovery first restores prior absence and retires the approved journal. A conditional shared install then requires continued receipt absence under its installation lock, uses the retained versioned executable and fixed approved identity, and rechecks product receipt absence and candidate custody before activation. No executable download or original source is required. Product receipt publication retains ADR 0072's absent-current atomic publication and full post-publication verification. The normal configuration/enrollment continuation and activation-last gate remain unchanged.

An interruption after prior restoration is resumable from the retained executable with absent shared pointers and receipts. An interruption after shared activation uses the committed-candidate receipt-completion path. Completed restoration, activation and receipt publication each record established change before the next operation; an entered failure without such evidence remains uncertain. A successful forward completion adds `complete_initial_binary_installation` to the existing action list. Independent legacy writers still require the separately tracked full coordination work; intermediate observations do not establish a continuous installation lease.

## Verification and remaining gates

Focused tests cover partial aliases, no-journal restored absence, missing original source, exact receipt completion and unchanged retry; unknown aliases, changed candidate bytes and late independent receipts remain intact on rejection. A disposable native-user public-CLI fixture removes original sources, the active pointer, a public alias and both receipts while retaining the exact initial journal. It exercises accepted-generation replay rejection and pending forward continuation with missing enrollment. These constructed interruption fixtures do not establish process-death, power-loss or signed release acceptance. Earlier-than-staged interruption, prior-generation upgrades, strong installations, all-writer coordination and other native platforms retain their own delivery gates.
