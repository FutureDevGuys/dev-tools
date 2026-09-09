---
authority: canonical
owner: dev-tools
---

# ADR 0034: Journaled receipt-less protocol adoption

status: proposed
verification: pending

## Context and decision

The legacy two-level adopter publishes v1 ownership and has no retained-version contract. Running it before v2 cutover both commits before product retirement and discards any separately authenticated retained identity. Receipt-less adoption therefore needs a distinct forward-only transaction rather than a sequence of old adoption followed by ordinary upgrade.

The additive Linux `versioned_v2::legacy_adoption` interface accepts the existing typed two-level request plus a complete product-authenticated proposed receipt, including an optional retained identity. Read-only `prepare` validates the receipt/request agreement, active and retained artifact custody, absence of existing installation authority, and exact legacy topology. It returns a nonserializable prepared value rather than publishing ownership. `commit` repeats these checks under the installation lock and compares captured alias/current presence before hardening modes or publishing a fence. A stale preflight fails before journal publication and product callback; lock admission may still create its file.

Inside explicit mutation, admitted directory modes are hardened and synchronized. A distinct strict `dev-tools-versioned-protocol-adoption-v2` journal records the complete layout, proposed receipt and original legacy topology at the existing installation journal path. It excludes v1 writers before the product callback. The callback authenticates active and retained identities and durably retires any independent product writers before pointer or receipt publication. It remains bounded, local and idempotent, does not mutate installation state or reacquire its lock, and follows the existing outer-product-lease-before-installation-lock order.

After callback success, adoption publishes active and optional previous pointers, rewrites only admitted aliases, retires the original current pointer and publishes the enclosing v2 receipt. It verifies the result before clearing the journal. Errors can include durable hardening or journal/publication progress; this interface does not claim unchanged state on error. It neither removes unrelated version directories nor infers retention authority from their presence.

## Recovery and authority

`resume` requires an existing strict adoption journal and independently checks layout, bounded artifacts, receipt equality and allowed original/published pointer states before repeating product authentication. It rechecks journal identity, installation state, artifacts and lock after the callback. Recovery completes forward; it never restores v1 authority or undoes product retirement. A published receipt must exactly equal the journal's proposed receipt. Completed repeats use ordinary v2 observation, not a fresh adoption or absent-journal resume.

`read_pending_receipt` exposes strict bounded metadata for product-owned proof selection without authenticating a release, checking artifact custody or mutating anything. `pending_recovery` gains the explicit `LegacyAdoption` classification. Normal activation recovery and ordinary protocol initialization reject this journal instead of treating it as their own transaction.

Release evidence, ancestor trust, retained-version selection and independent writer exclusion remain product responsibilities. Shared preflight and journal bytes are not signed-release authority. The comparison serializes cooperating installation writers, not hostile same-owner writers outside the protocol. No callback failure permits fallback to an old installer.

## Compatibility and rollout

The existing v1 adopter, its prohibition on retained fields, and existing v1/v2 receipt and journal formats remain unchanged. The new journal and additive APIs belong to unpublished installation 0.2.1; `PendingRecovery` gains a variant in that unreleased interface. No frozen archive or published product identity changes.

Product composition requires independently authenticated active and retained identities and explicit exclusion of every supported earlier writer; recognizing a shared journal does not grant release authority. Receipt-owned migration, initialized operation and receipt-less adoption retain separate admission contracts. This shared change does not establish a product-specific migration or writer-version policy.

## Verification and remaining acceptance

The initial public API counterexample ran the old two-level adopter against a requested retained identity and observed its loss. The new transaction preserves the complete active/retained receipt, excludes v1 mutation, and supports ordinary authenticated retained rollback after completion. Tests reject changed preflight topology or retained bytes before fencing, preserve failed callbacks and invalid journals, reject wrong recovery owners, and reauthenticate explicit resumption. They also cover callback-time journal/artifact drift, foreign or missing aliases, existing receipts, bounds, active-only adoption, originally absent pointers and preservation of unclaimed versions.

`adoption_resumes_forward_at_each_publication_boundary` interrupts after active, previous, each of two aliases, current retirement and receipt publication. Every case keeps command resolution valid and resumes with exact ownership while preserving an unmarked temporary. These controlled boundary errors are not process-death or power-loss evidence. `adoption_process_death_preserves_the_native_fence_for_authenticated_resume` separately terminates a real child without unwinding inside product cutover, checks the retained native journal, rejects missing proof and resumes after native lock release.

Qualify product proof selection, final legacy-history capture, fresh common admission, ordinary-run compatibility, native process interruption across fresh retirement and publication, clean signed successor online/offline operation and retained rollback before product cutover. Linux source and process tests do not establish power-loss durability or non-Linux support. Supersede this record if journal admission, retained ownership, callback authority or forward-only recovery changes.
