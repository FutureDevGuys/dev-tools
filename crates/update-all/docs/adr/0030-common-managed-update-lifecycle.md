---
authority: canonical
owner: update-all
---

# ADR 0030: Common managed update lifecycle

status: proposed
verification: pending

## Decision

The source adapter extends canonical `update` with `install [--offline]`,
`apply [--offline]` and network-free `rollback`. It uses the existing shared
operation loop and v2 nullable managed-change result. Status and check retain
their read-only/metadata-only boundaries. An external command is never adopted;
no setup, enrollment, policy or privilege is manufactured by an update.

The product retains one release-writer lease from mutation metadata admission
through local recovery, accepted-history publication and activation. Installation
locks remain inside the existing v2 installation primitives. Initialization has
a lease-bound inner entrypoint; it never reacquires the outer lease. A false
local-preparation result must preserve the initial snapshot: a cooperating
writer's intervening change blocks this attempt with a fresh observation rather
than returning a stale no-op or inventing a change fact.

Original signed metadata supplies the exact independently accepted history,
active identity and previous identity before cutover. Online mutation may obtain
these bounded metadata proofs from canonical product-owned version URLs; offline
mutation and rollback use local proof only. Receipt-less legacy topology uses
the existing forward-only v2 adoption, including independently authenticated
retained bytes. Ordinary v1 receipt repair is proof-bound and local. No proof is
inferred from a filename, observational version or self-reported build identity.

Recognized pending protocols remain unknown to observation. A narrow shared
pending-recovery snapshot lets an explicit mutation reach product preparation;
it is not a managed identity or recovery authorization. Strict bounded endpoint
metadata only selects proof inputs. Before any recovery effect the product
authenticates all required endpoint identities, and the selected existing
installation recovery API independently revalidates journal, custody and links.
Unknown journals, missing proofs and lost initialized authority fail closed.
Preparation reporting no change cannot continue from a pending snapshot.

Initialization retires the old release-state writer and preserves captured
history. The initialized product authority remains the only accepted ledger;
activation and rollback use conditional v2 operations against a freshly observed
receipt. A signed candidate is durably accepted before its activation, while
retained rollback never lowers release history. Ordinary work no longer invokes
the old automatic update path: the legacy configuration field is readable but
does not grant an implicit network or self-update boundary.

Online payload preparation runs only after local preparation and the installed
version no-op decision. Its exact root/manifest identity selects private immutable
payload cache bytes, which are reauthenticated before activation. Metadata-only
check never downloads them. Offline operations never fetch; a satisfied version
needs no retained payload. Explicit legacy bundle input snapshots and authenticates
the existing bounded nofollow inputs, and supplies held bytes to this same
transaction without a network fallback. A matching candidate preserves its
original check timestamp; newly supplied offline evidence has no online freshness.

Legacy self/product entrypoints for Update All delegate to the same lifecycle;
other products retain their own migration scope. Their boolean activation result
is emitted only for established completed outcomes. Unknown progress is never
translated into false. Their initialized local status no longer reads retired
legacy state or promotes its old timestamp to common freshness.

## Compatibility and limits

This completes source integration only. Signed release bytes and registry
archives are unchanged. This branch is unreleased and must receive a new product
version before authenticated construction; no replacement of published 0.1.12
is authorized. Initial mutation support remains the existing Linux backend;
other platforms retain unsupported results until their native gates pass.

Historical third-old executable recovery is a different operation. Common
rollback activates only the receipt-owned previous version. Offline candidate
intake still rejects generation/version rollback; this decision supplies no
nonactivating historical restore command and no manual-copy exception.

ADRs 0021–0023 retain their signature, custody and observation invariants; their
unfinished mutation integration is supplied here. ADR 0025's Update All bundle
entrypoints now use this backend; its complete-input, trust and offline boundaries
remain unchanged. The implicit automatic-update compatibility noted in ADR 0022
ends here; parsed old configuration does not revive that authority.

## Required qualification

Existing conformance coverage and native qualification remain pending. Before a release claims
support, qualify the standalone binary's initial install, repeat, online payload
preparation, offline cache-only mutation/no-op, external preservation, retained
rollback, missing-proof rejection and actual interruption at product retirement,
history publication and installation journal boundaries. Check nullable change
and fresh identity after every entered mutation and failed observation. Source
integration does not establish compiler or runtime acceptance.
