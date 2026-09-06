---
authority: canonical
owner: dev-tools
---

# ADR 0026: Local update mutation preparation

status: proposed
verification: pending

## Context

The common loop skips activation when the installed version already meets the authenticated candidate. Product-owned journal recovery and installation-protocol initialization can still be necessary in that case. Neither belongs in read-only inspection or metadata refresh, and hiding them in activation leaves them unreachable on an already-current request.

## Decision

The additive `UpdateAdapter::prepare_mutation` callback performs bounded product-owned local recovery or protocol initialization for explicit install, apply and rollback. Initial inspection, external/setup exclusion and operation-state admission precede it. Install/apply additionally acquire and validate their authenticated candidate before preparation; rollback supplies no candidate and remains network-free. Preparation cannot retrieve metadata or payloads, execute commands, create product policy or enroll credentials. Products retain custody, authentication, journal ownership, serialization and approval responsibility.

The default returns false without work, preserving existing adapters' operation ordering and observation counts. An override returning false establishes no durable installation change and leaves the supplied observation valid. True establishes durable change and requires a new read-only observation before version comparison or further mutation. A fresh managed observation admits continuation; an explicit install may also continue from absence, including initialization whose empty receipt classifies as managed. Unknown/external/setup-required observations, lost managed state during apply/rollback, and observation failure stop further mutation. Initial inspection errors still fail closed: this interface does not weaken receipt validation or teach the common layer to interpret pending product journals.

Errors after entering preparation have unknown change unless independently qualified by the adapter, and receive fresh observation under ADR 0019. Successful preparation's true change survives a later preflight, payload or activation failure, even if that later stage establishes false or cannot establish its own progress. Successful preparation followed by a version-satisfied request reports installed/updated/rolled-back rather than a false no-op. These outcomes concern completion of the requested lifecycle operation, including recovery, and do not promise that the active version changed. A false preparation result preserves existing no-op behavior. Matching versions never supply a missing change fact.

Preparation precedes artifact availability checks, so an explicitly requested offline mutation can complete local recovery and then report blocked because newer payload bytes are absent. That result reports true, not a rolled-back recovery or a successful update. Status and check never enter this callback. Candidate identity, timestamp and freshness rules, the separate online payload boundary, and conditional activation custody checks remain unchanged.

This additive trait method belongs to the unpublished update 0.2.0 generation. No schema, dependency, published archive or product entrypoint is replaced. Product integration must supply honest initial classification, local proof availability, explicit interrupted-cutover resumption and authenticated activation; this loop change alone does not qualify those behaviors or promote any product's conformance level.

## Verification

The public adapter regression first observed an already-current offline request skip recovery and return false. Tests cover same-version recovery without payloads, active-version changes in both directions before the no-op decision, initialization, rollback, failure progress and category preservation, fresh-observation failure, loss of ownership, offline missing bytes, later transport/activation errors, and exclusion from metadata-only and rejected preflight requests. Existing adapter, signed-provider and Artifact Update tests protect their separate contracts. Native product release, interruption, offline and retained-binary acceptance remain required before cutover claims.
