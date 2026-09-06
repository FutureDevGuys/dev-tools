---
authority: canonical
owner: dev-tools
---

# ADR 0021: Authenticated product-state cutover

status: proposed
verification: pending

## Context

The shared installation-protocol upgrade excludes the old installer, but cannot retire Update All's independent legacy metadata writer. Update All needs a product-owned transaction joining that upgrade with atomic-document retirement and authenticated ledger import.

## Decision

The transaction retains the product release lease before entering the installation lock. Inside the durable installation-upgrade journal, it retires `state.json` through the shared Linux retirement protocol, captures the final legacy document, imports all six acceptance fields into the shared manifest ledger, and authenticates supplied original signed metadata. Only then does it atomically publish `release-authority-v2.json` and acknowledge the installation callback. The permanent retirement record, captured bytes and directory fence remain owned by the shared retirement protocol. There is no downgrade to legacy writer authority on failure.

The new bounded, strict product document binds the captured content identity, unchanged shared ledger codec and at most three original root/manifest pairs: accepted history, active installation and retained installation can each need a distinct proof. Every original document has the existing 512 KiB bound. The enclosing bound includes worst-case JSON string escaping and ledger overhead. It supplies neither cache freshness nor downloaded artifact custody.

## Invariants

A nonempty acceptance ledger requires its exact signed accepted release, not merely a lower signed version. Every supplied retained proof is reauthenticated against the exact accepted root and the shared ledger's rollback/equivocation constraints. Active and previous receipt identities must each match an authenticated version, length and digest. The shared installation primitive independently verifies artifact bytes, layout and links. Missing proof is an error, including when receipt hashes are otherwise internally consistent.

An interrupted callback resumes under the same lock order. An already-published product document must match the captured source identity and authenticate the supplied receipt; it is not overwritten from newly observed history. An initialized repeat still requires the product authority document even though the installation primitive skips its callback. Missing or invalid initialized authority never becomes a default ledger or an automatic reimport. Genuine empty first use is an explicit mutation; a read-only missing-authority observation creates nothing.

## Rejected alternatives

The installation protocol alone leaves the old metadata writer enabled. Importing an empty ledger instead of captured history loses rollback and equivocation authority. Treating receipt hashes as sufficient release evidence confuses local file ownership with signed release authentication.

## Consequences and known limitations

Legacy product-v1 metadata is admitted only in this captured-history and receipt-bound migration path. It cannot authorize online discovery or another legacy release. Online candidate authority retains its independent source-bound policy. This compatibility belongs to Update All and remains until receipt-owned legacy rollback and migration are no longer supported; removing it requires source-bound successor and retained-binary acceptance, not merely the presence of a new schema.

The common adapter integration remains unfinished; no public entrypoint selects this transaction yet. No published binary, package archive or conformance level changes in this slice.

## Verification

The initial `cutover_retires_legacy_state_and_preserves_accepted_history` test ran the existing installation primitive alone and observed that the legacy metadata writer remained enabled. The product transaction makes that counterexample pass while preserving the signed acceptance identity and an unchanged repeat. The `empty_first_use_is_explicit_and_read_only_absence_creates_nothing` test exposed an incorrectly created directory mode before the transaction began creating its owned root through the shared installation primitive.

The product tests cover missing-proof interruption and retry, malformed captured history, unknown destination preservation, initialized authority loss, exact accepted-history preservation, receipt/proof mismatch, both retained identities, and product-writer contention. In particular, `missing_proof_retains_both_fences_and_explicit_retry_resumes` and `receipt_hashes_without_matching_signed_evidence_cannot_complete_cutover` protect the incomplete-cutover boundary. These are local source tests; the signed fixture establishes metadata authentication, while synthetic installation bytes are used only to demonstrate rejection. They do not establish signed installed-artifact acceptance or actual process-death recovery of this composition.

## Runtime acceptance

Before public cutover, integrate honest initial and pending-state observation, metadata-only proof acquisition, explicit resumption, common mutation-result reporting, new-ledger acceptance and receipt-owned activation/rollback. Preserve legacy entrypoint compatibility without letting retained binaries mutate the retired namespace. Run real source-bound releases outside a checkout through online/offline installation, repeat operation, retained rollback and process interruption. Native non-Linux backends remain separate gates.

## Supersession conditions

Supersede this record if product-state authority, the installation callback contract or the supported legacy migration window changes. Preserve final-history capture, authenticated receipt binding and an explicit recovery path that never re-enables retired writers.
