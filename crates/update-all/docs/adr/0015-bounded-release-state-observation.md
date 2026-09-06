---
authority: canonical
owner: dev-tools
---

# ADR 0015: Bounded release-state observation

status: proposed
verification: pending

## Context

The release reader used a file-type convenience predicate to decide whether accepted state existed. Directories and dangling links therefore became an empty acceptance history, while regular-file reads were unbounded. The common update adapter cannot safely reuse that behavior.

## Decision

Release-state observation uses the shared bounded atomic-document reader, retaining the existing JSON representation and location. Only genuine absence yields the initial empty state. Present nonregular, linked, oversized, empty or malformed documents fail without repair. The read bound is 64 KiB. On Unix the state file must have mode 0600, one link and the owner of its real non-group/other-writable product directory or nearest existing authority ancestor. Path roots must be absolute; shared native traversal rejects symlink components. Reading never creates directories, takes a writer lock or changes permissions.

## Invariants

- A present invalid state object never resets accepted release history.
- Read-only status does not adopt, repair or remove state.
- Exact valid legacy JSON and version/generation history remain readable within the bound.
- This document reader is not release authentication or permission to initialize new history.

## Rejected alternatives

Treating an unreadable or nonregular state object as absence conceals lost authority. An unbounded read lets local corruption consume arbitrary memory. A new state schema is unnecessary for this read correction and would complicate rollback compatibility without improving its guarantee.

## Consequences and known limitations

Previously tolerated unsafe state modes and links now fail instead of being read or silently ignored. The reader does not chmod or guess an intended replacement. Existing mutable-state serialization, writer custody, installation recovery and receipt-bound release proofs require their separate migration before a complete common product adapter can claim conformance. Native Windows reparse/ACL acceptance remains gated; bounded shared-file reading is not that acceptance.

## Verification

Named regression tests are `release_state_directory_is_not_missing_authority`, `release_state_symlink_is_not_missing_or_accepted_authority`, `release_state_oversized_document_is_not_accepted`, `release_state_absence_and_valid_boundary_reads_are_nonmutating`, `release_state_rejects_hardlinks_modes_and_socket_without_repair`, and `release_state_rejects_linked_and_writable_authority_parent`. The first three failed on the old reader before the production correction. Existing release-reader, migration, activation and rollback tests preserve valid behavior.

## Runtime acceptance

Run the source-bound standalone product against absent, valid and hostile fixture state outside a checkout. Confirm failure leaves bytes, links and permissions unchanged, valid accepted history remains visible, and no network or state initialization occurs. Qualify native filesystem behavior on each advertised platform before accepting this record.

## Supersession conditions

Supersede this record if accepted release state moves to a new authority format or storage backend. Preserve the distinction between absence and invalid authority and the bounded nonmutating observation contract.
