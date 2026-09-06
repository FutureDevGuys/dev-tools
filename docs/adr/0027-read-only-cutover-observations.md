---
authority: canonical
owner: dev-tools
---

# ADR 0027: Read-only cutover observations

status: proposed
verification: pending

## Context and decision

An interrupted product cutover may have fenced the legacy state path before publishing its new authority document. Metadata-only proof acquisition needs the captured accepted version, but invoking retirement to obtain it would perform recovery during a nonmutating operation. Similarly, complete v2 installation observation deliberately rejects pending journals; using it as the only metadata reader makes some explicit recovery requests unreachable.

The additive Linux `observe_retired_atomic_document` API reads recognized retirement history without directory or lock creation, locking, synchronization, record completion or recovery. Its outer absence result means no recognized published retirement fence, not permission to initialize history. A present observation contains either the captured bounded document or explicitly retired empty history. It shares target, parent, record and fence validation with the writer, and rejects missing/changed captured files, mismatched recorded identity, foreign fences, altered inventory and changed record observations. A post-exchange snapshot can be read before the writer records the captured digest or acknowledges durability; observation is not that acknowledgement.

The retirement implementation separates an unlocked read context from the lock-bearing writer through a private type parameter. Mutating methods require the lock-bearing type. Read-only fence inspection returns a held directory without syncing it; the writer retains its existing synchronization calls and lease order. The public retirement writer, permanent record and captured-file formats are unchanged.

The additive `versioned_v2::read_receipt_metadata` API validates the bounded receipt's outer schema, exact layout and inner structure. It does not inspect journals, links or artifact bytes, authenticate releases or authorize mutation. Its empty result means an initialized empty receipt; missing or invalid receipts are errors. Complete custody remains the separate `observe` contract.

The additive `versioned_v2::pending_recovery` API classifies recognized strict v2 journal metadata as protocol upgrade or activation. Missing journals return no pending operation. Unknown, malformed, foreign-layout and legacy journals fail instead of selecting a guessed recovery route. Classification does not check receipt equality, artifact custody or release authority; the selected mutation revalidates those independently. Products own any explicitly supported legacy recovery route.

## Product use and boundaries

Update All's local migration-history reader uses retirement observation to recover the original accepted version for proof acquisition without finishing the pending cutover. Captured origin history is not a replacement for an initialized product ledger and cannot reset its later acceptance state. Initial operation classification, candidate freshness, proof acquisition and lifecycle dispatch remain product-owned integration work.

These readers neither take a transactional snapshot against arbitrary concurrent same-owner mutation nor weaken mutation admission. A record-changing concurrent writer may produce an observation error; callers revalidate under the explicit mutation boundary. Retained-history observation remains confined to the qualified atomic-replacement writer model from ADR 0024. No new schema, dependency, published archive, public product entrypoint or platform support claim follows from these additive installation 0.2.1 interfaces.

## Verification and remaining acceptance

The Update All regression first failed when it read the fenced state path through the legacy document reader; it now obtains the captured accepted version while leaving the upgrade journal and unpublished product authority untouched. The v2 metadata regression first failed at complete observation's pending-journal boundary. The new metadata reader succeeds without repairing that journal and remains explicitly unable to establish custody of subsequently corrupted artifact bytes.

Existing retirement tests passed before and after separating read and writer contexts. Tests cover genuinely absent paths without creation, explicit empty retirement, unchanged captured bytes and file metadata, missing lock non-recreation, observation inside live writer boundaries, non-unwinding process-exit states, strict/bounded receipt reads, layout mismatch, unknown fields, hardlinks, journal classification and hostile retained-state rejection.

The explicit native gate `cutover_observation_has_no_write_sync_or_lock_syscalls` traces the production readers and rejects write-capable opens, filesystem mutation, synchronization and locking syscalls. It complements source and local process tests, not hardware power-loss acceptance or complete signed product migration. Run the common product adapter and real release binaries through online/offline operation, interruption and retained rollback before accepting the product cutover. Supersede this record if observation gains mutation authority, the snapshot contract changes, or native backend behavior changes.
