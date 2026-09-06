---
authority: canonical
owner: dev-tools
---

# ADR 0016: Serialized release mutation admission

status: proposed
verification: pending

## Context

The release engine loaded and wrote accepted history independently around metadata checks and activation. Concurrent cooperating invocations could therefore publish state derived from separate old snapshots, even though the installation foundation serialized individual activations. The shared update adapter needs one product-owned release mutation admission boundary.

## Decision

Check, install/update, and rollback retain a native exclusive nonblocking lease on the product root's fixed release-writer-v1.lock before their authoritative state load. Initial read-only preflight remains before lock creation, and state is reloaded after admission. The lease spans product-owned bounded retrieval, acceptance, installation and final state publication. It precedes any installation lock. Status does not acquire or create this lock. The lock file is retained permanently rather than unlinked while another opener could retain its inode.

## Invariants

- A competing participating mutation fails before metadata retrieval or activation rather than waiting or using an old state snapshot.
- Each product root has an independent writer identity; the shared lock primitive contains no product-specific policy.
- Restricted Sync Configs rollback eligibility is checked before lock creation and rechecked after admission, preserving its no-repair-before-preflight boundary.
- Native release and installation leases are not inherited by executed health-check commands; product callbacks must not wait for a competing holder or reacquire these locks in blocking mode.

## Rejected alternatives

An installation-only lock cannot serialize accepted metadata history. Removing a release lock on exit permits detached-inode concurrency. A blocking writer queue would let an unrelated invocation wait behind network retrieval without a user-visible admission decision. This first bounded engine integration deliberately serializes explicit same-product work instead of introducing optimistic network retries and a second acceptance protocol.

## Consequences and known limitations

Explicit checks now contend with installation and rollback for the same product. Failures can leave the small retained coordination record, but status still creates nothing. Older released binaries do not participate in this new lock: mixed-version concurrent mutation is not qualified, and the common release cutover must drain or otherwise exclude older writers before claiming serialized operation. This change preserves the existing state JSON and rollback format; it does not itself complete writer custody, retained signed proofs, network-free common operations or platform acceptance. It does not isolate another process already holding the same filesystem authority.

## Verification

The regression `release_mutation_rejects_a_live_writer_before_discovery` first demonstrated that the old engine entered discovery despite a held writer lease. `native_release_writer_excludes_mutations_but_not_status` launches actual product processes for check, install, update and rollback while a separate holder retains the native lease, verifies their prompt refusal and unchanged state, and confirms status remains available. Existing restricted-runtime rollback and release suites preserve their earlier eligibility boundaries.

## Runtime acceptance

Qualify competing source-bound release binaries outside a checkout, process interruption during retrieval and activation, retained-lock reuse, and the mixed-version cutover. Confirm native lock, filesystem, descendant and rollback behavior independently on each advertised platform before accepting this record.

## Supersession conditions

Supersede this record if network retrieval moves outside the lease under authenticated optimistic revalidation, a versioned state protocol excludes legacy writers, or the release-state authority changes. Preserve one serialized acceptance decision and receipt-safe activation.
