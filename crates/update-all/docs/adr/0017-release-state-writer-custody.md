---
authority: canonical
owner: dev-tools
---

# ADR 0017: Release-state writer custody

status: proposed
verification: pending

## Context

The legacy state writer created a predictable PID-named temporary and renamed it over the destination. It could truncate unrelated temporary bytes or replace a linked destination. Participating-writer serialization alone did not bind publication to the accepted history read at admission.

## Decision

Each release-state transaction retains its native writer lease, bounded document authority and initial document content identity together. The working state is parsed from that same admitted document. Publication consumes the transaction, rejects an unexpected creation, removal or changed history, and uses the shared bounded atomic-document writer with the original expected identity. Shared publication uses an exclusively created random temporary, no-clobber initial publication, and parent-directory synchronization. The existing JSON representation and location remain unchanged.

## Invariants

- Production release-state publication requires the admitted writer transaction; a fresh observation at commit cannot grant replacement authority.
- Invalid destinations and unmarked legacy temporaries remain untouched.
- State publication retains the reader's 64 KiB bound and Unix 0600 single-link authority.
- A failed or uncertain publication ends the transaction rather than refreshing its expected identity and retrying it.

## Rejected alternatives

A randomized filename alone would not protect the destination or accepted history. Re-reading the destination immediately before writing and treating that new identity as the expected state would bless lost updates. Changing the JSON schema is unnecessary for this correction and would introduce a separate rollback compatibility decision.

## Consequences and known limitations

This protocol coordinates participating writers and detects changes observed before replacement; it is not an atomic compare-and-swap against a hostile process with the same filesystem authority. Older binaries do not take the lease and still require the explicit mixed-version cutover gate. Parent-directory synchronization does not by itself qualify durability of newly created ancestor directories or complete the installation/release-state crash transaction. Other legacy cache and artifact writes, retained signed proofs and common adapter integration remain separate work. No new platform runtime claim follows from this source correction.

## Verification

The tests `release_state_writer_preserves_unmarked_temporary` and `release_state_writer_preserves_linked_destination` failed with the old writer before the correction. `release_state_writer_rejects_intervening_history`, `release_state_writer_rejects_unexpected_creation_and_removal`, and `release_state_writer_bounds_publication_and_retains_lease` cover the expected-history boundary, byte-identical unexpected creation, removal, size limits, no-op identity and lease lifetime. Existing release and native competing-process tests cover the participating entrypoints.

## Runtime acceptance

Exercise source-bound release binaries outside a checkout with hostile destinations, interrupted publication and retained rollback. Qualify first-use ancestor durability, installation/state recovery and mixed-version exclusion before accepting the full cutover. Native Windows and macOS custody require their own acceptance hosts.

## Supersession conditions

Supersede this record when a new state authority format or transactional backend replaces the bounded document protocol. Preserve original-history binding, owned-only publication and explicit failure recovery.
