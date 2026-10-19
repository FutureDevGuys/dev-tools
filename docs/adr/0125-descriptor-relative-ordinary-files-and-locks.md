---
authority: canonical
owner: dev-tools
---

# ADR 0125: Descriptor-relative ordinary files and resource locks

status: proposed
verification: pending

The integrated method names are clarified by [ADR 0129](0129-independent-file-publication-contracts.md)
to preserve the existing document-authority file interfaces independently.

## Decision

The Linux `ExistingDocumentDirectory` boundary gains narrow ordinary-file
operations alongside its existing nonempty document operations. `FileAuthority`
selects exact UID, GID, ordinary mode and a nonzero length bound.
`read_file_with_group`, `write_file_with_group` and `remove_file_with_group` permit zero-byte regular files while
retaining no-follow, single-link, bounded-content, named-versus-held identity,
descriptor-relative publication/removal and file/parent synchronization. The
writer requires the selected group on its staged and current files and assigns
it before synchronization/publication when needed. Special permission bits and
group/other write permission remain excluded. Existing `DocumentAuthority`
interfaces and serialized formats keep their nonempty contract.

The additive `ExistingDocumentDirectory::try_lock` opens or creates one exact
ordinary leaf through the retained parent, requires an empty single-link
mode-0600 file owned by that directory's selected owner, acquires a nonblocking
exclusive native lock and revalidates the still-named identity. It synchronizes
the lock file and selected parent before returning the existing
`InstallationLock` lease type. The caller owns resource naming, acquisition
order, permanent lock retention and the higher-level transaction. Existing
path-based installation-lock interfaces are unchanged.

These are focused filesystem mechanisms; they acquire no product names, path
discovery, configuration semantics, privilege policy or generic multi-document
transaction. [SyncConfigs ADR 0003](../../crates/sync-configs/docs/adr/0003-durable-overlay-publication.md)
selects them for its product-owned target/optional-receipt journal. It separately
owns exact retirement, serialized resource selection, receipt reservation,
forward recovery and acceptance. A zero-byte file is never interpreted as a
valid receipt, authority document or journal.

## Verification limits

This source integration has pending verification. Required primitive coverage
includes empty/nonempty read/write/removal, explicit group preservation,
owner/mode/link/bound violations, substituted parents/leaves, exclusive lock
contention and replaced lock names, file-before-parent sync ordering, unchanged
retry and uncertain failure after publication/removal. Existing document and
installation-lock coverage remains required. Product conformance, fresh-process
crash recovery, native filesystem custody, standalone release acceptance and
hardware power-loss behavior are separate gates. No non-Linux or native runtime
qualification follows from these source additions.
