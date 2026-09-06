---
authority: canonical
owner: dev-tools
---

# ADR 0019: URL-bound metadata cache

status: proposed
verification: pending

## Context

The legacy HTTP cache stored raw bytes and an ETag in separate files without the originating URL. A changed release URL could replay another resource's validator, and a not-modified response read an unbounded file after the request. The predictable temporary writer could overwrite unrelated files. None of these observations independently authenticates a release.

## Decision

Update All stores disposable HTTP metadata observations in a single versioned document containing the exact requested URL, original bytes and optional ETag. Root and manifest documents use new filenames, leaving legacy raw files and validators untouched throughout the retained-binary rollback window. No legacy cache is imported or used as validator authority.

Retrieval requires the admitted release-state writer lease. The shared bounded document reader admits the cache before contact. Only the exact matching URL can supply its validator; a not-modified response uses only the already admitted bytes associated with that validator. A modified response replaces the entire observation, including absence of an ETag. Publication rejects changes from the original content identity and uses the shared atomic writer. Invalid or unknown existing documents fail without repair or replacement.

## Invariants

- HTTP cache observations never grant release authenticity, accepted-history authority, installation authority or common-adapter freshness. Root and manifest verification remain required after retrieval.
- Reads and writes enforce both the serialized document bound and the nonempty original-body bound; JSON encoding overhead is included in the former.
- Unix cache destinations are owner-only single-link regular files. Linked, oversized, malformed and unmarked files are preserved on rejection.
- The lease spans retrieval and publication. A changed destination cannot become expected history merely by being observed after retrieval.

## Rejected alternatives

Importing the legacy ETag would grant URL authority that its format never recorded. Keeping two independently written files would preserve mismatched body/validator states after interruption. An authenticated release-bundle cache is not interchangeable with an HTTP observation cache and requires separate signed-proof and artifact acceptance. Predictable temporary names and direct filesystem reads bypass the shared custody boundary.

## Consequences and known limitations

The first new-reader check retrieves full metadata rather than reusing legacy validators. Legacy files remain available to retained binaries but are not rewritten or deleted by this reader; their eventual removal requires independent ownership evidence and closure of the rollback window. The cache is bounded and disposable, not an offline accepted-release ledger. The shared atomic writer does not provide hostile same-owner compare-and-swap, first-use ancestor durability or a complete installation/state crash transaction. Common adapter integration, mixed-version state-writer exclusion and native platform acceptance remain separate gates. Published binaries and archives are not replaced by this source change.

## Verification

The regressions `metadata_cache_does_not_replay_unbound_legacy_validator` and `metadata_cache_preserves_unmarked_temporary` failed against the legacy cache before its replacement. `metadata_cache_binds_validator_and_exact_bytes_to_url` covers conditional reuse, changed URLs and ETag removal. `metadata_cache_not_modified_uses_only_admitted_snapshot` rejects post-request file bytes as cache-hit authority. `metadata_cache_rejects_changed_publication_history` covers intervening writes, removal and byte-identical unexpected creation. `metadata_cache_bounds_disk_body_and_transport_outcomes` covers bounded reads, inclusive payload limits and typed response handling. `metadata_cache_rejects_linked_and_nonprivate_destinations` covers Unix custody and nonmutating identical publication.

## Runtime acceptance

Exercise the source-bound standalone binary outside a checkout through signed online discovery, first installation, repeated conditional checks, changed release URLs and retained rollback. Preserve legacy files and hostile cache fixtures. Qualify interruption and first-use durability before claiming the complete common update contract. Native macOS and Windows require their own filesystem and HTTPS acceptance.

## Supersession conditions

Supersede this record when a new shared transport-cache or persistent authenticated-release interface replaces these observations. Preserve exact resource binding, bounded custody, independent signature verification and owned-only retirement of legacy data.
