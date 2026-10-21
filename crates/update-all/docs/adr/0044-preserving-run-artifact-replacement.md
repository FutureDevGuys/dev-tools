---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0044: Preserving run artifact replacement

status: proposed
verification: pending

## Context

Rewriting task-run JSON previously truncated the prior artifact before writing
the replacement. A real completed-dashboard lifecycle in both engines proved
that a later process-local file-size write failure could turn valid run.json
into a one-byte prefix, even though the task had completed exactly once.

## Decision

RunLogSink serializes a complete JSON snapshot, stages it in an exclusively
created private sibling file, writes and flushes it, then publishes it with one
replacing rename. A failed staging write or publication does not delete or
truncate the prior artifact. Cleanup concerns only that invocation's stage;
there is no destination-unlink fallback. This covers run.json, task JSON and
restart.json, not append-only logs or the separate run-metadata writer.

Native acceptance also found abandoned metadata stages after the same write
failure. The separate metadata writer now closes its stage handle and attempts
to remove only that invocation's exclusively created stage before returning a
write, flush, permission or publication error. An open collision grants no
cleanup ownership, and cleanup never replaces the original causal error.

Admit an absent leaf or an ordinary writable file. Refuse observed symlinks,
nonregular files and read-only entries. On Unix, require the existing file's
owner to match the staging owner, one hard link, owner-write permission and no
special permission bits. A nontruncating, nonblocking, no-follow write-open
checks the existing leaf's actual write authorization. Its descriptor metadata
must match the observed leaf. Revalidate immediately before publication.
Ordinary owned writable 0644 artifacts can still become 0600, as before; a
failed replacement preserves the old mode. Windows refuses readonly and
observed reparse leaves; its native ACL/sharing acceptance remains pending.

The existing tempfile 3.27.0 dependency becomes direct rather than dev-only,
with no version, lockfile or feature changes. Its exclusive creation and
single-replacement API are selected; installation document primitives would
also impose their unrelated ancestor-authority and synchronization contracts.
Staging names have a bounded component, retaining a destination suffix only
for short names. Near-NAME_MAX destination names retain their original spelling.

The existing JSON inspection fields keep their meaning. Plain inspection also
shows the already-recorded metadata status and states that readable snapshots
do not verify a final invocation outcome. A retained task-complete exit-zero
snapshot plus finalizing metadata must not be described as successful invocation
finalization, nor as proof that the task should be replayed.

## Invariants

- Prior complete bytes and mode survive a failed staging write.
- Unexpected leaf entries and their targets/aliases are not repaired or adopted.
- A denied existing-file write is not bypassed using directory rename authority.
- Publication never removes the old destination first or retries by deleting it.
- Latest in-memory task evidence and sticky persistence failure remain intact.
- Failed persistence remains non-clean and cannot authorize a restart or replay.
- Namespace-atomic publication is not fsync or power-loss durability. ADR0036's
  separate pre-restart synchronization gate is unchanged.
- ADR0037's available evidence remains parseability, not invocation success.

## Rejected alternatives

Truncation destroys useful old evidence on a partial write. Reusing the metadata
writer's delete-destination fallback creates a visibility gap and loses the old
artifact if replacement fails. Silently replacing a symlink or hardlink adopts
unexpected state. Full destination names in staging names regress long task IDs.
Broad ancestor custody, global locking or a shared publication framework would
change unrelated contracts and are not required by this proven defect.

## Consequences and known limitations

An ordinary replacement needs temporary space for both snapshots. Cleanup is
best effort if the operating system also refuses removal of the owned stage;
unknown similarly named files are never removed. Owner/link/special-mode
refusal deliberately tightens unexpected artifact handling. Windows native
sharing, ACL/reparse and rename behavior and native macOS behavior are not
qualified by Linux tests. Metadata revalidation in an owned run directory is
participating-writer safety, not adversarial same-owner race exclusion or
protection against parent-directory replacement. A process-local EFBIG fixture
is not actual ENOSPC, power loss, filesystem exhaustion or a storage guarantee.
Metadata-stage cleanup is likewise best effort if removal itself fails and does
not run after a panic or process abort. Its existing replacement retry and
delete-destination fallback remain unchanged, outside this cleanup correction;
the artifact writer's stronger no-destination-unlink contract is not thereby
extended to metadata. No crash or power-loss durability is added.

## Verification

- `artifact_replacement_preserves_previous_bytes_after_partial_write`
- `artifact_replacement_publishes_complete_private_bytes_and_bounded_names`
- `artifact_replacement_refuses_unsafe_leaves_without_changing_them`
- `artifact_replacement_cleans_owned_stage_on_publication_and_revalidation_failures`
- `metadata_staging_cleans_partial_writes_without_changing_prior_evidence`
- `metadata_staging_open_collision_preserves_the_unowned_file`
- `metadata_staging_cleans_publication_failure_and_success_only`
- `plain_inspection_distinguishes_finalizing_from_available_snapshot`
- `persistence_failure_latches_without_producer_terminal_output`
- `general_enospc_stops_admission_settles_processes_and_restores_terminal`
- `restart_after_suppresses_unsafe_terminal_artifact_leaf`
- `restart_after_suppresses_failed_pre_request_evidence_sync`

## Runtime acceptance

Run the actual executable in both engines against an owned harmless Rust task
and PTY. After capturing valid task-complete artifacts while metadata remains
finalizing, lower only that candidate's soft file-size limit and dismiss the
dashboard normally. Require nonzero evidence failure naming run.json, exact
prior artifact bytes/mode, finalizing metadata and exactly one unchanged task
effect. Unlimited controls must finalize successfully. Independently inspect
JSON and plain history without modifying evidence. Retain the original red
probe and document any green-oracle-only change. Execute the unchanged existing
evidence-failure and harmless restart-backend tests; never issue a real restart.
Record both metadata and artifact staging families before fault injection and
after each candidate is reaped; require no abandoned stage in either family.
Repeat native platform acceptance before claiming supported-platform results.

## Supersession conditions

Supersede if artifact publication gains a different durability, ownership,
concurrent-writer, ancestor-custody or recovery contract, or inspection changes
the meaning of available evidence or recorded task outcomes.
