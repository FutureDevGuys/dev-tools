---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0037: Read-only damaged run inspection

status: proposed
verification: pending

## Context

A truncated run metadata file made history browsing fail for every neighboring
run. Missing or malformed final artifacts appeared to have zero tasks and zero
issues. Disk exhaustion and interruption make both cases operationally important.

## Decision

`runs inspect [QUERY] [--json]` observes run metadata and final run artifacts
without repairing, replaying, pruning, or invoking package managers. Its JSON
schema is `update-all-run-inspection-v1`. An exact directory name remains a usable
locator when recorded identity is unavailable; no substitute RunMetadata is
manufactured. Healthy legacy restore/resume fields retain their meanings. Their
task_count and issue_count now serialize null rather than zero when unavailable;
human output uses `?`. Invalid metadata neighbors are omitted with one warning.

## Invariants

- Inspection is local, network-free, read-only, and never requests privilege.
- Unknown identity, counts, and outcome stay unknown. A recorded running or
  finalizing status does not establish current process liveness.
- `available` evidence means only parseable supported metadata and final artifact.
  It does not certify execution, journal consistency, or installed package health.
- The journal and raw logs are not parsed or reconstructed by this command.
- Unsupported schemas, malformed shapes, unsafe files and oversized inputs are
  explicit observations, not empty successful runs.
- Symlinked directories are not traversed; artifact symlinks and nonregular files
  are rejected. Reads are bounded to 256 KiB metadata and 8 MiB final artifact.
- Exact directory-name inspection opens only that real child, so unrelated
  history cannot exhaust its scan budget.
- Enumeration is capped at 4096 entries, and initially observed eligible file
  lengths at 64 MiB; exceeding a scan bound fails explicitly, not partially.
- Rename still requires valid real metadata; retention rules in ADR0014/0033
  remain unchanged. Inspection entries never grant mutation ownership.

## Rejected alternatives

Invented UUIDs or terminal states disguise missing evidence. Automatic reruns
could repeat completed effects. An unrestricted doctor would imply system health
that local run artifact observation cannot establish. Silently skipping broken
rows conceals the reason operators need inspection.

## Consequences and known limitations

Consumers must accept nullable counts for unavailable legacy run evidence. A
read-only observation is not a coherent live filesystem snapshot and does not
provide adversarial parent-directory replacement race resistance. Native platform
acceptance is reported separately from automated Linux execution. No broad doctor
or package repair workflow is introduced.

## Verification

- `corrupt_neighbor_does_not_hide_healthy_history`
- `inspection_reports_unknown_without_rewriting_evidence`
- `wrong_shaped_artifacts_are_not_successful_empty_runs`
- `active_finalizing_metadata_and_warning_skips_remain_truthful`
- `unsupported_and_oversized_evidence_is_unknown`
- `symlinks_and_fifos_are_not_followed_or_opened`
- `exact_directory_inspection_works_beside_large_unrelated_history`

## Runtime acceptance

Run the actual executable against isolated healthy, damaged, unsupported,
oversized and special-file fixtures. Compare bytes, directory entries and modes
before and after inspection. Verify unknown plain/JSON counts, healthy exact
resume despite broken neighbors, bounded completion for FIFO input, preserved
finalizing state, and no package subprocess or network access. Repeat native
acceptance on supported platforms before claiming those runtime results.

## Supersession conditions

Supersede if inspection gains replay, repair, package health probes, journal
reconstruction, a new identity authority or incompatible schema semantics.
