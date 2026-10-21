---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0038: Terminal reported storage exhaustion

status: proposed
verification: pending

## Context

A package volume can fill while the run journal remains writable. Configured
command retries and NPM's batch-to-individual or root-health recovery could then
repeat mutations without restoring the missing storage. A command can already
have changed package files before reporting failure.

## Decision

Positive reported storage-exhaustion diagnostics stop automatic replay of that
failed command. The common command policy checks complete captured stdout and
stderr before retry or capture fallback. Capture-guard errors retain only the
classified storage observation when disposing captured output, not another raw
transcript. Generic package recovery does not override this terminal result.

NPM stops further automatic installs and recovery for its task when exhaustion
is first reported by a batch, an individual attempt, or root-health recovery.
Already verified rows remain observations; unverified targets remain unknown.
The task fails with a blocking advisory and does not claim rollback, cleanup,
complete installation, or a measured filesystem-capacity diagnosis.

## Invariants

- ENOSPC/EDQUOT tokens, supported explicit no-space/quota messages, and the
  retained typed capture observation dominate network/lock recovery heuristics.
- Storage errors beyond a concise display excerpt still stop replay.
- Ordinary successful updates and recoverable package-specific failures retain
  their existing bounded behavior.
- A program path containing ENOSPC is not a captured provider diagnostic.
- The current attempt settles before its failure is returned. Partial effects
  remain; stopping retries does not imply that no change occurred.
- The storage gate does not reroute temporary files, delete data, change quotas,
  elevate, invoke a repair tool, or mutate trust settings.
- Independent tasks retain the scheduler's existing failure/dependency policy.

## Rejected alternatives

Checking only the log filesystem misses distinct package/cache/temp volumes.
Retrying each planned package cannot repair an exhausted volume. Automatically
rolling back from manifests or output text would invent transaction authority.
Persisting all guard output again would duplicate bounded diagnostic ownership.

## Consequences and known limitations

This is classification of reported output, not a storage measurement or proof
that a later attempt cannot succeed. Historical or quoted diagnostics can be
ambiguous; narrowly recognized messages favor stopping further mutation. A
direct-TTY command with no observable output cannot be classified this way.
Earlier effects and independent running tasks are not undone. Native platform
acceptance and real package installation remain separate from harmless fixture
execution. ADR0002's healthy-root recovery and ADR0003's bounded evidence remain
in force outside this terminal reported-storage condition.

## Verification

- `storage_exhaustion_stops_common_and_npm_retries_without_losing_effects`
- `storage_failure_during_individual_or_health_recovery_stops_remaining_roots`
- `captured_storage_failure_stops_guard_retry`
- `successful_and_recoverable_npm_paths_still_work`
- `storage_failure_classification_uses_full_channels_not_program_name`

## Runtime acceptance

Run the standalone executable against a harmless Rust provider in a disposable,
user-owned prefix with two planned packages, writable run evidence and retries
set above zero. Verify one mutation after an initial reported storage failure,
no later mutation after exhaustion first occurs during recovery, retained partial
effects, truthful unknown post-state, and ordinary success/recovery controls.
Exercise stdout/stderr diagnostics beyond concise display limits and a real
capture guard after the diagnostic. Repeat native platform acceptance without
performing real package operations or changing user configuration.

## Supersession conditions

Supersede if typed provider transaction results replace text classification,
recovery gains rollback authority, or storage admission becomes a separate
measured and reserved resource contract.
