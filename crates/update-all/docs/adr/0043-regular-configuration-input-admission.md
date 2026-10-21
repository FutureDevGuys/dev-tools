---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0043: Regular configuration input admission

status: proposed
verification: pending

## Context

ADR 0042 made explicitly selected main configuration paths fail closed but left
discovered-default admission outside its scope. The first existing discovered
main path could still be a FIFO, blocking ordinary startup and configuration
validation. Explicit updater catalog paths likewise entered an ordinary file
read without regular-file admission. Isolated standalone executable tests
reproduced both hangs, including symlinks to FIFOs.

## Decision

Extend regular-file admission to the already-selected discovered main
configuration and external updater catalog reads. The main reader selects with
unchanged CLI, nonempty native environment, and default-candidate precedence,
then admits that selected path before any read. A nonregular selected candidate
is an error, never permission to skip to another discovered configuration.
Runtime loading and configuration validation share this admission.

This record extends the read-input scope deliberately excluded from ADR 0042;
it does not replace that record's explicit-selection or writer contracts.
Regular-file admission remains product-owned. Discovered catalog directories
retain their existing entry filtering and stricter rejection of symlinks.

## Invariants

- Main configuration and explicit catalog nonregular inputs fail before task,
  elevation, UI-preference or journal effects, with existing InvalidPlan exit 3.
- Explicit CLI selection still wins over environment and discovered candidates;
  an unset or exactly empty environment value preserves ordinary discovery.
- Symlinks to regular main files and explicitly named catalog files remain
  supported; native main paths and existing relative/literal catalog semantics
  remain unchanged.
- Discovered catalog non-file entries remain ignored, and their symlinks remain
  rejected rather than adopting explicit-catalog symlink semantics.
- Configuration-writing destinations retain their previous selection and absent
  target creation semantics. Default candidate discovery is not a writer guard.
- Task selection, UI defaults, completion, release and privilege policy do not
  change. No doctor or startup readiness gate is introduced.

## Rejected alternatives

Changing discovery to find the first regular file would silently select unrelated
work after a selected path becomes invalid. A timeout merely interrupts the hang
without defining admissible configuration input. Rejecting every symlink would
break ordinary supported file references. Changing catalog discovery policy is
unnecessary to repair the unguarded selected-file reads.

## Consequences and known limitations

Directories, FIFOs, sockets and devices are not configuration streams. Metadata
admission follows ordinary file symlinks and is not descriptor custody or a
race-proof guarantee against hostile replacement between inspection and read.
No file-size bound, canonicalization, expansion or filesystem discovery policy
is added. Existing metadata/read errors remain errors. Linux disposable-process
acceptance does not establish native macOS/Windows, signed-release or managed
installation qualification; this record remains proposed and pending.

## Verification

- `discovered_main_nonregular_inputs_reject_without_fallback`
- `explicit_catalog_nonregular_inputs_reject_before_effects`
- `discovered_main_and_explicit_catalog_regular_symlinks_remain_supported`
- `explicit_selection_bypasses_nonregular_discovered_main`
- `discovered_catalog_nonregular_filtering_and_symlink_rejection_are_preserved`
- `relative_catalog_paths_and_native_main_paths_remain_literal`
- `configuration_creation_still_accepts_an_explicit_absent_target`
- `configuration_writer_preserves_legacy_destination_selection_in_isolated_processes`

## Runtime acceptance

Preserve the failing standalone pre-fix executable and its digest, then rerun the
same bounded fixture matrix against the candidate. Clear inherited environment;
isolate HOME, XDG roots, temporary directories, current directory and PATH; close
stdin; own, kill and reap timed-out process groups. No installed provider or sudo
is available. Exercise ordinary zero-argument startup and config validation for
discovered main FIFO, symlink-to-FIFO and directory inputs with valid HOME
fallback, and explicitly listed catalog equivalents. Require prompt exit 3,
matching admission diagnostics and unchanged fixture inventories, file bytes,
Unix modes, symlink targets and directory modification times. Regular-file and
supported symlink controls must succeed; validation must remain read-only and
ordinary no-provider controls must record an empty completed task plan. Preserve
CLI/environment precedence, relative/literal/native paths, discovered catalog
filtering and symlink rejection, and writer creation controls. Verify the same
contracts in default and no-default feature builds. Native supported-platform
and installed-release gates remain separate.

## Supersession conditions

Supersede this record if configuration streams become supported, selected-file
failure permits fallback, discovered-catalog symlink policy changes, or
metadata admission is replaced with descriptor-held reading.
