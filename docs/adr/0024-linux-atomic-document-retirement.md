---
authority: canonical
owner: dev-tools
---

# ADR 0024: Linux atomic-document retirement

status: proposed
verification: pending

## Context and decision

A new lock cannot exclude a published legacy writer that does not acquire it. Update All 0.1.8's metadata checker publishes state by replacing one regular-file path. The additive Linux `dev-tools-installation::retire_atomic_document` boundary permanently fences that path with an owned empty directory and retains the final file for product-owned authentication and import. This complements ADR 0023's installation-writer fence. No product entrypoint selects this cutover yet.

The primitive retains a nonblocking per-target lock and strict 4 KiB retirement record in the source parent. Their basename is `.dev-tools-retired-document-<key>` with `.lock` and `.json` suffixes. The key hashes `dev-tools-retired-document-target-v1`, NUL and normalized absolute native path bytes. The parent must be caller-owned without group/other write permission; callers own ancestor trust. The record binds target, parent device/inode, random staging basename, fence device/inode, source mode and length bound, original presence, and eventual captured content identity. The source must be a bounded, nonempty, single-link, owner- and mode-matched regular file. The record denies unknown fields.

For existing history, a durable record and synced empty mode-0700 fence precede Linux `RENAME_EXCHANGE` under the retained parent descriptor. The source file moves to the staging pathname while the fence takes the source pathname atomically. Import receives the file captured at that boundary, not the earlier validation read. An old writer publishing first contributes its latest bytes; one publishing later cannot replace a directory with its prepared regular file. Captured bytes are admitted again, synchronized and bound by content identity in the permanent record. Products separately verify meaning and authenticity.

Explicitly allowed absent history uses `RENAME_NOREPLACE`. If an old writer creates the file first, the record durably changes from absent to existing before exchange. Existing history never changes back to absent. A caller requiring prior history rejects even a completed absent-history retirement. Missing archives, altered captured bytes, foreign directories, changed fence identities/inventory, and mismatched record authority fail closed. Retry synchronizes admitted storage before acknowledging success and never removes the fence or archive. Success reports retirement/record change; errors may follow mutation and carry no unchanged-state promise.

The record, lock, fence and captured file remain permanently retained while old participants can exist. There is no deletion or automatic downgrade API. The empty directory is retained before fallible record publication so a post-publication sync error cannot trigger temporary cleanup. Death before record publication may leave an unmarked empty directory or atomic-write temporary; the protocol never scans, adopts or deletes such entries. Names, ages and PIDs provide no cleanup authority.

## Boundaries and compatibility

This cooperating-owner protocol excludes atomic replacement of this exact path, not in-place writers or hostile same-owner mutation. Products must qualify their actual retained versions before selection. Callers retain one lease order, such as product, installation, then retirement lease. The primitive performs bounded local filesystem work and starts no process or network operation. Status does not call it; retirement and recovery are explicit mutations.

Existing APIs remain unchanged. The additive interface remains in unpublished installation 0.2.1; frozen packages and released binaries retain their exact bytes. Linux acceptance does not establish macOS or Windows/WSL support. Failed product authentication/import leaves a fenced, recoverable cutover, never permission to reset history or restore old writers.

[ADR 0027](0027-read-only-cutover-observations.md) adds separate nonmutating observation of recognized captured history. That reader does not invoke retirement, acknowledge durability or complete an interrupted record.

## Verification and remaining acceptance

The public regression first demonstrated that reading history alone permits an already-prepared stale rename to overwrite the source. It now asserts preserved bytes, rejected rename, the fence and unchanged retry. Tests cover absent history, last-writer capture, the absent-path race, interruption before/after exchange, non-unwinding native process exits, lease exclusion, missing/changed archives, lost pre-exchange history, source links/modes/bounds, strict record binding, replaced fences and unknown inventory preservation. Existing installation suites remain required.

The native `legacy_checker_cannot_replace_a_retired_state_directory` gate uses the digest-pinned published Update All 0.1.8 executable, public signed metadata and a delayed traced rename. It invokes this production primitive while that writer is prepared, verifies `EISDIR`, and rechecks retained bytes through the public retry API. This proves the qualified legacy replacement path, not full signed product migration or hardware power-loss recovery.

Product-owned authenticated-history import, signed-proof retention, source-bound online/offline installation, retained rollback and end-to-end interruption remain gates before product cutover. Supersede this record if the protocol or qualified writer contract changes; remove compatibility only after the product's retained-version window closes.
