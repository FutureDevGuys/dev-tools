---
authority: canonical
owner: dev-auth
---

# ADR 0050: Integration retirement preserves durable ownership ordering

status: proposed
verification: pending

## Decision

Receipt-owned workload and desktop integration reconciliation synchronizes the directory containing changed entries before publishing a receipt that no longer owns them. Desktop deactivation then removes its empty receipt and synchronizes the receipt directory. An already-absent desktop receipt retries that final directory synchronization without creating missing directories. This ordering prevents a completed deactivation from discarding removal authority while a launcher deletion remains unsynchronized.

The product-owned synchronization boundary retains an existing non-symlink directory descriptor, checks its native owner, rejects group/world write permission and verifies the named inode before synchronizing it. It creates no directories and changes no contents or permissions. Integration callers retain their existing responsibility for ancestor trust and writer exclusion; this is not a retrofit of coordination into legacy or nonparticipating writers. Unsafe custody and sync failure remain errors, leaving full setup/restoration pending rather than claiming durable acceptance.

The same ordering applies when reconciliation publishes new entries and their receipts. It does not itself add a journal that adopts partially published entries, resolve all lower-level mutation coordination, or qualify native crash teardown. Existing receipt schemas and accepted release bytes remain unchanged.

## Evidence

The explicit Linux syscall fixture requires workload unlink before bin-directory synchronization before clearing the workload receipt, and desktop unlink before desktop-directory synchronization before receipt unlink before receipt-directory synchronization. It also requires absent receipt retries to synchronize without another unlink. The test failed on the missing bin-directory synchronization before the implementation change. Injected `fsync` errors after desktop deletion and after receipt deletion exercise receipt preservation and recoverable absent-receipt retries respectively. Separate custody checks reject a wrong owner, writable directory and symbolic-link leaf and require no directory creation for absence.

These tests observe native Linux syscall ordering and injected failures. They are not hardware power-loss, signed installed strong-mode, non-Linux storage or whole-domain process-death acceptance.
