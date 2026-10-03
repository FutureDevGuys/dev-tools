---
authority: canonical
owner: dev-tools
---

# ADR 0047: Identity-bound atomic document removal

status: proposed
verification: pending

## Decision

The Linux installation foundation exposes `remove_atomic_document_if_unchanged` for restoring an approved absent document. The product supplies the exact path, bounded owner/mode authority and expected content identity, holds its writer exclusion and owns ancestor trust. The primitive rejects links, unsafe custody and different content; it removes only the admitted leaf under a retained parent descriptor. A missing leaf is an idempotent retry, not authority to remove a replacement. The parent must exist. Neither directories nor neighboring files are removed.

Successful removal and absent retries synchronize the retained parent directory. Failure after unlink can have uncertain durable progress and must remain recoverable through the caller's journal. This operation is not a permanent fence against a legacy writer and does not authorize configuration restoration or credential rollback by itself. Products must retain the prior generation and close admission before selecting it for restoration. Hostile same-owner mutation and nonparticipating writers remain outside the participating-writer exclusion contract.

The additive interface is Linux-only in the unpublished installation 0.2.1 source. Existing public functions, frozen registry packages and published executables keep their original bytes. Non-Linux support requires native custody and durability acceptance.

## Evidence

Public integration tests exercise exact removal, absent retries, different replacement preservation, hard links, symbolic links, symbolic ancestors and incorrect modes. The explicit Linux syscall fixture checks unlink-before-parent-sync, synchronization without a second unlink on retry, and recovery after an injected post-unlink sync failure. These are syscall and source-library checks, not product restoration, native process-death or hardware power-loss acceptance.
