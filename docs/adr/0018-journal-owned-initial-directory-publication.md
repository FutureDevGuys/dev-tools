---
authority: canonical
owner: dev-tools
---

# ADR 0018: Journal-owned initial-directory publication

status: proposed
verification: pending

## Decision

The additive Linux `publish_new_document_directory_recoverable` boundary reserves a complete private directory through a durable, bounded first-use journal. Artifact Update uses it for missing configuration and ledger directories and, through `StagingArea::initialize_recoverable`, for installation and cache-publication reservations. The prior directory publisher and `StagingArea::initialize` retain their existing interfaces and behavior. Existing configuration, ledger, cache, receipt and reservation bytes are unchanged.

A nonblocking, permanently retained per-target lock serializes this publication protocol. Its key is SHA-256 of `dev-tools-initial-directory-target-v1` followed by NUL and the exact normalized absolute native target-path bytes. The lock and journal live in the destination's parent as `.dev-tools-initial-<key>.lock` and `.dev-tools-initial-<key>.json`. The parent must be caller-owned without group/other write permission, or root-owned and sticky; trusted ancestor selection remains caller-owned. An internal explicit-owner lock path supports the latter without changing ordinary installation locks' parent-owner requirement. Lock acquisition still rechecks the named device/inode and single-link custody after acquisition.

The strict `dev-tools-initial-directory-publication-v1` journal is a single-link owner-only regular document bounded to 4 KiB. It binds the target key, parent device/inode, randomly allocated staging directory name and device/inode, exact document name and document-size limit. The staging directory is mode 0700. Journal publication and parent durability precede writing document bytes; the staged document is finalized to mode 0600, written and synced before the directory is synced and renamed without replacement through the retained parent descriptor. The final rename is synced before journal removal and another parent sync. No remote fields or executable actions enter the protocol.

An explicit publication retry validates the journal and acquires the same lock before recovery. Recovery removes only its exact staged directory after checking directory identity, owner/mode and a closed inventory containing at most its declared document. The document must be a bounded single-link regular file with no group/other, execute or special permissions; more restrictive owner permissions are allowed because a crash may precede permission finalization. Unknown entries, changed identities, symlinks, hardlinks and mismatched journal authority fail before deletion. Missing staged directories permit journal removal only; no final directory is deleted, adopted or treated as a successful new installation. Existing final entries always block fresh publication, even when the prior attempt published them before a later error.

This journal authorizes disposal of unpublished protocol-owned staging, not configuration content, release authentication, accepted generations or installation. Errors may follow recovery or publication, so callers retain their unknown-change failure contracts. Same-owner adversarial mutation is outside this cooperating-process protocol. Callers do not run the old and new initial-publication mechanisms concurrently for the same target, and do not remove a retained lock while this protocol remains usable.

Death before journal publication can leave an empty unmarked staging directory or an unmarked temporary from the atomic journal writer. Older unmarked temporaries likewise have no independently established ownership. Recovery does not scan or remove them; their names, ages and PIDs supply no deletion authority. They do not block a fresh publication attempt. Product-visible reconciliation of a journal left after final publication, retained reservation retirement and native release-binary crash acceptance remain distinct work. This slice does not claim complete staging garbage collection or completed Artifact Update release acceptance.

The additive APIs use installation crate version 0.2.1, and Artifact Update declares that minimum. Already signed 0.2.0 archives retain their exact original bytes; the successor requires its own source-bound publication generation before registry consumers can use these APIs. No dependency, feature, edition, MSRV or existing artifact version is changed incidentally.

## Verification

Subprocess fixtures terminate without destructors at pre-journal, post-journal, content-synced and post-publication boundaries. Tests distinguish preserved unmarked entries from recovered journal-owned staging and ensure published data is never replaced on retry. Hostile inventory, directory replacement, changed target/document/limit/schema/parent authority, unknown journal fields, unsafe permissions, links, bounds and live-writer exclusion receive regressions. Public staging tests verify reservation-format and lease compatibility; Artifact Update's configuration, ledger, installation, cache, rollback and local-only tests remain required. Power-loss durability and signed standalone product crash acceptance remain release gates rather than consequences of a passing process-death fixture.
