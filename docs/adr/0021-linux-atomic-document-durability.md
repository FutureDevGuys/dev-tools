---
authority: canonical
owner: dev-tools
---

# ADR 0021: Linux atomic-document durability

status: proposed
verification: pending

## Context

The shared atomic-document writer synchronized a temporary file and its final parent directory but used nondurable creation for ancestor directories. It also synchronized the temporary before setting final mode and owner. A byte-identical retry returned without syncing the document or final directory, so it could acknowledge a previous publication whose final sync had failed. These are distinct from atomic namespace visibility and from higher-level installation recovery.

## Decision

On Linux, atomic-document mutation uses the foundation's existing descriptor-relative durable ancestor opening. Each ancestor entry, including one left by a prior failed attempt, is synchronized before a descendant is acknowledged. A temporary's final metadata is applied before its file sync and publication. A byte-identical Linux retry synchronizes the admitted file and its parent before returning unchanged. Read-only bounded document observation does not synchronize storage.

The existing document format, expected-identity API, owned temporary behavior and boolean change result remain unchanged. Products continue to own writer serialization, ancestor trust and higher-level recovery. No new dependency or platform support claim is introduced.

## Invariants

- Successful Linux publication includes synchronization of ancestor entries, final file data and metadata, and the final parent entry.
- An idempotent acknowledgement does not skip the durability boundary solely because the visible bytes already match.
- Synchronization errors propagate; visible publication followed by sync failure is not reported as success or automatically rolled back.
- Read-only observation remains free of storage synchronization and repair.

## Rejected alternatives

Synchronizing only the immediate parent leaves newly created ancestors outside the durability boundary. A pre-permission file sync does not establish persistence of the final mode. Treating matching bytes as proof that a previous operation completed confuses visible state with durable acknowledgement. A second product-private ancestor walker would duplicate the shared filesystem boundary.

## Consequences and known limitations

Mutating calls, including clean no-ops, perform additional Linux sync operations. Local-only status reads remain unchanged. The guarantee depends on successful kernel/filesystem synchronization; syscall tests do not simulate hardware power loss or establish an atomic transaction across installation receipts, release history and artifacts. Hostile same-owner namespace races remain outside the participating-writer contract. Non-Linux ancestor and no-op durability remain gated by native implementations and acceptance; moving temporary synchronization after final metadata does not independently establish their support. Frozen registry archives and published release binaries are not replaced.

## Verification

The explicit Linux tests `atomic_document_publication_syncs_ancestors_and_retry` and `atomic_document_publication_syncs_final_file_mode` initially failed against the public writer's actual traced syscalls. After ancestor and metadata ordering were corrected, the former separately exposed the missing idempotent final-directory sync. `atomic_document_publication_retry_finishes_failed_parent_sync` injects an operating-system sync error after publication and verifies that an unchanged retry completes the file and parent sync without republishing. Existing bounded document and ownership tests remain required, along with affected product suites.

## Runtime acceptance

Run the explicit Linux syscall gate documented in the development guide with strace and ptrace permitted, then exercise source-bound product installation and recovery outside a checkout. Retain separate product-level crash, rollback, mixed-version and platform gates before claiming full conformance.

## Supersession conditions

Supersede this record when a different durable filesystem publication API replaces these primitives. Preserve the distinction between visibility, durable acknowledgement, unchanged retry and higher-level transaction recovery.
