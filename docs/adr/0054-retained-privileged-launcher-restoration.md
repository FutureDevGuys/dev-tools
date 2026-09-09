---
authority: canonical
owner: dev-auth
---

# ADR 0054: Retained privileged launcher restoration

status: proposed
verification: pending

## Decision

The Linux retained-installation component restores only the fixed `dev-auth-workload-launcher` leaf in its selected product data directory, using the exact original/candidate executable identities derived from retained product/shared receipts. Native root, a still-admitted inactive receipt and inactive transparent paths are required. The enclosing full-generation operation remains responsible for canonical system layout, exclusive setup ownership, durable restoration direction, stopped broker and workload absence. This component grants none of those authorities and does not enable the still-gated public strong restoration operation.

The prior immutable source is read through its retained existing directory with exact root ownership, ordinary 0755 mode, one regular-file link and bounded matching content. The current launcher is opened descriptor-relative with no symlink following or FIFO blocking. Its content and mode must match one of the retained release pairs; ordinary 0755 for those exact bytes is also admitted as an interrupted restoration intermediate. Absence, unowned bytes, hard links and unrelated permission bits fail without adoption or deletion. The prior release's product contract alone determines the final launcher mode: the legacy launcher is ordinary 0755, while the guarded successor uses 04755.

Restoration durably clears set-ID permission on the held current file before invoking the shared descriptor-bound ordinary-document publisher. After publication, the product reopens and verifies the exact prior bytes, assigns the prior release's mode on the held target, synchronizes the file and parent, and verifies the target again. Already-restored retries synchronize without republishing. Crashes before ordinary publication or before final permission assignment remain recoverable from exact retained bytes at 0755. Neither recognized contents alone nor candidate permissions authorize an old executable to become privileged. Same-owner root writers still require the enclosing operation's exclusion; descriptor retention is not a root-adversary sandbox.

The launcher precedes shared binary restoration within the retained component. [ADR 0055](0055-retained-setup-helper-restoration.md) supplies the separate helper executable/sidecar component, [ADR 0056](0056-retained-strong-generation-documents.md) supplies retained strong document selection, and [ADR 0057](0057-retained-native-service-shutdown.md) supplies bounded service shutdown, native absence observation and the disposable full-generation composition fixture. [ADR 0063](0063-retained-legacy-workload-link-ownership.md) supplies historical root-owned integration compatibility; [ADR 0064](0064-initial-strong-generation-withdrawal.md) supplies candidate-only retirement for initial absence. Signed/crash qualification remains incomplete. Credentials and credential-action receipts are unchanged. The exact accepted 0.3.11 executable/receipt compatibility is preserved; this does not rebuild or reissue its release bytes.

## Evidence

The root user-namespace restoration fixture first failed at the unavailable launcher operation, then separately exposed source special-bit acceptance and missing inactive-receipt enforcement before those guards were implemented. It exercises source fixtures representing both a legacy target and a guarded successor target, their distinct final modes, both ordinary-mode interruption states, repeat stability, unrelated bytes and modes, hard/symbolic links, absent launchers, special-bit immutable sources and active receipt rejection. The fixture also retains the prior binary/receipt/history checks. These tests do not execute the synthetic launcher contents and do not establish set-ID launch behavior, signed release, native process-death/power-loss, stopped-service or complete strong-generation acceptance.
