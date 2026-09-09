---
authority: canonical
owner: dev-tools
---

# ADR 0051: Withdrawal of externally retained installation activation

status: proposed
verification: pending

## Decision

The Linux installation foundation exposes `withdraw_versioned_installation_activation` for a caller that retains the exact installation receipt in its own durable recovery transaction. It removes only the receipt's public aliases, active/previous pointers and shared receipt, leaving immutable artifacts, the installation lock, directories and unrelated files intact. This is not a complete uninstall, artifact cleanup or permanent legacy-writer fence. The caller supplies release authentication, retained recovery authority, ancestor trust and exclusion of nonparticipating writers. The operation creates no new recovery protocol or permission to restore an older writer.

The existing installation lock serializes withdrawal. Existing roots and intact bounded artifacts are required on every invocation. A pending binary journal requires separate authenticated recovery. The current receipt must be either the exact retained receipt or absent from an interrupted withdrawal. Every declared link must be absent or a native-owner, single-link symbolic link to its exact retained target; an undeclared previous pointer fails closed. Complete receipt, artifact and link admission precedes the first removal. Held parent descriptors, named-directory identity checks and named-lock validation preserve the selected mutation boundary.

Aliases and pointers are removed through held directory descriptors and both directories are synchronized before identity-bound removal of the ownership receipt. Already-absent retries synchronize directory absence and never reactivate the installation. A failure can follow partial removal; the caller keeps its transaction pending and retries with the same retained receipt. The immutable executable remains available for that continuation even after public aliases disappear. Retention and the installation lock are never deleted by this primitive.

The additive API is part of unpublished installation 0.2.1. Existing strict shared receipt/journal schemas, frozen publication packages and released bytes are unchanged. A caller must not treat an absent shared receipt alone as proof that all activation pointers are absent; only the withdrawal postcondition establishes that result for the supplied retained inventory.

## Evidence and remaining work

Public source tests exercise exact removal, retries after partial alias/pointer/receipt removal, preservation of both immutable versions and unrelated recovery inputs, stable lock retention, absent-root rejection and pre-mutation refusal of foreign receipts, links, pending journals, hard-linked artifacts/aliases, undeclared previous pointers and insufficient artifact bounds. The native syscall fixture requires both pointer directories to be synchronized before receipt removal and the receipt directory afterward. Injected sync failures before and after receipt removal preserve resumable withdrawal and retained artifacts.

[Dev Auth initial user-installation restoration](0052-dev-auth-initial-installation-restoration.md) selects this primitive after establishing original absence and retaining exact candidate authority. The product keeps configuration and credential effects within retained authority and verifies the complete inactive/absent postcondition before completing its outer transaction. Native process-death, signed product and non-Linux acceptance remain separate requirements.
