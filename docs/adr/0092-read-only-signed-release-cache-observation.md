---
authority: canonical
owner: dev-tools
---

# ADR 0092: Read-only signed-release cache observation

status: proposed
verification: pending

## Decision

The additive `dev-tools-release::observe_cached_release` API checks whether an exact product/version/target artifact has a completed private cache entry without creating a directory, lock, receipt or recovery state and without synchronizing storage. An absent cache root, version entry or receipt means the artifact is not yet available. A present receipt requires exact owner and directory-mode custody, signed root/manifest/artifact verification, and agreement with the receipt. Tampering is an error, not cache absence.

The writer continues to publish the receipt last under its existing exclusive lock. A read may meet a concurrent writer and report absent or a transient error; it does not claim a transactional snapshot against arbitrary same-owner mutation. This observation is disposable payload-availability evidence only. Installation still reopens the cache through its existing lock, checks the accepted release ledger and plan, and revalidates artifact custody before activation. No mutating operation may treat an observed path or version string alone as authority.

Dev Auth uses this boundary to distinguish a signed metadata observation from an already prepared offline payload. Local `update status` and `update check` need not hash artifact bytes; a future admitted offline mutation can request the explicit availability observation before its setup-owned transition. This does not introduce a public mutating update operation or change an accepted installation format.

## Verification and remaining gate

Tests cover absent cache without initialization, receipt-last availability, signed exact-byte agreement and non-recreation of a removed receipt. Dev Auth tests confirm that metadata alone does not establish a prepared artifact. Native read-only syscall acceptance and the complete update mutation/recovery adapter remain pending; this source API is not platform support evidence.
