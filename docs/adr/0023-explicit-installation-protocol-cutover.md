---
authority: canonical
owner: dev-tools
---

# ADR 0023: Explicit installation-protocol cutover

status: proposed
verification: pending

## Context

Update All's published 0.1.8 installer participates in the shared installation lock, but its metadata checker does not. A new product release ledger therefore needs both an installation-writer fence and a separate product-owned legacy-state fence. Merely adding a new lock cannot exclude the published installer. Removing an upgrade journal before product-state migration completes would reopen installation mutation, and an absent receipt after first-install recovery would reopen old initialization.

## Decision

The additive Linux `dev-tools-installation::versioned_v2` module explicitly selects a new outer receipt and journal protocol at the existing installation receipt/journal paths and retains the existing installation lock. The v1 APIs and schemas are unchanged. The new outer documents deny unknown fields, bind the complete caller-selected layout and contain the unchanged v1 artifact/link ownership record. The inner record is not permission to use v1 writers; only the selected outer protocol controls mutation. Shared pointer publication, restoration, custody and artifact verification remain one implementation.

Explicit initialization preserves the active and retained versions, including their exact identities and aliases. Its durable upgrade journal precedes the product callback. The callback authenticates the supplied receipt and durably completes any product-owned state cutover before acknowledging success. It runs under the installation lock and must perform bounded local work without reacquiring that lock or waiting for its holder. Products with another outer writer lease retain a consistent outer-lease-before-installation-lock order. Initialization failures retain the upgrade journal and require explicit resumption; ordinary recovery never restores v1 authority. Resumption may repeat the callback even after receipt publication, so the callback must be idempotent. Existing normal or legacy-adoption journals require their own recovery before initialization.

An initialized empty installation has a durable v2 receipt whose installation record is null. A failed first activation can therefore restore empty installation state without removing the old-writer fence. An already-initialized retry does not recreate missing directories as an unchanged result; missing required custody fails, while an empty versions directory may remain absent until activation needs it. Observation is bounded, local and read-only, and rejects an uninitialized namespace instead of initializing it. Conditional apply and rollback reject pending journals, receipt changes and link drift before candidate publication. Normal recovery authenticates both transition receipts before restoring links or clearing a committed journal, and leaves the enclosing protocol unchanged. Product release history is never lowered by retained rollback.

## Boundaries and compatibility

The public v1 types, literal construction, paths and callable APIs retain their contracts. They reject the new outer documents rather than interpreting new authority. A pending upgrade can leave a readable v1 receipt, but its incompatible journal blocks v1 mutation. Old implementations may still prepare directories or a lock before rejecting a protocol; exclusion concerns activation and owned removal, not a universal no-filesystem-effects guarantee. There is no automatic downgrade or new v2 uninstall interface in this slice.

The protocol does not exclude product writers that bypass installation locking. Update All must separately retire the old release-state writer, preserve its last accepted history and retain authenticated proofs before adopting this module. No product entrypoint selects v2 yet. Products own bounded legacy adoption and retained-binary operation; a schema fence alone does not qualify those workflows. Frozen registry archives and published release binaries remain unchanged. Installation 0.2.1 remains the unpublished source generation for this additive interface.

## Verification

Public API tests cover empty initialization, v1 active/previous preservation, unchanged repeats, conditional activation and rollback, failed/resumed product cutover, receipt-committed upgrade resumption, absent read-only observation, unknown journal preservation, artifact bounds, and committed/uncommitted normal recovery from both empty and installed states. A separate process exits without unwinding inside the product callback; its retained upgrade journal excludes v1 activation and admits explicit resumption after the native lease is released by process death. Recovery rejection preserves its journal, and the callback cannot enter a competing installation lease. The initialized-empty retry test first exposed unintended directory repair before the no-op check. Existing v1 tests protect the extracted shared pointer and observation-lock primitives.

The explicit `legacy_installer_is_excluded_by_pending_and_committed_protocol_upgrade` gate runs the exact digest-pinned published Update All 0.1.8 binary in a disposable home. A successful local rollback is its control; the same engine must then reject pending and committed protocol upgrades without changing state, receipt or active target. Its synthetic current candidate supplies health text only and is not signed-release acceptance. Manually reconstructed interruption states prove recovery semantics, not power-loss durability or every syscall interruption.

## Remaining acceptance and removal

Before product cutover, qualify product-state retirement and authenticated-history import, real process interruption throughout upgrade and activation, source-bound online/offline installation, retained rollback and ordinary retained-binary operation outside a checkout. Native macOS and Windows/WSL implementations and acceptance remain separate gates. Keep v1 readers and retained artifacts until their documented rollback window closes; removal requires evidence that no supported participant needs them. Supersede this record if the shared installation protocol or product cutover authority changes.

The native `retained_legacy_ordinary_run_survives_pending_and_committed_cutover` gate covers the frozen 0.1.8 ordinary task path with its default automatic-update setting. It installs the digest-pinned published binary in a disposable home, retires state through the production primitive, and exercises pending and committed upgrade states through the public command link. The old automatic updater warns on the incompatible protocol and the selected local task still executes; tracing rejects IP networking and assertions preserve captured state, receipt, journal and active target. This does not establish new-adapter mutation, actual retained-version activation or all legacy entrypoints, and does not require disabling the user's automatic-update setting.
