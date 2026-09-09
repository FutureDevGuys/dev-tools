---
authority: canonical
owner: dev-tools
---

# ADR 0032: Conditional legacy-installation cutover

status: proposed
verification: pending

## Context

A product can authenticate an observed legacy receipt and prepare its migration evidence while an older installer still owns the v1 namespace. The general initializer intentionally admits the current legacy receipt and pending upgrades. Reusing it for a preflighted fresh migration can therefore fence an installation different from the one the product admitted, even if the later product callback rejects the changed identity.

## Decision

The additive Linux `versioned_v2::initialize_legacy_if_unchanged` interface accepts a required complete v1 receipt observation. Under the existing installation lock it rejects any pending journal, missing or non-v1 receipt, or inequality with that observation before publishing an upgrade journal or invoking the product callback. It verifies current artifact and link custody before fencing, retains the same installation lock through the callback, and preserves active/previous identities and aliases through the existing v2 transaction. Missing data roots are not recreated. Lock admission may create a lock file; rejection does not promise globally zero filesystem writes.

The product still authenticates release evidence and owns any independent legacy metadata-writer retirement. Its callback retains the existing bounded, local, idempotent contract and outer-product-lease-before-installation-lock ordering. A callback failure keeps the durable upgrade journal; subsequent attempts use explicit resumption, never the fresh conditional interface. Already-initialized repeats also require their separate observation route. The comparison governs cooperating installation writers, not hostile same-owner modification outside the protocol.

## Compatibility and rollout

Existing explicit, absent-only and resume-only initialization contracts remain unchanged. No receipt or journal schema, dependency version or frozen artifact changes. This additive API belongs to unpublished installation 0.2.1. Receipt-owned product composition, legacy entrypoints and signed successor acceptance remain separate work.

## Verification

`conditional_legacy_cutover_rejects_an_intervening_receipt_before_fencing` first exercised the general initializer after an intervening v1 installation and observed its product callback despite the changed receipt. The conditional interface rejects that counterexample with identical receipt bytes and no upgrade journal. Additional public API tests cover preserved active/previous ownership, callback lock exclusion, interrupted callback and explicit resumption, pending and initialized rejection, missing roots/receipts, unknown journals, artifact/link drift, and full receipt comparison including aliases and retained-version fields. Existing v1/v2 tests retain their compatibility contracts.

Product composition, clean signed successor migration and native process interruption across fresh cutover remain acceptance gates. This source test does not establish full product migration, power-loss behavior or non-Linux runtime support. Supersede this record if fresh migration admission, callback authority or the legacy compatibility window changes.
