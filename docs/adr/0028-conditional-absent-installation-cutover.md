---
authority: canonical
owner: dev-tools
---

# ADR 0028: Conditional absent-installation cutover

status: proposed
verification: pending

## Context

A product can observe an absent installation and then lose that condition to an older writer before acquiring the installation lock. Ordinary protocol initialization intentionally accepts legacy receipts for migration. Using it for an absent-only installation can therefore publish an upgrade fence or retire product state for an intervening installation that was never admitted for migration.

## Decision

The additive Linux versioned-v2 initialize-if-absent interface checks receipt and journal absence under the existing installation lock before layout preparation, upgrade-journal publication or the product-state callback. Any existing receipt or journal is rejected, including initialized empty receipts and pending first-use upgrades. Explicit recovery remains on the existing initializer and recovery interfaces. Directory and lock admission still occur; this API does not promise a globally write-free failure.

The existing initializer retains its migration and resumption semantics and delegates to the same implementation without the new condition. No wire schema, frozen archive or dependency version changes. The additive API belongs to the unpublished installation 0.2.1 source generation. Product integration must distinguish fresh cutover from initialized observation and own any outer product lease.

## Verification

Public integration tests cover an intervening legacy installation, fresh empty initialization, initialized and pending collisions, exact preservation of receipt/journal bytes, callback exclusion and explicit resumption through the existing interface. The existing protocol suite protects legacy migration, frozen-writer exclusion and conditional activation. Native process-interruption and actual product successor release acceptance remain separate gates.
