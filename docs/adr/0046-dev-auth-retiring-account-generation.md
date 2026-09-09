---
authority: canonical
owner: dev-auth
---

# ADR 0046: Retiring native accounts remain part of the setup generation

status: proposed
verification: pending

## Decision

Strong setup includes accounts removed by the replacement administrator policy in a separate `retiring_accounts` inventory. Planning derives this inventory from the existing root-owned system policy and native account lookup, then binds the old policy's exact bytes and each retiring account's name, UID, GID and home in the approved plan. The desired account set still exactly matches the replacement policy. An absent old policy means no retiring accounts; an unreadable, malformed or unsafe policy does not mean absence. Missing accounts require explicit identity recovery, not guessed homes or recycled identities. Desired and retiring inventories cannot overlap in native name, UID or home.

The new plan field is omitted when empty and defaults to empty when reading existing plans. Existing authority-bearing readers reject a nonempty field they do not understand. Revalidation does not silently expand an older approved plan that omitted an account: its inventory must agree with the prior policy and current native identities before mutation. User-only setup cannot contain retiring accounts.

Retiring accounts contribute both versioned configuration paths and integration receipts to the approved current-state inventory. Generation capture includes their receipt-owned workload links and desktop contents and rechecks the approved receipt bytes after enumerating those objects. Stopped replacement deactivates both desired and retiring accounts' owned integrations. Configuration and credential installation, broker authorization and final activation remain limited to the desired account set. Acceptance requires retiring integrations to be inactive. Unowned launchers are not removed, and old credential material is never copied into retention or restored.

After replacement starts, revalidation derives retiring accounts from the exact old policy in the matching retained generation, not the now-installed replacement policy. The native transition, canonical original plan, old policy identity and exact bytes must agree. This applies to pending recovery and verification of the same accepted generation. Before retention exists, the old policy must still match the approved current-state identity. Initial planning also compares the old policy used for account discovery with the final current-state snapshot, rejecting drift between those reads.

## Evidence and remaining gates

Focused source tests exercise native account derivation, missing-account and mode rejection, retention and deactivation of a retiring account's owned launcher, and preservation of unrelated files. The retention and deactivation assertions each failed against the previous candidate-only loop. Existing disposable installed user-only CLI acceptance remains a separate regression gate.

This closes the retiring-account inventory and deactivation gap, not the complete restore operation. Receipt-owned configuration restoration, transaction-aware installation rollback, native strong-mode multi-account crash acceptance and signed release qualification remain required. Account lookup equality protects the approved identity during this transaction; it does not establish the historical owner of an account that was already recycled before planning.
