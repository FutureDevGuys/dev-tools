---
authority: canonical
owner: dev-auth
---

# ADR 0059: Generation-bound user integration retirement

status: proposed
verification: pending

## Decision

Full-generation restoration selects workload launchers and desktop entries from retained approval for every desired and retiring account. Original receipt destinations and native-owner private custody must match the approved current-path inventory. Every original receipted entry must have exactly one retained object with the fixed account-relative destination, matching target or content digest, single-link custody and compatible ordinary permissions. Duplicate, missing, redirected or changed retained objects fail before mutation. Candidate names and desktop contents derive from the retained policy/configuration and compiled renderer, only when the approved intent could activate those integrations; retiring accounts have no candidate activation set.

Live receipts may equal the retained original, the derived candidate or their supported empty deactivation forms. A changed live receipt cannot expand removal authority. The operation examines the union of original and candidate entry names, including candidate entries published before their receipt. Existing setup already admits an exact candidate launcher target or desktop content before receipt publication; restoration uses that bounded candidate rule with explicit native-owner, single-link and permission custody. It does not treat a matching executable or digest at an arbitrary name as ownership.

Receipt-owned entries that differ from their admitted versions block retirement and are preserved. Unreceipted candidate-name collisions with unrelated files, links, types or custody are preserved without preventing restoration. An eligible unreceipted candidate entry is removed only if its target or content/permission pair exactly matches retained candidate authority. Content-read errors remain errors, not evidence of an unrelated file. Terminal verification examines the selected entries as well as receipt absence; deleting a receipt alone cannot establish retirement.

All entry and receipt observation/removal is descriptor-relative through `ExistingDocumentDirectory`. Its additive metadata observation holds an `O_PATH | O_NOFOLLOW` leaf descriptor, checks named and held identity plus parent custody, and returns native metadata without reading contents, opening a FIFO/device for I/O or following a symlink target. Metadata is not document or removal authority: those operations retain their exact content, owner and type checks. No parent is created, no target is followed or changed, and no file ownership or permission is repaired by retirement.

Each entry's directory is synchronized before the live receipt is removed and its own directory synchronized. Retained generation authority survives all partial progress, including absent-entry and absent-receipt retries. The enclosing setup owner retains admission exclusion, durable restoration direction and service/workload absence; descriptor retention does not provide atomic compare-and-unlink against an adversarial same-owner writer. The user-only restoration path selects this component. The public strong restoration gate remains closed until complete root-generation composition and native service/crash qualification pass. Existing receipt schemas and frozen release/package bytes are unchanged.

## Evidence

Launcher and desktop retirement tests first failed at their absent operations, then passed exact removal, unchanged retry and discovery of unreceipted candidate entries. Separate tests failed when unrelated candidate-name collisions incorrectly blocked retirement; the corrected boundary preserves those entries. Tests reject expanded live receipts and receipt-owned target/content/permission drift before removing entries, preserve unrelated names with candidate-identical bytes, keep link targets unchanged and require selected-entry absence after receipt removal. Retained selection tests cover desired and retiring accounts and reject wrong ownership, special bits, redirected paths, changed identities, duplicate objects and missing objects.

The public shared metadata test first failed at missing regular-file observation. It checks ordinary files, dangling symlinks, directories and FIFOs, rejects traversing names and rejects a replaced selected parent. The existing shared mutation tests retain their exact removal and custody checks.

The disposable native-user CLI fixtures exercise both prior-installation restoration and initial absence with candidate launchers and desktop entries published without receipts. They remove original source inputs, reject configuration drift without changing the transition, preserve an unrelated link to the same candidate, restore inactive authority and verify an unchanged retry. The explicit namespace-root fixture `cargo test -p dev-auth --lib setup_v3::restoration::integration::tests::native_root_integration_retirement_preserves_account_and_directory_boundaries --locked -- --ignored --exact` exercises distinct desired and retiring UIDs, rejects a redirected bin parent and wrong-owner receipted link, removes selected integrations and receipts, and preserves unrelated account files and directory ownership/modes. It uses subordinate UID mappings and disposable paths, not host service mutation, signed release, process-death/power-loss or complete strong-mode acceptance.
