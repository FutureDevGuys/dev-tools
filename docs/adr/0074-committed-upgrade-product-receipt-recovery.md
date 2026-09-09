---
authority: canonical
owner: dev-auth
---

# ADR 0074: Committed upgrade product receipt recovery

status: proposed
verification: pending

## Decision

[ADR 0078](0078-complete-strong-candidate-receipt-recovery.md) additionally permits strong receipt completion with a complete committed candidate, all privileged assets intact and native services quiescent. Its identity-and-mode-conditioned replacement also admits the legacy private strong receipt without altering privileged files.

[ADR 0075](0075-staged-user-upgrade-forward-recovery.md) extends this decision to the exact uncommitted staged user-only upgrade and resumption from its restored prior endpoint. Missing upgrade receipts and incomplete strong installations remain outside that extension.

Linux setup recovery can complete the product receipt for a user-only version upgrade after the exact shared candidate has committed while the product receipt still describes the retained prior release. This extends ADRs 0044, 0069 and 0072 without admitting an uncommitted upgrade, a missing upgrade receipt, incomplete strong assets or new release selection. ADR 0073 remains the separate initial staged-binary forward path.

The current product receipt must equal the retained prior receipt with transparent activation removed, matching ordinary pre-install deactivation. Version and mode must establish a distinct user-only successor. The existing pure constructor derives the prospective candidate receipt and retained previous release from the approved plan and prior history. Existing transition validation rejects unsigned replacement of authenticated prior state and inconsistent provenance. Exact shared observation requires the complete approved candidate receipt and, when a journal remains, the complete retained prior-to-candidate transition in its original direction.

Admission retains the current product document's bounded shared-reader byte identity as replacement authority. Recovery rechecks both its parsed prior identity and exact bytes before binary settlement and publication. Shared atomic-document publication compares against that original document identity; a late different receipt, including an independently rewritten equivalent JSON document, is not overwritten by that proof. Full candidate verification precedes product receipt publication and ordinary configuration/enrollment continuation. Setup exclusion, native running candidate identity, retained plan/documents, pending forward direction and activation-last behavior are unchanged.

Successful completion adds `complete_upgrade_binary_receipt` to the recovery action list. Established journal settlement and product receipt publication each contribute known change before later failure. Original source files and release downloads are unnecessary. The prior executable remains receipt-owned for its rollback window. Observation does not replace the outstanding all-writer coordination requirement.

## Verification and remaining gates

Source tests cover committed upgrades with and without a journal, unavailable original source, exact candidate receipt/history, unchanged retry, uncommitted rejection, late equal-meaning byte rewrites and unsigned successor rejection for authenticated prior state. A disposable native-user public-CLI fixture constructs a prior installation, retains its receipt through a committed upgrade, removes original inputs, rejects accepted-generation replay and resumes pending setup while preserving missing-enrollment gating. These fixtures reconstruct interruption states; signed upgrades, process-death and power-loss qualification, pre-commit upgrades, strong assets and non-Linux native recovery remain separate delivery gates.
