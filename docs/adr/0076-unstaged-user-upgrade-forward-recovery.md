---
authority: canonical
owner: dev-auth
---

# ADR 0076: Unstaged user-only upgrade forward recovery

status: proposed
verification: pending

## Decision

[ADR 0077](0077-unstaged-initial-user-installation-recovery.md) separately extends approved-source recovery to retained first-installation absence, including an installation layout that has not yet been created.

A retained user-only upgrade may resume before its versioned executable has been staged. This extends ADR 0075 only when the current product receipt is the exact retained inactive prior receipt, the shared installation is the complete retained prior endpoint, no binary journal exists and the candidate executable is absent. The running executable must match the retained candidate's approved length and digest before admission. Its current path can supply the fixed bytes; the original source path and release cache remain unnecessary. There is no new public source-selection option, download or release grant.

The existing shared transition observer establishes prior receipt, artifact, activation and journal state without mutation. Product preflight validates its layout and pointers and uses the bounded shared artifact reader to verify the selected running source's native owner, regular-file custody, executable mode and exact identity. A missing candidate version directory is permitted; an existing directory must retain product authority. A present mismatched candidate is not treated as missing, and a journal requiring absent candidate bytes cannot be repaired from this alternate source.

After ordinary retained-plan/document, native-account, pending-direction, admission-exclusion and enrollment-input checks, exact shared recovery revalidates the prior endpoint. Conditional shared installation then requires the unchanged prior receipt under its lock, publishes from the selected source using the original approved identity, verifies the staged artifact and rechecks product authority before activation. The product receipt is replaced only against ADR 0074's original byte identity. Source replacement, changed prior authority, new journals and unknown destination entries reject rather than becoming new authority. Existing fixed-identity shared publication remains authoritative if a source changes after product observation.

Successful completion uses the existing `complete_upgrade_binary_installation` action and change accounting. Later interruption resumes through the staged, committed or completed path already defined by ADRs 0074 and 0075. The copied command must retain the core `dev-auth` name or its supported release filename to enter the public CLI; basename dispatch is unchanged. Initial recovery before installation layout creation, missing upgrade receipts, incomplete strong assets and new release selection remain separate requirements.

## Verification and remaining gates

Source tests cover absent and existing empty version directories, absent original input, exact final receipt/history, unchanged retry, changed source before mutation, late independent candidate bytes and rejection of a newly appeared journal with an absent staged artifact. The native-user public-CLI fixture executes a separate correctly named approved copy after removing original inputs and the canonical candidate, retains the complete prior installation, rejects accepted-generation replay and checks pending continuation with enrollment still missing. Constructed interruption fixtures do not prove process-death or power-loss behavior. Signed recovery, all-writer coordination, initial-layout recovery, incomplete strong installations and non-Linux native acceptance remain delivery gates.
