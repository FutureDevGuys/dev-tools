---
authority: canonical
owner: dev-auth
---

# ADR 0077: Unstaged initial user-only installation recovery

status: proposed
verification: pending

## Decision

Linux setup recovery may complete a retained first user-only installation before its candidate, installation lock, launcher directory or versions directory exists. This extends ADR 0073's staged-only boundary using ADR 0076's exact approved running-source selection. Paired retained product/shared absence, current product receipt absence, intact retained plan/documents, native installation owner, pending forward direction and setup exclusion remain mandatory. Retention must already exist; absence of the private setup generation cannot authorize initialization or reconstruct approval.

The shared read-only installation observer establishes absence of a managed receipt and binary journal without creating an installation lock. That observation is deliberately not proof of an empty or externally unowned namespace. Product preflight separately requires all candidate product pointers to be absent, validates existing layout directories and uses the shared no-follow existing-directory interface to distinguish missing bin/versions directories from unsafe path authority. The existing setup data root must remain owned. An existing candidate version directory must be owned; a missing one is permitted. Source custody and exact length/digest are checked through the bounded shared reader. Unknown files, links, receipts and journals remain untouched on admission failure.

With no binary journal to settle, recovery reobserves absence and enters the existing conditional shared installer directly. The installer acquires or creates its installation lock and checks receipt/journal absence before candidate publication. It prepares the managed layout, copies only the fixed approved identity and rechecks product authority before activating the initial binary. Product receipt publication, complete verification, missing-enrollment handling and activation-last continuation reuse the earlier recovery paths. No shared API or publication identity changes are required.

The operation reports `complete_initial_binary_installation` on successful completion. Errors after entered layout preparation can represent uncertain change; neither the initial absence observation nor a later false change contribution may turn that into an unchanged result. A crash after staging or commit resumes through ADR 0073 or ADR 0072. Candidate execution from a downloaded copy retains the existing core filename contract. Strong installation assets, missing upgrade product receipts, all-writer coordination and fresh release authorization are not supplied by this path.

## Verification and remaining gates

Source tests cover an absent versus existing initial layout, no read-only lock/directory creation, exact final receipt, unchanged retry without the external source, late unknown journal, symlinked launcher directory, independent launcher bytes and a newly installed unrelated shared generation. The native-user public-CLI fixture passes after removing original configuration and binary inputs, both receipts, the canonical candidate and initial installation layout while retaining setup approval; it checks accepted-generation replay rejection and pending continuation with enrollment still missing. These are constructed interruption fixtures, not process-death, power-loss or signed release evidence. Strong assets, writer coordination and other platform acceptance remain separate delivery gates.
