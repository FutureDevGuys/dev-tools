---
authority: canonical
owner: dev-auth
---

# ADR 0075: Staged user-only upgrade forward recovery

status: proposed
verification: pending

## Decision

[ADR 0076](0076-unstaged-user-upgrade-forward-recovery.md) additionally admits an absent candidate when no binary journal exists and the complete retained prior installation remains, using the exact approved running binary as the fixed source.

Linux setup recovery may finish a retained user-only version upgrade before its shared candidate receipt commits. This extends ADR 0074's committed-only requirement while retaining its exact inactive prior product receipt, byte-bound replacement authority, approved successor identity and provenance checks. The versioned candidate must already exist. Missing upgrade product receipts, unstaged candidates, strong installations and new release selection remain outside this path.

The initial staged-binary mechanism from ADR 0073 now accepts either explicit prior absence or the exact retained prior shared receipt. Admission verifies the shared transaction's endpoints and direction, prior and candidate artifact custody, retained plan/documents, native owner and running candidate, pending forward phase and setup exclusion. Product pointer preflight admits only missing pointers or exact targets from the selected prior/candidate transition. Without a journal, shared observation requires the prior installation's complete activation, and an additional bounded shared artifact read verifies the staged candidate. Unknown pointer files and targets are preserved rather than repaired.

Exact shared recovery restores the retained prior endpoint and retires its journal. Conditional shared installation then requires that same prior receipt under the installation lock, revalidates its complete state and the already-staged candidate, and activates only the fixed approved successor. The product callback rechecks its exact prior receipt authority and product-owned layout before shared activation. Product receipt completion uses ADR 0074's identity-conditioned atomic replacement, followed by complete installation verification and ordinary configuration/enrollment continuation.

An interruption after prior restoration resumes with the same staged candidate and a settled prior shared receipt. An interruption after candidate commit resumes through committed upgrade receipt completion. Each established restoration, activation and receipt publication records known change before the next step; uncertain entered failures remain uncertain. Successful forward completion adds `complete_upgrade_binary_installation` to the existing action list. This does not restore credentials, activate workloads before enrollment, extend release authority or replace the separately required all-writer coordination.

## Verification and remaining gates

Source tests cover partial activation, resumption from a restored prior without a journal, absent original source, exact final receipts and unchanged retry. Unknown pointer files are preserved; a late product receipt collision after binary recovery leaves the verified prior installation and an established-change result. Initial-installation and committed-upgrade tests remain regression gates. A disposable native-user public-CLI fixture retains prior receipts, constructs the exact uncommitted upgrade journal with missing activation pointers, removes original sources and checks accepted-generation replay rejection, missing-enrollment continuation and unchanged retry. These constructed fixtures do not establish process-death, power-loss, signed release or other native platform acceptance. Strong assets, earlier-than-staged recovery and full writer serialization remain separate delivery gates.
