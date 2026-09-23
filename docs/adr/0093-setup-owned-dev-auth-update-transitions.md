---
authority: canonical
owner: dev-auth
---

# ADR 0093: Setup-owned Dev Auth update transitions

status: proposed
verification: pending

## Decision

Dev Auth's Linux `update apply` uses the shared update orchestrator for installation classification, signed metadata freshness, offline payload availability, artifact preparation and no-op ordering. It never installs a binary or edits policy independently. The admitted native installation owner retrieves the exact accepted full setup generation, verifies its current postcondition, and stages its retained source documents in an owner-only temporary directory under the receipt-owned data root. Credential actions normalize to preservation so a version update cannot repeat rotation, revocation or enrollment. A missing or unrestorable accepted generation requires explicit setup or recovery rather than fabricating a new policy.

The staged signed release and preserved deployment intent produce one full setup plan and digest. The old binary revalidates the exact candidate, then invokes that candidate as a bounded private update worker with no credential stdin and no captured terminal output. The worker rechecks the plan, private staging custody, accepted release and its own candidate identity before entering the existing setup apply transaction. It writes a bounded, value-free private result bound to the plan digest and version. The parent converts that result into the common update result and re-observes the installation; unknown post-mutation progress remains unknown. Parent death terminates the worker, and a timeout stops its owned process group. Setup's retained transition remains the recovery authority after any interruption.

An absent first installation returns `requires_setup` because Dev Auth must not invent administrator policy or enrollment. Strong-mode mutation requires the native installation owner; the public command does not borrow an active administrator grant or silently elevate. `update rollback` calls the same retained full-generation restoration as `setup restore`, including its inactive terminal state and initial-absence case, and never contacts the network. Binary-only setup rollback remains disallowed for a full generation. Linux status/check retain the account-local metadata cache; non-Linux commands return fixed unsupported results until native equivalents are implemented and accepted.

## Boundaries and remaining acceptance

The private update worker is not a general root runner. Its input is one private plan under the selected installation data root, and the existing setup plan, native account, source-document, candidate, ledger and journal checks remain mandatory. The worker's result is observational, not authority to install. Temporary source files are removed after the parent observes the worker; an interrupted parent may leave an owner-only staging directory for later explicit cleanup, but that directory is never adopted as plan authority by a retry.

Source and disposable user-only tests cover accepted-generation source preservation, worker no-op, absent offline payload denial, external installation classification and full-generation initial-absence rollback. These do not prove a signed version-changing apply, strong native approval, interrupted worker recovery, privilege component preservation, or Windows/macOS support. Those are release gates. The common update interface must not be advertised as fully supported before the signed standalone Linux gate passes.
