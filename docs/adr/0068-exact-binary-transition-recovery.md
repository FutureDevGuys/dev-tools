---
authority: canonical
owner: dev-tools
---

# ADR 0068: Exact binary-transition recovery

status: proposed
verification: pending

## Decision

The installation foundation provides an additive Linux recovery interface that binds the journal's complete prior receipt, including explicit absence, and complete next receipt in their original roles. Membership in a set of allowed receipts does not authorize an arbitrary transition between those receipts. The existing caller-verification recovery interface remains compatible; both interfaces use one implementation of lock acquisition, receipt/journal agreement, bounded artifact verification, committed settlement, uncommitted prior restoration and durable journal retirement.

Products authenticate the supplied endpoint receipts and own installation layout, ancestor trust, native identity, admission exclusion and service lifecycle. The exact-transition interface checks the journal against those endpoints under the installation lock before invoking the product verifier or changing links. With no journal, only one of the supplied endpoints is admitted; normal verification still rejects incomplete activation rather than repairing it. A same-receipt observation is not a fresh release grant or proof against an intervening change away from and back to those bytes. Lock-file creation and uncertain progress after entered mutation retain the existing API contract.

The corresponding read-only observer uses the same checks through a nonblocking lock on the existing lock file. It never creates that file, restores links, removes a journal or synchronizes storage. Its typed result distinguishes the current receipt from the presence of a pending journal. Observation does not hold a lease across a later operation or guarantee that an uncommitted transition's partial links can be repaired; mutation must revalidate. Committed and settled receipts verify artifact content once alongside their exact links, retaining the same directory-custody and read-bound checks.

Dev Auth initial-generation restoration uses this interface with an absent prior receipt and the retained candidate receipt. Initial absence cannot authorize a journal claiming that the candidate was already installed before that transition, even when every receipt individually names approved bytes. This tightens the binary-journal boundary without changing the surrounding restoration direction or authorizing a new release. Prior-generation restoration and forward installation recovery need their own complete transition selection; this interface alone does not implement either product workflow.

## Evidence and remaining gates

Shared tests cover committed and uncommitted recovery, explicit prior mismatch, reversed endpoint roles, rejection before the verifier, unchanged journal/receipt/active link on rejection and an unchanged settled retry. The Dev Auth initial-restoration fixture exposed acceptance of a noninitial journal whose prior and next both named the approved candidate; the integrated exact-transition call rejects it while preserving the journal. Existing artifact-integrity, legacy-adoption, absent-installation and bounded-read tests remain required.

This is source-level Linux evidence. Signed product integration, process-death and power-loss qualification, full retained forward recovery and other native platform adapters remain separate gates. No dependency, frozen archive or published version identity is replaced.
