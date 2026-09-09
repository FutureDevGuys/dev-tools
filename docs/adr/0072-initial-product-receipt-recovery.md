---
authority: canonical
owner: dev-auth
---

# ADR 0072: Initial product receipt recovery

status: proposed
verification: pending

## Decision

[ADR 0078](0078-complete-strong-candidate-receipt-recovery.md) additionally permits completing the initial strong product receipt only after the shared candidate and every fixed privileged asset verify and native services are quiescent.

[ADR 0074](0074-committed-upgrade-product-receipt-recovery.md) separately permits completion of a committed user-only upgrade when the current product receipt still exactly represents its retained inactive prior release; missing upgrade receipts remain outside that path.

[ADR 0073](0073-initial-staged-binary-forward-recovery.md) extends this decision for an exact staged initial user-only candidate before shared receipt commit, including resumption after prior absence is restored.

Linux setup recovery can complete a missing Dev Auth product receipt for an already committed first user-only binary installation. This narrowly extends ADRs 0044 and 0069: the retained generation must establish paired prior product/shared receipt absence, the exact approved candidate must already be committed in the shared installation, and the current product receipt must be absent. Strong installations, upgrades with missing receipts and uncommitted shared binary state remain outside this case.

Ordinary installation and retained recovery use one pure product receipt constructor driven by the selected request, artifact identity, authenticated provenance when present, and retained history. Construction performs no authentication or publication. Recovery validates that prospective receipt against the actual executable, aliases, layout and native programs, then uses the exact shared-transition observer. It still requires the matching private retained plan and documents, installation owner, exclusive setup lease, exact running candidate bytes and pending forward direction. An accepted generation cannot replay this completion, and original source/configuration files are unnecessary.

After full admission, recovery rechecks product receipt absence and the committed shared candidate under the installation lock. It can settle only the exact approved committed journal. Product receipt publication uses the shared bounded, owner-mode-checked atomic-document primitive with absent-current authority and no-clobber publication. A late different product receipt is preserved. The complete installation is verified before ordinary configuration/enrollment continuation; missing credentials keep admission closed and return promptly.

Successful receipt completion contributes `complete_initial_binary_receipt` to the existing recovery action list. Established journal settlement or receipt publication is recorded before later operations, so a subsequent failure does not erase known change. This operation does not copy or install executable bytes, obtain a fresh release grant, recover an uncommitted binary journal or alter native approval policy. Existing writer-serialization requirements remain; observation is not a lease against an independently authorized legacy writer.

## Verification and remaining gates

Source tests exercise committed shared state with and without a journal, removal of original executable input, exact product receipt content/mode, unchanged retry, uncommitted rejection and a late unknown receipt collision. A separate disposable native-user public-CLI fixture covers missing original sources, accepted-generation replay rejection, pending receipt completion, missing enrollment and unchanged retry without activation. These fixtures reconstruct the interruption state; they are not process-death or power-loss evidence. Signed strong migration, pre-commit binary interruption, prior-generation receipt completion and full writer coordination remain delivery gates.
