---
authority: canonical
owner: dev-tools
---

# update-all architecture decisions

Read the applicable records before changing `update-all` configuration,
scheduling, package-manager reconciliation, or run artifacts.

| ADR | Decision | Status | Verification |
| --- | --- | --- | --- |
| [0001](0001-ordering-versus-health-dependencies.md) | Ordering versus health dependencies | accepted | verified |
| [0002](0002-npm-lifecycle-script-attribution-and-recovery.md) | NPM lifecycle-script attribution and recovery | accepted | verified |
| [0003](0003-structured-failure-evidence.md) | Structured failure evidence | accepted | verified |
| [0004](0004-attributable-aur-failure-containment.md) | Attributable AUR failure containment | superseded | pending |
| [0005](0005-verified-repository-retirement.md) | Verified repository-retirement recovery | proposed | pending |
| [0006](0006-product-scoped-authenticated-releases.md) | Product-scoped authenticated releases | superseded | pending |
| [0007](0007-npm-global-mutation-authority.md) | NPM global mutation authority | proposed | pending |
| [0008](0008-shared-release-and-installation-foundations.md) | Shared release and installation foundations | proposed | pending |
| [0009](0009-managed-completion-root.md) | Managed completion publication root and snapshot health | proposed | pending |
| [0010](0010-completion-inventory-and-binding-authority.md) | Completion inventory and binding authority | proposed | pending |
| [0011](0011-native-completion-protocol-and-trust-authority.md) | Native completion protocol and trust authority | proposed | pending |
| [0012](0012-help-derived-completion-ir-and-query-authority.md) | Help-derived completion IR and query authority | proposed | pending |
| [0013](0013-five-shell-immutable-completion-activation.md) | Five-shell immutable completion activation | proposed | pending |
| [0014](0014-bounded-run-retention.md) | Bounded run retention | superseded | pending |
| [0015](0015-bounded-release-state-observation.md) | Bounded release-state observation | proposed | pending |
| [0016](0016-serialized-release-mutation-admission.md) | Serialized release mutation admission | proposed | pending |
| [0017](0017-release-state-writer-custody.md) | Release-state writer custody | proposed | pending |
| [0018](0018-shared-https-admission.md) | Shared HTTPS admission | proposed | pending |
| [0019](0019-url-bound-metadata-cache.md) | URL-bound metadata cache | proposed | pending |
| [0020](0020-bounded-candidate-health.md) | Bounded candidate health | proposed | pending |
| [0021](0021-authenticated-product-state-cutover.md) | Authenticated product-state cutover | proposed | pending |
| [0022](0022-common-local-update-observation.md) | Common local update observation | proposed | pending |
| [0023](0023-common-authenticated-metadata-refresh.md) | Common authenticated metadata refresh | proposed | pending |
| [0024](0024-canonical-release-assets-after-incomplete-index.md) | Canonical assets after an incomplete GitHub release index | proposed | pending |
| [0025](0025-explicit-offline-signed-bundle-intake.md) | Explicit offline signed-bundle intake | proposed | pending |
| [0026](0026-command-output-fidelity-and-bounded-diagnostics.md) | Command output fidelity and bounded diagnostics | proposed | pending |
| [0027](0027-execution-owned-cancellation-outcomes.md) | Execution-owned cancellation outcomes | proposed | pending |
| [0028](0028-task-terminal-sudo-authentication.md) | Task-terminal sudo authentication | superseded | verified |
| [0029](0029-implementation-first-linux-sudo-delivery.md) | Implementation-first Linux sudo delivery | accepted | verified |
| [0030](0030-common-managed-update-lifecycle.md) | Common managed update lifecycle | proposed | pending |
| [0031](0031-nonactivating-authenticated-artifact-retention.md) | Nonactivating authenticated artifact retention | proposed | pending |
| [0032](0032-executing-build-run-provenance.md) | Executing-build run provenance | proposed | pending |
| [0033](0033-mandatory-task-run-evidence-and-shared-scheduling.md) | Mandatory task-run evidence and shared scheduling | proposed | pending |
| [0034](0034-compatible-privilege-fallback-modes.md) | Compatible privilege fallback modes | proposed | pending |
| [0035](0035-owned-dashboard-input-and-bounded-display.md) | Owned dashboard input and bounded display | proposed | pending |
| [0036](0036-opt-in-post-run-restart.md) | Opt-in post-run restart requests | proposed | pending |
| [0037](0037-read-only-damaged-run-inspection.md) | Read-only damaged run inspection | proposed | pending |
| [0038](0038-terminal-reported-storage-exhaustion.md) | Terminal reported storage exhaustion | proposed | pending |
| [0039](0039-preserve-unclassified-npm-directories.md) | Preserve unclassified NPM directories | proposed | pending |

| [0040](0040-truthful-blocked-run-outcomes.md) | Truthful blocked run outcomes | proposed | pending |
| [0041](0041-terminal-reported-npm-authority-failure.md) | Terminal reported NPM authority failure | proposed | pending |
| [0042](0042-explicit-configuration-read-selection.md) | Explicit configuration read selection | proposed | pending |
| [0043](0043-regular-configuration-input-admission.md) | Regular configuration input admission | proposed | pending |
| [0044](0044-preserving-run-artifact-replacement.md) | Preserving run artifact replacement | proposed | pending |
| [0045](0045-truthful-operation-observations.md) | Truthful operation observations | proposed | pending |
| [0046](0046-completion-sync-result-observations.md) | Completion sync result observations | proposed | pending |
| [0047](0047-startup-terminal-sudo-reuse.md) | Original-terminal sudo reuse with captured custom-task results | accepted | verified |

`proposed` plus `verification: pending` means code and automated gates exist,
but the record's runtime acceptance has not passed. `accepted` requires
`verification: verified`. A superseded proposal may remain pending when a later
record replaces it before runtime acceptance. A material change to an accepted
decision requires a new numbered record with `status: superseded` and a link
from the old record to its replacement; accepted records are not silently
rewritten.
