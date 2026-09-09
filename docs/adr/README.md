---
authority: canonical
owner: dev-tools
---

# Dev Tools architecture decisions

Read the applicable records before changing a public product contract or cross-product foundation. The normative current behavior is defined by [the product standard](../product-standard.md).

| ADR | Decision | Status | Verification |
| --- | --- | --- | --- |
| [0001](0001-standalone-products-and-shared-rust-foundations.md) | Standalone products and shared Rust foundations | proposed | pending |
| [0002](0002-common-product-cli-and-explicit-network-boundaries.md) | Common product CLI and explicit network boundaries | proposed | pending |
| [0003](0003-native-release-administration-and-separated-authority.md) | Native release administration and separated authority | proposed | pending |
| [0004](0004-typed-privilege-operations-and-plan-bundles.md) | One-shot authorization and bounded administrator sessions | proposed | pending |
| [0005](0005-rust-operational-language-and-platform-policy.md) | Rust operational language and platform policy | proposed | pending |
| [0006](0006-public-producer-private-consumer-direction.md) | Public producer and private consumer direction | proposed | pending |
| [0007](0007-provider-neutral-secret-operations.md) | Provider-neutral secret operations | proposed | pending |
| [0008](0008-trusted-hook-execution-context.md) | Trusted hook execution context | proposed | pending |
| [0009](0009-smart-workload-continuation-bindings.md) | Smart workload continuation bindings | proposed | pending |
| [0010](0010-cancellable-public-command-input.md) | Cancellable public command input | proposed | pending |
| [0011](0011-strict-authority-request-decoding.md) | Strict authority-request decoding | proposed | pending |
| [0012](0012-static-product-completion-rendering.md) | Static product completion rendering | proposed | pending |
| [0013](0013-compiler-intercept-maintenance-boundary.md) | Compiler intercept maintenance boundary | proposed | pending |
| [0014](0014-skills-sync-explicit-repair-transition.md) | Skills Sync explicit repair transition | proposed | pending |
| [0015](0015-dev-cache-read-only-root-observation.md) | Dev Cache read-only root observation | proposed | pending |
| [0016](0016-artifact-update-common-doctor-result.md) | Artifact Update common doctor result | proposed | pending |
| [0017](0017-binding-target-specific-resolution.md) | Binding target-specific resolution | proposed | pending |
| [0018](0018-journal-owned-initial-directory-publication.md) | Journal-owned initial-directory publication | proposed | pending |
| [0019](0019-truthful-common-update-mutation-results.md) | Truthful common update mutation results | proposed | pending |
| [0020](0020-separate-update-artifact-preparation.md) | Separate update artifact preparation | proposed | pending |
| [0021](0021-linux-atomic-document-durability.md) | Linux atomic-document durability | proposed | pending |
| [0022](0022-linux-public-regular-file-stdout.md) | Linux public regular-file stdout | proposed | pending |
| [0023](0023-explicit-installation-protocol-cutover.md) | Explicit installation-protocol cutover | proposed | pending |
| [0024](0024-linux-atomic-document-retirement.md) | Linux atomic-document retirement | proposed | pending |
| [0025](0025-product-authority-ledger-import.md) | Product-authority ledger import | proposed | pending |
| [0026](0026-local-update-mutation-preparation.md) | Local update mutation preparation | proposed | pending |
| [0027](0027-read-only-cutover-observations.md) | Read-only cutover observations | proposed | pending |
| [0028](0028-conditional-absent-installation-cutover.md) | Conditional absent-installation cutover | proposed | pending |
| [0030](0030-published-authority-upgrade-recovery.md) | Published-authority upgrade recovery | proposed | pending |
| [0032](0032-conditional-legacy-installation-cutover.md) | Conditional legacy-installation cutover | proposed | pending |
| [0033](0033-read-only-legacy-adoption-preflight.md) | Read-only legacy-adoption preflight | proposed | pending |
| [0034](0034-journaled-receiptless-protocol-adoption.md) | Journaled receipt-less protocol adoption | proposed | pending |
| [0037](0037-dev-auth-local-doctor-and-explicit-execution-results.md) | Dev Auth local doctor and explicit execution results | proposed | pending |
| [0038](0038-dev-auth-logical-resource-authority.md) | Dev Auth logical resource authority | proposed | pending |
| [0039](0039-dev-auth-versioned-workload-authority.md) | Dev Auth explicit v3 workload authority and native adaptation | proposed | pending |
| [0040](0040-dev-auth-logical-delivery-and-native-projections.md) | Dev Auth logical delivery and native child projections | proposed | pending |
| [0041](0041-dev-auth-enrollment-authorized-native-launch.md) | Dev Auth enrollment-authorized native workload launch | proposed | pending |
| [0042](0042-dev-auth-versioned-setup-authority.md) | Dev Auth schema-bound setup authority and destinations | proposed | pending |
| [0043](0043-dev-auth-setup-admission-exclusion.md) | Dev Auth setup admission exclusion and durable activation state | proposed | pending |
| [0044](0044-dev-auth-installed-candidate-recovery.md) | Dev Auth recovery from retained approval and installed candidate | proposed | pending |
| [0045](0045-dev-auth-legacy-rollback-exclusion.md) | Dev Auth native maintenance exclusion and full-generation protection | proposed | pending |
| [0046](0046-dev-auth-retiring-account-generation.md) | Dev Auth retiring-account inventory, retention and deactivation | proposed | pending |
| [0047](0047-identity-bound-document-removal.md) | Identity-bound Linux document removal and durable absence | proposed | pending |
| [0048](0048-dev-auth-restoration-direction-state.md) | Dev Auth durable restoration direction and inactive terminal state | proposed | pending |
| [0049](0049-dev-auth-user-generation-restoration.md) | Dev Auth retained user-generation restoration | proposed | pending |
| [0050](0050-dev-auth-integration-retirement-durability.md) | Dev Auth durable integration retirement ownership ordering | proposed | pending |
| [0051](0051-retained-activation-withdrawal.md) | Retained installation activation withdrawal | proposed | pending |
| [0052](0052-dev-auth-initial-installation-restoration.md) | Dev Auth initial user-installation absence restoration | proposed | pending |
| [0053](0053-existing-document-directory-authority.md) | Descriptor-bound documents in an existing directory | proposed | pending |
| [0054](0054-retained-privileged-launcher-restoration.md) | Dev Auth retained privileged launcher restoration | proposed | pending |
| [0055](0055-retained-setup-helper-restoration.md) | Dev Auth retained setup helper restoration | proposed | pending |
| [0056](0056-retained-strong-generation-documents.md) | Dev Auth retained strong-generation documents | proposed | pending |
| [0057](0057-retained-native-service-shutdown.md) | Dev Auth retained native service shutdown | proposed | pending |
| [0058](0058-existing-directory-symbolic-link-retirement.md) | Descriptor-bound symbolic-link retirement | proposed | pending |
| [0059](0059-retained-user-integration-retirement.md) | Dev Auth generation-bound user integration retirement | proposed | pending |
| [0060](0060-retained-forward-integration-retirement.md) | Retained integration retirement in forward setup | proposed | pending |
| [0061](0061-native-owner-workload-link-publication.md) | Native ownership of root-published workload links | proposed | pending |
| [0062](0062-explicit-symbolic-link-owner-authority.md) | Explicit symbolic-link owner authority | proposed | pending |
| [0063](0063-retained-legacy-workload-link-ownership.md) | Dev Auth retained legacy workload-link ownership | proposed | pending |
| [0064](0064-initial-strong-generation-withdrawal.md) | Dev Auth initial strong-generation withdrawal | proposed | pending |
| [0065](0065-prompt-free-user-enrollment-read.md) | Dev Auth prompt-free user enrollment reads | proposed | pending |
| [0066](0066-component-validation-and-admitted-provider-observation.md) | Dev Auth component validation and admitted provider observation | proposed | pending |
| [0067](0067-product-validation-of-retained-executables.md) | Product validation of retained executables | proposed | pending |
| [0068](0068-exact-binary-transition-recovery.md) | Exact binary-transition recovery | proposed | pending |
| [0069](0069-dev-auth-committed-binary-journal-settlement.md) | Dev Auth committed binary-journal settlement | proposed | pending |
| [0070](0070-bounded-open-artifact-observation.md) | Bounded open-artifact observation | proposed | pending |
| [0071](0071-fixed-setup-artifact-authority.md) | Fixed setup artifact authority | proposed | pending |
| [0072](0072-initial-product-receipt-recovery.md) | Dev Auth initial product receipt recovery | proposed | pending |
| [0073](0073-initial-staged-binary-forward-recovery.md) | Dev Auth initial staged-binary forward recovery | proposed | pending |
| [0074](0074-committed-upgrade-product-receipt-recovery.md) | Dev Auth committed upgrade product receipt recovery | proposed | pending |
| [0075](0075-staged-user-upgrade-forward-recovery.md) | Dev Auth staged user-only upgrade forward recovery | proposed | pending |
| [0076](0076-unstaged-user-upgrade-forward-recovery.md) | Dev Auth unstaged user-only upgrade forward recovery | proposed | pending |
| [0077](0077-unstaged-initial-user-installation-recovery.md) | Dev Auth unstaged initial user-only installation recovery | proposed | pending |
| [0078](0078-complete-strong-candidate-receipt-recovery.md) | Dev Auth complete strong-candidate receipt recovery | proposed | pending |
| [0079](0079-retained-strong-helper-completion.md) | Dev Auth retained strong helper completion | proposed | pending |
| [0080](0080-retained-strong-system-definition-completion.md) | Dev Auth retained strong system-definition completion | proposed | pending |
| [0081](0081-retained-strong-launcher-completion.md) | Dev Auth retained strong launcher completion | proposed | pending |
| [0082](0082-retained-strong-binary-forward-recovery.md) | Dev Auth retained strong binary forward recovery | proposed | pending |
| [0083](0083-conditional-document-directory-preparation.md) | Conditional document-directory preparation | proposed | pending |
| [0084](0084-native-setup-exclusion-across-broker-and-maintenance.md) | Native setup exclusion across broker and maintenance | proposed | pending |
| [0085](0085-linux-workload-lifecycle-and-public-restoration.md) | Linux workload lifecycle and public restoration | proposed | pending |

Product-scoped records remain with their product. The existing [Update All ADR series](../../crates/update-all/docs/adr/README.md) remains authoritative for Update All decisions until an applicable record is explicitly superseded.

`proposed` plus `verification: pending` means implementation or acceptance remains incomplete. `accepted` requires `verification: verified`. A material change to an accepted decision requires a new numbered record and a replacement link; accepted decisions are not silently rewritten.
