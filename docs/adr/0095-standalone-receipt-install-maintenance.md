---
authority: canonical
owner: dev-auth
---

# ADR 0095: Standalone receipt-bound maintenance adapter

status: proposed
verification: pending

Producer-specific qualification details are superseded by [ADR 0096](0096-producer-neutral-native-receipt-qualification.md).

## Decision

ADR0094's reusable lifecycle gains one production effect definition: `dev-tools-receipt-install-v1`. Its [closed public contract](../dev-tools-receipt-install-v1.md) fixes a standalone native entrypoint, sealed canonical request, independently pinned root deployment evidence, exact derived resources and bounded result protocol. No generic executable protocol is admitted. The fixture protocol remains absent from ordinary builds.

The supplied implementation is a standalone artifact of the existing Syscfg receipt/journal installer. Dev Auth depends only on the optional protocol role and independently root-custodied artifact. It does not locate a Syscfg product, source checkout or user installation; no sibling runtime is required. The existing installer owns receipt authority, guarded publication, unknown occupants, partial hardlink recovery and journal-bound resume. This avoids inventing a parallel installer.

One explicit administrator grant can run separately invoked status/install/replacement/resume/reverse-replacement plans, with the same operation/resource audience, conserved budgets, hard/idle expiry, kernel peers and positive descendant cleanup as ADR0094. Fixed dedicated system targets exclude the live adapter, Dev Auth enforcement and host execution hooks, including physical bind aliases. No payload execution, special-bit/file-capability publication, global command alias, service control or network effect is admitted.

## Bootstrap and exclusion

An administrator must independently approve the executor's artifact/source/build identity and deploy its exact root-owned image and canonical deployment record. The record is not a signature or authority derived from the installed candidate. Candidate/predecessor generation digests and source bindings likewise come from independent approved evidence. No grant, policy, root custody or signing authority is manufactured by source tests or the fixture preparer.

The grant retains shared Dev Auth setup exclusion. The receipt installer has a separate journal lock in its dedicated namespace, so its maintenance does not mutate the held setup generation. Dev Auth self-upgrade and live adapter/policy replacement remain out-of-session normal setup operations. Public Update All invoking-user installation is not relabeled as privileged maintenance.

## Verification gate

Conformance tests enforce the closed protocol in ordinary product builds, exact provenance/scope, canonical producer/consumer vectors, result-status failure, read-only status and alias comparison. Syscfg separately tests real fresh/repeated/replacement/reverse publication, independently bound resume and actual existing hardlink recovery.

The runnable real native matrix uses a normal candidate binary and the authentic standalone installer, independently prepared root generations and real administrator approval. It covers reuse/no-op/replacement/interrupted-resume/reverse replacement, revocation and hard expiry during a stopped real transaction, and protected bind-alias denial. Positive held-cgroup cleanup, exact installed bytes/receipt/modes, unchanged sentinels and setup exclusion are required. A missed fault window fails; it is not treated as acceptance. These native cases, ADR0094's27-case containment matrix and signed setup/restoration remain NOT RUN by source validation. No deployed maintenance support is claimed until they pass.
