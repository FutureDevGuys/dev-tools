---
authority: canonical
owner: dev-auth
---

# ADR 0071: Fixed setup artifact authority

status: proposed
verification: pending

## Decision

The product installation entry point receives a fixed artifact length and digest from its caller. Approved-plan application supplies the original plan identity, repair supplies the installation receipt's identity, and the explicitly unsigned direct-install interface selects its source identity once. Subsequent measurements can reject changed source bytes but cannot replace that authority. Any authenticated-release identity must agree with it. The shared executable publication request uses this same identity and verifies the copied or existing versioned bytes before activation. The product's post-publication observation must also agree before it can construct a receipt or install privileged integration assets.

Previously, an outer plan check was followed by a lower-level source measurement whose new digest became publication authority. A source replacement between those checks could therefore change the installed bytes without changing the approved plan. Keeping the selected identity across that boundary closes this gap without requiring an immutable source pathname or another approval. It does not change source ownership policy, authenticate unsigned input or replace normal release verification.

## Verification

A product regression test replaces the source with equal-length different bytes after the caller's identity observation and requires lower-level rejection before creating installation directories. Repair of changed receipted bytes must preserve the receipt and leave a missing launcher absent. Shared publication tests retain changed-source, exact-length and approved-digest checks. Signed native migration and recovery remain separate release acceptance requirements.
