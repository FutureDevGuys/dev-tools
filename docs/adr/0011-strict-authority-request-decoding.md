---
authority: canonical
owner: dev-tools
---

# ADR 0011: Strict authority-request decoding

status: proposed
verification: pending

## Context

The product standard requires authority-bearing documents to reject unknown fields. Enum-level Serde strictness does not apply to internally tagged unit variants: their default visitor discards the remaining map. Separately, Dev Auth's broker and control request enums did not deny unknown fields even though their envelopes did. This allowed undeclared request options or apparent scope restrictions to disappear before validation. Existing server-side session grants still bound available authority; this is not evidence that ignored fields could enlarge a grant.

## Decision

Dev Auth broker and control request variants reject undeclared fields during frame decoding, before session mutation or capability dispatch. Unit requests (`probe` and `gh_execution_token`) use a private empty-struct deserializer because enum-level strictness alone is insufficient. The smart-binding continuation target uses the same product-private mechanism. Artifact Update's version-rule unit variants and check-only verification use an equivalent private decoder within their owning configuration module.

Public Rust unit variants, valid request serialization, frame limits, request identifiers, operation validation, and protocol version 2 remain unchanged. Previously ignored fields are invalid input, not extension negotiation: a future request capability needs an explicit schema and applicable protocol-version decision. Response DTO behavior is unchanged; this decision does not impose request strictness on observational result evolution. Parsing errors remain closed by the broker connection boundary without reflecting input or parser details to a peer.

This correction does not add a generic export operation, change provider scope, weaken native peer admission, or make the incomplete smart-binding foundation a live execution interface. Binding receipts still require their separate structural, identity and custody checks. Updated source must pass the normal signed release and native acceptance gates before installed-product behavior is claimed.

## Verification

Public decoder tests round-trip valid typed request bytes and reject unknown options inside broker and control requests. Continuation-target tests preserve the public unit value and canonical JSON while rejecting extra execution constraints. Artifact configuration tests cover unit and data-bearing rules, and the configuration-editing CLI proves invalid proposals leave existing bytes unchanged. Focused tests, strict lints, the workspace suite and target checks guard integration; native protocol and release acceptance remain required.
