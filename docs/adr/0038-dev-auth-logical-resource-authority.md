---
authority: canonical
owner: dev-tools
---

# ADR 0038: Dev Auth logical resource authority

status: proposed
verification: pending

## Context

Existing Dev Auth capabilities select provider references through v2 authority profiles. General credential operations need a common logical-name resolution boundary before GitHub, SSH, signing and exported-secret consumers can share provider implementations without sharing unrestricted credential authority.

## Decision

The credential portion of administrator policy v3 separates named provider instances, credential slots, logical resource bindings and account-scoped resource caps. The initial production provider configuration is a pinned 1Password executable; the consumer boundary uses the product-neutral `SecretProvider` trait. Provider substitution is tested through an independent implementation, not a runtime environment switch or alternate authority source.

A resource binding fixes its credential slot, opaque provider reference, exportability class, permitted purposes and projection rights. Each resource cap selects narrower rights for explicit native accounts. A workload selects a subset of that cap. Resolution validates all declarations, including unused ones, and rejects duplicated rights, missing bindings, account expansion and purpose/projection expansion. Native identity matching is exact at this boundary. Provider-specific account canonicalization, if required on a native platform, belongs before this boundary and must not be inferred by case folding arbitrary caller input.

Operation-only resources cannot carry read or projection rights. Different logical names or credential slots referencing the same literal provider-instance/reference pair cannot disagree on exportability. This check does not infer equivalence between different provider references or across provider instances; the administrator remains responsible for those declarations. Projection rights require read authority, but declaring a projection does not implement or qualify its native custody.

Resolved grants retain references in opaque, non-debuggable, non-serializable typed material. Exported reads check the exact provider instance, selected credential slot, product purpose, provider capabilities and provider metadata before retrieval. Cancellation and the same absolute operation deadline are checked before and after provider stages. Binary material remains zeroizing secret material and is not converted into diagnostic strings. Provider references never become consumer arguments.

## Integration and migration

The component is composed into explicit `dev-auth-administrator-policy-v3` and `dev-auth-user-config-v3` documents under ADR 0039. The running source can resolve existing capability families through the common logical-resource boundary and select the provider by credential slot. This does not make an in-memory grant a native admission token or qualify setup, exported operations or projections. No public CLI operation may accept these in-memory grants as authority. No installed policy is silently upgraded, and automatic admission or administrator privileges are not implied by logical resolution.

## Verification

Component tests resolve generic named resources, reject account and right expansion, preserve operation-only restrictions across literal aliases, and exercise independent-provider binary reads. Negative provider tests cover mismatched instance/slot, provider nonexportability, expiry and cancellation between metadata and retrieval and after retrieval. Full acceptance additionally requires real enrolled 1Password operations through the public CLI, all supported projections and existing capability families, native admission, rotation/revocation and signed standalone migration. Component success is not evidence that these remaining integrations are operational.
