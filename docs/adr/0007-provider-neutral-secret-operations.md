---
authority: canonical
owner: dev-tools
---

# ADR 0007: Provider-neutral secret operations

status: proposed
verification: pending

## Context

Standalone products need exportable secrets, public key material, and operation-only signing without making any one provider, credential format, policy model, or product the shared authority. Returning provider-native references or secret values through diagnostics, serialized plans, or general-purpose command configuration would make safe composition and future provider adoption brittle.

## Decision

`dev-tools-secret` defines opaque provider identifiers and references, logical secret names, purposes, capability discovery, one absolute deadline and cancellation context, zeroizing secret material, public material, signatures, and value-free error categories. A `SecretProvider` implementation exposes health, metadata, explicitly exportable reads, public material, and signing through those types.

Provider adapters own provider authentication and protocol behavior. Products own authorization policy, logical-name resolution, audit policy, user interfaces, and any projection into a child process. The shared crate performs no ambient credential discovery, logging, serialization of secret material, product-specific branching, or provider-specific interpretation.

Exportable reads and operation-only authority are distinct capabilities. A provider may return an explicitly exportable value to a trusted product, return public material, or perform a cryptographic operation without exposing the private key. Products must reject an operation that policy or provider capabilities do not authorize.

Dev Auth administrator policy binds logical names to provider authentication slots, opaque references, purposes, native users, profiles, and projection rights. User configuration can only narrow these bindings. `secret read` deliberately exports only an authorized exportable value to the selected output; `secret public` returns public material; `secret exec` projects approved values into a retained child through stdin, descriptors or handles, private ephemeral files, or an explicitly permitted environment overlay. Projection lifecycle, cancellation, and cleanup are owned by the product, not by provider output or caller-supplied shell text. Operation-only GitHub App, host-authentication, SSH-signing, and release-signing private keys cannot be selected for export or projection.

## Invariants

- Secret material is bounded, non-cloneable, non-debuggable, non-serializable, and zeroized on drop.
- Provider-native references are opaque outside the trusted adapter boundary and never appear in shared diagnostics.
- One trusted adapter operation retains one process-local absolute deadline and cancellation signal across every provider stage; a stage does not reset the authority window. The context is not serialized or delegated as authority. When an adapter uses a child process, the parent derives its bounded child timeout from the remaining absolute budget, retains cancellation, and owns terminalization.
- Shared errors communicate only a fixed category. Provider output and secret-bearing context do not become diagnostics.
- Secret literals never enter CLI arguments, authority documents, plans, receipts, or diagnostics. An explicitly permitted environment projection is confined to its approved child and is documented as observable within the relevant native trust boundary; it is not an ambient authentication source.
- A product may compile an adapter into its standalone binary, but no product invokes another product to access a secret provider.

## Verification

Contract tests cover identifier and reference bounds, compile-time diagnostic opacity, material zeroization, capability separation, cancellation, and deadline expiry. Product acceptance additionally uses provider-neutral fakes and the product's real adapters while proving that secret values do not enter argv, ambient environment, plans, receipts, logs, diagnostics, or process-visible command lines.

## Runtime acceptance

An adapter and projection mode are accepted independently. Dev Auth's first adapter is 1Password with its enrolled service-account token confined to the broker and sealed provider-child transport. Other providers and platform-native secret stores remain unsupported until their own protocol, custody, cancellation, and live-operation acceptance pass.
