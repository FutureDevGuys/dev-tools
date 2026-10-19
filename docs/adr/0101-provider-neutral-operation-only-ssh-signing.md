---
authority: canonical
owner: dev-auth
---

# ADR 0101: Provider-neutral operation-only signing

status: proposed
verification: pending

## Decision

Dev Auth's Linux broker invokes SSH and release-manifest signing through the focused `SecretProvider::sign` operation rather than 1Password-specific signing paths. The selected administrator policy and admitted workload still bind the credential slot, opaque reference, key purpose, fingerprint or release public key, and allowed release products before provider use. The provider returns only a bounded signature; the broker verifies it over the exact requested payload against the declared public identity before any response. A provider that signs with a different key or returns malformed bytes is denied. Public signing frontends cannot select a provider reference or export a private key.

The 1Password adapter reads the declared private key into zeroizing process memory, parses supported native SSH or raw Ed25519 release-key material, signs within the operation deadline, and drops the material. Its `SecretProvider` capabilities and metadata advertise signing; this is an adapter capability, not a grant to sign arbitrary references. Logical operation-only policy and the broker's session grant remain the authority. Release-manifest signing retains its distinct raw 64-byte signature format and product-scoped verification; an SSH-format signature cannot substitute for it. The adapter's internal read is not a caller-facing exportable-resource operation.

## Verification and remaining gates

Source tests exercise an independent fake provider that refuses export and public-material reads but signs the declared SSH payload through the same broker verification helper. Separate source tests exercise provider-backed raw Ed25519 release signing, wrong-key denial, and the distinct SSH format. A synthetic installed user-only workload exercises both SSH and release-manifest signing through the 1Password-shaped adapter, verifies both signatures against declared public keys, and denies key export. Real 1Password, installed strong-mode, WSL, Windows, macOS and signed-distribution acceptance remain open; a trait implementation alone is not native support.
