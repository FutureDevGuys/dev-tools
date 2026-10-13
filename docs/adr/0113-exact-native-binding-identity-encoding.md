---
authority: canonical
owner: dev-auth
---

# ADR 0113: Exact native binding identity encoding

status: proposed
verification: pending

## Context

The source-only smart binding foundation in [ADR 0009](0009-smart-workload-continuation-bindings.md) and [ADR 0017](0017-binding-target-specific-resolution.md) stores native executable device and inode identities as `Option<u64>`. Encoding them as JSON numbers lets JCS canonicalization round values above the exact IEEE-754 integer range. TOML's signed integer `Value` boundary also cannot represent every native `u64`. Neither representation may change the executable identity being pinned or hashed. Current source has no binding TOML writer; the TOML regression protects the public identity type's serialization boundary.

This v2 foundation remains an unintegrated draft: it has no installed workload bindings and does not activate proxies, participate in setup, or admit workloads. The encoding correction therefore regenerates draft evidence rather than migrating an accepted installed receipt format.

## Decision

Only `ExecutableIdentity.device` and `ExecutableIdentity.inode` serialize present values as exact canonical unsigned decimal strings in JSON, JCS and TOML. Their grammar is `0|[1-9][0-9]*`, with a maximum value of `18446744073709551615`. Absent values remain omitted; absent or JSON null values decode as `None`. The Rust fields remain `Option<u64>`. Length, mode, owner, group, generation, action order and search cursor retain their existing numeric representations.

Readers accept legacy nonnegative integral values when the input format can represent them exactly within `u64`. JSON integer tokens can cover the full unsigned range; TOML `Value` integer inputs cover its signed range. Floating-point inputs, including integral-looking floats and exponent forms, are rejected. String inputs reject signs, whitespace, non-ASCII digits, leading zeros, malformed values and overflow. Decoding an integral value provides no executable authority: existing native identity comparisons remain exact, and rounded or otherwise mismatched evidence must never be accepted as the current native identity.

## Draft regeneration and compatibility

The plan and receipt schemas remain v2 because this is a correction to the unintegrated foundation. Canonical receipt and plan bytes change wherever a native identity is present. Every affected earlier draft plan must be rebuilt from current native inspection and receive a new approval digest. Plans embedding a predecessor receipt must also regenerate `current_receipt_sha256` using the corrected receipt encoding; retaining the old numeric predecessor hash fails canonical plan validation. Editing representations while preserving old approval or predecessor digests is insufficient.

No installed setup receipt, enrollment, release ledger or active workload binding is migrated. Legacy integral decoding does not restore old approval digests, infer lost identity bits, or accept relabeled v1 documents. No published binary or accepted version is reissued. Setup integration, proxy activation, admission, privilege models and native launch acceptance remain separate requirements under ADR 0009 and ADR 0017.

## Verification and remaining acceptance

The existing `smart_bindings` integration suite exercises JSON and JCS round-trips at `2^53 + 1` and `u64::MAX`, TOML round-trips beyond its signed integer range, exact legacy integral decoding and string re-emission, absent identity preservation, unchanged other numeric fields, malformed and floating-point rejection, and rejection of old numeric predecessor hashes. These source-level serialization regressions do not establish installed binding, native activation or cross-platform runtime support.
