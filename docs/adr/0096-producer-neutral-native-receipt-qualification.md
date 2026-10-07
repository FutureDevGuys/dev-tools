---
authority: canonical
owner: dev-auth
---

# ADR 0096: Producer-neutral native receipt qualification

status: proposed
verification: pending

## Problem

The optional receipt-install protocol was producer-neutral, but its native acceptance harness decoded a downstream receipt schema, constructed that producer's generation names and hard-coded its installed sidecar. ADR 0095 also described that downstream implementation as the supplied prerequisite. This violated ADR 0006 even without a Cargo path dependency or runtime checkout lookup.

## Decision

Supersede those producer-specific qualification assumptions, preserving the production protocol and its authority boundaries. Fixture v2 takes independently supplied artifact evidence: exact request binding, raw receipt bytes and digest, executable length and digest, tool and binary. Receipt contents remain opaque to Dev Auth. A bounded observation layout supplies receipt filenames and journal JSON pointers inside already approved resource roots. No helper, private schema or producer-specific name is discovered or invoked.

The optional adapter's actual native transaction, interruption/resume, reversal, revocation, hard-expiry and bind-alias cases remain mandatory before claiming adapter compatibility. The ordinary candidate, separately approved executor, original artifact evidence, genuine administrator approval, exact scopes, positive process cleanup and unchanged sentinels remain required. Generic source tests do not count as native acceptance. Private-consumer deployment acceptance is owned by that consumer, never a prerequisite for the public product.

## Migration and verification

Fixture v1 is rejected rather than silently reinterpreted. Regenerate preparation and final inputs using v2; do not reuse v1 approval artifacts. The production v1 request/result protocol and installed Dev Auth remain unchanged. Public synthetic tests cover receipt-digest mismatch, executable bounds, filename traversal, JSON-pointer validation, changed journal receipts and unknown fields. Native v2 runs remain NOT RUN until performed; earlier observations cannot establish their success.
