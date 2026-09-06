---
authority: canonical
owner: dev-tools
---

# ADR 0018: Shared HTTPS admission

status: proposed
verification: pending

## Context

The legacy release transport followed redirects automatically and checked host history afterward. It also contacted an initial unapproved HTTPS origin before rejecting its response. A final signature check cannot undo unintended network contact.

## Decision

Update All uses the shared release foundation's conditional HTTPS transport with its existing five GitHub release hosts, three-redirect bound, 30-second deadline and product user-agent. The shared transport validates each initial or redirected URL before contact, strips conditional validators on redirect and rejects unsolicited or redirected not-modified responses. It retains the established GitHub JSON versus artifact byte representation headers and enforces inclusive bounded nonempty bodies. Update All no longer owns a direct HTTP-client dependency or automatic-redirect implementation.

The shared foundation exposes a value-free admission-error marker so Update All can retain its integrity/authority failure category without parsing diagnostic strings. Ordinary transport failures remain operational errors. The product converts the typed not-modified response to a private typed cache outcome; text containing similar words is not a cache-hit signal.

## Invariants

- Remote metadata cannot extend the product-owned allowed-host set.
- A denied initial origin or redirect is rejected before contact, not after response receipt.
- Release authentication, accepted history and installation authority remain independent of HTTP success or validators.
- A legacy cache hit does not establish the complete common adapter's authenticated freshness and URL-bound custody contract.

## Rejected alternatives

Retaining post-contact redirect validation preserves unintended egress. Copying the shared redirect loop into Update All would recreate two transport authorities. Treating every shared failure as an integrity violation would misclassify ordinary network outages, while matching error text would make the cache or exit contract depend on presentation.

## Consequences and known limitations

Malformed, credential-bearing, fragmented and off-policy URLs fail earlier. Successful retrieval requires HTTP 200 rather than accepting arbitrary successful status codes; unsolicited partial responses cannot become complete metadata. Existing cache filenames, legacy metadata readers and release-state JSON remain unchanged. The remaining cache path still needs bounded, URL-bound observation and ownership-safe publication before common-adapter or offline freshness acceptance. Product release acceptance must include real signed online discovery and installation through this source generation. No published archive is replaced by this source change.

## Verification

The regression `release_https_rejects_unapproved_origin_before_connecting` first failed against the old code: an isolated process connected to the fixture's unapproved loopback listener before rejection. The corrected path rejects with the integrity category and leaves the listener without a connection. `release_https_response_preserves_bytes_and_typed_cache_outcome` covers the product response mapping. Shared-foundation tests independently cover off-policy redirect non-contact, relative resolution, deadlines, representation headers, inclusive byte bounds, validator scoping and typed value-free admission failures.

## Runtime acceptance

Run the source-bound standalone binary through real signed release discovery, first installation and a repeat check outside a checkout. Exercise redirects and cache responses without broadening the host policy. Qualify platform-native HTTPS behavior on each advertised platform before accepting this record.

## Supersession conditions

Supersede this record when product release locations or the shared transport contract changes. Preserve pre-contact authority admission and the distinction between transport observation, release authentication and installation authority.
