---
authority: canonical
owner: dev-tools
---

# ADR 0020: Bounded candidate health

status: proposed
verification: pending

## Context

Candidate health accepted a version prefix instead of an exact version boundary: an executable reporting 1.2.30 could satisfy a signed 1.2.3 candidate. The private subprocess implementation waited for process exit before draining pipes, so output could block execution or be collected without a size bound. Killing and reaping only the direct child did not provide the shared foundation's process-domain cleanup.

## Decision

Update All runs candidate health through the existing shared bounded-command foundation with the product's native health arguments, closed standard input, a ten-second deadline and a 4 KiB limit for each output stream. Supported Unix process-domain supervision remains owned by that foundation. The product checks successful exit, valid UTF-8 output and an exact version boundary. The existing optional space-separated build metadata remains readable during the legacy version-output transition; this correction does not claim the complete common one-line version interface.

Timeout and output-limit violations retain the product integrity category. Ordinary execution failures remain operational errors. The original typed command failure, including available cleanup evidence, remains in the error chain without including captured output in diagnostics.

## Invariants

- A different patch, prerelease or build identifier cannot satisfy the expected signed version by sharing its textual prefix.
- Product health uses the exact candidate path and product-owned arguments; remote metadata cannot supply a command or shell program.
- Both captured streams have independent bounds; a successful exit does not bypass those bounds.
- Process supervision is shared rather than implemented by a second private runner.

## Rejected alternatives

Keeping prefix comparison accepts the wrong reported version. Reading output only after waiting for exit permits pipe backpressure to deadlock the candidate. Adding another product-private drainer and process-group supervisor would duplicate a high-risk foundation. Requiring new version-output formatting from retained binaries would conflate this correction with the later common-CLI cutover.

## Consequences and known limitations

Oversized health output and invalid UTF-8 now fail even when a candidate exits successfully. The shared command dependency adds no new third-party package versions. This correction preserves the existing prepared command's environment and working directory; explicit child-context admission and held-executable identity remain gates for the complete adapter. Health output is not independent release authenticity or installed-receipt evidence. Supported Unix cleanup covers the admitted process group, not deliberately detached descendants. Other platforms retain the foundation's documented direct-child and polled-file limitations and require native acceptance before support is claimed.

## Verification

The regressions `candidate_health_rejects_a_version_prefix_match` and `candidate_health_bounds_both_output_streams` failed before the correction; the latter observed accepted oversized stdout on its isolated rerun. `candidate_health_requires_the_signed_version` preserves the existing build-metadata line. `candidate_health_preserves_arguments_status_and_inclusive_limits` covers exact native arguments, closed input, successful inclusive per-stream limits, failed status, malformed text and typed ordinary launch failure. The shared command suite independently covers deadline, overflow and process-domain terminalization.

## Runtime acceptance

Run real source-bound release candidates outside a checkout through installation, repeat operation and retained rollback. Exercise bounded failure and process cleanup on each claimed platform. Qualify the complete common adapter's child context, artifact custody and version-output contract separately before accepting full product conformance.

## Supersession conditions

Supersede this record if candidate health moves to a structured native protocol or a different supervised execution boundary. Preserve exact expected identity, bounded capture, typed failures and explicit native process-ownership limits.
