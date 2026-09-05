---
authority: canonical
owner: dev-tools
---

# Dev Tools architecture decisions

Read the applicable records before changing a public product contract or cross-product foundation. The normative current behavior is defined by [the product standard](../product-standard.md).

| ADR | Decision | Status | Verification |
| --- | --- | --- | --- |
| [0001](0001-standalone-products-and-shared-rust-foundations.md) | Standalone products and shared Rust foundations | proposed | pending |
| [0002](0002-common-product-cli-and-explicit-network-boundaries.md) | Common product CLI and explicit network boundaries | proposed | pending |
| [0003](0003-native-release-administration-and-separated-authority.md) | Native release administration and separated authority | proposed | pending |
| [0004](0004-typed-privilege-operations-and-plan-bundles.md) | One-shot authorization and bounded administrator sessions | proposed | pending |
| [0005](0005-rust-operational-language-and-platform-policy.md) | Rust operational language and platform policy | proposed | pending |
| [0006](0006-public-producer-private-consumer-direction.md) | Public producer and private consumer direction | proposed | pending |
| [0007](0007-provider-neutral-secret-operations.md) | Provider-neutral secret operations | proposed | pending |
| [0008](0008-trusted-hook-execution-context.md) | Trusted hook execution context | proposed | pending |
| [0009](0009-smart-workload-continuation-bindings.md) | Smart workload continuation bindings | proposed | pending |

Product-scoped records remain with their product. The existing [Update All ADR series](../../crates/update-all/docs/adr/README.md) remains authoritative for Update All decisions until an applicable record is explicitly superseded.

`proposed` plus `verification: pending` means implementation or acceptance remains incomplete. `accepted` requires `verification: verified`. A material change to an accepted decision requires a new numbered record and a replacement link; accepted decisions are not silently rewritten.
