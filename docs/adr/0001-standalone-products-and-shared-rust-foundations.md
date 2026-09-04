---
authority: canonical
owner: dev-tools
---

# ADR 0001: Standalone products and shared Rust foundations

status: proposed
verification: pending

## Context

Dev Tools products are released independently. Requiring one product to invoke another or copying release, installation, process, and protocol logic across binaries would make standalone distribution unreliable and create multiple security authorities.

## Decision

Every public product is independently downloadable and operational. Reusable semantics live in focused product-neutral Rust crates and are compiled into each consumer. Products own their policy, layout, lifecycle, presentation, and authorization through typed inputs. Shared crates contain no product-name branches, and the workspace does not create a broad catch-all core crate.

## Invariants

- A public product has no runtime dependency on a sibling product or source checkout.
- Shared mechanisms do not acquire product policy.
- Released binaries contain the shared implementation they use.
- A shared primitive has one authoritative implementation and adversarial contract suite.

## Consequences

Individual binaries may be larger than thin wrappers, while runtime setup becomes smaller and deterministic. Cargo features and release optimization keep unused shared functionality out of a product artifact.

## Verification

The conformance suite runs each product with sibling products and source checkouts absent. Cargo dependency checks reject product-to-product edges and product-name branches in shared foundations. Focused shared-crate suites cover every public primitive.

## Runtime acceptance

Install and exercise each public product from its release artifact on a clean Linux environment with no repository checkout or other Dev Tools executable present. Other platforms require separate native acceptance.
