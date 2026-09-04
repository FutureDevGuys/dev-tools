# Mission

Preserve the standalone Dev Tools product contract and keep reusable behavior in focused, product-neutral Rust foundations.

# Read First

Before changing a public product contract or cross-product behavior, read `docs/product-standard.md`, `docs/adr/README.md`, and every applicable repository or product ADR.

# Boundaries

Public products SHALL build, test, release, install, and operate without another Dev Tools product, a source checkout, an interpreter, or a private downstream repository.

Dev Tools SHALL NOT read, invoke, import, discover, test against, document as required, or otherwise depend on private downstream consumer code, policy, manifests, state, or paths.

Reusable mechanisms SHALL live in focused shared crates with typed product-owned inputs. Shared crates SHALL NOT acquire product policy, product-name branches, or a broad catch-all ownership surface.

Public CLI, protocol, release, installation, or privilege contract changes SHALL update the applicable conformance tests and SHALL record a material architectural change in a new or superseding ADR.

# Verification

Keep each integration slice independently buildable and testable. A target build does not establish runtime support; claim support only after the native acceptance required by the product standard and applicable ADR passes.
