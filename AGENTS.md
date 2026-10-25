# Mission

Preserve the standalone Dev Tools product contract and keep reusable behavior in focused, product-neutral Rust foundations.

# Read First

Before changing a public product contract or cross-product behavior, read `docs/product-standard.md`, `docs/adr/README.md`, and every applicable repository or product ADR.

# Boundaries

Public products SHALL build, test, release, install, and operate without another Dev Tools product, a source checkout, an interpreter, or a private downstream repository.

Each product SHALL run from explicit configuration or command-line options alone, SHALL provide a command that writes its default configuration, and SHALL assume no particular host, account, path, or distribution beyond its documented platform support.

Products and their consumers SHALL interact only through released executables and documented CLI, protocol, and file contracts.

Dev Tools SHALL NOT read, invoke, import, discover, test against, document as required, or otherwise depend on private downstream consumer code, policy, manifests, state, or paths.

Reusable mechanisms SHALL live in focused shared crates with typed product-owned inputs, and each mechanism SHALL have one implementation that every product needing it compiles in. Shared crates SHALL NOT acquire product policy, product-name branches, or a broad catch-all ownership surface.

Public CLI, protocol, release, installation, or privilege contract changes SHALL update the applicable conformance tests and SHALL record a material architectural change in a new or superseding ADR.

# Verification

Verify a change by running the product the way its users will, then the tests that cover it. A target build does not establish platform support; advertise a platform only after the product standard's native acceptance passes on it.

Tests SHALL create the files, environment, and fake providers they need in private temporary locations, and SHALL pass unchanged on any supported host, independent of the developer's home directory, accounts, installed tools, credentials, network, and root access.

# Work State

Keep the work state in `context/state.md`: each unfinished item or active risk in a line or two, naming what remains, where its work lives (branch, pull request), and what it waits on. Remove resolved items.
