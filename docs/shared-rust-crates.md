# Shared Rust crates

Dev Tools exposes narrowly scoped Rust foundations for products and downstream consumers. Each crate is independently versioned and publishable to crates.io; a released product compiles the required implementation into its own binary and has no runtime dependency on another Dev Tools product.

The public package set is `dev-tools-command`, `dev-tools-product`, `dev-tools-installation`, `dev-tools-privilege`, `dev-tools-reconcile-protocol`, `dev-tools-release`, and `dev-tools-update`. Their initial public API line is `0.1.x`. Within this workspace, internal dependencies use both a local path and a compatible SemVer requirement. Outside the workspace, consumers use only the registry version and commit its registry checksum in `Cargo.lock`.

Package readiness is distinct from registry publication. The repository does not yet implement the authenticated crates.io publication and source-provenance verification path, so downstream production cutover remains blocked. A downstream must not substitute a Git revision or neighboring checkout while waiting. Cutover requires the exact registry version, its lockfile checksum, and separately authenticated evidence binding the uploaded crate bytes to the reviewed source.
