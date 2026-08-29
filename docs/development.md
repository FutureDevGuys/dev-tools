# Development and validation

Rust validation uses formatting, Clippy with warnings denied, workspace tests, and the product integration tests. Python validation uses an isolated environment, pytest, and package installation from the built artifact. Release validation additionally audits source and Git objects, dependencies and licenses, fixtures, metadata, documentation, archives, signatures, links, and platform claims.

No release or platform support claim is made from compilation or unit tests alone when a native runtime acceptance gate is documented.

The local validation surface is:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
python -m pytest tests sync-configs/tests
python sync-configs/scripts/build_zipapp.py
```

Run the authenticated release-set recipe only from the exact clean revision intended for publication. The recipe embeds the full source commit and a clean-tree marker in every Rust artifact, remaps checkout and user paths out of compiler metadata, and produces no private-key material; release acceptance compares the metadata and installed digest with the signed artifact before support is claimed.
