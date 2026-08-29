# Development and validation

Rust validation uses formatting, Clippy with warnings denied, workspace tests, and the product integration tests. Python validation uses an isolated environment, pytest, and package installation from the built artifact. Release validation additionally audits source and Git objects, dependencies and licenses, fixtures, metadata, documentation, archives, signatures, links, and platform claims.

No release or platform support claim is made from compilation or unit tests alone when a native runtime acceptance gate is documented.

The bounded `gh-dev-auth` child grammar is reviewed against one exact upstream GitHub CLI source revision and build output. A GitHub CLI update requires reviewing the new upstream command and internal Git invocation surfaces, updating the pinned source revision and exact version output together, extending the adversarial argument corpus before admission, and publishing a new signed `dev-auth` release. Workstation provisioning installs GitHub CLI normally and uses offline `dev-auth validate` as the single fail-closed compatibility gate; it does not duplicate the version policy.

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
