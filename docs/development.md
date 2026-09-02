# Development and validation

Rust validation uses formatting, Clippy with warnings denied, workspace tests, and the product integration tests. Python validation uses an isolated environment, pytest, and package installation from the built artifact. Release validation additionally audits source and Git objects, dependencies and licenses, fixtures, metadata, documentation, archives, signatures, links, and platform claims.

No release or platform support claim is made from compilation or unit tests alone when a native runtime acceptance gate is documented.

The bounded v0.2 `gh-dev-auth` compatibility frontend remains release-frozen while the v0.3 workload broker is under acceptance. Its child grammar is reviewed against one exact upstream GitHub CLI source revision and build output. The v0.3 same-name workload frontend does not parse GitHub CLI grammar: an admitted session passes argv to the administrator-pinned native executable and supplies only the broker-derived child environment.

The managed v0.2 `git-dev-auth` grammar remains a rollback security boundary and accepts no new syntax. Dev-auth v0.3 instead forwards all Git argv within an admitted workload and narrows authority through the operating-system session, resolved resource entitlement, provider permissions, command-scoped credential/signing configuration, and terminal denial without human fallback. Platform claims require native routing and child tests; a Windows cross-compile or Wine run is useful implementation evidence but cannot replace current-user ACL, path identity, process isolation, Credential Manager, and named-pipe acceptance on native Windows.

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
