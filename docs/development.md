# Development and validation

Rust validation uses formatting, Clippy with warnings denied, workspace tests, and the product integration tests. Python validation uses an isolated environment, pytest, and package installation from the built artifact. Release validation additionally audits source and Git objects, dependencies and licenses, fixtures, metadata, documentation, archives, signatures, links, and platform claims.

No release or platform support claim is made from compilation or unit tests alone when a native runtime acceptance gate is documented.

The bounded `gh-dev-auth` child grammar is reviewed against one exact upstream GitHub CLI source revision and build output. A GitHub CLI update requires reviewing the new upstream command and internal Git invocation surfaces, updating the pinned source revision and exact version output together, extending the adversarial argument corpus before admission, and publishing a new signed `dev-auth` release. Workstation provisioning installs GitHub CLI normally and uses offline `dev-auth validate` as the single fail-closed compatibility gate; it does not duplicate the version policy.

The managed `git-dev-auth` grammar and command-scope isolation are a security boundary, not a convenience wrapper. A newly admitted Git option or command requires a failing argument-contract test first, review of every local configuration, attributes/filter, hook, helper, path, protocol, editor/pager, subprocess, and unsigned-author escape it can activate, plus tests proving rejection precedes runtime or credential access. Git behavior is bounded to the documented minimum on major version 2; changing that range requires reviewing path probes, credential quit behavior, lazy-fetch suppression, SSH signing, fsmonitor disabling, and every admitted command against the new source line. Platform claims require native routing and child tests; a Windows cross-compile or Wine run is useful implementation evidence but cannot replace current-user ACL, path-identity, process-sharing, Credential Manager, and named-pipe acceptance on native Windows.

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
