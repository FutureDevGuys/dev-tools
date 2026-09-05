---
authority: canonical
owner: artifact-update
---

# Artifact Update

`artifact-update` is a standalone, configuration-driven updater for independently packaged applications and assets. It compiles the same `dev-tools-update` library that public Dev Tools products use; products do not invoke the sibling CLI for normal update behavior.

The `artifact-update-config-v1` document is local authority. Each artifact has a stable identifier, package kind, source, version convention, verification policy, and ordered target selectors. Exact names, anchored globs, and Rust linear-time regular expressions are deterministic; a selector matching multiple assets fails as ambiguous instead of guessing. Named captures are limited to version, channel, operating system, architecture, libc, runtime, and variant.

`artifact-update list`, `status`, and `doctor` are local-only operations. `status` reports unknown when authenticated cache evidence is absent rather than contacting a provider or assuming the installed version is current. Network discovery, conditional cache refresh, authenticated installation, receipts, rollback, additional source adapters, and configuration editing remain gated rollout work and are not claimed by the initial command surface.

The configuration parser is strict, one-megabyte bounded, rejects unknown fields and duplicate identifiers, and compiles selectors once per load. A catalog accepts at most 256 selectors overall and 64 per artifact. Each expression has a 1,024-byte source limit, a 64-KiB compiled-program limit, and a 64-KiB DFA-cache limit. Selection accepts at most 4,096 candidates and requires the entire filename to match, including when a regex contains alternation. Named `os` and `architecture` captures must equal the requested target; other captures remain inert metadata. Explicit selector target constraints apply as well.

Candidate URLs use the existing HTTP URI parser and require HTTPS with a nonempty authority, no user information, no fragment, and a valid port when supplied. Candidate filenames reject path separators, control characters, and dot-directory names. This syntactic check is not network authorization: future fetching also enforces locally declared host, redirect, and size policy. Install-capable verification is separate from version discovery; `check-only` sources never authorize mutation. Signed-manifest configuration pins a local hexadecimal Ed25519 `trusted_root_public_key` alongside its root-document URL; a remote root URL alone supplies no trust anchor.

For example, a check-only catalog can describe an unrelated packaged executable without knowing its implementation language:

```toml
schema = "artifact-update-config-v1"

[[artifacts]]
id = "example"
kind = "native-binary"
source = { type = "github", owner = "ExampleOrg", repository = "example" }
version = { type = "semver-tag", prefix = "v" }
verification = { type = "check-only" }
selectors = [{ type = "glob", pattern = "example-*-linux-x86_64", os = "linux", architecture = "x86_64" }]
```

Inspect it with `artifact-update list --config /absolute/path/config.toml --json` or `artifact-update status --config /absolute/path/config.toml --json`. These commands do not discover releases yet. The current executable is a development-stage configuration/selection foundation, not a release-ready installer or a claim of native platform acceptance.
