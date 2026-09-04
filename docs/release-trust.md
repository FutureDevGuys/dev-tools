# Release trust

Dev Tools products use independent stable tags: `update-all/vX.Y.Z`, `dev-auth/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`. The installed updater resolves anonymous GitHub Releases metadata for its supported install targets, selects the greatest stable semantic version for the requested product, and then authenticates the attached root document, product manifest, and artifact. Syscfg consumes the same authenticated format when it provisions `dev-auth`; `update-all` does not manage that credential boundary. Neither path relies on GitHub's repository-wide latest-release pointer.

The recovery-only Ed25519 root key authorizes the release key in a signed public root document. It is encrypted in the project owner's credential vault and excluded from routine release builds. Routine releases consume the public document and cannot accept the root private key; they use only the release key to sign per-product manifests. New `dev-tools-product-v2` manifests bind the product, generation, semantic version, engine protocol, exact source commit, and one or more target artifact URLs, byte lengths, and SHA-256 digests. Persisted root and product generations, versions, manifest hashes, and binary hashes reject rollback and same-generation equivocation. Root rotation uses one incremented root document signed by both the current and next roots; the new Update All release embeds the next public root, after which a later incremented document can be signed only by that root.

`update-all product install <product>` performs an explicit installation for the updater's supported product set. `update-all product update-if-installed <product>` leaves an absent product absent. A command that does not resolve into the product-owned Dev Tools state root is externally managed and is reported without replacement. `dev-auth` is always externally managed by workstation policy.

Root authorization is a one-time or rotation-only operation. It consumes the root private key and the release public key, then emits a signed public document:

```sh
python scripts/build-root-document.py \
  --root-private-key /run/user/$(id -u)/dev-tools-signing/root.key \
  --release-public-key /run/user/$(id -u)/dev-tools-signing/release.pub \
  --trusted-root-public-key crates/update-all/trust/root-public-key.txt \
  --generation 1 \
  --output /run/user/$(id -u)/dev-tools-signing/dev-tools-root.json
```

Routine release construction uses one clean-checkout recipe with the signed public root document. A verified dev-auth workload can ask its broker to sign a canonical release document with an authorized profile; the profile name is deployment-defined (`publish` is illustrative below, while this repository's workstation deployment uses `source-maintenance`). Only the public release-key identifier is supplied to the builder, while the private key remains behind the broker's 1Password boundary. Release signing is a distinct opt-in authority: the administrator cap lists exact `release_signing_products`, the user profile narrows that list and declares a separate raw Ed25519 `release_signing_key`, and Git signing or SSH authentication grants cannot satisfy a release request. During migration the broker validates canonical stable `dev-tools-product-v1`, `dev-auth-product-v2`, `dev-tools-product-v2`, and `dev-tools-crate-set-v1` payloads. Binary releases use only shared product v2; shared-crate publication uses the independently granted `dev-tools-shared-crates` namespace.

```toml
# administrator policy
[authority_caps.release]
release_signing_products = ["dev-auth", "update-all", "sync-configs", "dev-tools-shared-crates"]
release_signing_keys = [{ private_key_ref = "op://Automation/dev-tools release signing key/private key", public_key = "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072" }]

# native user's config-v2.toml
[authority_profiles.publish]
release_signing_products = ["dev-auth", "update-all", "sync-configs", "dev-tools-shared-crates"]
release_signing_key = { private_key_ref = "op://Automation/dev-tools release signing key/private key", public_key = "11686a3552e97ca8d717b24007da01716c308dd526340e50a15461f400850072" }
```

```sh
release_signer_profile=source-maintenance # exact name from the installed config-v2.toml
next_dev_auth_generation=NEXT_UNUSED_GENERATION
/usr/bin/env -u ARGV0 "$HOME/.local/bin/release-builder" \
  "$PWD/scripts/build-release-set.py" \
  --product dev-auth \
  --public-git-command /usr/bin/git \
  --release-signer /usr/local/bin/dev-auth \
  --release-signer-profile "$release_signer_profile" \
  --release-key-id release-ca568413f0f27130 \
  --manifest-generation "$next_dev_auth_generation" \
  --output "${XDG_CACHE_HOME:-$HOME/.cache}/dev-tools-release/dev-auth-release-set"
```

The owner-only `--release-private-key` mode remains available for initial bootstrap and recovery. It is mutually exclusive with the external signer mode and is not the routine strong-mode path.

Release publication is a separate operation from construction and signing. Run the standalone native publisher from a clean canonical checkout inside an admitted workload whose profile grants the required source-maintenance Git, GitHub, and SSH-signing operations. Its exact same-name `git` and `gh` children receive only that workload authority. `EXPECTED_GIT_SIGNING_PUBLIC_KEY` is the public OpenSSH key from the approved workload profile; it is reviewed input rather than a value discovered from repository Git configuration. Outside an admitted workload, `git` and `gh` intentionally remain native human passthrough and SHALL NOT be used for unattended publication.

```sh
"$HOME/.local/bin/release-admin" set publish \
  --source-root "$PWD" \
  --release-root "$HOME/.cache/dev-tools-release/dev-auth-release-set/releases" \
  --trusted-root-public-key "$PWD/crates/update-all/trust/root-public-key.txt" \
  --source-commit "$(/usr/bin/git rev-parse HEAD)" \
  --repository FutureDevGuys/dev-tools \
  --dev-auth-command /usr/local/bin/dev-auth \
  --git-signing-public-key "$EXPECTED_GIT_SIGNING_PUBLIC_KEY" \
  --git-command /usr/local/bin/git \
  --gh-command /usr/local/bin/gh \
  --format json
```

The publisher accepts only source-bound shared product-v2 manifests and independently proves a verified strong workload admission before any provider action. It authenticates every signed manifest and artifact before provider mutation, clears ambient Git/GitHub authority from each child, requires the Git fetch and push URLs to name the exact publication repository, creates and verifies the exact signed source-tag object, creates only matching non-draft stable GitHub releases, anonymously re-downloads every published asset without the admitted `gh` identity, and verifies exact length and SHA-256. Its admitted `dev-auth`, `git`, and `gh` launchers and resolved executables must be root-owned and reachable only through root-owned non-writable path components; execution pins the validated executable while preserving each same-name launcher as `argv[0]`. A second invocation is an idempotent verification pass. It refuses dirty source, conflicting tags or releases, unexpected files, provider errors disguised as absence, and artifacts that change before upload. An ambiguous tag or release write succeeds only when the independently read final state exactly matches the signed set.

Legacy `dev-tools-product-v1` does not cryptographically bind artifact provenance to the source tag, while `dev-auth-product-v2` binds only the historical Dev Auth release shape. New releases use shared `dev-tools-product-v2`, which requires the exact source commit and authenticates the complete target set. Legacy readers remain only for explicitly bounded migration and receipt-owned rollback and never report v1 as source-bound. After a product cuts over, its online authority accepts only source-bound schemas.

The signed public root document is tracked at `release-trust/dev-tools-root.json`; `--root-document` exists only for rotation rehearsal and verification. The recipe refuses a dirty checkout, derives each selected product's version and the exact full source commit from `HEAD`, uses the commit timestamp as `SOURCE_DATE_EPOCH`, builds the selected products from scratch, and then invokes `scripts/build-signed-release.py` for each nested release. The signer verifies the root document against the compiled public trust root, requires the selected release public key to be authorized and unrevoked, and independently verifies every external signature before producing deterministic canonical signed JSON. Private keys never belong in the repository, build logs, command output, or release archives.

Repeat `--product` to construct more than one product from the same exact source revision. Omit it to select all five only on `linux-x86_64`: `sync-configs` is presently accepted solely for that release target, so an all-products build on any other target fails closed before compilation and must instead name only the accepted products explicitly. For multiple products, repeat the generation option as `--manifest-generation update-all=7` and `--manifest-generation dev-cache=9`; every selected product must be named exactly once. Each product therefore keeps its own version and manifest generation, and independent nested release lines never need to be artificially synchronized. The output path should live on persistent owner-controlled storage rather than a memory-backed temporary filesystem.

Each product uses independent nested tags: `update-all/vX.Y.Z`, `dev-auth/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`.

Stable manifests identify versioned artifacts, byte lengths, SHA-256 hashes, and protocol compatibility. A Dev Tools Ed25519 release key signs product manifests; the recovery-only root key authorizes, rotates, or revokes release keys. Persisted generation, version, manifest hash, and binary hash prevent rollback and equivocation. Recovery restores the root credential from the encrypted vault, verifies its public-key checksum against the compiled trust root, authorizes or revokes a release key, and removes the recovered private material from the release workspace immediately afterward.
