# Release trust

Dev Tools products use independent stable tags: `update-all/vX.Y.Z`, `dev-auth/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`. The installed updater resolves anonymous GitHub Releases metadata for its supported install targets, selects the greatest stable semantic version for the requested product, and then authenticates the attached root document, product manifest, and artifact. Syscfg consumes the same authenticated format when it provisions `dev-auth`; `update-all` does not manage that credential boundary. Neither path relies on GitHub's repository-wide latest-release pointer.

The recovery-only Ed25519 root key authorizes the release key in a signed public root document. It is encrypted in the project owner's credential vault and excluded from routine release builds. Routine releases consume the public document and cannot accept the root private key; they use only the release key to sign per-product manifests. Each manifest binds the product, generation, semantic version, engine protocol, target, artifact URL, byte length, and SHA-256 digest. Persisted root and product generations, versions, manifest hashes, and binary hashes reject rollback and same-generation equivocation. Root rotation uses one incremented root document signed by both the current and next roots; the new Update All release embeds the next public root, after which a later incremented document can be signed only by that root.

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

Routine release construction uses one clean-checkout recipe with only the signed public root document and an owner-only release key:

```sh
python scripts/build-release-set.py \
  --product update-all \
  --release-private-key /run/user/$(id -u)/dev-tools-signing/release.key \
  --manifest-generation 6 \
  --output "${XDG_CACHE_HOME:-$HOME/.cache}/dev-tools-release/update-all-v0.1.5"
```

The signed public root document is tracked at `release-trust/dev-tools-root.json`; `--root-document` exists only for rotation rehearsal and verification. The recipe refuses a dirty checkout, derives each selected product's version and the exact full source commit from `HEAD`, uses the commit timestamp as `SOURCE_DATE_EPOCH`, builds the selected products from scratch, and then invokes `scripts/build-signed-release.py` for each nested release. The signer verifies the root document against the compiled public trust root, requires the supplied release key to be authorized and unrevoked, and produces deterministic canonical signed JSON for identical inputs. Private keys never belong in the repository, build logs, command output, or release archives.

Repeat `--product` to construct more than one product from the same exact source
revision, or omit it to construct all five. For multiple products, repeat the
generation option as `--manifest-generation update-all=6` and
`--manifest-generation dev-cache=9`; every selected product must be named
exactly once. Each product therefore keeps its own version and manifest
generation, and independent nested release lines never need to be artificially
synchronized. The output path should live on persistent owner-controlled
storage rather than a memory-backed temporary filesystem.

Each product uses independent nested tags: `update-all/vX.Y.Z`, `dev-auth/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`.

Stable manifests identify versioned artifacts, byte lengths, SHA-256 hashes, and protocol compatibility. A Dev Tools Ed25519 release key signs product manifests; the recovery-only root key authorizes, rotates, or revokes release keys. Persisted generation, version, manifest hash, and binary hash prevent rollback and equivocation. Recovery restores the root credential from the encrypted vault, verifies its public-key checksum against the compiled trust root, authorizes or revokes a release key, and removes the recovered private material from the release workspace immediately afterward.
