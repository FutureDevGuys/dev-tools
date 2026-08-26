# Release trust

Dev Tools products use independent stable tags: `update-all/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`. The installed updater resolves anonymous GitHub Releases metadata, selects the greatest stable semantic version for the requested product, and then authenticates the attached root document, product manifest, and artifact. It does not rely on GitHub's repository-wide latest-release pointer.

The operationally offline Ed25519 root key authorizes the release key in a signed public root document. Routine releases consume that document and cannot accept the root private key; they use only the release key to sign per-product manifests. Each manifest binds the product, generation, semantic version, engine protocol, target, artifact URL, byte length, and SHA-256 digest. Persisted root and product generations, versions, manifest hashes, and binary hashes reject rollback and same-generation equivocation. Root rotation uses one incremented root document signed by both the current and next roots; the new Update All release embeds the next public root, after which a later incremented document can be signed only by that root.

`update-all product install <product>` performs an explicit installation. `update-all product update-if-installed <product>` leaves an absent product absent. A command that does not resolve into the product-owned Dev Tools state root is externally managed and is reported without replacement.

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
  --root-document /run/user/$(id -u)/dev-tools-signing/dev-tools-root.json \
  --release-private-key /run/user/$(id -u)/dev-tools-signing/release.key \
  --manifest-generation 1 \
  --output /tmp/dev-tools-release
```

The recipe refuses a dirty checkout, derives the product version and exact full source commit from `HEAD`, uses the commit timestamp as `SOURCE_DATE_EPOCH`, builds all four products from scratch, and then invokes `scripts/build-signed-release.py` for each nested release. The signer verifies the root document against the compiled public trust root, requires the supplied release key to be authorized and unrevoked, and produces deterministic canonical signed JSON for identical inputs. Private keys never belong in the repository, build logs, command output, or release archives.

Each product uses independent nested tags: `update-all/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`.

Stable manifests identify versioned artifacts, byte lengths, SHA-256 hashes, and protocol compatibility. A Dev Tools Ed25519 release key signs product manifests; an offline root key authorizes, rotates, or revokes release keys. Persisted generation, version, manifest hash, and binary hash prevent rollback and equivocation. Production releases remain disabled until this contract and its recovery procedure pass the publication gate.
