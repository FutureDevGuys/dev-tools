# Release trust

Dev Tools products use independent stable tags: `update-all/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`. The installed updater resolves anonymous GitHub Releases metadata, selects the greatest stable semantic version for the requested product, and then authenticates the attached root document, product manifest, and artifact. It does not rely on GitHub's repository-wide latest-release pointer.

The offline Ed25519 root key authorizes the online release key. The release key signs per-product manifests. Each manifest binds the product, generation, semantic version, engine protocol, target, artifact URL, byte length, and SHA-256 digest. Persisted root and product generations, versions, manifest hashes, and binary hashes reject rollback and same-generation equivocation.

`update-all product install <product>` performs an explicit installation. `update-all product update-if-installed <product>` leaves an absent product absent. A command that does not resolve into the product-owned Dev Tools state root is externally managed and is reported without replacement.

Release construction uses `scripts/build-signed-release.py` with owner-only raw Ed25519 key files. The recipe refuses a root private key that does not match the compiled public trust root and produces deterministic canonical signed JSON for identical inputs. Private keys never belong in the repository, build logs, command output, or release archives.

Each product uses independent nested tags: `update-all/vX.Y.Z`, `dev-cache/vX.Y.Z`, `sync-configs/vX.Y.Z`, and `skills-sync/vX.Y.Z`.

Stable manifests identify versioned artifacts, byte lengths, SHA-256 hashes, and protocol compatibility. A Dev Tools Ed25519 release key signs product manifests; an offline root key authorizes, rotates, or revokes release keys. Persisted generation, version, manifest hash, and binary hash prevent rollback and equivocation. Production releases remain disabled until this contract and its recovery procedure pass the publication gate.
