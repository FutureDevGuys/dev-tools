---
authority: canonical
owner: dev-tools
---

# ADR 0003: Native release administration and separated authority

status: accepted
verification: runtime acceptance remains required before release administration is declared complete

## Context

Release administration spans deterministic compilation, offline root authorization, routine manifest signing, provider publication, anonymous verification, and installation. A standalone native implementation removes interpreter and checkout dependencies, but consolidating orchestration must not consolidate those authorities.

## Decision

A native `release-admin` product owns deterministic build orchestration, manifest and root construction, offline verification, operation-only signer invocation, admitted publication, anonymous redownload verification, root rotation, and audit reporting. The command coordinates distinct authorities through typed inputs and never receives raw routine signing keys or ambient publication credentials. Each command is exposed only when its implementation enforces this decision; unavailable stages remain absent rather than delegating to a repository script.

Crate archive inspection uses the Rust `flate2` and `tar` libraries behind strict compressed-size, expanded-size, entry-count, entry-type, path, and metadata bounds. It reads package name and version from the normalized embedded `Cargo.toml`, rejects Cargo's dirty-worktree flag, and requires the embedded VCS commit to equal the declared source commit. Cargo defines that VCS file as a best-effort snapshot rather than provenance proof, so this check is necessary but never substitutes for clean-checkout construction and independent reproduction. Native construction requires the selected checkout to be canonical, clean, and at the exact commit, requires every tracked entry to be a regular file, retains the exact Git and Cargo executable identities, creates two private non-local clones, runs Cargo offline in separate target directories, rejects symlinks and submodules, and publishes only byte-identical package archives. This dedicated archive dependency is accepted because treating a caller-provided filename as package identity would invalidate the authorization boundary; release administration does not invoke a platform archive executable or caller `PATH`.

Binary releases use one canonical `dev-tools-product-v2` manifest per product version. Shared Rust packages use one canonical `dev-tools-crate-set-v1` authorization inventory per publication transaction. Both contracts sign a declared source commit and exact artifact byte identities; the crate-set contract additionally binds the fixed public registry, package name, stable SemVer, length, and SHA-256 for every `.crate` file. The inventory alone does not prove that the package bytes were derived from the declared commit. Native build orchestration must produce the packages from a clean exact checkout and the acceptance gate must reproduce those bytes independently before signing. Existing `dev-tools-product-v1` and `dev-auth-product-v2` documents remain readable only for explicitly bounded migration and receipt-owned rollback; new release metadata is never written in those forms. Product release authority switches to source-bound schemas at cutover and never resolves a later source-unbound release.

## Invariants

- Build, root, signing, publication, and privileged installation remain independently authorized.
- Every published artifact binds the exact product, source commit, target, length, digest, version, and generation.
- Every published shared crate is present in one signed crate-set inventory whose authority is granted independently from binary-product signing; registry upload cannot select or alter package bytes, and reproducible construction separately proves their source derivation.
- Registry publication is externally irreversible and begins only after the entire signed set verifies locally. An ambiguous upload is resolved by anonymously authenticating the registry index checksum and downloaded package before any retry.
- A selected target is verified as one projection of the complete signed target set; accepting one target never permits unsigned additions or substitutions.
- Remote metadata cannot select commands or privileged effects.
- During migration, the incumbent release tooling remains authoritative until native parity and rollback acceptance pass. Cutover removes the incumbent implementation rather than retaining a second authority.

## Verification

Rust integration tests replay the frozen release corpus, compare deterministic output byte-for-byte, reject authority confusion, target substitution, schema downgrade, and tampering, publish only exact reviewed identities through admitted operations, and anonymously re-download every asset for verification.

## Runtime acceptance

Produce two independent byte-identical release sets, sign them operation-only, publish one reviewed set, verify it anonymously, install it from outside the checkout, and prove an idempotent second pass and retained rollback before retiring Python release administration.
