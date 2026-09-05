---
authority: canonical
owner: dev-tools
---

# ADR 0003: Native release administration and separated authority

status: proposed
verification: pending

## Context

Release administration spans deterministic compilation, offline root authorization, routine manifest signing, provider publication, anonymous verification, and installation. A standalone native implementation removes interpreter and checkout dependencies, but consolidating orchestration must not consolidate those authorities.

## Decision

A native `release-admin` product owns deterministic build orchestration, manifest and root construction, offline verification, operation-only signer invocation, admitted publication, anonymous redownload verification, root rotation, and audit reporting. The command coordinates distinct authorities through typed inputs and never receives raw routine signing keys or ambient publication credentials. Each command is exposed only when its implementation enforces this decision; unavailable stages remain absent rather than delegating to a repository script.

The first crates.io version of a new package is a deliberate bootstrap exception because crates.io cannot configure Trusted Publishing before that version exists. The native bootstrap command accepts one explicitly supplied token only through standard input after every public precondition passes. On accepted Linux hosts it keeps that token in zeroizing memory and a sealed anonymous memory descriptor, invokes one held Cargo executable from a clean exact source clone with verification builds disabled because the signed package bytes were already reproduced independently, and installs itself as Cargo's only credential provider. The provider releases the token only when Cargo's publish request, checksum, registry, live process ancestry, executable identity, signed crate inventory, and declared source commit all agree. No token is written to argv, environment variables, a named file, Cargo credentials, a plan, receipt, diagnostic, or log. The bootstrap runs in the current user's trust boundary and is not presented as hostile-same-user protection. After initial ownership exists, the package uses crates.io Trusted Publishing with short-lived GitHub Actions OIDC authority; the bootstrap token is revoked and does not become steady-state release infrastructure.

Crate archive inspection uses the Rust `flate2` and `tar` libraries behind strict compressed-size, expanded-size, entry-count, entry-type, path, and metadata bounds. It reads package name and version from the normalized embedded `Cargo.toml`, rejects Cargo's dirty-worktree flag, and requires the embedded VCS commit to equal the declared source commit. Cargo defines that VCS file as a best-effort snapshot rather than provenance proof, so this check is necessary but never substitutes for clean-checkout construction and independent reproduction. Native construction requires the selected checkout to be canonical, clean, and at the exact commit, requires every tracked entry to be a regular file, retains the exact Git and Cargo executable identities, creates two private non-local clones, runs Cargo offline in separate target directories, rejects symlinks and submodules, and publishes only byte-identical package archives. This dedicated archive dependency is accepted because treating a caller-provided filename as package identity would invalidate the authorization boundary; release administration does not invoke a platform archive executable or caller `PATH`.

Binary releases use one canonical `dev-tools-product-v2` manifest per product version. Shared Rust packages use one canonical `dev-tools-crate-set-v1` authorization inventory per publication transaction. Both contracts sign a declared source commit and exact artifact byte identities; the crate-set contract additionally binds the fixed public registry, package name, stable SemVer, length, and SHA-256 for every `.crate` file. The inventory alone does not prove that the package bytes were derived from the declared commit. Native build orchestration must produce the packages from a clean exact checkout and the acceptance gate must reproduce those bytes independently before signing. Existing `dev-tools-product-v1` and `dev-auth-product-v2` documents remain readable only for explicitly bounded migration and receipt-owned rollback; new release metadata is never written in those forms. Product release authority switches to source-bound schemas at cutover and never resolves a later source-unbound release.

## Invariants

The published signer-bootstrap release has one version-bound verification exception: exact Dev Auth `0.3.11` uses source-bound `dev-auth-product-v2` with one target. Authenticated verification and idempotent publication of that existing release remain available through its compatibility window, but construction always emits shared product v2. The exception does not apply to another product or version, including build-metadata variants. Dev Auth permits that exact release at bundle/online intake while preserving exact accepted predecessor bytes for offline use and rollback. All later releases require shared product v2. This reader compatibility does not relax source binding, reproducibility, native approval, anti-rollback, or equivocation protection, and it does not authorize reissuing an accepted version with new bytes.

- Build, root, signing, publication, and privileged installation remain independently authorized.
- Every published artifact binds the exact product, source commit, target, length, digest, version, and generation.
- Every published shared crate is present in one signed crate-set inventory whose authority is granted independently from binary-product signing; registry upload cannot select or alter package bytes, and reproducible construction separately proves their source derivation.
- Registry publication is externally irreversible and begins only after the entire signed set verifies locally. An ambiguous upload is resolved by anonymously authenticating the registry index checksum and downloaded package before any retry.
- The manual crates.io bootstrap is accepted only on Linux, handles one explicit stdin credential without persistence, publishes only Cargo-produced bytes whose checksum is already signed, and is retired after Trusted Publishing is configured.
- A selected target is verified as one projection of the complete signed target set; accepting one target never permits unsigned additions or substitutions.
- Remote metadata cannot select commands or privileged effects.
- During migration, the incumbent release tooling remains authoritative until native parity and rollback acceptance pass. Cutover removes the incumbent implementation rather than retaining a second authority.

## Verification

Rust integration tests replay the frozen release corpus, compare deterministic output byte-for-byte, reject authority confusion, target substitution, schema downgrade, and tampering, publish only exact reviewed identities through admitted operations, and anonymously re-download every asset for verification.

## Runtime acceptance

Produce two independent byte-identical release sets, sign them operation-only, publish one reviewed set, verify it anonymously, install it from outside the checkout, and prove an idempotent second pass and retained rollback before retiring Python release administration.
