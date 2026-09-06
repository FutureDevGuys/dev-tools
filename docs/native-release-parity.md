# Native release administration cutover

`release-admin` owns release construction, offline root authorization, operation-only signing, local verification, admitted publication and anonymous asset verification. The Python release implementations and their implementation-specific tests are retired. Their last source is recoverable from Git history; restoration is a source-level rollback decision, not an active second release authority. The public release schemas, accepted artifacts and retained product rollback data are unchanged by removing those scripts.

## Preservation evidence

The incumbent `test_signed_release.py` and `test_release_publication.py` baseline passed all 28 parameterized cases before retirement. The native acceptance mapping preserves the intended behaviors, with deliberate contract changes called out below.

| Incumbent responsibility | Native acceptance |
| --- | --- |
| Independent product versions, selected native Cargo binaries, generation mapping and executable names | `set_build` version/grammar/naming tests and `set_build_constructs_one_exact_source_bound_release_without_python`; the controlled Cargo fixture checks selected arguments, offline mode and source identity |
| Exact clean source, public Git selection and deterministic environment | Shared clean-checkout/package tests, explicit held Git/Cargo inputs, isolated fixture Git configuration, remap tests and two independent release builds |
| Deterministic root construction and dual-root rotation | `construction_parity` compares frozen canonical envelope bytes in both input-key orders and verifies the result with both synthetic roots |
| Tracked trust-root agreement | `tracked_root_document_matches_the_product_trust_anchor` authenticates the tracked root with the product public trust anchor |
| Deterministic signed artifact metadata and operation-only signer interface | `construction_parity` compares exact signed bytes and signer stdin against independently captured vectors; existing manifest/set verification tests bind source, target and artifact digest |
| Wrong, revoked, malformed or failing signer | Native tests reject revoked authority before signer invocation and reject wrong-key signatures, invalid encoding/length/framing, oversized output, stderr and nonzero status without publishing metadata |
| Signed source tags, exact release assets and idempotent publication | Native `publication` tests and admitted live publication with a nonmutating second invocation and independent anonymous downloads |
| Tampered artifact, unsupported target and provider outage | Native publication tests reject all before any unauthorized create/upload; ambiguous writes resolve only from exact final state |
| Root-owned same-name launcher custody | Native launcher tests reject user-owned paths, relative names and wrong launcher names independently from strong workload admission |

The frozen synthetic construction corpus lives in `tests/fixtures/releases/native-construction.json`. Its README defines exact test-only key seeds, artifact bytes, provenance and schema projection. Its signatures came from the incumbent Python canonicalizer and Ed25519 helper, not the native implementation under test. Both writers retain canonical JSON followed by one newline. Signed production reader fixtures remain separate and unchanged.

## Deliberate contract changes

The native interface requires explicit absolute source/tool paths and a private offline Cargo home; it does not retain Python CLI spellings, caller-PATH defaults, raw routine release-key input or ambient build credentials. Routine signatures remain operation-only. Root private-key custody is stricter: native Linux reads bounded owner-only, single-link regular files through checked paths. New product manifests always use source-bound `dev-tools-product-v2`; the exact Dev Auth 0.3.11 historical verification/publication exception remains bounded to its original bytes. Legacy v1 construction and general source-unbound publication are not compatibility requirements.

Native build and publication acceptance is Linux-first. Target naming tests cover native and `.exe` artifact shapes but do not establish macOS, Windows or WSL runtime support. Unsupported build hosts remain fail-closed instead of inheriting the old script's platform-name inference as a support claim. Anonymous native HTTPS verification replaces authenticated `gh release download`, and publication independently requires strong workload admission rather than inferring it from a root-owned launcher.

## Runtime gate

The native path produced two independent byte-identical signed Dev Cache 0.1.8 release sets from source `2cefec9daffa4e6270a58f1449eb54987bcf091e`, published the authenticated set through the admitted Git/GitHub boundary and anonymously verified every asset. A second publication reported no mutation. Update All installed those exact bytes, repeated installation without mutation, and restored 0.1.7 then 0.1.8 through retained rollback with networking disabled. A fresh isolated home installed and ran 0.1.8 without source checkout access or external executables on PATH. [Compiler acceptance](dev-cache-compiler-performance.md) records the artifact digest and runtime checks.

The separate crates.io bootstrap and Trusted Publishing gates remain required for registry distribution; binary release parity does not claim those uploads occurred. Follow [shared-crate transactions](shared-crate-publication.md) and [ADR 0003](adr/0003-native-release-administration-and-separated-authority.md).
