---
authority: canonical
owner: dev-auth
---

# ADR 0065: Prompt-free user enrollment reads

status: proposed
verification: pending

## Decision

The unreleased Linux user-only workload path honors an explicitly resolved `enrolled_noninteractive` admission choice without calling the potentially interactive keyring entry reader. A noninteractive outer invocation with missing or approval-required admission remains blocked. Explicit enrolled admission selects the prompt-free path even when the caller did not supply `--non-interactive`; absence of that flag does not change the selected policy into permission to prompt. The existing interactive legacy path and strong-mode native enrolled guard remain separate.

The product reads already-enrolled Secret Service items through the same locked Rust Secret Service implementation used by its existing keyring backend. It uses the fixed current-user `/run/user/UID/bus` after the existing owner, socket and environment-custody checks, rejects a service not observed running, negotiates the existing encrypted session, and searches only the exact `service` and `username` attributes used by keyring enrollment. Every required slot must have exactly one unlocked match and no locked matches. The reader never calls unlock, prompt, collection creation, migration or enrollment, never falls back to another credential source, and never retries. A store that locks between lookup and retrieval is unavailable. The presence check is not a reservation of the service's bus name and does not establish a general no-service-activation guarantee; the prompt-free contract relies on the standard non-prompting search/read/session methods, not on service ownership remaining unchanged.

One five-second deadline covers connection, authentication, session negotiation and all slot reads. The launch boundary owns a current-thread Tokio runtime and drives the already-selected zbus async-io executor within the same operation; it does not detach a credential worker. Retained socket custody shuts the transport down on completion, timeout or dropped in-flight work. It does not claim to undo a service's access audit or other completed read effects. Values enter zeroizing storage before UTF-8, delimiter and 64-KiB validation. Backend diagnostics and returned values never enter failure messages.

Enrollment retrieval completes before creating the user broker socket or starting a workload. An unavailable prompt-free store produces a value-free `enrollment_unavailable_without_interaction` blocked result with exit 3 and `started=false` through explicit workload launch. Later entered supervisor errors keep their existing unknown-progress semantics. The supervisor rechecks explicit enrolled admission under the setup exclusion lease before entering this path. This does not resolve the separately tracked coordination gaps for older or lower-level policy writers.

## Dependency boundary

Direct Linux dependencies expose the already-locked `secret-service` 5.1.0, `zbus` 5.19.0 and `futures-util` 0.3 implementations; no package version, cryptographic authority, TLS implementation or runtime is replaced. Secret Service and futures-util declare MIT-or-Apache-2.0 licensing, and zbus declares MIT. The async-io/Rust-crypto feature selection retains the existing keyring transport and crypto graph; Tokio's existing runtime gains an explicit time-feature requirement. AES, CBC and HKDF direct dependencies are test-only uses of the already-locked RustCrypto packages, each MIT-or-Apache-2.0. They implement a deliberately insecure synthetic test server, never production enrollment or key exchange. No dependency type becomes a public product interface.

## Evidence and remaining qualification

The admission test first rejected explicit user-only enrolled policy as unsupported, then passed with the new route while retaining approval-required denials. Native protocol tests launch an owned D-Bus daemon with no activation directories and a synthetic Secret Service. They exercise encrypted retrieval with exact enrollment attributes, locked/missing/mixed/ambiguous matches, relocking, bounded authentication/search/read stalls, cancellation after an entered read, malformed/oversized encrypted values, fixed diagnostics and observed client disconnection. The slow-lookup/second-stage test also rejects a counterexample that extends the overall deadline and would let a later call receive a fresh budget. Unlock and prompt counters remain zero. Binary-module result tests exercise the actual finalization path for blocked enrollment and unknown-progress backend errors. These tests do not open the operator's desktop bus or retrieve real credentials.

This is source-level admission and native synthetic-protocol evidence, not signed installation, vendor-store compatibility, real provider use or full user-only workload teardown acceptance. The existing setup activation, signed public-binary, live enrolled provider and platform gates remain in force. Windows, WSL and macOS do not inherit this Linux implementation or its authority.
