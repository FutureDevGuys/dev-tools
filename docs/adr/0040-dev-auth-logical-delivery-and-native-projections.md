---
authority: canonical
owner: dev-auth
---

# ADR 0040: Logical delivery and native child projections

status: proposed
verification: pending

## Decision

The source CLI exposes `secret read RESOURCE`, `secret public RESOURCE`, and `secret exec` with explicit `--stdin RESOURCE`, `--fd FD=RESOURCE`, `--file VARIABLE=RESOURCE`, and `--env VARIABLE=RESOURCE` projections before `-- COMMAND ...`. Callers select logical names, never provider references or credential literals. All operations require existing native workload admission and return promptly without opening an admission prompt. Execution observations use the separate protected `--result-file` destination under ADR 0037; stdout belongs exclusively to the resource or child.

The Linux source candidate additionally exposes `secret sign-ssh --purpose authentication|git-signing --fingerprint SHA256:...` for admitted operation-only SSH keys. It takes at most 24 KiB of raw payload bytes from standard input only after local admission is verified, with a 30-second absolute input deadline, selects the current broker-verified profile, and writes only the binary signature to standard output. The exact key fingerprint and purpose are rechecked by the broker against that workload's operation-key grant; no private key or provider reference is exported. The optional result file remains value-free and separate from signature bytes. Invalid selection, absent admission, input timeout, denied key authority, broker failure, and output failure have distinct fixed exit categories. The command does not request fresh approval or turn an exportable resource into signing authority.

[ADR 0134](0134-provider-neutral-operation-only-ssh-signing.md) records the provider-neutral SSH and release-signing adapter and the broker's declared-key verification. The provider may handle private material inside its trusted process boundary, but the operation response contains only a signature.

The native broker resolves the selected workload cap, native account, resource cap, narrowed resource rights and exact provider/credential slot before contacting a provider. Read and public purposes are distinct, and every child projection requires its separately declared projection right. Public material cannot substitute for exportable authority. Failures return fixed value-free categories; request audits hash logical names and never serialize resource bytes. Binary responses have a separately bounded response frame, bounded base64 decoding and redacted, zeroizing material. Production transport zeroizes encoded response and receive buffers, including interrupted receives. This is an internal version-3 transport, not a new SDK or supported public broker protocol.

Linux stdin, descriptor and file-path projections use anonymous, owner-read-only, sealed memory files. File-path projection passes `/proc/self/fd/N` to the child through the requested variable; it creates no persistent pathname or secret-bearing receipt. Descriptor targets are distinct, bounded and duplicated only in the child from retained close-on-exec sources above the target range. An explicit environment projection accepts native bytes except NUL and is observable through the operating system's child-environment trust boundary. It cannot replace admission, loader or executable-search environment variables. No parent ambient environment is modified. Provider material is zeroizing; native command environment allocations and child copies are not claimed to be erased by the provider material's destructor.

The child inherits native arguments, cwd and streams. `dev-tools-command` owns the reusable retained process-group runner, terminal foreground handoff, thread-local signal forwarding, native status and cancellation mechanics. The product owns logical policy, projections and the absolute boot-relative authority deadline. Process-directed signal forwarding requires a single-threaded launcher or caller-owned process-wide signal routing; the foundation changes no global signal disposition or another thread's signal mask. The Dev Auth CLI enters this runner without starting background threads.

The runner preserves an unreaped leader while signaling its group on normal completion or cancellation, avoiding group-identifier reuse before cleanup. An owned process group is not containment against descendants that deliberately leave it, nor does leader exit establish every descendant's terminal state. The enclosing admitted workload's native supervisor remains responsible for whole-domain authority loss, revocation and hard-deadline teardown. User-only mode must not be represented as a root-enforced hostile-descendant boundary.

## Verification and qualification

Protocol tests cover logical-only requests, binary limits and redacted responses. Broker tests cover purpose/projection narrowing and retained provider dispatch. Public-binary tests cover prompt-free unadmitted denial, no child start and separate value-free results. The published topic includes a disposable installed user-only fixture that exercises `secret sign-ssh` through a synthetic enrolled provider, verifies the returned signature against the declared public key, and denies key export and stale-session reuse. Native projection tests exercise binary stdin, descriptors and files, explicit environment delivery, NUL rejection, reserved-variable collisions, seal enforcement and handle cleanup. Shared runner tests cover native arguments/streams, nonzero status, signal status and prestart/in-flight cancellation. Terminal and process-tree behavior, a live real provider through the installed public binary, standalone v3 setup and native Windows/WSL/macOS qualification remain separate acceptance requirements; these source tests do not claim them.
