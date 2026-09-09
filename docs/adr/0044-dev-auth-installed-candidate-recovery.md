---
authority: canonical
owner: dev-auth
---

# ADR 0044: Installed-candidate setup recovery

status: proposed
verification: pending

## Decision

[ADR 0076](0076-unstaged-user-upgrade-forward-recovery.md) permits an unstaged user-only upgrade from the exact approved running candidate only while its retained prior installation remains complete and no binary journal exists.

[ADR 0074](0074-committed-upgrade-product-receipt-recovery.md) additionally permits completing a committed user-only upgrade whose product receipt still describes the retained inactive prior release.

[ADR 0073](0073-initial-staged-binary-forward-recovery.md) extends candidate continuation to the retained staged first user-only binary before shared commit, without admitting new releases or incomplete strong/upgrade installations.

[ADR 0069](0069-dev-auth-committed-binary-journal-settlement.md) supersedes the unconditional pending-binary-journal rejection for exact committed candidate journals only; incomplete candidate installations remain outside this recovery case.

[ADR 0072](0072-initial-product-receipt-recovery.md) additionally permits the narrowly retained initial user-only missing-product-receipt case after the exact shared candidate is committed. It does not admit pre-commit binary recovery or incomplete strong installations.

`dev-auth setup recover` resumes an already-owned setup from its private transition and retained generation, without an original plan file, candidate policy/configuration files, executable download or disposable release cache. Recovery does not discover, download, install or authorize another release. It requires the installation's native owner, the stable exclusive setup lease, intact retention and an already-installed candidate. A transition interrupted before a verifiable candidate installation remains blocked; retention alone is not a restore operation.

The retained original plan remains the approval authority. Recovery checks its canonical digest against the transition, its exact native installation layout, and its complete candidate-document inventory and bytes. Non-mutating installation observation checks the active receipt, executable, product aliases and strong-mode assets. It rejects a pending binary journal without repairing or deleting it. The shared legacy verifier performs recovery and cannot serve this admission boundary or public setup verification. Candidate length, hash, version, mode, native programs and any source-commit/root-generation/manifest-generation claims must agree with that receipt. Strong recovery requires retained authenticated-release claims; a user-only candidate retains its original user-owned release contract. These checks establish continuation of the previously admitted transaction, not fresh release availability or permission to initialize an installation.

Ordinary Linux full-setup retries also use non-mutating installation observation before deactivating an existing installation. The setup lease and matching pending plan do not authorize an unrelated binary journal; the deactivation preflight must not invoke the legacy verifier's implicit repair. A pending binary journal remains intact until a separately admitted binary-recovery operation owns it.

Recovery must execute the exact candidate bytes. A private installation-validation proof is bound to the original plan and can only satisfy revalidation of that same plan; it cannot supply an installation request. Public planning and ordinary apply retain their live release-verification boundary. Native accounts, programs, workspaces, policy narrowing and credential-slot selection are revalidated using the retained inputs before recovery enters mutation.

Pending recovery uses the same configuration, credential-action, broker-readiness, activation-last and acceptance implementation as ordinary setup. Missing inputs return promptly without prompting, leave admission closed and preserve the pending generation. Explicit credential inputs use the existing protected stdin, descriptor and file interfaces, limited to slots already declared by the retained plan. Rotation and revocation receipts remain authoritative; neither recovery nor a retry recreates old credentials. An accepted transition may be verified as a no-op, but failed verification does not authorize replay of an already-accepted setup.

The new command's argument parser, help and completion share one definition. Following valid argument parsing, success, missing-input and failure reports use `dev-auth-setup-recover-v1`. The report carries the process exit code and a fixed value-free error kind. Established change or no change is boolean; failure after entering mutation is `changed: null` unless the completed operation independently established progress. Pre-mutation authority rejection is unchanged and exits 4, invalid credential-slot input exits 2, blocking or missing-input conditions exit 3, and entered operational failure exits 1. Raw error chains and credential input values are not serialized. Native privilege is not acquired implicitly, and the existing exact-plan sudo setup helper does not gain a generic recovery or root-write interface.

## Evidence and remaining gates

The disposable native-user CLI fixture stages logical authority with a missing credential, deletes the original configuration inputs, repeats the pending setup, removes the original executable source and invokes the installed public command. It requires unchanged retained state and a structured input-required result rather than activation or dependence on discarded inputs. A differently hashed executable must fail before mutation. A deterministic committed binary-journal fixture exposed the legacy verifier deleting that journal during an authority rejection; public verification and recovery admission must instead preserve its exact bytes. This is not a process-death or power-loss simulation. Unknown credential slots reject unchanged, while an invalid descriptor for a required slot exercises the entered-failure report with unknown change. Focused retention checks cover changed bytes, short-lived configuration-input custody and suppression of private error text.

This is source-binary Linux evidence, not signed strong-mode, live enrollment or native non-Linux acceptance. Candidate-independent repair of an interrupted binary installation, prior-generation restoration, lower-level mutation coordination and whole-domain crash teardown remain separate requirements. Recovery is gated where a native non-mutating observation backend is unavailable. The exact-plan privileged helper needs a separately bounded recovery operation before ordinary native-user strong recovery can use that convenience surface. Production activation remains gated by the complete migration and release acceptance contract.
