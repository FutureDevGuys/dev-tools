---
authority: canonical
owner: dev-auth
---

# ADR 0078: Complete strong-candidate receipt recovery

status: proposed
verification: pending

## Decision

[ADR 0079](0079-retained-strong-helper-completion.md) extends this boundary to completion of the ordinary setup helper and sidecar while privileged launcher and system assets must still be complete. The original receipt-only case and its evidence remain applicable.

Linux retained setup recovery may complete a strong installation's product receipt after the approved shared candidate has committed and all fixed privileged assets already verify. This extends ADRs 0072 and 0074 beyond user-only receipts without granting strong binary staging, asset repair or privileged-file publication. Initial recovery requires paired retained receipt absence and current product receipt absence. Upgrade recovery requires the exact retained inactive prior product receipt, a distinct candidate version and preserved authenticated history. Effective root, canonical strong paths and matching retained release provenance remain required; a source-built fixture's synthetic provenance does not authenticate a release.

Admission verifies the committed shared candidate, exact binary and public aliases, complete compiled system-asset digests, native programs, privileged launcher bytes and release-selected permissions, ordinary setup helper and matching sidecar. Missing or changed assets fail rather than being installed. Uncommitted binary receipts and unstaged strong candidates remain outside this path. The existing fixed-unit service observer additionally requires stopped, disabled, job-free units with the selected fragment paths and no independent drop-ins, plus native kernel-domain and broker-socket absence. This is observation only: receipt recovery cannot stop services, reload the manager, clear permissions or alter an override. The enclosing public operation retains native-account checks, private approval/documents, pending direction and the stable setup exclusion lease.

Recovery rechecks complete assets and service quiescence before binary-journal settlement, under its verification callback and before product receipt publication. An exact committed journal may be retired without changing the selected executable or links. Existing action names remain `complete_initial_binary_receipt` and `complete_upgrade_binary_receipt`. Established journal settlement remains known change if a later independent receipt prevents publication. Ordinary configuration/enrollment continuation follows complete product verification; receipt completion does not supply credentials or activate a workload.

Upgrade admission retains both the exact current document identity and its observed supported mode. The shared existing-directory replacement interface compares that identity and mode before publishing the new receipt. This supports the historical root-owned 0600 prior receipt and current 0644 prior receipt while selecting the strong successor's ordinary 0644 contract. User-only upgrades use the same conditioned replacement at 0600. Initial publication retains absent-current authority. A mode change, byte rewrite, missing expected receipt or foreign document is not implicitly adopted. No privileged helper, sidecar or system definition is rewritten by this operation.

## Verification and remaining gates

Three separately isolated native systemd fixtures cover initial absence, a 0644 prior receipt and a legacy-private 0600 prior receipt. Each holds setup exclusion, uses the production retained proof and publication path, verifies complete receipt/history and unchanged retry, rejects an uncommitted strong binary, rejects a missing helper and active sockets without losing the journal, and preserves a late independent receipt after established journal settlement. The upgrade fixtures also reject a late switch between the two otherwise supported receipt modes without replacing it. Helper, sidecar and system-asset inode/mode observations remain unchanged across receipt completion. These fixtures use synthetic executable/provenance data and do not launch those payloads or retrieve credentials.

Run the ignored `setup::recovery_native::native_disposable_strong_*_receipt_completion` tests individually in explicitly owned, bounded, network-free systemd containers with private cgroups and no host mounts. Fixed product paths must initially be absent. The pinned Fedora fixture's vendor-wide timeout drop-in must be moved aside only inside that container to reproduce the qualified no-drop-in layout; production rejection remains unchanged, as in ADR 0057. The container owner removes the fixture after success or failure. All-writer coordination, incomplete strong asset/binary recovery, signed public-CLI and process-death acceptance, active-broker teardown and non-Linux native qualification remain delivery gates.
