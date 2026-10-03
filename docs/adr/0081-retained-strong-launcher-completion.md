---
authority: canonical
owner: dev-auth
---

# ADR 0081: Retained strong launcher completion

status: proposed
verification: pending

## Decision

[ADR 0082](0082-retained-strong-binary-forward-recovery.md) integrates this component with initial/upgrade binary recovery before candidate commit, including retained-source staging.

Retained Linux strong recovery may complete the fixed privileged workload launcher after the approved shared binary commits. This extends ADR 0080 using the product-owned descriptor checks and ordinary-publication sequence from ADR 0054. It grants no arbitrary executable, path, permission, root acquisition, binary staging or service activation authority. The outer owner retains effective root, canonical strong layout, exact release provenance, native-account and retained-generation validation, inactive aliases and setup exclusion. Every selected system definition and helper leaf must already be admitted, and native services/domains/sockets must be quiescent, before launcher mutation.

The launcher proof holds its existing canonical root data directory and candidate source directory. The source must be exact root-owned, bounded, single-link ordinary 0755 candidate bytes. The current fixed launcher may be absent or match the exact candidate/prior executable with that release's own launcher permission, or ordinary 0755 as an interrupted intermediate. Legacy bytes do not gain set-ID merely because the successor uses it. Unknown bytes, wrong owner, symbolic/hard links, unrelated permission bits and redirected parents reject without adoption. The selected content identity and mode or absence remain bound through the first mutation; a later admissible edit requires a fresh proof.

Completion first revalidates the committed binary, selected product receipt, admitted definitions/helper pair and native stopped-state evidence. When replacement is required, it clears set-ID on the held prior inode and records the established syscall before synchronization and named-identity checks. The shared ordinary-document writer then conditionally publishes exact candidate bytes at 0755. Only after rechecking that candidate and the enclosing generation does the product assign the candidate release's fixed final permission on the held file, synchronize it and its parent, and verify the completed pair. The prior inode remains ordinary after replacement, including through an independently retained open descriptor. No shared set-ID publisher or general permission capability is introduced.

Each established permission or content change is reported before later checks. A failed callback or independent file collision cannot erase known progress, grant privilege to unrelated bytes, overwrite the independent leaf or publish the product receipt. A fresh proof can resume recognized ordinary prior/candidate intermediates after conflicting state is independently corrected. A matching complete launcher synchronizes without republishing; a completed product receipt retry remains read-only.

One private strong-completion group owns the admitted launcher, definitions and helper pair. Launcher completion precedes system-definition publication/reload, then helper completion and conditional product receipt publication. Other components revalidate the completed launcher around their writes. Partial asset verification is private to this retained proof; ordinary installation/runtime verification always checks the full asset set. Final strong completion requires loaded stopped/disabled units without a pending reload. Public arguments, receipt schemas and action names remain unchanged.

## Evidence and remaining gates

Three isolated native systemd fixtures exercise initial absence, successor upgrade and a retained synthetic `0.3.11` prior release. They cover absent launchers, ordinary and release-permission candidate/prior pairs, full product/history verification and unchanged retries. An open prior descriptor proves set-ID was cleared before replacement. The legacy fixture rejects prior bytes at successor set-ID permissions. Other checks reject stale valid publication, unsafe modes, hard/symbolic links and a set-ID candidate source.

A callback replaces the launcher after ordinary publication; recovery preserves the independent bytes and prior product receipt. Additional callbacks invalidate the helper immediately after each available launcher mutation boundary: ordinary candidate publication, candidate permission assignment and prior privilege withdrawal. Known change and the exact intermediate mode survive each failure. Fresh proof admission rejects the independent helper and resumes only after correction. Fixed definition and helper inode/mode observations remain unchanged by launcher completion.

Run `setup::recovery_native::native_disposable_strong_initial_launcher_completion`, `native_disposable_strong_upgrade_launcher_completion` and `native_disposable_strong_legacy_launcher_completion` individually with `--ignored --exact` under the disposable systemd contract in ADR 0078. These use synthetic retained executable/provenance bytes and do not execute the set-ID payload or authenticate a release. Signed public-CLI installation and recovery, actual process death/power loss, missing-parent completion, uncommitted strong binaries, all-writer coordination, active-broker teardown and non-Linux native qualification remain required. Exact accepted `0.3.11` verification compatibility remains unchanged; no legacy release is rebuilt or reissued.
