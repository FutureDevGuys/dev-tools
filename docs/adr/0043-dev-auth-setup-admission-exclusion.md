---
authority: canonical
owner: dev-auth
---

# ADR 0043: Setup admission exclusion and durable activation state

status: proposed
verification: pending

## Decision

Full setup and native workload admission share one stable, runtime-scoped lock per installation mode and native owner. Workloads hold nonblocking shared leases; setup requires a nonblocking exclusive lease. Concurrent workloads remain possible, but an active workload or another setup prevents a new setup mutation promptly. The runtime lock is not removed with installation artifacts. The product-neutral installation foundation supplies shared locking with the same filesystem custody and post-acquisition named-inode validation as its existing exclusive lock.

The Linux privileged dispatcher and user-only supervisor acquire their leases before loading executable policy and retain them through their owned cleanup. The system broker independently retains leases for pending and active registrations, including after dispatcher failure. Cleanup failure retains exclusion until cleanup succeeds; an expired pending registration uses the same teardown path. This coordination does not itself prove descendant containment, and a process lock cannot substitute for whole-domain native cleanup after broker death.

Before full setup deactivates integrations or changes release/configuration state, it retains an owner-private immutable generation under the approved plan digest and then publishes a `dev-auth-setup-transition-v1` marker binding both that digest and the retained generation's exact length and hash. The generation includes the approved plan, exact candidate policy/configuration bytes, prior policy/configuration and receipt bytes, and receipt-owned workload links and desktop contents. Candidate capture rechecks every source against its approved identity before publication; later removal or replacement of a source cannot change the retained bytes. V3 migration also retains the separate v2 user authority paths. Executable payloads remain under their immutable installation receipt authority; credential values are never copied into this journal. Credential-action receipts are evidence, not authority to reverse enrollment effects.

Pending state denies new successor admissions even after setup exits or the machine restarts. Only the same pending plan with intact retention may resume, including interruption before installation creates a candidate receipt. A pending retry never recaptures partially changed state. An orphaned generation cannot be replaced with different bytes. Full postcondition verification and retention integrity precede atomic acceptance publication; public read-only setup verification does not treat a pending marker as accepted. Identical retries synchronize unchanged bytes without rewriting the logical state.

Pending retries resolve candidate policy and configuration from the retained generation, not from the original source paths. The reader checks the complete plan, ordered document inventory, lengths and hashes, then repeats native account, program, workspace and policy validation. Configuration installation uses short-lived owner-private inputs through the existing digest-checking installers; recovery never recreates a caller's original source path. Credential-action receipts retain their independent authority across this retry. This source-document recovery does not make a missing release cache or executable candidate available.

An absent marker preserves the existing legacy installation path. Already-accepted state does not require a new marker merely because an equivalent setup plan was rendered again. Unknown schemas, malformed markers, unsafe custody and another pending plan fail closed. New markers and changed installation state remain visible to the setup change report.

Acceptance itself requires the exact retained plan digest even when the marker is already accepted. A newly rendered equivalent plan whose full postcondition is satisfied instead leaves the existing accepted generation untouched; verifying equivalent state does not accept another transaction or replace its rollback inputs.

## Compatibility and remaining gates

Older released executables do not participate in this protocol. Stopped-broker migration, receipt-owned privileged-launcher replacement and the user-only legacy-session absence check remain necessary; a lock cannot retroactively coordinate an old writer. Direct lower-level policy/configuration maintenance, uninstall and rollback still require integration with the full retained transaction before the successor is production-ready.

Public Linux legacy repair, binary-only rollback and uninstall share this native exclusion and reject full-generation state under [ADR 0045](0045-dev-auth-legacy-rollback-exclusion.md). Configuration-aware restoration and coordination of the remaining lower-level mutations are still incomplete.

Retention is not by itself an implemented restore operation. Candidate-independent recovery, receipt-owned rollback, immutable binding activation, crash teardown and signed native acceptance remain release gates. Restoring configuration cannot undo credential rotation or revocation. No production installation or credential enrollment is authorized merely by these source changes.

Strong replacement retains and deactivates accounts removed by the candidate policy under [ADR 0046](0046-dev-auth-retiring-account-generation.md). Their native identities and both configuration versions remain part of the approved generation without granting them candidate activation authority.

## Evidence contract

Tests cover concurrent shared leases, writer exclusion, detached lock inodes, durable pending state after writer exit, same-plan resume, mismatched acceptance, missing/drifted retention, orphaned snapshot preservation, post-cleanup lease release and retained exclusion after failed cleanup. Disposable native-account setup tests require a pending marker and retained generation while credentials are missing and an unchanged repeat. Native release acceptance must also exercise pending-session expiry, killed dispatchers and brokers, power-loss recovery, live admitted workloads and receipt-owned rollback.
