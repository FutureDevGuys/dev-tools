---
authority: canonical
owner: dev-auth
---

# ADR 0082: Retained strong binary forward recovery

status: proposed
verification: pending

## Decision

Linux strong setup recovery extends the exact binary-transition mechanism used by user-only recovery to an approved candidate whose shared binary receipt has not yet committed. Initial recovery requires retained/current product receipt absence and exact prior shared absence. Upgrade recovery retains the exact inactive prior product receipt and complete shared endpoint/history. The pending private setup generation, native root owner, canonical strong layout, exact running candidate, retained release provenance, native-account checks and setup exclusion remain mandatory. No new release, destination, alias, credential or approval is selected.

Staged recovery reuses the exact shared transition observer/recovery and conditional installation APIs. Product preflight admits only pointers belonging to the selected prior/candidate transition, verifies native programs and layout, and admits the complete fixed strong asset group before mutation. An exact uncommitted journal is rolled back to its retained prior endpoint before the same approved candidate is conditionally installed. Without a journal, the prior shared installation must already verify. The staged executable remains available through pointer restoration. All selected launcher, helper and system-definition observations and native stopped-state evidence are rechecked around binary restoration and inside the shared pre-activation callback without reacquiring its installation lock.

When the candidate executable is absent and no binary journal exists, the exact approved running candidate can supply its bytes. The strong helper/launcher proofs retain that source directory and exact leaf name, requiring root-owned ordinary 0755, single-link, bounded exact content. This preserves the public CLI's normal core/release-filename invocation contract; the source grants no destination or release authority. Initial recovery can also precede creation of the installation lock, binary directory and versions directory; retained setup data must already exist. Read-only absence admission does not create those directories or claim an empty namespace. Conditional shared installation rechecks absence under its own lock and prepares only the managed layout. Existing unsafe directories, unknown pointers, receipts and journals remain untouched.

After binary commit, the existing strong-completion group finishes the launcher, definitions/reload and helper pair before conditional product receipt publication. Its source remains bound for the current proof. Losing an external source after commit can therefore fail that attempt while retaining known change and the committed binary; a fresh proof selects the immutable installed candidate and no longer needs the original input. Completed receipt retries remain read-only. Initial/upgrade binary action names remain available when no asset publication is selected; the existing strong-installation names cover simultaneous fixed-asset completion.

The enclosing operation revalidates retained documents, native identities and forward direction before entering mutation, then continues ordinary configuration/enrollment and activation-last verification. Recovery does not stop active services to manufacture admission, revive completed restoration, replace missing upgrade product receipts, weaken source ownership, or adopt a new binary merely because the version matches. Errors after entered shared layout preparation can remain uncertain until an established mutation is reported. No shared API, schema or frozen publication identity changes.

## Evidence and remaining gates

Four disposable native systemd fixtures cover initial and upgrade staged/unstaged binary recovery. Staged cases cover exact uncommitted journals, partial aliases/active pointers and already-restored prior endpoints without journals, alongside missing launcher/helper/sidecar and a unit definition. A stale helper observation and an independent alias reject before binary settlement. A late product collision after journal rollback leaves the verified prior shared endpoint, known change and untouched missing strong leaves; correction plus a fresh proof resumes successfully.

Unstaged cases start with every fixed strong asset missing and no immutable candidate. The initial case also removes the installation lock, bin directory and versions directory and checks that read-only proof acquisition does not recreate them. Tests require complete final product/shared receipts and unchanged retry without the external source. A late unknown journal, changed source, source special bits and source hard link reject without staging. Removing the external source after actual candidate commit preserves the prior product receipt and absent launcher, and a fresh installed-candidate proof completes without that source. Existing complete-receipt tests still reject a stale committed proof after the shared endpoint changes, while fresh proofs can now select the uncommitted forward transition.

Run the four ignored `setup::recovery_native::native_disposable_strong_{initial,upgrade}_{staged,unstaged}_binary_completion` tests individually by their exact names under the network-free, mount-free, private-cgroup systemd contract in ADR 0078. Synthetic executable/provenance bytes are not executed or signature-verified. Signed public-CLI recovery, actual process death/power loss, fixed system-definition parent prerequisites, all-writer coordination, active-broker teardown and native non-Linux qualification remain distinct delivery gates.
