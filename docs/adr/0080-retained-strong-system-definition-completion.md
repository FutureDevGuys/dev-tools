---
authority: canonical
owner: dev-auth
---

# ADR 0080: Retained strong system-definition completion

status: proposed
verification: pending

## Decision

[ADR 0081](0081-retained-strong-launcher-completion.md) extends this path to fixed retained launcher completion before publishing system definitions.

Retained Linux strong recovery may complete the five fixed compiled system definitions after the exact approved binary is committed and the privileged launcher already verifies. This extends ADR 0079 without granting binary staging, privileged-launcher publication, service start/stop/enable, arbitrary destinations or release authority. Effective root, canonical strong layout, inactive aliases, retained release provenance and the enclosing generation's approval, native-account validation and setup exclusion remain required. Missing destination parents are not created by this component.

The candidate asset digest map must equal the executing candidate's compiled inventory. A prior strong receipt may contribute only the same exact path set and valid retained digests. Each current leaf must be absent or a root-owned ordinary 0644, bounded single-link regular document matching the exact candidate or retained prior digest. All leaves are admitted through held `ExistingDocumentDirectory` parents before mutation, retaining each observed content identity or absence. Unknown content, redirected parents, symbolic/hard links and special permission bits reject without adoption. A later otherwise admissible writer invalidates the selected proof; a fresh proof may resume an interrupted mixed generation.

Publication uses the shared existing-directory document boundary. Before each write, recovery rechecks the committed candidate and selected product receipt, privileged launcher, observed helper pair, previously published target definitions and remaining selected definitions. Each established write is reported before further checks. A later collision preserves independent bytes and known progress. The component does not claim atomic exclusion against an independent root writer; the outer setup lease and retained pending generation remain the participating-writer authority.

The existing fixed-unit observer admits loaded retained units or explicit terminal `not-found` observations while definitions are incomplete. Every unit must be stopped, disabled and job-free, with no foreign fragment/drop-ins or process authority, and kernel broker/workload domains and socket paths must be absent. A missing file never grants permission to stop a process. Once all candidate definitions are present, the component submits a fixed noninteractive manager reload only when a definition remains unloaded or needs reload. A successful request is recorded before final observation; completion requires loaded stopped/disabled units without a pending reload and independent kernel/socket absence. No start, stop, enable or disable request is available through this path. Native commands reuse the existing bounded shared runner and service-operation budget.

System definitions complete before the helper pair and conditional product receipt. Complete receipt retries remain read-only. The strong-installation action names introduced by ADR 0079 also cover selected definition publication. No public arguments, schemas, generic publication primitive, frozen package or release bytes change.

## Evidence and remaining gates

The service-backend regression covers reload from explicit missing definitions, successful request followed by failed loaded-state verification with known change preserved, unchanged retry, active-unit rejection and late kernel population. Two isolated native systemd fixtures exercise initial and retained-upgrade recovery with wholly absent and mixed absent/prior/candidate fixed definitions, full final installation verification, root ordinary modes and unchanged retry. They reject stale valid publication, foreign content, special bits and hard/symbolic links across all five leaves. A callback writes independent bytes into a later definition after the first actual publication; recovery preserves those bytes and the prior product receipt, and resumes only after correction and a fresh proof. Active socket state remains a rejection even when its unit file has disappeared. Helper and privileged-launcher inode/mode observations remain unchanged.

Run `setup::recovery_native::native_disposable_strong_initial_assets_completion` and `native_disposable_strong_upgrade_assets_completion` individually with `--ignored --exact` in the owned, network-free, mount-free, private-cgroup disposable systemd environment described by ADR 0078. The fixture uses synthetic executable/provenance bytes and does not execute those payloads, authenticate a release or retrieve credentials. Signed public-CLI recovery, actual process death, missing-parent and privileged-launcher completion, uncommitted strong binaries, all-writer coordination, active-broker teardown and non-Linux native qualification remain delivery gates.
