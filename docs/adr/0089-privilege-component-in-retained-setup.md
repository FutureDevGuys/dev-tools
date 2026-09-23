---
authority: canonical
owner: dev-auth
---

# ADR 0089: Privilege component in retained setup

status: proposed
verification: pending

## Decision

Privilege-only setup is an explicit feature selection under the existing strong installation owner, not another installer or root directory. `purpose = "privilege_only"` uses deployment-document/intent v2, binary-plan v3 and full setup-plan v4. Omitted purpose retains credential setup and its existing canonical encodings. The new purpose requires Linux system ownership, empty credential/user-configuration actions and unconfigured native Git/gh fields; it does not discover those tools, consume a provider, or enroll a credential. Inactive setup is the template default. Transparent activation selects the native sudo bridge and privilege coordinator, not credential Git/gh aliases.

The existing installation receipt, setup exclusion, immutable retained generation, pending/accepted/restoring phases and exact-source recovery remain the sole owners. The privilege component adds fixed library, service, PolicyKit action, private policy, sudoers fragment and shared sudo-configuration identities to that generation. Payload metadata binds the embedded helper and declarative assets to the selected executable. Planning runs from the selected candidate; recovery already requires its exact approved bytes. Policy/configuration before-state is retained before mutation, activation is last, and verification precedes acceptance. Restoration reinstates the retained before-state with integrations inactive and does not reverse enrollment.

The sudo configuration renderer preserves unrelated bytes and native file mode. A marker alone is not ownership: replacing or removing a bridge block requires its retained exact bytes. Implicit native sudoers plugins are made explicit only inside the removable owned block. Native `cvtsudoers` inspection rejects an independent group plugin rather than overriding it. Other privilege integration files require retained ownership; an administrator-supplied privilege policy remains a separately parsed input. The privilege policy is published root-private because exact plans may include sensitive environment values. The native library is bounded at 16 MiB and remains ordinary, non-set-ID data.

The source path supports fresh privilege-only installations and same-purpose retained transitions. Replacing an existing credential installation with privilege-only intent is rejected. A credential deployment may instead select a separate `privilege_policy` under strong ownership. That full-generation v4 plan retains the existing credential installation purpose and binary-plan v2 shape, carries both policies and the native privilege payload, and preserves user configuration and credential action authority. Setup stops both native services under the same admission exclusion, activates privilege after credential integration, verifies both components, then accepts one retained transition. Restoration withdraws the owned privilege integration before restoring the retained credential, user and binary generation. Credential-only replanning cannot silently abandon an accepted privilege component.

Privilege-only restoration also restores the shared strong-installation definitions retained by the same generation. These are not credential configuration: omitting users or credential policy does not omit the receipt-owned systemd, sysusers and tmpfiles definitions. Observe their exact before/candidate pairs before mutation, stop the core services before restoring their definitions, and withdraw helpers only afterward. Initial restoration requires their absence; prior-generation restoration requires their retained bytes and permissions. Terminal retries verify these definitions as well as privilege integration and binary ownership.

## Admission and ordinary authorization

Installed privilege admission uses short shared setup leases around publication and native startup. Pending/restoring state or an exclusive setup writer denies new grants, delegation and privileged admission. Native sudo keeps the lease through managed policy/admission, not the running command. Long grants and running commands do not hold the setup writer out for their entire lifetime; the setup owner can stop the coordinator and prove its native domain empty. Observations, revocation and leave remain reducing/read-only operations. Explicit isolated native fixture runtimes do not inspect or lock the real installation.

Setup and recovery cannot execute inside the privilege domain they must terminate. `setup apply --authorize polkit` uses a receipt-validated exact helper through the focused one-shot privilege foundation, independently of sudo and reusable grants. The PolicyKit route rejects credential stdin before authorization; explicit protected credential files remain available. Its native input/output stays inherited. Unsupported noninteractive/deadline combinations fail before spawning, and ambiguous process statuses remain native statuses rather than invented approval/denial evidence.

## Verification and remaining gates

Regressions cover the missing Git/gh dependency, provider-free deployment normalization, legacy encoding, preserved native configuration, unowned block/group-plugin denial, strict service/teardown observations, short admission leases, independent setup context, literal PolicyKit helper invocation and credential-free selection of shared restoration definitions. Opted-in disposable systemd fixtures exercise privilege-only public recovery and inactive restoration with Git/gh unavailable and no credentials or password phase, including a separately selected partial-withdrawal case before the service-manager reload. Retained approval is synthetic; these are not signed intake or real-grant evidence. The partial-state fixture does not simulate hardware power loss or qualify every interruption point.

Release qualification still requires signed fresh setup and upgrade, all interruption points, native acceptance of composite existing-installation preservation, coordinator crash and pending-sudo quiescence across cutover, installed launch-with-grant, ordinary sudo/Ansible under the installed bridge, overnight acceptance and the applicable native platform gates. Source checks do not waive them.
