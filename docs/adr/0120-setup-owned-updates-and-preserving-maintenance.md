---
authority: canonical
owner: dev-auth
---

# ADR 0120: Setup-owned updates and preserving maintenance

status: proposed
verification: pending

## Update authority

Dev Auth adds the common `update status`, `check`, `install`, `apply` and
`rollback` grammar and the v2 common result. Status uses authenticated local
metadata; check is the explicit metadata network boundary. Artifact preparation
is separate and is reached only by online install/apply needing newer bytes.
Unmanaged executables report external. First installation returns requires-setup
because the update layer cannot create policy or enroll credentials. An ordinary
user targeting a Strong installation likewise receives requires-setup; the
existing native administrator handoff remains explicit.

Apply requires an intact Accepted full setup generation and its current exact
product receipt. The parent process authenticates the selected release, snapshots
retained public policy/configuration/binding sources into owner-only staging,
and retains the staging lock and directory descriptors. All intent fields stay
bound to the accepted generation. Mutable binding refresh may observe new bytes
at the approved native location while preserving intent; a different continuation
location is rejected. Unchanged pins rebase against the current source-free set
and separately verify copied executable and private shell payload custody.
No original policy/configuration source checkout is required.

The authenticated candidate executes through the existing held-executable and
bounded-command foundation. Retained ancestor/file descriptors prevent pathname
substitution at execution. The candidate inherits only the private staging
lock/directory descriptors, closed stdin, controlled environment and working
directory. Its private request/result schemas deny unknown fields and bind the
request digest, retained predecessor and exact release identity. The worker has
no network callback or credential input. It reauthenticates the exact locally
accepted release and derives the replacement setup plan using its own embedded
native grant payload. A plan built by the old executable cannot supply the new
release's sudo bridge digest. Fixed stage diagnostics contain no caller values
or captured child output.

The normal full setup lease, native independent execution checks, coordinator
shutdown, current-state CAS, retained before/candidate generation and final
activation ordering remain authoritative. The source staging lock survives
parent descriptor closure. Reclamation removes only complete recognized private
snapshots with an unlocked, same-inode owner-only lock, intact directory identity
and exact recognized regular single-link children. Foreign or incomplete entries
are retained for explicit inspection.

## Credential preservation

Credential-bearing updates derive `dev-auth-setup-plan-v6`, adding the optional
`dev-auth-credential-preservation-v1` observation. Legacy v3/v4/v5 encoding omits
the field and remains unchanged. The observation binds the exact Accepted plan,
product receipt, credential readiness disposition and completed-action receipt
digest or absence. It contains no credential value. Before any mutation, the
exclusive setup owner proves the predecessor and retained source mapping; an
entered retry proves its exact retained plan. An unaccepted predecessor, foreign
source, missing retention, changed credential disposition or changed action
receipt rejects before enforcement mutation.

Full setup generation credential observations are metadata-only. Strong mode observes
credential-file custody and size without opening its contents. UserOnly observes
only exact service/username attributes with Secret Service SearchItems on the
already-running unique bus owner. It never opens an encryption session, requests
credential values, unlocks a collection or prompts. A unique unlocked item is
present; no matching item is absent. Locked or ambiguous matches, unsupported
metadata methods and unavailable session/service/transport are explicit errors,
never absent enrollment. The whole lookup has one bounded deadline and retains
and closes its socket custody. This applies transitively to update planning,
fingerprints, preservation snapshots, postconditions, maintenance and retries.
Enrollment presence does not establish credential content or provider usability;
explicit credential operations retain their existing value validation.

V6 never enters enrollment, rotation, revocation or credential input. Existing
completed action authority is preserved verbatim, including intentionally revoked
slots. Repeating original declarations with empty input would not establish this
contract: a missing completion record must never cause action replay. The
preservation observation is checked again before activation and by postcondition
and recovery. V6 recovery rejects credential sources. Existing schemas retain
their original explicitly approved credential behavior. Older readers fail closed
on the new schema/field; signed release qualification determines rollout.

Rollback is offline and uses full retained inactive restoration rather than the
legacy binary-only swap. It restores authenticated receipt-owned retained bytes,
keeps integrations inactive, preserves irreversible credential actions and
retains one-way restoration direction and resumability.

## Preserving maintenance

The public Linux `setup repair` and `setup uninstall` commands select the full
maintenance route whenever a full setup transition marker exists. Malformed or
unsafe markers select that route and fail closed; they never authorize legacy
fallback. The legacy library-native functions retain their full-generation guards.
This supersedes ADR 0045's public CLI refusal with the composed source route; signed native qualification remains a release gate. Binary-only rollback remains forbidden for full generations;
common update rollback continues to use complete retained inactive restoration.

Maintenance extends retained direction with `repairing`, `uninstalling` and
`uninstalled_inactive`. It retains the original setup generation exactly and
captures one separate immutable `dev-auth-setup-maintenance-generation-v1`
snapshot before publishing direction. The snapshot binds the operation, exact
candidate-derived binary receipts, selected document/binding authority and
value-free credential readiness/action-receipt evidence. It never retains
credential material. Same-direction retries use exactly that snapshot; terminal
publication validates both retained identities. Repair can return to Accepted
only after the complete preserved postcondition. Uninstall remains terminal and
inactive; a separately approved new setup is required for future activation.
Pending setup and restoration retain their own recovery routes.

The native owner holds one nonblocking exclusive setup lease across observation,
mutation and verification. Maintenance-domain absence and independent execution
remain mandatory. An active grant coordinator is stopped before proving its
native domain empty. Broker/dispatcher/helper replacement uses the retained
bounded service shutdown backend and complete unit/domain/socket postconditions.
Active workloads and legacy user sessions block mutation. Existing native
administrator/authentication handoffs remain explicit and unchanged.

Repair accepts only exact candidate-owned endpoints or narrowly authorized
absence. A focused product-neutral retained-receipt repair primitive reconstructs
missing shared receipts/activation aliases from typed retained authority, after
observing every artifact/link and refusing pending journals or foreign endpoints.
Product-owned helpers/configuration are repaired from retained candidate bytes.
Copied executable pins and private shell payloads require intact retained custody;
missing third-party bytes are not rediscovered or copied from a mutable live
source. Binding sets are republished from exact accepted source-free authority,
with no generation advancement or mutable target rehash. Aliases and desktops
activate only after payload and configuration verification.

No repair/uninstall path enters credential enrollment, rotation, revocation or
input. Completed-action receipt bytes and readiness disposition are checked
against the separately captured maintenance snapshot before enforcement mutation,
again before activation, and on retry. Missing or drifted completed authority
cannot cause replay. Uninstall preserves the current selected configuration and
credential state while retiring exact owned integrations, activation pointers,
receipts, privileged helpers and service definitions. Grant withdrawal removes
only its retained owned sudo block and component files, preserving unrelated
native configuration and grant policy. It does not restore an older Dev Auth
bridge/library or previous policy. Every selected object is observed before the
first removal; foreign replacements reject. Terminal verification proves complete
inactive enforcement and exact preserved metadata.

Immutable candidate/version artifacts, copied/private binding payloads and
retention remain explicit continuation/rollback custody. This operation does not
claim complete artifact disposal or credential/configuration purge. The result
includes the retained retry executable after public aliases are removed. Known
change, known no change and unknown entered progress remain distinct; snapshot
publication and direction changes count as durable managed change. All failures
are fixed, value-free categories.

Source regressions must cover retained snapshot immutability/direction, missing
owned endpoint repair, foreign/journal refusal, unchanged repeat, complete inactive
retirement and preserved configuration/action bytes. The existing disposable
installed user fixture is extended through the public commands and retained
executable retry; no second native harness is introduced. Formatting/static checks
are the current evidence. Compiler, lint, signed upgrades, Strong combined
coordinator/broker teardown, each crash boundary, copied/private binding custody,
credential byte preservation and native platform qualification remain gates.

## Verification and release gates

Source regressions cover the common local grammar/results, invalid invocation
without caller-value diagnostics, external/setup classification, private worker
exclusion from completions, retained staging lock lifetime and strict private
request/result authority. Existing setup, grant, binding, release and restoration
regressions continue to own their boundaries. This slice has been parsed and
formatted only; compiler and runtime execution are deferred by the explicit
Syscfg compiler quiet window. No test-driven result is claimed.

Routed builds, focused tests and lint must precede acceptance. Disposable native
signed credential-only, privilege-only and combined upgrade/rollback acceptance
must exercise changed embedded bridge/maintenance payloads; original source
removal; mutable and copied/private binding retention; credential and completed
receipt byte preservation; active coordinator/broker quiescence; worker timeout,
parent death and process-domain cleanup; each crash publication boundary;
foreign drift; and unchanged retry. Native non-Linux adapters, production install,
release publication and full conformance promotion remain unclaimed.
