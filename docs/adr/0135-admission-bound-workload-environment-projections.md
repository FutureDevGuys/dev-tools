---
authority: canonical
owner: dev-auth
---

# ADR 0135: Admission-bound workload environment projections

status: proposed
verification: synthetic Linux user-only acceptance passed; Strong and signed delivery pending

## Decision

Reuse the v3 workload's existing trusted launcher, logical-resource resolver,
broker and final native process lifecycle. An optional `secret_projections` list
on the administrator workload cap authorizes exact logical-resource/destination
pairs. The user workload may select only an exact subset. Each selected resource
must independently retain exportable read and environment-projection authority
through the cap, profile and workload. Empty lists preserve the legacy default.
No new command selector, provider, broker, shell template, harness adapter or
credential storage is introduced.

The first declarative slice supports environment destinations only:

```toml
secret_projections = [
  { resource = "service-token", kind = "environment", target = "SERVICE_TOKEN" }
]
```

The same declaration belongs in the workload cap and its narrowed user workload.
The already configured trusted executable remains the consumer. Arguments after
`workload launch NAME --` are raw native arguments to that executable, not another
executable selector. Argument policy is unchanged: a trusted shell or another
program that itself executes arguments retains that explicitly selected power.
Do not configure a generic command executor when policy intends one fixed tool.

Destinations cannot override admission markers, executable-search/loader controls,
managed Git/GitHub/SSH settings or shell startup controls. Validation happens
before provider work and rejects duplicate/unknown targets, unsupported projection
kinds and undeclared authority. Standalone `secret exec` retains ADR0040's separate
arbitrary-command authority and four projection forms; it is not a security-
equivalent substitute for a configured consumer.

## Admission and custody

A version/domain-tagged JCS SHA-256 digest binds the resolved launcher path and
exact ordered projection list into the existing session authority. Ready responses
carry that optional digest. The final consumer gate compares session, owner,
execution UID, workload, profile, mapping and existing hard deadline before any
secret read, then again after all reads and command preparation. A renewed soft
lease does not extend the hard deadline. Some-to-None mapping removal is checked,
not treated as a legacy bypass. Missing/denied/unrepresentable material or changed
admission prevents target execution. No ambient value substitutes for a failed
projection. Unrelated inherited environment semantics are unchanged.

Before fetching material, the final gate retains the configured executable using
`dev-tools-command::HeldExecutable`. Pathname replacement during retrieval cannot
redirect delivery. This preserves existing launcher trust; it does not freeze an
ordinary owner-writable executable at initial admission, prevent authorized
in-place writes, or create a hostile-same-user isolation claim. Existing Strong
root custody and copied/pinned binding identity checks remain mandatory.

The existing `secret_execution::Prepared` owns command preparation. Its callback
enters the existing user-only, Strong, sandbox-final or nested launch path. Values
are never sent through root-dispatch environment handoffs or sandbox-adapter argv.
All values are acquired before final consumer spawn/exec and before the existing
native launch-grant activation/release barrier. Preparation does not refresh a
Sudo timestamp or change grant scope/lifetime. Failure preserves existing pending-
grant revocation and session cleanup. No provider timeout, bootstrap timeout or
native security permission is expanded. The existing 15-second startup-proof
window includes these reads while a broker read may wait longer; slow-provider
failure and pending-grant revocation need explicit native acceptance, not a
silent timeout increase.

As with explicit environment projection, bytes enter the native child's OS
process-environment trust boundary; command environment allocations and child
copies are not claimed to be zeroized. Values do not enter policy, receipts,
control observations or product diagnostics. This declaration cannot protect a
secret from a consumer explicitly trusted to receive it.

## Compatibility and rollout

The optional authority field defaults to None and is omitted for empty legacy
workloads. The broker protocol remains an internal matching-installation protocol.
Old strict authority decoders reject a nonempty new registration; new final gates
reject absent/mismatched digests for nonempty declarations. No silent fallback to
standalone secret exec or ambient credentials is allowed. Install matching core
and helpers through existing signed setup/update ownership. Keep active policy
unchanged until that exact platform and release are qualified. Retained immutable
rollback versions retain their previous authority files and behavior.

## Acceptance

Source tests cover cap/profile/workload narrowing, reserved destinations, omitted
legacy bytes, malformed protocol fields, mapped and unmapped admission changes,
late failure with no target start and raw argv/environment preservation. Source
review checks each final launch integration seam; the focused copied-shell test
requires native root-custodied system executable ancestry. Neither mocks nor
wiring review establish Strong or sandbox runtime acceptance. The installed synthetic user-only fixture must
prove direct arbitrary native consumers and stock executables, actual provider
selection, path replacement during retrieval, admitted mapping reload denial,
nonzero status/streams/cwd/UID, redacted failures and session cleanup. Private
fixtures do not consume real credentials or modify host setup.

Source/build success is not installed native acceptance. Strong root/cgroup,
sandbox custody, approved-grant activation and cleanup, signed installation/update
and real Sudo/PAM-facing behavior remain separate gates under ADR0115, ADR0119 and
ADR0131. Finite privileged operation tests, prompt-free approval-required denial
or an ordinary secret child do not prove stock Sudo authentication works. This
slice adds no Sudo installation, NOPASSWD rule, password injection or live policy
change.

### Disposable namespace custody

The synthetic user-only fixture maps only its native fixture UID. Host-root
files under the bound `/usr` consequently appear as overflow UID 65534 and are
correctly rejected by the executable-custody validator. Its configured stock
`printenv` consumer is therefore a byte-identical copy prepared in legitimate
fixture-user custody before policy declaration and admission. The exact copied
path is the admitted launcher. The v4 metadata-only native diagnostic observed rejection of the unmapped
system path and did not execute it. The diagnostic reports custody rather than
requiring a particular host UID map. The repaired configured-consumer fixture passed on native Linux with synthetic
material. It qualifies ordinary system-tool behavior and raw argv through the
same interface, not host-root custody inside the disposable namespace. The
separate copied-shell component also passed. Native Strong qualification remains
a separate pending gate.
