---
authority: canonical
owner: update-all
---

# ADR 0031: Nonactivating authenticated artifact retention

status: proposed
verification: pending

## Context

An operator may need to retain an original authenticated historical artifact
without activating a downgrade or changing accepted release history. Existing
candidate intake and rollback do not provide that separate custody operation.

## Decision

Add the explicitly offline operation:

```text
update-all product retain PRODUCT --root-document ABS --manifest ABS --artifact ABS [--json]
```

PRODUCT is an existing registered product. The paths select complete original
local input, never a destination or trust override. The supplied signed root must
be the **exact currently accepted root**, not merely the root distributed with
the historical release. Its present key revocations and the current fixed
product/target/URL/protocol policy authenticate the original stable source-bound
product-v2 manifest. Future versions/generations and equivocation at accepted
boundaries remain rejected. Artifact length and SHA-256 must match exactly.

## Invariants

This is explicit new retention authority. It does not assert prior historical
acceptance and does not install a downgrade. It neither advances nor resets the
monotonic ledger, changes trust or release caches, initializes an installation,
repairs pointers, invokes setup or privilege, executes an artifact, activates a
version, or changes active/previous receipt identities. Ordinary install/apply
antirollback and rollback eligibility are unchanged. An independently owned pin
protects retained content from ordinary version retirement; it grants no
permission to activate that content.

Protection concerns ordinary managed update retirement and rollback, not an
explicit owned uninstall. Old binaries that do not understand retention pins
remain outside the participating-writer contract and must be quiescent.

## Custody and interruption

Initial support is Linux x86-64 with an already valid managed installation and
an existing independently accepted ledger. External commands, absent or damaged
installation authority, pending installation transitions, lost history, unsafe
inputs and unknown destinations fail closed. There is no adoption of an
unowned destination even when its bytes happen to match the signed artifact.
Already receipt-owned active/previous content may gain explicit retention
ownership; that first publication is a change. An exact fully retained repeat
is a synchronized no-op.

The product holds its existing nonblocking release-writer lease once, through
authentication, publication and final observation. Participating product writers
use this same lease; older implementations must be quiescent. Existing shared
installation observations take and release their own short observation locks;
there is no nested release lease or callback that reacquires an installation
lock. Retention does not invoke activation, migration or recovery primitives.

Only the typed product layout plus the authenticated version derives the
destination `versions/VERSION/ARTIFACT`. Product-private `retention-v1` stores a
bounded strict intent journal and one bounded strict retention receipt per
version. Each binds the exact layout, product, target, version, source commit,
manifest bytes/digest and artifact length/digest. A journal precedes destination
directory and file publication. All file publications use descriptor-retained
parents, no-replace initial publication, final data/mode sync and parent sync.
Only exact receipt or journal ownership admits an existing destination.

After executable and proof receipt publication, the product publishes the
foundation's typed ownership pin. Both ordinary v1 and v2 cleanup validate that
pin's exact derived version, layout, owner, executable mode, length and digest
before preserving it. Invalid pin custody blocks destructive cleanup rather
than becoming an unchecked keep list. A fresh read-only installation observation
must still equal the initial active/previous receipt before exact journal
retirement and success. No code copies or rewrites activation receipts.

Interruption preserves the original installation plus a recoverable retention
intent. Repeating the explicit command requires the same manifest/payload,
reauthenticated against the then-current accepted root/policy. Root rotation
does not rewrite the intent: only the current root input is substituted while
the original manifest and content binding stay exact. A different pending
bundle is blocked, never cancelled or reinterpreted. Partial candidate staging
left by process death is neither age-selected nor removed by a broad cleanup.

## Rejected alternatives

Lowering accepted history to install historical content, treating retention as
activation authority, or adopting an equal-byte unowned destination would violate
the decision. Broad cleanup of interrupted staging cannot replace exact retained
journal and receipt ownership.

## Consequences and known limitations

The additive `update-all-product-retention-v1` JSON document reports product,
operation, fixed outcome/error kind, exit code, nullable `changed`, and the
authenticated retained identity on success. Change concerns retention journals,
receipts, pins, directories and executable publication, not the acceptance
ledger or disposable caches. Before mutation it is false; after entered
uncertain publication it is null unless earlier change is established; a
completed receipt-current repeat is false. Errors never serialize input paths,
authority text or subprocess output. JSON stdout remains one document. Exit
categories are 0/1/2/3/4/130 under the product standard.

This operation is separate from ADR 0030's common lifecycle and ADR 0025's
candidate bundle intake. Those operations still cannot admit a historical
candidate by lowering accepted history. Workspace ADR 0126 defines the additive
foundation pin and strict fresh-document publication. Existing published crate
APIs, archives, release bytes and installation schemas are not replaced. This
source prepares unreleased Update All 0.1.13; accepted 0.1.12 remains immutable.
Source-bound dependency publication remains required for external crate users.
This source record claims no compiler, native or platform acceptance.

## Verification

Related existing intake regression contracts are
`offline_signed_bundle_rejects_invalid_signed_authority_before_activation` and
`offline_signed_bundle_rejects_unsafe_and_bounded_inputs`.
They cover signed-input rejection and custody boundaries, not the new retention
operation. Retain-specific conformance changes and execution remain pending.

## Runtime acceptance

Under the current no-tests source-only instruction, conformance changes and
execution remain pending. Before release, qualify signed native retention of a
missing historical file, active/previous retention, exact repeat, subsequent
normal v1/v2 upgrade and rollback with pinned content preserved, lower-generation
candidate rejection on the normal install path, revoked signer/current-root
rejection, unsafe custody and equal-byte unowned collision, competing writers,
and actual process interruption at journal, artifact, receipt, pin and journal
retirement boundaries. Verify every activation/ledger/trust/cache byte and
pointer is preserved by retain, value-free failure/nullable progress, native
filesystem durability and network isolation. Old writers require a separately
established quiescent cutover; source formatting is not acceptance evidence.

## Supersession conditions

Supersede this record if retention changes activation, accepted-history or trust
authority, destination ownership, participating-writer rules, or supported native
scope. Preserve explicit nonactivating custody and exact interrupted-intent binding.
