---
authority: canonical
owner: dev-auth
---

# ADR 0117: Deployment-selected binding source lifecycle and code trust

status: proposed
verification: pending

## Decision

Continue [ADR 0009](0009-smart-workload-continuation-bindings.md) and
[ADR 0017](0017-binding-target-specific-resolution.md) through explicit
deployment-selected plans and a setup-owned binding set. The successor draft
schemas are `dev-auth-workload-binding-plan-v3` and
`dev-auth-workload-binding-receipt-v3`. Each intent includes `code_trust` as
`pinned` or `mutable` and an optional desktop-entry selection. This supersedes
the unintegrated v2 draft contract; v1/v2 plans and foundation receipts are
rejected and must be regenerated with new plan/predecessor/approval digests.
No installed receipt, enrollment, release ledger or published binary is
relabeled or reissued.

Preserve [ADR 0113](0113-exact-native-binding-identity-encoding.md) exactly:
native device/inode fields remain `Option<u64>` in Rust and emit canonical
unsigned decimal strings in JSON, JCS and TOML. Legacy integral identity values
decode only where exact, and every native comparison remains exact. A matching
hash of rounded or noncanonical plan bytes cannot transfer approval.

`pinned` remains the public planning default. A user-owned executable or
user-writable ancestry requires the explicit `mutable` choice. Changing code
trust is a rebind. Native containment and resolved credential/workload authority
remain separate from same-user mutable-code trust. Mutable strong launchers
require an active root-custodied installed binding set, exact native account,
configured workload/launcher and receipt-owned alias at each launch boundary.
Unbound strong launchers retain independent root custody. Later edits at the
approved mutable location do not cause runtime rehashing or extend admission.
Refresh still observes new exact bytes; a different continuation location
requires explicit rebind.

`dev-auth-deployment-v3` names each binding's native user, binding name, absolute
plan path and exact lowercase SHA-256. An explicitly empty list withdraws prior
bindings. Existing v1/v2 deployment sources cannot silently abandon a binding
generation. The full setup successor uses plan v5 when binding selection is
explicit, before the optional grant component's v4 selection. Both components
retain the existing one setup lock, source capture, before-state, journal,
recovery/restoration direction, quiescence and activation-last transaction.
Bindings are not embedded in user workload configuration or a second store of
admission authority.

`workload bind` uses one parsing/help/completion definition. `plan` drafts an
initial target; `rebind` changes intent against a selected source predecessor;
`refresh` preserves intent and location; `propose` creates a separate complete
deployment proposal. `remove` produces a proposal, and `rollback` produces a
new digest-bound plan selecting its verified predecessor intent plus a complete
proposal. Rollback advances the generation; it cannot revive an old native
session, reinstall third-party bytes or substitute a disappeared target.
The selected source bytes and digest are checked before its authority is used.
For plans, raw digest and canonical JSON are checked before deserializing the
typed plan; canonical typed authority bytes and action/predecessor structure
must then match. Unchanged proposals preserve the original source bytes.
Output files are private, created without clobbering, and no command edits an
external source in place or claims activation.

Root-owned pinned executable generations remain a separate copied-artifact
authority. Their per-generation nested installation ledger and replayable
retirement markers retain exact active/prior bytes. They require independently
root-owned non-writable ancestry and native copied-file projection checks;
mutable same-user code does not gain a byte pin. Accepted recovery can verify
retained structure and copied artifacts after original bytes change; unfinished
transitions still verify newly approved bytes before acceptance. A missing,
drifted or foreign store never permits original-path fallback or mutable trust.

## Public shell definitions

Pinned-shell planning accepts at most 64 KiB of public UTF-8 source only from
stdin, with `--source-stdin --acknowledge-public-shell-source`, an exact selected
root-custodied shell executable and pinned code trust. Source and shell identity
are digest-bound and retained in plan/predecessor evidence. The administrator
workload cap separately declares `allow_pinned_shell = true`, default false;
narrowing cannot enable a permission absent from upper authority.

The source mechanism supplies a sealed, owner-only, nonexecutable descriptor.
An already admitted native command receives its private descriptor pathname and
separate caller arguments while retaining workload stdin. Source contents do
not enter argv or environment; ambient shell startup selectors are removed.
Acknowledgement does not interpret arbitrary shell language or expand resolved
credential authority.

Installed binding sets contain a `PinnedShellSource` reference with exact source
digest/length, the selected shell's complete native identity and the explicit
acknowledgement. They never contain shell text. Private approved plans retain the
full definition; normalization preserves the generation, intent and exact shell
identity while replacing source text with its exact digest/length. Predecessor
digests remain the digest of the canonical captured predecessor plan evidence;
setup compares the normalized authority against the installed source-free set.

Full setup v5 owns the durable payload. Strong payloads live below
`/var/lib/dev-auth/private-shell-bindings/<uid>`, with root-owned private
directories at mode 0700 and source/metadata documents at mode 0600. User-only
payloads use the selected account's product data directory with the same private
modes. Metadata binds the exact native account, alias and normalized generation;
generation names bind the generation number and source digest. Descriptor-held
ancestors and bounded no-follow, single-link document reads prove custody.
The component creates only private suffixes after setup establishes its product
directory. Candidate observation admits only an exact complete generation or
an exact partial candidate; foreign entries and drift fail. Replayable retirement
records remove source/metadata before the exact empty generation and remove the
record last. Accepted collection retains active and previous references in both
the accepted and retained prior sets.

Pending setup establishes the public Strong binding parent with exact root-owned
mode 0755 before nonempty publication; incompatible existing modes fail instead
of being changed. Every existing ancestor and the existing selected leaf pass
held custody, traversability and exact leaf-mode admission before directory
publication or storage synchronization. The held chain is reverified around
preparation; an absent suffix is never adopted after admission. This keeps
source-free 0644 receipts and copied pins traversable
by the selected native account while private shell suffixes remain mode 0700.
It publishes private payloads and copied Strong executable pins before
writing source-free sets and activating aliases/Desktop entries last. Every
forward set write or withdrawal proves the exact native destination, candidate
installation receipt and Pending retained v5 plan, digest and source inventory.
Restoration uses a distinct observed before/candidate lane, retires candidate
aliases and private artifacts, restores prior authority and finishes inactive.
Private-payload and copied-pin repairs contribute to setup's change result.
Restoration observes all aliases for one native account together. Its separate
typed complete-prior/partial-candidate lane admits a retirement marker only from
the exact changed-candidate inventory, verifies the retained prior remains
complete, and replays that marker before iterating other candidate generations.
Runtime verification continues to reject every outstanding retirement marker.

The authenticated root dispatcher seals the approved source into anonymous memory
owned by the selected non-root native account at mode 0600, with write/grow/shrink
and seal seals. A bounded descriptor frame transfers exactly one owned descriptor
before the existing environment frame; truncated, foreign or excess ancillary
data fails with received descriptors closed. The native supervisor verifies the
installed generation, owner, mode, length, seals and source digest before retaining
the descriptor across the gate. User-only launch captures its own private source
inside the existing cleanup-owned admission path. Direct, nested and sandbox
execution repeat current installed selection and broker-verified workload/profile
proof. The inherited numeric descriptor hint supplies no admission. Adapter routes
retain the sealed descriptor and preserve their own argument grammar. Source
creation/receipt normalizes ownership outside descriptor slots 0, 1 and 2 so a
closed standard stream cannot become source data or a reserved inherited hint.
User-only final shell commands independently retain and verify the exact shell
executable, then use the focused shared `HeldExecutable::into_command` mechanism.
It owns the complete validated holder and a procfs-verified executable duplicate
above compact adapter slots; it preserves the canonical argv0 and existing
borrowed command API. Replacing the original pathname cannot switch that command
to new shell bytes. Holding an inode retains the existing independently approved
root-custody requirement; it does not make authorized in-place writes immutable.

An adapter separately declares `inherited_descriptor_arguments`, default empty.
It is a bounded literal argument vector with exactly one `{count}` substitution;
no flag is guessed, no shell evaluates a template and user narrowing cannot change
the selected adapter's declaration. Product-owned inputs contain at most three
verified descriptors, ordered proof, execution release and optional shell source.
The product duplicates them above compact slots, derives exact slots 3 through 5
and adds only the declared preservation arguments before the adapter separator.
Compact mapping happens only during native exec replacement. User-only launch
first spawns an installed native sandbox intermediate, which repeats broker/current
policy proof and then execs the adapter; mapping cannot clobber a spawn error pipe.
An owned guard restores each pre-existing compact open-file description and its
descriptor flags if exec/preparation fails, and closes only slots that were
previously absent. Private native intermediates prepare this replacement in a
single thread; an unrecoverable restoration terminates that intermediate rather
than continuing with invalid live descriptor owners. An empty declaration
fails when descriptors are required; a dropped descriptor still fails at the final
native probe. Existing diagnostics, native identity, streams, nested hard deadlines
and teardown remain owned by their current paths.

## Verification and gates

The source preview preserves current credential, maintenance, command and
metadata APIs. It adds focused tests for exact raw/canonical selection, v2
rejection, source preservation, predecessor refusal, refresh/rollback/removal,
adjacent native identity rejection, shell acknowledgement/seals/argv separation
and non-widening shell permission. Existing temporary binding fixtures now
explicitly select mutable trust under the new v3 contract.

Focused setup/deployment cases cover v3/v4/v5 selection, empty withdrawal,
Pending/Accepted drift and exact workload/Desktop authority. Private-store cases
cover canonical custody, source/meta partial recovery, exact retirement and
retained-generation collection. Descriptor cases cover source-free authority,
sealed transfer, absent/extra/truncated rights and wrong-body refusal. An isolated
case covers a closed-stdin source allocation, and a private-store case exercises
interrupted candidate retirement while preserving its complete prior. Adapter
cases cover the bounded compact count, literal template validation and default
unsupported behavior; the shared owned-command case replaces an original pathname.
One ignored disposable-container fixture covers retained mutable+pinned binding recovery and
inactive restoration without importing a separate update/editor/service harness.

Only formatting and read-only patch checks are performed in this preview.
Compilation and tests are deferred to the parent's routed storage/process guard.
Signed-release acceptance and native full setup/recovery/restoration remain gates,
including private shell publication/replacement/withdrawal, original source
deletion, exact source handoff under forged hints, adapter FD preservation, native
alias/tool-plane routing, copied-pin projection after original byte replacement,
native identity/groups, writable workspaces, terminals/streams/signals, nested hard
deadlines and cgroup teardown. Accepted recovery still requires the configured
original native location/custody; its retained copied bytes are authoritative.
The captured grant baseline has no setup-aware update family; preserving selected
grant/binding state through that separate family is a remaining source seam.
No install, credential use, release or runtime/platform support is established.
