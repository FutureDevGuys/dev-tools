# ADR 0003: Serialized durable overlay publication

status: proposed
verification: pending

## Decision

The product owns one local overlay transaction boundary for manifest and
standalone JSON/TOML overlays and standalone TOML removal. A managed overlay
publishes its target and ownership receipt as one recoverable transition. An
unmanaged overlay or TOML removal has a target-only transition; inactive receipt
arguments grant no receipt authority. Sudo targets remain copy-only.

This is forward recovery, not a promise that two independent file renames are
simultaneously visible. Before the first target effect, a strict owner-only
`sync-configs-overlay-transaction-v1` journal durably retains the operation,
normalized absolute source/target, admitted source digest, selected parent
device/inode, exact before/candidate UTF-8 target states and optional exact
receipt transition. Receipt v1 bytes and their ID/path-list format remain
compatible. The journal is bounded to 256 MiB; each text input/target is bounded
to 16 MiB and each ownership receipt to 1 MiB. New or materialized targets use
mode 0600; existing ordinary-file UID/GID/mode are retained.
Authority paths and raw link destinations retain bounded native byte arrays;
non-UTF-8 names are not converted lossily into another target identity.

Every mutating entrypoint takes a permanent, nonblocking lock beside the target.
The basename is `.sync-configs-overlay-<key>.lock`; `key` is SHA-256 of
`sync-configs-overlay-leaf-v1`, NUL, and the exact native leaf-name bytes. The
selected real parent supplies the rest of the resource identity. A managed
overlay takes the same resource lock beside its receipt; distinct locks are
acquired in native path order. Thus a changed managed ID or `--state-root` cannot
create another lock for the same target, and targets sharing a receipt exclude
one another. These names stay retained while this protocol can run. The
`.sync-configs-overlay-` target/receipt basename namespace is reserved.

A managed transition first durably publishes a strict mode-0600,
64-KiB-bounded `sync-configs-overlay-receipt-reservation-v1` document beside the
receipt, with suffix `.receipt`. It binds that receipt ID to the exact target,
target-parent identity, source and operation. This reservation survives process
death and prevents a different target from reusing the receipt while the target
journal is pending. A matching reservation without a journal authorizes only
its own exact cleanup: it can precede journal publication or follow completed
target/receipt publication. It does not establish target validity or grant
authority to restore either leaf.

Selected directories and regular files use the existing typed installation
primitives. The narrow additive `FileAuthority` and
`ExistingDocumentDirectory::{read_file_with_group,write_file_with_group,remove_file_with_group}` interfaces admit
empty ordinary files and require the selected native GID as well as UID/mode.
Its additive `try_lock` opens, validates, locks and synchronizes a permanent
empty mode-0600 resource lock through the retained parent descriptor, returning
the existing `InstallationLock` lease type. Lock creation cannot be redirected
through a replaced parent pathname.
Existing document interfaces retain their nonempty contract. Files must be
single-link, owned by the effective caller, have ordinary modes without
group/other write permission, and live beneath an existing caller-owned parent
without group/other write access. Missing parents are explicitly prepared with
mode 0700; existing directory modes are never repaired by this transaction.
Parent preparation and permanently retained locks can precede a content journal.

Target and receipt observation, publication, removal and synchronization retain
their selected parent descriptors and revalidate named versus held identity.
Sources are bounded regular UTF-8 inputs, read through an opened handle and
checked again before journal publication. An existing target symlink is read as
input but is never written through. Its exact owner-matching raw link is removed
and synchronized before publishing a regular candidate. The journal recognizes
that absent intermediate state; its referent is not mutated. Target and receipt
parents are synchronized after their respective publication/removal, and both
candidate postconditions are rechecked before journal retirement. Journal
retirement is synchronized before receipt-reservation retirement and sync.

Retrying the same source path, target, operation and receipt selection acquires
the same locks and finishes the retained candidate before considering current
source contents. The live target and receipt must each match a retained
before/candidate state (or the explicit symlink-unlink gap); parent identities,
ownership, modes, types, bounds and exact receipt fields are revalidated first.
Unknown content, missing reservations, conflicting requests, unsafe custody or
changed parents stop with recovery evidence retained. No returned-error rollback
overwrites current data. Errors after journal entry can follow durable effects;
they do not establish unchanged state. Successful recovery counts as change even
when the following merge is a no-op.

Dry-run and check do not create locks, parents, reservations or journals and do
not recover pending work. An observable pending target journal or selected
receipt reservation blocks their ordinary projection. A missing TOML removal
target still does not parse an unused source. Normal mutating removal may prepare
its selected parent and retained lock even when the target is already absent.

## Exact retirement

Retirement removes only exact previously receipted or source-owned leaves and
empty ancestors. A formerly owned leaf that is now a nonempty target container
requires structural normalization; it cannot authorize deletion of target-only
descendants. An ancestor still containing current source-owned leaves is not
retired merely because its receipt representation became more precise. New TOML
receipts enumerate inline-table leaves, preserving target-only inline children;
ambiguous legacy container claims fail closed when their whole source retires.
Standalone removal uses the same parser-based leaf selection and suppression
preservation as overlays, including multiline values. ADR 0001's NaN comparison
and suppression directives remain authoritative. Explicit mutually exclusive
sibling policy retains its separately declared subtree-retirement authority.
Arrays remain atomic source-owned values, as in the existing merge contract.

## Limits and verification

The durable mutation implementation is Linux-only. Other runtimes retain
read-only planning and reject a required write. The protocol excludes updated
cooperating writers using these locks; it does not fence an older released
writer, external editor or hostile same-owner process. Operators must quiesce
older writers. Ancestor trust remains the caller's responsibility. Moving a
selected parent or changing a pending transaction's source path/operation or
receipt selection does not rebase recovery authority. Unmarked staging left by
process death is never discovered, adopted or removed by name or age. No binary
rollback reverses completed configuration edits.

Verification remains pending. Required public gates include exact retirement
and target-only preservation (including inline tables and shape drift), ordinary
metadata and symlink handling, no-op/dry-run/check behavior, target and receipt
lock aliasing, cross-target pending-receipt exclusion, substituted parents and
leaves, malformed/oversized journals and receipts, and fresh-process recovery at
reservation, journal, target, receipt and cleanup boundaries. Native filesystem
and signed standalone release acceptance, plus hardware power-loss durability,
remain separate gates. Source review alone establishes none of those claims.
