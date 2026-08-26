---
authority: canonical
owner: dev-tools
---

# ADR 0007: NPM global mutation authority

status: proposed
verification: pending

## Context

An NPM global update can discover packages under a system-owned prefix and only
fail after starting a batched install. Retrying each package repeats the same
authority failure, produces misleading task noise, and risks modifying files
that belong to the operating-system package manager. NPM's readable inventory
does not establish mutation authority.

## Decision

Before any NPM filesystem cleanup, provider reconciliation, global install, or
global update, resolve `npm prefix -g`, `npm root -g`, and every planned package
location. Mutation is allowed only when the prefix, root, executable directory,
and existing package locations are owned by the current non-root user and are
writable. Planned locations must remain inside the canonical global root.

Packages whose installed files have a reliably detectable system-package owner
are excluded from NPM mutation and reported with that owner. Remaining packages
under an unsafe tree are reported as unowned residue. The task returns one
blocking authority advisory and performs no mutation. It does not infer sudo,
change ownership, or retry the batch package by package.

Malformed `npm outdated -g --json` output fails closed. The updater does not use
an unscoped `npm update -g` fallback because that command cannot preserve the
per-package authority boundary.

On Windows, mutation is limited to a non-read-only prefix under the current
user's profile, local application data, or roaming application data roots. No
system-wide Windows prefix is adopted automatically.

## Invariants

- Readable global packages do not imply writable update authority.
- No NPM mutation begins before the complete planned location set passes.
- Root-owned, other-user-owned, non-writable, escaped, and unknown locations
  fail closed.
- System-manager ownership is reported only when a supported ownership query
  succeeds.
- Unowned system-prefix residue is never silently treated as manager-owned.
- Update All never elevates NPM or rewrites global-tree ownership.

## Rejected alternatives

- Retrying a failed batch package by package repeats an authority failure and
  cannot make a system-owned prefix safe.
- Automatically using sudo would let NPM overwrite files owned by the system
  package manager and would turn a detection failure into implicit adoption.
- Changing prefix ownership would silently transfer authority for unrelated
  packages and is outside an updater's responsibility.
- Treating every package under a system prefix as manager-owned would hide
  untracked residue that the manager cannot update or remove safely.
- Keeping the unscoped `npm update -g` parse fallback would discard the planned
  package set precisely when authority must be most conservative.

## Consequences and known limitations

A mixed system prefix may contain both manager-owned packages and historical
unowned residue. The manager-owned packages are delegated; the residue remains
blocked until the operator installs it under a per-user Node or NPM prefix.
Windows profile-root and read-only checks are conservative but do not replace a
full ACL authority proof, so ambiguous Windows layouts remain blocked.

## Verification

Named regression tests:

- `npm_blocks_non_writable_global_prefix_before_any_mutation`
- `npm_invalid_outdated_payload_never_runs_unscoped_update_fallback`
- `npm_permission_failure_suppresses_individual_retry_storm`
- `unix_npm_authority_rejects_root_and_non_writable_ownership`

## Runtime acceptance

Exercise one user-owned NPM prefix and one system-owned mixed prefix. Acceptance
requires the user prefix to update normally; the system prefix must issue no
`npm install`, `npm update`, sudo, ownership, or cleanup command, must identify
known system-package owners, and must report unowned residue once. Repeat both
runs to confirm stable reporting and no retry storm.

## Supersession conditions

Supersede this record if NPM exposes a machine-readable authority and ownership
protocol that proves global package mutations without filesystem inspection, or
if a supported platform API provides a stronger non-mutating ACL authority
check.
