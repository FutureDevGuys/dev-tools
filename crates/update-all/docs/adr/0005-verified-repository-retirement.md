---
authority: canonical
owner: dev-tools
---

# ADR 0005: Verified repository-retirement recovery

status: proposed
verification: pending

## Context

An Arch repository can retire a formerly separate dependency by moving its
contents into another repository package. A full upgrade then asks whether the
old package may be removed because the incoming package conflicts with it.
Unattended `yay --noconfirm` answers no and blocks the entire upgrade, including
health-dependent service handling. Package-name exceptions are brittle, while
a general automatic-removal rule can silently widen into unrelated removals.

ADR 0004 correctly requires exact attribution and full bulk completion for AUR
source/build recovery, but its blanket prohibition on automatic removals also
prevents a repository-defined retirement that can be proved as one safe full
upgrade transaction.

## Decision

Preserve each exact pacman removal question as an ordered incoming/removal pair.
Only a failure consisting exclusively of those questions may enter this lane.
The repository package executor uses PyALPM and the configured pacman databases
to prepare a no-lock, download-only, non-committing full system upgrade with the
proposed removals.

Approval requires every removal candidate to be dependency-installed, absent
from configured sync repositories and AUR, and explicitly conflicted by its
incoming sync package. Transaction preparation must succeed, project every
incoming package as an addition, and project exactly the validated candidates
as removals. Metadata uncertainty fails closed. A semantic fingerprint of the
local and configured sync package databases must remain unchanged through proof
and immediately before retry.

After approval, retry the original full upgrade once without refresh and append
only `--ask=4`, preserving unrelated arguments. Pacman/yay owns the single
atomic upgrade and removal transaction. Completion additionally requires every
approved removal to be absent, every incoming package to be installed, and
`pacman -Dk` to succeed. Only then may health-dependent tasks run.

## Invariants

- Production policy and code contain no package-name allowlist or exception.
- A conflict pair remains ordered as incoming package and removal candidate.
- Mixed, ambiguous, build, checksum, file, lock, or unavailable-metadata
  failures never enter this recovery lane.
- No separate `pacman -R`, dependency bypass, partial upgrade, or refreshed
  retry is permitted.
- The projected removal set equals the approved set; implicit extra removal is
  always blocking.
- Proof and retry use the same package-database fingerprint.
- Bounded structured request/result artifacts accompany complete task-log
  subprocess evidence.
- ADR 0004's attributable AUR source/build rules remain in force.

## Rejected alternatives

- Package-specific allowlists encode transient repository history in shared
  updater policy.
- Blindly answering all conflict questions cannot distinguish retirement from
  an operator-owned package choice.
- A separate removal command creates an intermediate package state and weakens
  full-upgrade atomicity.
- Dependency bypass flags can produce a locally inconsistent package database.
- Treating missing PyALPM or AUR metadata as absence turns uncertainty into
  destructive authority.

## Consequences and known limitations

Arch recovery now depends on the cataloged `python-pyalpm` runtime and reachable
AUR metadata. A safe repository retirement can remain blocked during metadata
outages or when output no longer matches pacman's exact question form. The
fingerprint is a semantic package/database fingerprint rather than a filesystem
snapshot; irrelevant file metadata changes do not invalidate an otherwise
identical proof.

## Verification

Named regression tests:

- `repository_retirement_retry_removes_refresh_and_adds_only_conflict_answer`
- `package_recovery_classifier_covers_common_manager_failures`
- `upgrade_conflict_bridge_persists_bounded_request_and_result`

## Runtime acceptance

Repair the installed command, then run
`update-all --plain --only=yay,arch-update-services` twice on the live Arch host.
The first run must record a projected removal set equal to the actual atomic
outcome, complete remaining updates, and run service handling only after package
success. The second run must show no pending package update or unexplained
mutation. If sudo or required metadata is unavailable, this decision remains
proposed and pending rather than weakening its proof.

## Supersession conditions

Supersede this record if pacman/yay provides a stronger machine-readable
transaction protocol, PyALPM changes its preparation contract, or another
authority can prove the same ordered conflict, exact removal closure, metadata
freshness, atomicity, and post-transaction health properties.
