---
authority: canonical
owner: dev-auth
---

# ADR 0130: Mode-bound setup transition root

status: proposed
verification: pending

## Decision

Linux full setup retains its previous generation before installing the candidate.
The first retained document can therefore create the installation data root
before the binary installer sees it. The generic atomic-document ancestor
creator requests mode 0755, which a restrictive umask can reduce to 0700. The
later installation layout correctly rejects that root rather than silently
changing an existing directory's permissions.

Dev Auth selects the existing descriptor-relative directory preparation from
ADR 0083 for this root. Its ordinary mode comes from the same product constant
as the shared binary installation layout. Observation precedes generation
capture without creating or synchronizing directories. After successful capture
and validation, preparation publishes each missing suffix with final ownership
and permissions before exposing its name. Retention is then written before the
admission marker and candidate installation, preserving the existing ordering.

An existing root must already satisfy the exact installation mode. No existing
directory is chmodded, a newly appeared directory invalidates admitted absence,
and symlinks or unsafe ownership are rejected. A root left with the wrong mode
by an older failed attempt is not adopted or repaired without its own recovery
authority. The immutable generation and transition records remain mode 0600;
their schemas, digest authority, retry behavior and native setup exclusion do
not change. Generic atomic-document creation and other products are unchanged.

## Verification

The regression runs the real transition-retention function in isolated child
processes with umasks 0022 and 0077. Before the correction, the restrictive case
created mode 0700 instead of the layout's 0755. Both cases must publish the
correct root, retain owner-matching private records and retry without replacing
the root or recapturing the generation. Additional tests preserve wrong-mode
directories, symlinks, a valid late writer, absent state after failed capture,
and pending authority after mode drift.

These focused fixtures do not establish signed Strong installation, systemd or
SELinux compatibility, workload streams, native privilege or cleanup support.
The signed fresh-install/workload/restoration case must be rerun with a newly
constructed source-bound candidate. Previously signed candidate bytes and
their failed acceptance result remain unchanged.
