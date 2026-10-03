---
authority: canonical
owner: dev-tools
---

# ADR 0062: Explicit symbolic-link owner authority

status: proposed
verification: pending

## Decision

The Linux existing-directory foundation adds explicit-owner symbolic-link observation and removal. A caller may select a leaf owner independently of the retained directory owner, just as ordinary document authority already does. The original methods continue to require the directory owner. The shared foundation assigns no special meaning to UID 0 and does not infer removal authority from observed metadata.

The explicit operations retain exact raw target comparison, single-link symlink custody, bounded empty-path target reading, named-versus-held identity checks, descriptor-relative removal and parent synchronization. They do not follow or change the target, change ownership, create parents or relax directory custody. Caller-owned writer exclusion and retained recovery remain necessary; errors after unlink have uncertain progress. This additive interface belongs to unpublished installation 0.2.1 and changes no frozen package, receipt or release identity.

Product compatibility must separately bind any admitted owner to retained authority, destination and target. Merely finding a root-owned link at a candidate name is not authorization to remove it. Dev Auth selects this boundary through the bounded historical ownership contract in [ADR 0063](0063-retained-legacy-workload-link-ownership.md).

## Evidence

The public regression first failed because the explicit-owner API was absent. Its mapped-root execution checks a UID-0 link in a UID-1000 directory: default-owner and wrong-owner operations reject, explicit-owner observation and exact retirement succeed, absent retry is unchanged, target contents and UID/mode/inode are preserved, and parent replacement blocks both observation and removal. The ordinary shared integration suite retains unsupported-type, hard-link, raw-target and malformed-name coverage. This is source-level native filesystem evidence, not signed product, crash/power-loss or non-Linux acceptance.
