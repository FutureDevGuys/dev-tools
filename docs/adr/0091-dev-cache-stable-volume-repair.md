---
authority: canonical
owner: dev-cache
---

# ADR 0091: Stable volume evidence for automatic cache-root repair

status: proposed
verification: pending

## Decision

The root marker keeps its v2 root and runtime-domain identities and adds optional `stable_volume_identity` evidence. Unix `st_dev` identifies a currently allocated device, not a permanent filesystem; its renumbering alone is not a cache-volume replacement. Root preparation may refresh that transient observation automatically only when retained native filesystem evidence matches. A mismatching or unavailable retained stable identity fails closed even if the device number is unchanged or reused. Missing roots, unmarked populated directories and canonical-path changes remain errors; repair does not create a replacement cache root, move data, reset domains or discard contents.

Linux obtains the filesystem type and ID through native descriptor-bound `fstatfs`/`fstatvfs` calls for the selected ext-family, XFS, Btrfs, F2FS, ZFS, tmpfs and overlay contracts. Persistent-filesystem IDs survive device-number reallocation; tmpfs and overlay evidence identifies that filesystem instance and does not authorize a recreated instance. Unknown filesystem contracts retain the old strict device check instead of guessing equivalence. macOS obtains the volume UUID with native `getattrlist`; Windows retains the existing Win32 volume-serial authority. No configured mount path, hostname, distribution-specific helper, shell command, source checkout or private downstream policy participates in these adapters. Filesystem identifiers are continuity evidence, not proof against deliberate clones or a same-owner adversary.

An older marker without stable evidence is enrolled automatically during ordinary writable preparation only while its original volume check still succeeds. A legacy mismatch cannot establish prior filesystem identity; it remains an actionable error rather than automatic adoption of the currently visible disk. Explicit operator repair may establish the missing baseline after independent volume verification. Older readers ignore the additive field but cannot themselves implement repair; rollback to those readers retains their historical device-number limitation.

Runtime labeling uses the actual native OS, with WSL selection restricted to Linux. The formerly unqualified macOS path no longer calls itself Linux. Its newly selected runtime domain does not merge or delete a previous mislabeled domain; Linux, WSL and Windows domain keys are unchanged by this correction.

Preparation serializes needed marker updates using a bounded native file lock, rereads the marker and filesystem evidence under that lock, and preserves concurrent domain registrations. New marker bytes are staged through a unique no-clobber file, synchronized, atomically renamed, and followed by parent synchronization on Unix. Predictable old temporary-file names, symlinks and unrelated contents are not reused. Ordinary readers do not acquire this write lock. [ADR 0015](0015-dev-cache-read-only-root-observation.md) remains authoritative: observation may recognize an unchanged filesystem after renumbering, but never refreshes the marker, probes writability or creates state.

## Verification and release boundary

Regressions distinguish same-filesystem renumbering from device-number reuse by a different filesystem, preserve marker/domain/cache contents, keep observation read-only, refuse legacy mismatch without stable evidence, serialize concurrent repair, and preserve an unrelated target behind an old predictable temporary symlink. Source checks cover native Linux and Windows/macOS target adapters; actual OS runtime acceptance is separate from cross-compilation. Native filesystem reformat/clone behavior, hardware power-loss durability and hostile same-owner directory replacement are not claimed from these tests. Signed distribution, installed interception and rollback remain release gates.
