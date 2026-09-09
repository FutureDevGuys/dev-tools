---
authority: canonical
owner: dev-tools
---

# ADR 0058: Descriptor-bound symbolic-link retirement

status: proposed
verification: pending

## Decision

The Linux `ExistingDocumentDirectory` boundary adds symbolic-link observation and retirement without following or modifying link targets. The selected directory's owner is also the required link owner. The leaf must be a single ordinary name and the object must be a single-link symbolic link with a nonempty target bounded to 4096 bytes. Ordinary document APIs continue to reject symlinks.

Observation opens the symlink itself descriptor-relative with `O_PATH | O_NOFOLLOW`, reads its target through empty-path `readlinkat` into fixed bounded storage, and verifies its named identity and retained parent. It does not synchronize storage. Target comparison during removal uses exact raw native bytes, not normalized path-component equality; relative and non-UTF-8 targets remain representable without granting permission to traverse them.

Retirement validates the exact target and named held inode before descriptor-relative unlink, synchronizes the selected directory and verifies absence. An absent retry synchronizes the parent without another unlink. Replaced parents, hard-linked symlinks, regular files, directories, FIFOs, wrong targets and malformed names fail without adoption. The operation creates no directories, publishes no links and changes no ownership or permissions.

As with ordinary document removal, the caller owns writer coordination, ancestor trust and retained recovery. This is not an atomic compare-and-unlink against an adversarial same-owner leaf writer; descriptor retention confines operations to the selected directory but does not prevent its owner from concurrently replacing entries. Errors after unlink have uncertain progress and must not discard the caller's durable removal authority. The additive interface belongs to unpublished installation 0.2.1; existing APIs, schemas, frozen registry packages and accepted release bytes are unchanged.

## Evidence

The public integration test first failed at the missing link-observation operation. It now checks exact retirement, synchronized absent retry, unchanged target contents and rejection after selected-parent replacement while preserving both directories' links. Additional tests require exact raw non-UTF-8 target comparison, reject normalized-but-different target bytes, preserve unsupported object types and hard-linked symlinks, and reject traversing names and invalid target bounds. Native syscall ordering, cross-account product retirement and interrupted root-generation acceptance remain separate qualification work.
