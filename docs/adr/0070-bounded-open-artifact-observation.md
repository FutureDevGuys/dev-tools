---
authority: canonical
owner: dev-tools
---

# ADR 0070: Bounded open-artifact observation

status: proposed
verification: pending

## Decision

The installation foundation owns bounded digest observation of an already-open Unix regular file. It starts at offset zero, reads at most the observed length plus one byte, rejects oversized inputs before product validation, and compares inode, size, ownership, mode, link count and modification/change timestamps after reading. Products supply descriptor-metadata validation and own path traversal, permission, link and authentication policy. The caller exclusively owns the file cursor during observation. The existing path-based artifact identity API retains its nonempty, single-link policy and delegates Unix hashing to this same implementation; other platform behavior is unchanged.

Dev Auth opens setup executable sources with final-component no-follow and nonblocking flags, applies its executable mode policy to opened metadata, then checks that the named path still identifies the measured regular inode. Its retained legacy hard-link compatibility and existing ancestor policy remain unchanged. Setup observation does not authorize execution, publish bytes, or authenticate a release. Later installation and recovery still verify the exact approved digest through their own custody boundaries.

Stable metadata during observation is not an immutable-byte guarantee against a filesystem or privileged writer capable of hiding changes. No pathname observation supplies a lease against replacement after return. The API does not claim either property or replace retained/quarantined execution custody.

## Verification

Shared tests cover offset reset, exact bounds, validation rejection, legacy link-policy separation, empty-file policy, growth, truncation, same-length writes and metadata changes. Dev Auth tests cover regular hard-linked sources, unsafe modes, oversized sparse files, final symlinks and nonblocking FIFO rejection. Existing setup migration and restoration tests remain required; signed installation and native platform acceptance are separate release gates.
