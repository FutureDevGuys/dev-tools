---
authority: canonical
owner: dev-tools
---

# ADR 0067: Product validation of retained executables

status: proposed
verification: pending

## Decision

The Linux `dev-tools-command` retained-executable primitive owns no-follow path traversal, retained descriptors, validated procfs execution and child descriptor inheritance. Products can tighten its baseline through `HeldExecutable::open_with_validation`, whose callback receives a borrowed descriptor and a typed directory/executable role. The callback runs once per opened source-path component after shared validation and can reject construction, never bypass shared validation. `AsFd` exposes the retained executable for existing descriptor-based native transports without transferring ownership.

Dev Auth consumes this mechanism directly. Its effective UID and supplementary-group execution checks, rejection of every group/other-writable ancestor including sticky shared directories, and denial of known remote/host-shared/userspace executable filesystems remain product-owned. Other consumers keep the shared baseline unless they supply stricter policy. Non-Linux backends are unchanged. Retaining an inode is not immutable-byte custody or protection against an authorized writer changing metadata or content.

## Verification and release

The shared contract suite exercises callback identity across source replacement, exactly-once component observation, product rejection and inability to override baseline rejection. Dev Auth retains its source replacement, symbolic-link, mode, identity and filesystem tests and explicitly tests its stricter sticky-directory policy. Guarded provider transport and the installed user-only workload fixture qualify the integrated native path; they do not establish strong admission, signed setup, whole-workload cleanup or another platform's support.

Changed source targets command 0.1.3. The already signed command 0.1.2 archives and their publication transaction remain unchanged. Publication of new bytes requires a separate clean, authenticated source and package identity.
