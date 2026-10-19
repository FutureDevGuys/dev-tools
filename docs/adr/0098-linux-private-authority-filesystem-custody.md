---
authority: canonical
owner: dev-auth
---

# ADR 0098: Reject host-shared Linux private authority

status: proposed
verification: pending

## Decision

Linux and WSL private Dev Auth configuration, cache, runtime, and private frontend files reject recognized network, host-shared, and userspace-projected filesystem types at their opened directory or file descriptor, in addition to current-user ownership and owner-only permissions. The rejected types include WSL's 9P Windows-host mounts. Existing executable custody uses the same filesystem classification; writable Git workspaces remain governed by their separate workspace policy and are not reclassified as private credential authority. Unrecognized filesystem types are not claimed to be local by this check and remain a native qualification question.

Private directory and file paths must be absolute. Directory checks use a no-follow directory descriptor so the filesystem and ownership observations refer to the opened object. Private file checks use the already retained no-follow file descriptor. This does not claim to prevent a privileged host administrator from accessing WSL or to identify every possible remote filesystem type. It prevents mode-bit presentations on known host-shared mounts from being mistaken for a private Linux user boundary and preserves independent WSL runtime state rather than falling back to Windows-managed files.

## Verification and remaining gates

Source tests cover the filesystem classification and private directory/file validation, including symlink rejection. A real WSL distribution still needs native proof for Linux-home acceptance, Windows-host-mounted authority denial, Secret Service, Unix agent lifecycle, no Windows credential fallback, and installation/recovery. A Linux target build alone is not WSL acceptance.
