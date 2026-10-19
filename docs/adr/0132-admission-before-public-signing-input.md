---
authority: canonical
owner: dev-auth
---

# ADR 0132: Admission before public signing input

status: proposed
verification: pending

## Decision

Linux `secret sign-ssh` and `sign-release-manifest` check the current native workload admission before reading standard input. The shared binary-frontend reader enforces each operation's byte limit and one 30-second absolute input deadline, including a writer that keeps a pipe open without supplying bytes. After input, the caller rechecks the same local session claim and broker-verified session before requesting signing. The broker still validates exact profile, key identity, purpose, product authority, deadline, and native caller identity; this front-end check is neither an approval nor a replacement for broker enforcement.

An unadmitted command returns without consuming or waiting for input. A revoked or replaced session cannot receive bytes prepared under its predecessor. SSH signatures use their own raw binary stdout, while the release-manifest command retains its existing base64 presentation. Neither command logs payload or credential values. Non-Linux builds fail before reading stdin until their native signing backend exists.

## Verification and remaining gates

The checks described below are retained source fixtures and historical topic evidence. They have not been rerun against this integrated source; native and signed acceptance remain pending.

Source checks cover absent admission with an endless input source, bounded regular-file input, an oversized input, and a stalled pipe. A disposable installed user-only fixture covers a synthetic provider-backed SSH signature and key-export denial. Real-provider, installed strong-mode, WSL, Windows, macOS, and signed-distribution acceptance remain open.
