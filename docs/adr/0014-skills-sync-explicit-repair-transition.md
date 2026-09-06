---
authority: canonical
owner: dev-tools
---

# ADR 0014: Skills Sync explicit repair transition

status: proposed
verification: pending

## Decision

Skills Sync adds `repair` as an explicit spelling for its existing broad mutating `doctor` workflow before changing the latter to the common read-only diagnostic contract. Both spellings use one implementation and preserve argument handling, default adoption/link policy, lock normalization, upstream invocation, dry-run behavior, errors and exit codes. Both retain the existing JSON `command: "doctor"` value during this expansion so changing the invocation does not also require changing result consumers. No persisted data format or new runtime dependency is introduced.

New repair examples and completion metadata expose `repair`. The existing `doctor` spelling remains mutating in this stage; neither command is advertised as the common local-only doctor. Repair may invoke the caller-selected upstream skill provider and is not a network-free diagnostic interface. Public standalone/common lifecycle qualification remains incomplete.

Skills Sync owns this compatibility window. A signed accepted release must ship the explicit spelling before a later release changes `doctor`; release notes must identify the changed command and the replacement invocation. Callers must migrate repair invocations before that cutover. Repository tests cannot establish migration of external consumers. Until release and consumer acceptance justify cutover, keep legacy behavior and its tests. The eventual read-only implementation needs separate no-mutation/no-network conformance evidence and an explicit result-schema transition; this source addition alone authorizes neither the cutover nor a full-standard claim. Rollback to a pre-expansion binary requires restoring the `doctor` invocation; no data rollback is needed for this alias.

## Verification

Linux public-binary contract tests run each spelling against an isolated private home and a native empty-inventory fixture. They compare exact dry-run documents and absence of created state, apply the explicit repair to create the canonical empty lock, and require repeated repair and legacy doctor to agree without another planned lock repair or altered lock bytes. Static five-shell generation and native Bash root completion cover discoverability. These are bounded source tests, not upstream-provider installation/adoption acceptance or native Windows/macOS qualification. The existing locked `tempfile` package is test-only and adds no released binary dependency.
