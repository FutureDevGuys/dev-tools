---
authority: canonical
owner: dev-cache
---

# ADR 0102: Scoped status and single-pass space observation

status: proposed
verification: pending

## Decision

Default `dev-cache status`, including no subcommand, reports current-workspace routing without enumerating the resource catalog, other workspace identities or trash. The existing optional `maintenance` field is null and the additive `maintenance_scope` is `not_observed`; null is not an empty catalog or a healthy maintenance result. Explicit `status --full` retains the exhaustive live maintenance object and reports `maintenance_scope: full`. Disabled routing remains unobserved. This supersedes ADR 0015's unchanged-status-shape statement only for the scope of maintenance observation. Root observation, workspace ownership and routing authority remain unchanged and read-only.

`doctor` remains the explicit exhaustive health audit. It observes the root and audits maintenance and activation once, then reuses those same observations for its checks and embedded status. Invalid catalog/workspace records, unrecovered trash and failed/incomplete automatic maintenance retain their unhealthy meaning. A failed embedded routing-status observation still makes doctor unhealthy. No summary is invented from the historical automatic result, and no persistent probe or health cache is introduced.

`report` uses one traversal of the current runtime-domain root. Each observed ordinary file contributes its apparent length once to exactly one class: `workspaces` to `repos_bytes`, `cache` to `shared_bytes`, `artifacts/blake3` to `artifacts_bytes`, and everything else to additive `other_bytes`. Artifact metadata remains outside `artifacts_bytes`, preserving its existing meaning. `bytes` is the checked sum of the same class observations. Hard-linked directory entries retain their prior per-entry apparent-byte accounting; this is not allocated storage or unique-inode measurement. Concurrent writers mean the result is a live observation, not a filesystem snapshot or a promised reclaimable amount.

Successful reports add `complete: true`, `cancelled: false`, `measurement: live-apparent-bytes`, entry/file counts and `links_skipped`. A failed or interrupted scan emits one result with `complete: false`, a fixed `error_kind`, and null total/class sizes; partial observations are never returned as complete totals or fabricated zero values. Operational scan/free-space failures return exit 1, and orderly cancellation returns 130. `free_bytes` is a separate live filesystem observation and is null if unavailable. Invalid root/configuration observation retains the existing command error behavior before a report scan starts.

The report scan installs Ctrl-C cancellation, checks it between entries, and prints best-effort progress only on stderr, initially and at most once per second between traversal steps. A failed progress write does not replace the scan outcome. Traversal keeps at most 32 directory handles open and fails explicitly past depth 256. WalkDir can buffer directory entries inside an iterator step when its open-handle limit is reached: descriptor use is bounded, but memory and per-step cancellation latency are not strictly bounded. Filesystem calls and stderr writes can block in the operating system; this is cooperative interruption, not a hard elapsed-time guarantee. Cancellation neither starts GC nor changes owned files.

## Custody and compatibility limits

The scanner validates that its domain root is a normal descendant of the selected root and rejects symlink/reparse/non-directory traversal-root ancestors. It disables traversal-root and nested link following. Nested symlinks and reparse entries are excluded from ordinary-file sizes, counted as `links_skipped`, and never descended into. Pathname preflights and WalkDir iteration do not retain ancestor descriptors or defeat concurrent replacement by the same owner. No new filesystem, mount or Windows support claim follows from this correction.

Root marker, resource and workspace identity schemas, usage timestamps, GC action authority and deletion behavior are unchanged. No scan coordination file is created. Simultaneous explicit reports may still scan independently. Existing version/configuration subprocess probes, PATH scans and executable hashing remain environment-dependent and can still be slow; status is independent of cache catalog/tree size, not universally latency-bounded. `doctor` and `status --full` still require whole-catalog/workspace observation, and their existing metadata readers are not redesigned here. GC's repeated payload measurements and action-count-only bound remain separate work. No idle-I/O scheduling or persistent adapter-version cache is claimed.

## Verification and release boundary

Synthetic tests prove default status and path do not open an unrelated blocking catalog record, distinguish unobserved default status from full audit, retain doctor's invalid-catalog failure and matching maintenance observations, visit report entries once, preserve category meanings and totals, return unknown sizes for failure/cancellation, exclude links, reject redirected root ancestors, and rate-limit progress with a synthetic clock. Public report output remains one JSON document with progress on stderr. Existing diagnostic read-only, activation, root identity and compiler hot-path tests remain required.

These are source regression gates. Atomic-flag tests do not establish actual signal delivery or the public exit-130 path. Cold HDD latency, concurrent real-build throughput, signal handling during uninterruptible device I/O, native Windows reparse acceptance, signed distribution and installed rollback qualification remain unverified release gates.
