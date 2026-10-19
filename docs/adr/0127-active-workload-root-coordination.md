---
authority: canonical
owner: dev-cache
---

# ADR 0127: Active workload root coordination

status: proposed
verification: pending

## Context

A routed outer command publishes scoped activity before delegating to its native tool. Releasing the shared root lease at that transition lets applied maintenance acquire exclusive coordination while the native workload is still running. If that workload later launches a routed compiler or linker, nested setup correctly fails its nonblocking shared acquisition. The already-admitted build then fails before its real compiler or linker starts.

Checking activity after maintenance acquires exclusive coordination cannot close this gap: nested setup can fail during that check, including while a filesystem observation stalls. An environment marker or process ancestry does not grant permission to skip coordination.

## Decision

`ActiveLease` owns the existing shared `RootLease` through the routed workload's active lifetime. Transition still requires a nonempty resource scope and durable publication of its sorted, deduplicated activity record. Publication failure returns no active lease and releases setup coordination. No handle duplication, inherited-descriptor protocol, new environment authority or on-disk format is introduced.

Current delegation waits for its native child with `Command::status`. Resource completion bookkeeping occurs before the active lease is dropped. Dropping an active lease attempts to remove its activity record before releasing the retained shared root lease; existing best-effort record cleanup and stale-record validation are unchanged. Existing post-workload automatic maintenance remains after that release. Nested setup acquires another ordinary shared lease and retains the same custody and resource checks.

Applied maintenance therefore cannot acquire exclusive coordination during an active routed workload using this contract, including while that workload may launch nested setup. Existing automatic maintenance defers when exclusive acquisition is unavailable; explicit applied collection reports busy. Neither waits for an active workload to release its lease. Read-only shared preview can still coexist with setup and activity and retains its advisory, active-resource exclusion and nonmutation rules.

This supersedes the release-after-publication lifetime in [ADR 0013](0013-compiler-intercept-maintenance-boundary.md) and the permission for unrelated applied collection during active work underlying [ADR 0100](0100-nonblocking-cache-observation-and-setup.md) and [ADR 0103](0103-dev-cache-indexed-gc-size-observation.md). Their compiler maintenance exclusion, nonblocking acquisition, stable lock identity, read-only observation, size accounting, journals and deletion-authority checks remain unchanged.

## Consequences and limits

The root-wide exclusion is deliberately conservative: applied maintenance for unrelated resources also defers. Explicit artifact removal, applied migration and root relocation also require exclusive coordination, so they report busy while an active routed workload retains its shared lease. Long-running or continuously overlapping workloads can postpone collection indefinitely. Once all shared leases have ended, maintenance uses its existing exclusive recovery, planning, revalidation and mutation lifecycle. Activity records remain resource-specific evidence; they do not authorize collection outside that lifecycle.

An exclusive collector that already owns coordination is not preempted. New setup still fails busy until it settles. Older processes that released their root lease on entering activity are not retroactively protected. All participants must use the same root coordination and this lifetime contract for the guarantee to apply. Parent death, escaped or background descendants, mixed older binaries and kernel-blocked filesystem calls remain separate limits. This change provides no cancellation authority over another process and no bounded scan-time claim.

## Verification and acceptance

Focused lease regressions require exclusive maintenance to remain unavailable after scoped activity publication, before and after compatible nested setup, and while an independent nested activity outlives its outer activity. Exclusive acquisition must succeed after the last activity is dropped. Abandoned setup, publication failure and independent record cleanup retain their existing coverage.

GC contracts require active-resource abstention and unchanged payloads in shared preview, deferral or busy failure for applied collection during active work, and normal collection after activity ends. Native delegation coverage must retain output and exit status while exercising nested setup and post-workload maintenance.

These source contracts do not establish deployment. Focused executable checks and native installed-release acceptance remain pending. Qualification must demonstrate maintenance exclusion throughout a real routed outer command and nested compiler/linker invocation, ordinary maintenance after completion, and preserved cleanup and child status on success and failure. Existing foreign maintenance and earlier failed build evidence remain untouched.
