---
authority: canonical
owner: dev-cache
---

# ADR 0106: Bounded read-only resource catalog inventory

status: proposed
verification: pending

## Context

The scoped status in ADR 0102 avoids catalog work but cannot explain resource
retention. Full status audits the entire catalog, and the indexed GC observation
in ADR 0103 still traverses the entire runtime-domain payload. Automatic
collection caps actions only after that admission and measurement. A small
action cap therefore does not bound planning cost on a large cache.

## Decision

Add `dev-cache inventory [--json] [--max-entries N]
[--max-metadata-bytes N] [--max-millis N]` as a separate, read-only observation
of resource catalog metadata. It performs no payload traversal, workspace
reconciliation, activity scan, trash recovery, native tool execution, free-space
probe, size calculation or GC action selection. It neither refreshes usage
timestamps nor changes automatic maintenance, retention defaults, storage roots
or deletion authority. It does not discover or adopt external build targets.

The default scan admits at most 1,000 directory entries, reads at most 4 MiB of
catalog content and checks a 1,000 ms cooperative deadline between entries.
CLI ceilings are 100,000 entries, 64 MiB and 60,000 ms; zero is rejected.
Every yielded directory entry consumes the entry budget, even if its name is
not JSON. Each JSON record is capped at 64 KiB. The reader reserves one extra
byte to detect growth and accounts all bytes read, including malformed records.
An oversized record is an explicit issue, never silently omitted as healthy.
The reader never materializes the complete directory just to sort or count it.
Returned records are sorted only after bounded enumeration; partial subsets
follow filesystem enumeration order and are neither pagination nor a stable
sample. At exactly the entry threshold, the result is conservatively partial
without consuming another directory entry to establish EOF.

The `dev-cache-inventory-v1` result declares `scope:
resource-catalog-metadata`, the selected budgets, actual observed entry/byte
counts, fixed per-record limit and elapsed scan time. `enumeration_complete`
means only that directory EOF was reached. `complete` additionally requires no
record or observation issues. A budget stop leaves both completion claims
false and sets a fixed `stopped_reason`. `records_observed` is the returned valid
record count, never a claim about an unobserved catalog total. Invalid, foreign,
misnamed or unsafe records produce value-free issue kinds and `complete: false`.
Exit 0 means complete catalog observation, 3 means budget-limited observation,
and 1 means an observation issue, including when a budget also stopped the scan.
Existing invalid invocation, root and busy-coordination errors retain their
normal command behavior. JSON emits exactly one stdout document when a scan
result exists.

Each summary includes resource identity, adapter/kind, relative path, cleanup
strategy, last-use timestamp, effective age threshold, age class, persistent
hazards and whether the resource is an intentionally retained final output.
Age calculations match current GC policy, including its temporary-resource
grace and maintenance timestamps. An old resource is not thereby collectible:
activity, current pressure, path existence, workspace authority and action
revalidation are not observed. `activity_scope` is always `not_observed`;
`payload_bytes` and `reclaimable_bytes` are always null, including for an empty
catalog. No action list is produced. Native program arguments and environment
values are deliberately absent from the summary.

## Custody and limits

Inventory uses the existing read-only root observation and nonblocking shared
coordination lease from ADRs 0015 and 0100. It can coexist with routed setup and
activity; exclusive maintenance makes it fail promptly without repairing or
creating coordination. Catalog/ancestor pathname preflights reject links and
reparse points. Record reads reject nonregular entries before opening and
recheck handle metadata; Unix uses `O_NOFOLLOW | O_NONBLOCK`, and Windows uses
`FILE_FLAG_OPEN_REPARSE_POINT`. Resource records retain their existing
root/domain/identifier/relative-path validation. These controls add no
descriptor-relative ancestor custody or isolation from a same-owner adversary.

Budgets apply to the catalog scan, not existing configuration/root observation,
coordination setup, serialization or output. The deadline is cooperative;
filesystem syscalls can block on an unhealthy device, and parsing, bounded path
validation and result sorting are not asynchronously interrupted. One slow
operation can overrun the requested interval. Bounded records and yielded
entries limit application memory growth, but this is not a hard process RSS or
kernel-I/O deadline. Concurrent metadata changes remain live, non-atomic
observations. Missing resources are not repaired or claimed empty.

## Verification and scope

Public-binary synthetic fixtures cover complete output, one JSON document,
retained/hazard/age distinctions, active-work coexistence, unchanged fixture
inventory and bytes, invalid CLI budgets, entry and content-byte stops,
oversized and invalid records, nonblocking exclusion, missing coordination,
symlink/FIFO records and a redirected catalog. An unrelated depth-257 payload
and malformed activity/maintenance records remain untouched and do not make
the scoped observation fail. Deterministic unit fixtures qualify deadline
handling, the exact-entry conservative boundary and growth-probe byte accounting.
Existing default and experimental product gates remain required.

This is a source-level diagnostic improvement. It does not make ordinary GC
bounded, add future-task reservations, establish native Windows/WSL acceptance,
measure a cold multi-terabyte cache, publish a release or repair an installed
binary. Those remain separate qualification and authorization boundaries.
