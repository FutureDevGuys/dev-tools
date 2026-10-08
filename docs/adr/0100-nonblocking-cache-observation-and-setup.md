---
authority: canonical
owner: dev-cache
---

# ADR 0100: Nonblocking cache observation and routed setup

status: proposed
verification: pending

## Decision

A read-only GC preview takes a nonblocking shared observation lease on the existing root coordination file. It can coexist with routed setup and active workloads. The preview neither creates coordination nor publishes activity, removes stale records, recovers trash or mutates cache data. Missing, redirected and non-regular coordination still fails closed. This supersedes only the exclusive preview-lock decision in ADR 0015.

A preview is advisory, not an atomic snapshot. It reports zero reclaimed bytes and reuses its initial domain-size observation for preview accounting instead of a second full-domain walk; changes made by concurrent workloads are not reported as preview reclamation. Routed setup may publish new records or update existing ones while it scans, and active work may change payloads. Concurrent observation errors remain errors rather than invented success. No printed action is retained deletion authority: applied collection continues to acquire exclusive coordination and recompute its plan using current activity and resource evidence before mutation. Existing activity publication ordering, active-resource exclusions, transaction journals and all deletion rules remain unchanged.

Routed setup also uses nonblocking shared acquisition. If exclusive maintenance owns the lock, setup reports a clear busy failure immediately. It does not silently wait, remove or replace the lock, ignore permission/identity failures, or launch an unprotected or unrouted workload. Callers can retry once maintenance is finished. Generic intercept error propagation and exit categories are unchanged. This is a lock-wait bound, not a guarantee that filesystem open/metadata syscalls cannot block on a failing device.

Applied collection still owns the exclusive root lease during its current planning and mutation lifecycle. Shortening that critical section requires a separately reviewed revalidation protocol and is not claimed here. This slice eliminates preview-caused exclusion and unbounded setup waits; it does not establish that large scans or applied maintenance are inexpensive, nor does it skip nested intercept coordination based on untrusted provenance.

## Verification

Focused tests hold an observation lease while new routed setup acquires its own shared lease, retain exclusive mutation exclusion until the observers leave, and verify that no unscoped activity record is published. A held exclusive maintenance lease makes both preview and setup fail or defer without waiting for release. A bounded test controller releases the fixture lock before joining a blocking regression, so failure cannot hang the suite. Full preview contracts continue to require unchanged fixture contents, stale-record preservation, missing-lock rejection, symlink/reparse and FIFO rejection, plus applied GC protection of active resources. Existing executable custody fixtures cover Unix symlinks and Linux FIFOs; native Windows reparse and locking acceptance remains outstanding.

No dependency, on-disk schema, credential, installation or release identity changes are introduced. Platform-native lock behavior and signed installed-release acceptance remain separate qualification requirements. Source checks do not claim that the user's installed 0.1.11 binary is repaired.
