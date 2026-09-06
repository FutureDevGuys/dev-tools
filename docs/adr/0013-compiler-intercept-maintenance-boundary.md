---
authority: canonical
owner: dev-tools
---

# ADR 0013: Compiler intercept maintenance boundary

status: proposed
verification: pending

## Context and decision

[Issue 40](https://github.com/FutureDevGuys/dev-tools/issues/40) reports compiler probes returning their expected diagnostics immediately but remaining in Dev Cache while unrelated caches are scanned. Automatic maintenance ran before and after each compiler delegation. Even an interval-skipped invocation first calculated pressure through a full cache-tree size walk, so interval throttling did not bound the per-compiler cost.

Dev Cache excludes the Ccache and Sccache adapters from automatic maintenance in the intercept path. This covers compiler aliases and direct compiler-cache launchers without interpreting compiler arguments or guessing which failures are harmless. Cache routing, explicit native overrides, resource registration, activity leases, completion timestamps, child output and exit status remain unchanged. Other routed commands and explicit collection retain the existing maintenance policy. Compiler-only workloads may accumulate disposable cache data until explicit collection; no daemon or deferred child process is introduced to hide that cost.

The excluded effect is full-root automatic inspection or collection, not ordinary bounded-per-resource lifecycle bookkeeping. A configured maintenance interval cannot re-enable it on the compiler critical path. Changing this boundary requires evidence for an independently bounded mechanism rather than merely moving a full scan before delegation.

For other commands, pressure inspection measures the cache tree only when a configured size cap requires it and free-space pressure has not already established the result. An interval-skipped invocation with no size cap and adequate free space therefore performs no full-root size walk. Configured size limits, free-space thresholds, due maintenance and explicit collection retain their existing semantics.

## Verification and acceptance

`compiler_probes_preserve_routing_and_failure_without_triggering_automatic_gc` covers repeated calls through all six compiler aliases with real child output and expected failure status. `compiler_cache_launchers_do_not_trigger_automatic_gc` covers direct Ccache and Sccache wrappers. On Linux with strace available, `compiler_probe_does_not_scan_unrelated_cache_tree_when_strace_is_available` observes the public executable's filesystem calls and rejects unrelated-tree access. These tests fail against the prior behavior. Existing native override, routing, catalog, lease and explicit-GC tests remain required.

The ignored `compiler_probe_scaling_measurement` provides an explicit nine-sample comparison with 0, 4,000 and 12,000 unrelated files, preserving child output/status and keeping fixture creation outside timing. [Measurement notes](../dev-cache-compiler-performance.md) record its scope. Signed installed-artifact acceptance against real compiler probes and representative builds remains required before closing the issue or claiming deployment.

`interval_skipped_maintenance_without_size_cap_does_not_scan_cache_tree` traces an ordinary npm invocation with fresh maintenance state and rejects unrelated-tree access; it fails against the prior unconditional size walk. `pressure_detection_preserves_free_space_and_size_thresholds` retains coverage of absent, exceeded and unexceeded size caps and free-space pressure.
