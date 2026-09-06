# Compiler intercept performance probe

The synthetic public-binary fixture in `crates/dev-cache/tests/compiler_hot_path.rs` reproduces issue 40's unrelated-tree traversal without using a real user cache. Run `cargo test -p dev-cache --test compiler_hot_path compiler_probe_scaling_measurement -- --ignored --nocapture` with a short private `TMPDIR`. It creates a configured root with automatic maintenance enabled, a routed GCC alias, a cache-launcher fixture requiring the routed environment, and a compiler fixture that emits stdout/stderr and exits 1. Nine sequential invocations are measured at each unrelated-tree size; setup and teardown are outside timing. Native strace coverage independently checks filesystem access rather than inferring traversal from elapsed time.

The local Linux debug-build comparison used two Cargo jobs, debug symbols and incremental compilation disabled, the same locked dependencies and an owner-controlled tmpfs. This is implementation evidence, not a release benchmark or a claim about native compiler execution time. Host scheduling varied between runs; raw microsecond samples are retained below so the medians do not hide that variation.

| Unrelated files | Before samples (µs) | After samples (µs) |
| --- | --- | --- |
| 0 | 7128, 7541, 7551, 7917, 7930, 7978, 8151, 8301, 8471 | 9883, 10340, 12873, 13018, 13189, 13704, 13705, 13792, 16561 |
| 4,000 | 30984, 31102, 31516, 31918, 32580, 32871, 32874, 33351, 34789 | 8911, 9595, 11576, 12078, 12252, 12769, 12852, 13099, 13210 |
| 12,000 | 77947, 78014, 78790, 79467, 81364, 81644, 82689, 82833, 85787 | 9443, 9802, 10604, 11053, 12747, 13130, 15589, 18446, 20695 |

Before the correction, median latency rose from 7.93 ms to 81.36 ms with unrelated-file count. Afterward it remained between 12.25 and 13.19 ms in the isolated comparison. The empty-tree sample was slower in that later run, so these samples support removal of the measured traversal cost, not a universal startup-speed improvement. All samples completed with the expected output and exit status; no useful compiler work was dropped. The deterministic trace test fails before the correction and passes afterward. Native installed-release acceptance, cold-cache measurements and representative build-level timings remain separate gates.
