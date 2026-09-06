# Compiler intercept performance probe

The synthetic public-binary fixture in `crates/dev-cache/tests/compiler_hot_path.rs` reproduces issue 40's unrelated-tree traversal without using a real user cache. Run `cargo test -p dev-cache --test compiler_hot_path compiler_probe_scaling_measurement -- --ignored --nocapture` with a short private `TMPDIR`. It creates a configured root with automatic maintenance enabled, a routed GCC alias, a cache-launcher fixture requiring the routed environment, and a compiler fixture that emits stdout/stderr and exits 1. Nine sequential invocations are measured at each unrelated-tree size; setup and teardown are outside timing. Native strace coverage independently checks filesystem access rather than inferring traversal from elapsed time.

The local Linux debug-build comparison used two Cargo jobs, debug symbols and incremental compilation disabled, the same locked dependencies and an owner-controlled tmpfs. This is implementation evidence, not a release benchmark or a claim about native compiler execution time. Host scheduling varied between runs; raw microsecond samples are retained below so the medians do not hide that variation.

| Unrelated files | Before samples (µs) | After samples (µs) |
| --- | --- | --- |
| 0 | 7128, 7541, 7551, 7917, 7930, 7978, 8151, 8301, 8471 | 9883, 10340, 12873, 13018, 13189, 13704, 13705, 13792, 16561 |
| 4,000 | 30984, 31102, 31516, 31918, 32580, 32871, 32874, 33351, 34789 | 8911, 9595, 11576, 12078, 12252, 12769, 12852, 13099, 13210 |
| 12,000 | 77947, 78014, 78790, 79467, 81364, 81644, 82689, 82833, 85787 | 9443, 9802, 10604, 11053, 12747, 13130, 15589, 18446, 20695 |

Before the correction, median latency rose from 7.93 ms to 81.36 ms with unrelated-file count. Afterward it remained between 12.25 and 13.19 ms in the isolated comparison. The empty-tree sample was slower in that later run, so these samples support removal of the measured traversal cost, not a universal startup-speed improvement. All samples completed with the expected output and exit status; no useful compiler work was dropped. The deterministic trace test fails before the correction and passes afterward. The following section records subsequent installed-release acceptance; cold-cache measurements and representative build-level timings remain separate gates.

## Signed Linux installation acceptance

The signed Dev Cache 0.1.7 artifact (`4cce4e5944252f327b388a75903f0b054882ff211064de5a9f04c905418ddbb2`) was installed through authenticated Update All and its ownership-checked intercepts reactivated. Twelve sequential live GCC/G++ probes, three repetitions of each compiler with `-qversion` and `-V`, returned the expected exit 1 within a five-second bound. The earlier installed 0.1.6 `gcc -qversion` reproducer exceeded that bound. The 0.1.7 samples ranged from 0.0044 to 0.8858 seconds; these are end-to-end observations under ordinary host load, not controlled startup benchmarks.

Six subsequent interleaved direct/intercept `-qversion` comparisons preserved stdout, stderr and exit status exactly. Direct calls took 0.0033–0.0045 seconds and intercept calls 0.3736–0.4418 seconds. That remaining per-invocation cost is not attributed to maintenance: native syscall traces of the installed intercept showed no directory-enumeration calls, and the focused trace showed only workspace Git discovery followed by Ccache and GCC. The comparison does not establish the cause of the residual overhead or promise direct-compiler-equivalent latency.

Autoconf completed `AC_PROG_CC` and `AC_PROG_CXX` through the installed intercepts, including compile/link checks. Separate real C and C++ programs compiled, linked and produced their expected output. The installed `doctor --json` also completed with every reported check healthy and complete routing while the filesystem was mounted read-only and networking disabled. This qualifies the signed Linux correction and read-only observation path; cold-cache benchmarking, broader build throughput and native Windows/WSL acceptance remain distinct.
