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

## Residual setup-flush correction

A subsequent timestamped syscall trace attributed the residual installed 0.1.7 delay mainly to seven serial metadata flushes on the selected storage root. Their individual elapsed times were 0.058478, 0.039383, 0.050490, 0.053433, 0.047709, 0.054352 and 0.042959 seconds. The initial unscoped lease record was immediately replaced by a scoped record before delegation even though the held root lock already excluded collection during setup.

The 0.1.8 release keeps setup-only lease metadata in memory and durably publishes the scoped record before unlocking. Repository identity, resource registration and completion writes retain their existing synchronization. Four lease-setup integration tests cover collector exclusion, abandonment, publication failure and independent same-process activities; the last case also prevents the previous PID/second filename collision.

Two independent native release builds from signed source `2cefec9daffa4e6270a58f1449eb54987bcf091e` produced identical artifacts with SHA-256 `e12fe877b587fc9e4ec9a3600fdd6c252198babf5d45cbca68385795cae7a969`. The comparison below interleaved nine calls per variant and argument through installed 0.1.7 and the signed 0.1.8 candidate, from the same temporary workspace and live cache configuration. Both variants used the same PATH with the installed intercept directory removed so they selected native upstream tools. An initial comparison that accidentally nested the candidate through the installed intercepts was rejected; a separately located executable must not inherit another installation's intercepts when measuring one layer.

| Compiler probe | 0.1.7 samples (ms) | 0.1.8 samples (ms) |
| --- | --- | --- |
| GCC `-qversion` | 450.90, 429.15, 417.38, 452.71, 368.12, 370.03, 376.51, 421.41, 426.02 | 362.41, 366.86, 361.01, 319.62, 377.17, 335.70, 396.40, 383.28, 343.73 |
| GCC `-V` | 8.17, 6.35, 11.28, 5.58, 9.01, 5.42, 7.79, 5.64, 6.51 | 5.63, 7.12, 9.72, 7.26, 13.27, 6.16, 10.22, 6.81, 10.14 |
| G++ `-qversion` | 402.21, 387.90, 433.75, 409.85, 354.00, 403.54, 410.19, 386.90, 418.17 | 386.33, 301.35, 721.42, 467.66, 375.54, 394.14, 327.70, 376.23, 385.77 |
| G++ `-V` | 4.03, 8.18, 5.99, 5.33, 9.09, 3.91, 4.18, 6.84, 5.04 | 5.02, 6.36, 4.28, 4.37, 5.61, 3.50, 5.13, 5.81, 4.69 |

All 72 invocations preserved direct compiler stdout, stderr and exit status exactly. The `-qversion` medians decreased from 421.41 to 362.41 ms for GCC and 403.54 to 385.77 ms for G++; host-load variability and the candidate outlier preclude a universal latency or tail-improvement claim. The short `-V` path is a separate workload, not evidence of the flush correction. Subsequent native traces showed six flushes for 0.1.8 versus seven for 0.1.7, with no directory enumeration and a single native Ccache/compiler delegation. This qualifies removal of the redundant operation, not elimination of the remaining durable bookkeeping cost or a cold-cache/build-throughput improvement.

The candidate passed Autoconf `AC_PROG_CC`/`AC_PROG_CXX` and real C/C++ compile, link and expected-output checks with native upstream selection; the installed intercepts also passed both real-language fixtures. Authenticated native publication and anonymous asset verification succeeded; repeat publication was nonmutating. Update All installed the exact signed bytes, repeat installation and intercept activation were nonmutating, and network-isolated retained rollback restored 0.1.7 and then 0.1.8. A separate empty home mounted into an isolated process namespace passed online first installation and repeat installation with no external executables on PATH and no source checkout available; the fresh binary returned its clean signed build identity with networking disabled. These checks qualify the Linux release correction; broader native-platform and full product conformance gates remain separate.
