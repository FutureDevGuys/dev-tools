# Artifact staging transfer probe

The shared release staging API uses bounded memory independently of artifact size. Its isolated body-copy probe compares the existing `read_bounded_body` plus SHA-256 and sink write with the new streamed copy, SHA-256 and sink write. Both authenticate exactly the same generated zero-filled payload; no input-sized fixture allocation is included. It does not measure TLS, redirects, network speed, filesystem writes, fsync, installation or whole-product memory.

## Reproduction and scope

Build with `cargo test -p dev-tools-release --locked --lib --no-run`. Run the resulting library test executable directly with `--ignored --exact stream::tests::transfer_memory_probe`. Set `ARTIFACT_TRANSFER_MODE` to `buffered` or `streamed` and `ARTIFACT_TRANSFER_MIB` to `1`, `64` or `128`. Measure each invocation in a separate process using per-child `wait4` peak resident memory, not cumulative child accounting from a shell or reused supervisor. Interleave the two modes for three trials at each size. The ordinary unit suite intentionally ignores this measurement test.

The following raw measurements used Linux x86-64, Rust 1.98.1, the locked dependencies and the unoptimized test profile on 2026-09-05. Each cell lists the three successive trials. Elapsed time includes test startup and fixed-buffer construction of the expected digest, common to both paths; it is not a download-latency measurement. Peak RSS also includes the process-launch baseline (about 12 MiB here), so these observations cannot resolve the streamed helper's exact allocation below that floor.

| Input MiB | Mode | Peak RSS KiB, trials 1–3 | Elapsed seconds, trials 1–3 |
| --- | --- | --- | --- |
| 1 | buffered | 12180, 12372, 12372 | 0.053, 0.056, 0.054 |
| 1 | streamed | 12372, 12372, 12372 | 0.052, 0.051, 0.052 |
| 64 | buffered | 135532, 135248, 135352 | 3.206, 3.250, 3.213 |
| 64 | streamed | 12372, 12372, 12372 | 3.156, 3.132, 3.138 |
| 128 | buffered | 266356, 266268, 265892 | 6.402, 6.363, 6.444 |
| 128 | streamed | 12372, 12372, 12372 | 6.268, 6.252, 6.296 |

All 18 transfers completed and verified their expected digest. The buffered path's resident-memory growth reflects its full response allocation; the streamed path stayed at the process-launch floor over this range. This supports the bounded-memory transfer choice, not a whole-product performance or native-platform support claim. The small elapsed-time difference is not used as a speed claim. An initial cumulative-accounting run was discarded after an anomalous final sample inherited earlier child usage; the table uses only per-child measurements.

The correctness suite separately checks signed metadata and configured bounds before transfer, HTTP status rejection, exact-length success, truncation, excess bytes, wrong digest, bounded write chunks, short writes and read/write/flush errors. Streaming can write unverified partial bytes before detecting failure; the public API requires caller-owned quarantine storage and disposal on failure. Publication and installation remain separate gates.
