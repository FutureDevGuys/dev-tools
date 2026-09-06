---
authority: canonical
owner: dev-tools
---

# ADR 0015: Dev Cache read-only root observation

status: proposed
verification: pending

## Decision

Dev Cache separates observation of an initialized cache root from preparation for routed work. `RootHandle::observe` validates the existing marker, canonical path, volume, current runtime-domain registration and required directory layout without writing a probe, enrolling a domain or creating missing directories. Missing state is an error to report, not implicit repair authority. Successful observation does not prove writability. `status`, `doctor`, `report`, `path`, migration previews and explicit GC previews use this path, including the status details embedded in doctor output; ordinary root preparation and routed operations keep their initialization behavior.

This corrects an unintended side effect of diagnostic discovery. Existing initialized roots retain their report shape and identity. Incomplete roots now remain incomplete and are reported rather than silently repaired. No marker schema, domain identity, CLI grammar, resource usage timestamp or receipt changes. The existing native tool/version/configuration probes are unchanged; this correction does not prove all subprocess behavior or complete common-doctor schema/network conformance.

Writable preparation uses a unique no-clobber probe rather than overwriting and removing a predictable PID-named entry. Existing file and symlink collisions are left untouched. Probe creation uses owner-only Unix permissions and explicit cleanup is attempted after write failure. Interrupted residual probes are not adopted or automatically deleted. This is not a new same-owner adversary isolation boundary.

GC previews retain nonblocking exclusive coordination through the existing root lock, opened without write or creation access, for the lifetime of planning. They neither clean stale activity records nor recover trash; Linux records proven dead are ignored for planning but retained for applied collection to clean. Busy coordination preserves `collect_if_idle` deferral. Missing coordination fails rather than falling back to an unlocked plan. Explicit root initialization prepares the stable lock, including an already configured root reached through `config init-root`; an older root missing that file must be explicitly initialized before previewing collection. The lock is never removed or replaced by normal operations. Existing applied collection and automatic maintenance retain preparation, stale-record cleanup and recovery. A plan remains an observation, not a retained authorization to execute its listed paths later; apply computes its own current plan.

Both lock-opening modes reject non-regular final handles, Unix symlinks and Windows reparse points. Unix opens use `O_NOFOLLOW | O_NONBLOCK` so a FIFO cannot block before type validation, and new Unix coordination files use mode 0600. Windows uses `FILE_FLAG_OPEN_REPARSE_POINT` followed by handle metadata validation. These are final-component controls, not a claim of race-proof ancestor custody or isolation from a same-owner filesystem adversary. The Unix constants use a direct default-feature-disabled edge to already locked `libc` 0.2.189 (MIT OR Apache-2.0, `rust-lang/libc`, source `ef0906e20828777175f65caa7e681a0ce33c559a`); no package version, runtime, network stack or unsafe source is added. The existing build script and lock checksum remain unchanged. The private installation-file helpers enforce a different owner-only document/layout contract and are not reused for this product's existing coordination format.

## Verification

Public-binary tests run diagnostic commands and migration previews with an isolated home and empty tool-search path. Missing layout and missing runtime registration remain unmodified and produce unhealthy/error results. A deterministic old root-directory modification time detects even temporary create/delete probes on Linux. Separate root preparation tests preserve pre-existing PID-named regular files and symlinks with unrelated targets. GC tests compare complete fixture inventory and file bytes across preview, preserve stale records until applied collection, reject missing or redirected coordination, bound FIFO rejection, and hold/release a real shared lease to prove nonblocking exclusion without timing sleeps. Existing root initialization, runtime-domain, routing, resource catalog, activation and maintenance tests remain required. Native Windows/WSL acceptance and signed installed-artifact qualification remain release gates.
