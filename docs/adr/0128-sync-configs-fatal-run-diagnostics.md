---
authority: canonical
owner: sync-configs
---

# ADR 0128: SyncConfigs closed fatal-run diagnostics

status: proposed
verification: pending

## Context and decision

The engine retains typed hook, privilege and authentication failures, but the fatal CLI boundary reduces JSON to `convergence_failed`. Default event logging records only run start/end and exit status for that path. A run without an explicit transcript can therefore lose the distinction between a hook execution timeout, privileged-command timeout and authentication failure. Elapsed time or the last observed process is not evidence of a particular error variant.

The product adds one closed `FailureDiagnostic` projection from `EngineError`, computed once in the fatal CLI branch. The existing JSON `error_kind: convergence_failed`, human rendering and exit status remain unchanged. An additive `failure` object carries the same projection in fatal JSON, optional terminal run metadata and an Error-level `run_failure` event. It distinguishes typed hook timeout with pre/post phase, privileged-command timeout, authentication process failure with cached-check/prompt stage and optional OS code, and authentication unsuccessful exit with stage and optional exit code/signal. Remaining errors retain a generic `convergence_failed` kind. Process error text and the platform's I/O-kind spelling are not serialized.

Nested hook privilege and privileged-target command errors use the same projection as direct privilege errors. A cleanup failure whose primary error has already become a string remains generic; no string is parsed to reconstruct a cause. Normal unsuccessful hooks and other aggregate report failures retain their existing per-entry report behavior. Interruption finalization continues to take precedence and return 130 without reclassifying it as a fatal timeout.

The projection accepts only typed variants and native numeric status fields. It contains no error-chain rendering, executable/target path, operation label, manifest content, command, environment, provider output or captured stream. It introduces no dependency on a consumer, host profile or machine path.

The recorder retains the projection independently of optional event-channel availability and persists it through the existing terminal metadata publication before the final event. Logging remains best effort and does not change convergence results. Existing style/level filters, byte limits, storage custody, retention and platform restrictions remain authoritative. Older run metadata without `failure` remains readable through an optional defaulted field; prior readers ignore the additive field. Unknown future failure kinds deserialize to the generic kind rather than making an otherwise readable run disappear. The schema version is unchanged. Older runs without a typed cause remain unknown.

No hook/privilege timeout, runner, cleanup, authentication, stdin/TTY, policy, raw-output retention, profile/default selection or desired-state behavior changes. No native operation is retried by this diagnostic correction. A later release must use a new product version rather than replacing accepted 0.3.0 bytes.

## Verification and acceptance

Existing conformance cases are extended in source for fatal JSON compatibility, typed cause projection and terminal metadata/event persistence, including optional event write failure. No new test framework or consumer fixture is introduced. Build, tests, lint, CI, native failure reproduction and installed acceptance are unrun under the source-only instruction. Independent source review can verify the mapping and publication order but does not establish runtime behavior or identify a historical failure cause.
