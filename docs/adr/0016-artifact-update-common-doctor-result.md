---
authority: canonical
owner: artifact-update
---

# ADR 0016: Artifact Update common doctor result

status: proposed
verification: pending

## Context

Artifact Update is a planned product in the conformance inventory. Its initial doctor validates local configuration, emits `artifact-update-doctor-v1` only on success and sends configuration failures through the generic text-only CLI error path. The product standard instead requires one common machine-readable operation result, including failures. Configuration validity alone does not establish installation health or release authenticity.

## Decision

`doctor --json` uses the existing typed `dev-tools-operation-result-v1` result with product `artifact-update` and operation `doctor`. Product-owned fields retain `healthy`, `network_accessed` and successful `artifact_count`, and add `scope: configuration` to identify the actual inspection. Configuration and invocation rejection produce a failed, unchanged result with exit 2 and a fixed `invalid_configuration` or `invalid_invocation` error kind. Human failure messages do not repeat configuration bytes, parser excerpts or caller-supplied paths.

Inspection retains the existing bounded no-follow configuration reader and catalog parser. It does not prepare configuration directories, load caches, acquire installation locks, initialize ledgers, retrieve metadata or verify installed artifacts. A valid catalog produces exit 0 and the existing human success line. Missing, unreadable or malformed configuration retains the prior exit-2 category; this increment does not introduce finer configuration-I/O classification. The other artifact-operation result formats and persisted documents are unchanged.

## Compatibility and rollout

This is an intentional doctor-output schema cutover in the planned product, not an additive change within `artifact-update-doctor-v1`. Source users consuming the earlier prototype schema must update their schema check to the common identifier and handle nonzero-exit JSON results; successful health/count fields retain their meaning. No legacy doctor-format flag or durable-data migration is introduced. This does not change any installed binary or release artifact. Reverting the source slice before publication restores the prototype presentation without state repair because both implementations are read-only.

The product remains at the `build_info` conformance stage until its remaining common lifecycle operations and native acceptance are complete. Artifact Update owns standalone release acceptance of this format and its documented configuration-only scope; a source test or target build is not a full-standard or platform-support claim.

## Verification

Product CLI contract tests exercise valid, malformed and missing configuration and invalid invocation with a cleared environment and unavailable command search path. They assert the common identity, result category, single JSON document, fixed value-free failure kind, health scope, unchanged source bytes and absence of newly created local state. Human success output remains covered separately. Existing artifact configuration, status, installation, rollback and completion tests remain applicable. These tests do not constitute packet-level network capture or native release acceptance.
