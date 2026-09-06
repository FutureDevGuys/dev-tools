---
authority: canonical
owner: dev-tools
---

# ADR 0020: Separate update artifact preparation

status: proposed
verification: pending

## Context

The original update adapter exposed one metadata refresh callback but required its returned artifact to be already available before install or apply. This either blocked online installation after a metadata-only refresh or encouraged downloading payloads during `update check`. It also blocked a clean offline no-op when the installed version already met the authenticated candidate but disposable payload bytes were absent.

## Decision

`UpdateAdapter::refresh_authenticated_candidate` remains metadata-only. The additive `prepare_artifact` callback is an explicit online install/apply boundary, invoked only after candidate identity validation and the installed-version no-op decision, and only when payload bytes are unavailable. It prepares private authenticated quarantine or cache bytes without changing managed installation state. It cannot replace any verified release field or refresh the candidate timestamp. Returning incomplete availability blocks activation; failure remains a preflight failure with no installation change. Product-owned activation independently rechecks custody, accepted release authority and installation preconditions.

Status, check, rollback and offline operations never call artifact preparation. Offline mutation requiring newer bytes still blocks without an authenticated cached payload. A version-satisfied request returns no-op without requiring payload retention, including expired offline evidence; this does not assert fresh currentness, and the result retains its cache freshness classification.

The default callback reports unsupported rather than inventing a product transport. Existing adapters that supply already available bytes need not implement it. The pending update 0.2.0 source generation includes this additive seam alongside ADR 0019; no signed archive or published version is replaced. Provider discovery, source codecs and existing Artifact Update operation-specific outputs are unchanged. Actual product adapters, native transport isolation, and released-binary installation acceptance remain gates rather than consequences of these fixture tests.

## Verification

Tests first reproduced both the blocked metadata-only online update and the blocked version-satisfied offline request. Public adapter tests exercise online preparation, no preparation during local/check operations or with already available bytes, exact release/timestamp preservation, incomplete preparation, and failure before installation. Existing signed source, cache, offline and product suites continue to qualify their independent authority boundaries.
