---
authority: canonical
owner: dev-auth
---

# ADR 0091: Metadata-only stable-release observation

status: proposed
verification: pending

## Decision

Dev Auth separates explicit stable-release metadata observation from artifact preparation. A check retrieves the release index, root, and manifest, verifies the source-bound product/target signature and selected stable version, and writes one private atomic observation containing the signed bytes and local check time. If the release list omits required assets, discovery fetches only the selected latest stable release by its numeric GitHub release ID and requires the detail to retain that exact ID, tag and stable classification before selecting assets. This addresses incomplete list projections without guessing URLs or replacing manifest authentication. The check does not request artifact bytes or change the installed generation. A local observation read creates no cache state, reauthenticates the signed bytes, and supplies no installation authority by itself. An absent or expired observation cannot establish currentness.

Artifact preparation consumes the exact checked signed metadata, fetches only its signed artifact URL and length, verifies the bytes, and uses the existing accepted-release cache and ledger. It cannot replace the selected release identity or refresh the check time. Existing `setup plan` online staging uses these two boundaries in sequence; offline staging continues to require the exact previously accepted cached artifact.

The private observation is serialized under its own stable lock and compare-before-replace document identity. An older finishing check cannot overwrite newer observed metadata; conflicting metadata at the same check second is rejected. Linux status/check use the current account's platform cache independently of the root-owned accepted-release ledger, so ordinary users can observe signed public metadata without gaining installation authority. Root setup staging retains its own accepted-ledger preflight. A cache observation is disposable and never a substitute for setup-plan approval, receipt-owned installation, rollback custody, or the administrator-policy transaction. The Linux candidate exposes `update status` and `update check` through the shared result orchestrator; a source-tree or externally managed binary reports `external` without fetching or creating state. Other platforms emit the common value-free unsupported result until a native release-storage adapter exists. Mutating `update` operations remain unavailable rather than succeeding through an incomplete setup bypass.

## Remaining gate

This partial read-only interface does not complete the canonical `update` CLI. The product adapter still needs read-only cached-artifact availability for offline update, explicit setup-aware install/apply approval, retained full-generation rollback and failure/recovery mapping before the mutation interface is enabled. The Linux read-only adapter classifies transport, signed-metadata, custody and operational failures into fixed common result categories without exposing their source text. Signed standalone installation and native acceptance remain release gates.

## Verification

Local tests cover absent observations without cache creation, signed metadata reauthentication, distinct user-observation and accepted-installation custody, stale and conflicting observation writes, fixed error categories, exact release-ID fallback, source-tree external results, completion grammar and installed user-only local status. The opt-in network test fetches only signed release metadata into a disposable cache. These checks do not qualify mutation or native strong-mode public status.
