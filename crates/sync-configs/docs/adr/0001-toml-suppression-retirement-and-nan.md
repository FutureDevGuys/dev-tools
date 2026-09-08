# ADR 0001: Preserve TOML suppression through key retirement

status: proposed
verification: pending

## Decision

TOML overlay semantic comparison treats two NaN values as equal, including signed NaN, while retaining ordinary finite and infinity comparisons. An untouched target NaN must not cause the semantic postcondition to reject an otherwise valid overlay. Source/target conflict policy and the postcondition remain in place.

Recognizable target comment directives that disable assignments or tables retain their meaning when a receipt-owned key or empty table retires. Parser formatting trivia can be attached to the retired item, so rendering restores only directives whose semantic path is missing. Restored directives precede active tables; former table-scoped assignments are fully qualified so relocation preserves meaning. Surviving directives are not duplicated, and suppression for a currently absent source setting is retained for a later revision.

The directive scanner uses parser-provided string spans to exclude comment/header-looking lines inside literal and basic multiline strings, arrays and inline tables. String contents do not grant suppression authority. Receipt ownership and conflict precedence remain authoritative. No file format, runtime dependency or private consumer policy is introduced.

## Verification and release

Public overlay tests cover nested/array/signed NaN, genuine finite/infinity conflicts, retired root/nested keys, empty-table retirement, future-source directives, multiline-string counterexamples and repeat convergence. Public CLI tests exercise receipt-backed retirement with NaN and suppression in one target. The original semantic error, lost directive and false multiline-string suppression each had a failing regression before correction.

Signed source-bound release and installed-artifact acceptance remain pending; source tests do not authorize downstream artifact cutover. Binary rollback does not reverse an already-applied configuration merge.
