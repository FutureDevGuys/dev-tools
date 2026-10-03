---
authority: canonical
owner: dev-auth
---

# ADR 0060: Retained integration retirement in forward setup

status: proposed
verification: pending

## Decision

Linux setup apply and installed-candidate recovery use the generation-bound workload and desktop retirement from ADR 0059. The full setup caller holds admission exclusion and validates native identities. Before selecting retirement, it reads the durable retained transition and requires pending direction, exact approved plan equality, matching canonical plan digest and an intact candidate-document inventory. A live receipt cannot widen the selected names, targets or contents. The installation receipt's absence does not skip retained user integration retirement; other metadata errors fail instead of masquerading as absence.

The composite operation selects both integration families for every desired and retiring account and observes them all before its first integration removal. Drift known at that boundary blocks retirement without removing valid integrations in another account. Later filesystem changes or failures can still leave partial progress; the pending generation and each descriptor-bound removal's durable ordering preserve retry authority. This is not atomic multi-account deletion or protection against an uncoordinated same-owner writer.

Forward recovery removes exact owned candidate entries published before their receipts, while preserving unrelated names and incompatible unreceipted candidate-name collisions. It does not activate workloads while enrollment remains incomplete. Completed retirement contributes its established change result directly to setup apply and recovery reports, since the existing document fingerprint does not enumerate unreceipted candidate entries. Entered failures retain the existing unknown-progress result contract. No receipt, transition or result schema changes.

The old Linux forward reconciliation route is removed from this boundary. Non-Linux setup retains its existing implementation until native descriptor-bound retirement exists; Linux source and namespace tests do not qualify another platform. The public strong restoration gate, existing binary-installation recovery limitation, frozen release compatibility and signed-release acceptance requirements are unchanged.

## Evidence

The disposable native-user CLI regression first failed because recovery left an unreceipted candidate launcher active. After routing retirement through retained authority, a second assertion failed because the completed removal was reported as unchanged. The corrected path removes both candidate integrations, preserves an unrelated link to the same executable and retains exact generation bytes after original source files are removed. The fixtures then republish the integrations and exercise prior-installation or initial-absence restoration and unchanged retry.

The explicit namespace-root integration fixture exercises the composite retirement across distinct desired and retiring UIDs. Drift in the last account's owned desktop entry rejects the whole operation before the first account's valid launcher or receipt is removed. Restoring the fixture's original bytes allows exact retirement, unchanged retry and independent postcondition verification while unrelated account files and directory custody remain intact. This is native source-fixture evidence, not signed strong-mode setup, live enrollment, process-death or power-loss acceptance.
