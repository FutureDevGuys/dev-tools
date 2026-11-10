---
authority: canonical
owner: dev-cache
---

# ADR 0144: Explicit GC protected paths

status: proposed
verification: pending

## Contract

Manual `gc --protect-path ABSOLUTE_MANAGED_PATH` is repeatable and narrows, never expands, existing cleanup authority. Each path must be within the current runtime domain cache, workspace or artifact payload trees (control metadata and trash are rejected), with no parent components or symlink/reparse ancestry. Missing leaves are permitted. Source checkout paths are not cache paths: callers must identify every managed resource to retain, including shared resources when ownership is uncertain. This option does not infer repository ownership or alter policy/configuration.

An action is excluded if its primary path, destination, or any companion overlaps a protected path in either direction. Filtering occurs before size/pressure selection and action caps. Excluded actions appear as explicit abstentions. Protection is invocation-local and does not affect later automatic GC; combining the option with automatic mode is rejected.

Because interrupted-transaction recovery runs before planning, protected apply refuses any existing trash or journal entries before entering recovery. It does not delete committed trash, restore originals, or edit those journals. Ordinary unrestricted recovery is unchanged. Root coordination and existing fresh mutation admission remain mandatory.

## Evidence and limitations

Synthetic public/core journeys must prove companion and descendant protection, sibling collection, unchanged preview, committed/uncommitted recovery refusal, invalid path rejection, and CLI parsing. Native qualification of a candidate binary is separate from tests and compilation. No live collection, installed activation, signed release or platform qualification is established by this document.

Cloud source evidence (2026-11-10): 222 tests passed with two existing ignored and three explicitly filtered capability-dependent tests (two ptrace, one Unix socket bind). Unfiltered suite fails on those cloud-denied capabilities. Public binary fixtures cover repeated protection, protected compound payload preservation, invalid/control/symlink inputs and automatic-mode conflict. Core fixtures cover committed/uncommitted recovery refusal and sibling collection; unit evidence covers reconciliation destination and ancestor overlap, not a native rehome journey. Independent review reproduced then verified correction of initially accepted control-path exclusions. Native desktop acceptance and all real ownership mappings remain required before live cleanup.
