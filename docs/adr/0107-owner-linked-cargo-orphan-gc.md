---
authority: canonical
owner: dev-cache
---

# ADR 0107: Owner-linked Cargo orphan collection

status: proposed
verification: pending

## Problem and scope

Managed Cargo intermediates live at `cache/cargo/intermediate/<worktree-id>`, outside their identity directory at `workspaces/<prefix>/<worktree-id>`. Previously, the existing orphan grace could retire an absent worktree's identity while leaving its intermediate resource under ordinary stale/pressure policy. Deleting the identity also discarded the evidence needed to relate that resource to a disappeared worktree.

Join only positively owned, disposable Cargo intermediates to an eligible current-domain orphan identity. This does not change routing, configuration defaults, ordinary stale/pressure cleanup, retained final-output policy, resource schemas, other runtime domains or external storage. Missing workspace metadata is not evidence of an orphan: historical resources whose owner record is already gone cannot acquire this new deletion authority.

## Admission and abstention

The new `orphan-workspace-cargo` action requires all of the following:

- A valid current-domain workspace identity, at its expected identity path, and exactly one valid Cargo intermediate catalog record at the matching managed intermediate path. Adapter, kind, owned-directory strategy and a recognized UUIDv4 generation must match. The complete catalog must have no malformed records and no other resource overlapping either transaction root, including ancestor and nested resources.
- Both authority documents are ordinary no-follow files, at most 64 KiB, beneath real-directory ancestry of at most 256 components. The local stronger deletion route rejects unknown top-level fields and duplicate known fields without changing existing schema readers globally.
- The owner and every resource-use timestamp are no younger than the existing orphan grace and none is in the future. Cargo must have a completion timestamp at least as recent as its start. Missing/inconsistent completion, persistent hazards, active overlapping resource paths and unknown ownership all abstain. These are additional conditions for this route, not modifications to ordinary stale/pressure policy.
- On Unix, the canonical worktree's final no-follow lookup returns exactly `NotFound`; its immediate parent and every ancestor are present, real directories, and the immediate parent's device matches the device in the recorded worktree filesystem identity. An existing/recreated directory, dangling link, redirected ancestor, missing parent, device mismatch, permission error or other I/O error is not proof of disappearance. Non-Unix records lack the required filesystem evidence and abstain from this route.
- No pending identity-reconciliation destination overlaps either root. Reconciliation is allowed to complete separately; a subsequent GC pass can make a fresh decision. This prevents an earlier action from rebasing new catalog ownership into an already admitted compound without adding a full catalog scan for each group.

If expected Cargo storage exists but evidence is absent, malformed, incomplete or uncertain, retain the workspace identity and report why. Existing metadata-only orphan behavior remains only when a complete catalog has no overlapping Cargo resource and a component-by-component no-follow observation establishes that the expected Cargo subtree is absent. A missing leaf behind a redirected ancestor is not that proof.

Workspace identities currently store Unix device/inode observations, not stable volume UUIDs for every source ancestor. This deliberately conservative continuity check cannot prove the history of a reused device number or provide descriptor custody against a same-owner adversary. A source mount point that still exists is protected; missing parents and changed devices abstain. Broader offline-volume recovery and source identity migration are outside this change.

## Planning, application and recovery

The owner directory and Cargo intermediate directory are two explicit `companion_paths` in one action, with the owner also remaining the primary reporting path. One shared payload traversal measures both and checked arithmetic sums their bytes. Nested standalone candidates under either root are suppressed, so selection does not double count the same payload. One action-cap slot selects both or neither. It remains an action budget, not a bound on bytes, metadata enumeration or elapsed time.

The printed plan is observational only. Applied collection retains exclusive root coordination and fresh in-memory owner/resource snapshots. Immediately before mutation, it checks the exact action against those snapshots, re-reads bounded owner/resource metadata and generation, checks source disappearance and ages again, and re-observes resource activity. Catalog-overlap authority comes from the initial complete catalog under exclusive coordination and the reconciliation exclusion, not an additional per-action scan. Previews retain shared read-only coordination and may become stale; apply always computes its own plan.

Both roots use the existing owned-trash journal in one transaction. Pre-commit staging failure restores staged members; interrupted uncommitted recovery restores all members. A conflicting recreated destination fails recovery while preserving staged bytes and the journal. Only an exact no-follow `NotFound` establishes absence during staging, restoration or journal retirement; permission and other observation errors fail recovery while retaining its journal and any remaining staged bytes. After commit, recovery finishes removal. The exact Cargo catalog record is removed after the transaction. An interruption after committed deletion can leave a stale catalog record; that record cannot reconstruct missing owner authority. No new recovery schema or transaction authority is introduced.

Retained final outputs remain outside both fixed transaction roots and are never selected by this action. Existing generic retained-path protection and retain-strategy policy remain unchanged. No source checkout or external target directory is moved or deleted.

## Qualification boundary

Pending source gates cover public-binary preview/apply JSON and nonmutation, repeated collection, compound byte accounting, zero/one action caps, active leases, existing/recreated sources, incomplete/recent/future/hazardous records, missing owner/catalog, invalid/unknown/duplicate authority, redirected/unavailable ancestry, device mismatch, overlapping resources, reconciliation deferral, retained outputs, changed admission snapshots, and one/two-member interrupted recovery with rollback conflicts.

All scenarios must run on isolated synthetic owned-storage fixtures. Native acceptance additionally needs supported Unix filesystem/mount behavior, permissions and I/O failures, actual rename/interruption failures, and installed binary qualification. No native platform acceptance, live cleanup, signed release, installed activation, or rollback qualification is established by source inspection or compilation. GC still performs its existing domain size scan; this correction does not make GC a cheap bounded inventory.
