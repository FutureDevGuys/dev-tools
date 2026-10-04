---
authority: canonical
owner: update-all
---

# ADR 0025: Explicit offline signed-bundle intake

status: proposed
verification: pending

## Context

An operator can already possess the exact signed root, source-bound product
manifest and native artifact while network discovery or download is unavailable.
The product release entrypoints need a bounded local input path without turning
HTTP observations into release authority, weakening trust, or manufacturing an
installation receipt. The complete common update mutation adapter remains a
separate cutover.

## Decision

Only `update-all product install PRODUCT` and `update-all product update PRODUCT`
gain explicit bundle intake. Each requires `--offline --root-document ABS
--manifest ABS --artifact ABS` together; the existing optional `--json` remains.
No bundle options preserves the existing online operation. Product status, check,
update-if-installed and rollback, all self commands, and common update commands
do not gain these flags. Both explicit bundle entrypoints use the same
product-owned offline installation boundary and the existing activation result
and error surface.

Native intake initially fails closed outside Linux x86-64. It snapshots nonempty
local inputs with the shared bounded nofollow document reader. All paths must be
absolute and contain no parent traversal or symlink components. Inputs must be
single-link regular files owned by the invoking uid or root, without special
mode bits or group/other write permission. Root and manifest bodies are bounded
at 512 KiB each; the artifact is bounded at 256 MiB. Path and custody admission
belong to the release adapter, independent of CLI parsing.

The supplied root must authenticate under the fixed compiled root key. Only
stable source-bound product-v2 manifests are admitted, with the selected product,
actual native target, protocol and existing signed GitHub artifact-URL authority.
An offline path is not a trust override or an alternate artifact origin. No
metadata or artifact URL is contacted. Exact artifact length and digest are
verified before installation recovery or candidate execution.

The product retains its existing nonblocking release-writer lease from accepted
history admission through final publication. Missing or reset accepted history beside
managed receipts, journals, version storage or pointers fails closed; local
intake never reconstructs it from installed bytes. Authentication rejects rollback and
equivocation against that history before recovery. Original signed bytes are
stored through the shared authenticated release cache in a product-owned root
keyed by exact root and manifest hashes. Existing installation recovery uses the
prior accepted state. The admitted root, generation, version, manifest and binary
identities are durably accepted before candidate activation, while the same
writer lease remains held. Active and previous version observations are then
synchronized from the installation receipt. Every publication remains bound to
its admitted history; a failed or uncertain publication ends that transaction.

## Invariants

- Offline intake neither contacts a network source nor falls back to online
  discovery when admission fails. The signed artifact URL is validated as
  authority, not used as a download request.
- Local file names, cache presence and self-reported version output cannot grant
  release trust. There is no production signing-key or root-trust override.
- The last successful online-check timestamp is preserved exactly, including
  absence. Accepting offline evidence does not establish fresh online currentness.
- External public commands retain the existing external/no-change outcome and
  are not overwritten. Managed activation and rollback remain receipt-owned.
- The change result concerns managed installation state, including recovered
  journals and repaired links. Cache or accepted-metadata writes alone do not
  establish installation change. An exact receipt-current repeat is unchanged
  only when it requires no managed recovery or repair.
- Failed health or activation may leave authenticated cache and newly accepted
  release history. Exact retry uses normal recovery without lowering accepted
  history. Retained receipt-owned rollback remains separate from candidate intake.
- No code synthesizes signed proof or an installation receipt. Existing shared
  verification, bounded health and installation primitives retain their authority.

## Rejected alternatives

Using local files as an implicit fallback after a failed online check obscures
the network boundary and input selection. Accepting arbitrary root keys or URLs
would create a second release authority. Advancing accepted history only after
activation lets an interrupted or failed activation forget authenticated
anti-rollback evidence. Treating a cache publication as installation change or
treating a recovered receipt-current request as a clean no-op misreports durable
managed state. Moving this narrow feature into the unfinished common mutation
adapter would couple it to unrelated protocol migration.

## Consequences and known limitations

An operator must supply the complete original signed bundle and safe absolute
paths. A newer authenticated bundle that fails health can still advance accepted
history, so an older candidate cannot be used to bypass that decision; retry the
exact bundle or use the existing authenticated receipt-owned rollback operation
when eligible. The cache is not a replacement for durable history or proof that
the requested version is installed. This additive source change does not alter
release versions, accepted artifact bytes, online discovery, automatic update
behavior, common-operation schemas or conformance level. Mixed-version writers,
real process-death recovery and non-Linux native support remain separate gates.

## Verification

The parser regressions `product_offline_bundle_arguments_are_all_or_none`,
`product_offline_bundle_arguments_preserve_paths_and_json` and
`product_offline_bundle_flags_are_scoped_to_install_and_update` protect the exact
entrypoints, complete-input requirement, path forwarding and existing JSON flag.
The release-adapter regressions include
`offline_signed_bundle_installs_repeats_upgrades_and_rolls_back`,
`offline_signed_bundle_rejects_rollback_and_equivocation_before_recovery`,
`offline_signed_bundle_rejects_lost_history_without_repair_or_downgrade`,
`offline_signed_bundle_recovers_first_install_journals_and_owned_alias`,
`offline_signed_bundle_recovers_receipt_commit_before_state_publication`,
`offline_signed_bundle_acceptance_failure_ends_writer_without_forgetting_publication`,
and `offline_signed_bundle_preserves_freshness_and_metadata_only_no_change`.
Together with the remaining offline intake tests they cover original signed evidence,
stable source and target binding, fixed trust and revocation, length and digest,
rollback and equivocation, unsafe inputs, external collisions, writer exclusion,
early history acceptance, failed-publication identity, interruption and exact
retry, managed change accounting, unchanged online-check timestamps and absence
of network invocation. Test-only signing keys stay in private fixture boundaries.
Source tests do not establish native signed-release acceptance.

## Runtime acceptance

Run the exact source-bound standalone Linux x86-64 candidate outside a checkout
with a reviewed original signed bundle, traced network isolation and clean
managed roots. Qualify first install, unchanged repeat, upgrade, retained
rollback, hostile custody and collisions, competing writers, failed health and
real interruption before and after accepted-history and installation-journal
publication. Verify receipt-owned recovery, stable timestamp preservation and
the exact signed native binary identity. Record this native acceptance before
marking the decision accepted; compilation and synthetic fixtures are
insufficient. Other native platforms require their own custody and runtime gates.

## Supersession conditions

Supersede this record if bundle format, platform scope, trust authority or
accepted-history ordering changes, or if these entrypoints migrate to the common
update mutation adapter. Preserve explicit complete inputs, no network access,
durable monotonic history, original signed proof, receipt-owned mutation and
honest recovery/change results.
