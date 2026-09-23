---
authority: canonical
owner: update-all
---

# ADR 0024: Canonical assets after an incomplete GitHub release index

status: proposed
verification: pending

## Context

GitHub's public release list and tag-summary endpoints can report an empty embedded asset array for a newly published release while the release-ID, dedicated asset-list and direct-download endpoints expose the complete uploaded set. The installed Update All 0.1.9 then refuses ordinary latest-product discovery even when an exact authenticated root/manifest URL route can verify and install the signed release. The listed tag remains useful stable-version evidence; the embedded asset array is not always a complete availability observation.

## Decision

Update All still selects the greatest stable product-scoped SemVer tag from bounded anonymous GitHub release metadata. When that selected release's list view omits one of the fixed root-document or product-manifest assets, it constructs only the missing URL from the product-owned canonical GitHub release-download base, the selected tag and the fixed asset name. Duplicate named assets remain an error, and it never downgrades to an older release just because the newest listing is incomplete. The shared release selector accepts the canonical base as an explicit typed input; it contains no product or repository branch.

The canonical URL is HTTPS, rejects authority credentials, query and fragment input, and percent-encodes the tag as one path segment. The existing HTTPS host/redirect admission runs before contact. Fetching a nonexistent asset still fails; fetched root and manifest bytes still require normal signature, source-binding, anti-rollback and artifact-URL verification before an update. This is metadata-discovery repair, not permission to accept unsigned or unlisted payload bytes. An exact root/manifest URL override retains its separate existing behavior.

## Invariants

The stable tag selection, latest-version choice and accepted release history do not change. A missing embedded asset permits only a canonical URL attempt, not a successful release conclusion. Duplicate required assets never use fallback. No URL base is learned from untrusted release metadata. Downloaded bytes, rather than an asset name or HTTP status alone, remain the signed authority for installation. No new host, redirect, credential or background network behavior is admitted.

## Rejected alternatives

Falling back to the next older listed version would hide a broken latest release and could cause downgrade. Trusting the dedicated asset list without signature verification would move authority into another unsigned GitHub response. Retrying the same assetless list indefinitely does not make the current host usable. Rewriting the published release assets or replacing an accepted tag would violate immutable release custody.

## Consequences and known limitations

An incomplete list can cause one canonical root/manifest fetch that later fails if the assets truly are absent; this is an operational failure, never a no-op or downgrade. GitHub repository/product release layout remains product-owned and native platform support is unchanged. Update All 0.1.9 remains immutable and cannot gain this behavior in place. Release-admin's separate idempotent public readback may still disagree with GitHub's list view; that publication boundary is not silently relaxed by this reader change.

## Verification

`product_release_resolution_recovers_canonical_urls_from_an_incomplete_index` protects the exact Update All base and latest-version choice; `product_release_resolution_uses_latest_stable_matching_tag` protects existing stable selection. Shared release tests separately reject duplicate required assets and unsafe bases. Source lint, format, product tests, target checks and signed native release acceptance are required.

## Runtime acceptance

The triggering public `dev-cache/v0.1.10` release had all three uploaded assets at its release-ID and direct-download endpoints while GitHub's release-list/tag endpoints embedded zero assets; Update All 0.1.9 rejected ordinary discovery, although its exact authenticated URL route installed and rolled back the same signed artifact. The new standalone reader must pass ordinary discovery against that public state, then pass signed installation, repeat and offline rollback without an override before its Linux release is accepted. Other native platforms remain separate gates.

## Supersession conditions

Supersede this record if product release layout changes, unsigned discovery no longer selects the latest stable tag, or a different authenticated publication authority replaces GitHub releases. Preserve signature and anti-rollback admission independent of provider listing completeness.
