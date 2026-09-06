---
authority: canonical
owner: dev-tools
---

# ADR 0022: Common local update observation

status: proposed
verification: pending

## Context

The legacy self-status document copies observational version and check-time fields from state.json. It cannot represent an interrupted product cutover or establish the common authenticated-cache freshness contract. The common operation loop needs a product-owned read-only entrypoint before mutation routing changes.

## Decision

`update-all update status [--json]` runs through the shared update loop and emits the v2 common result. On Linux, the product adapter distinguishes absence, an external public command, receipt-owned installation and recognized pending v2 cutover. Complete installation observation verifies local receipt custody, artifact bytes and links without creation or recovery. Initialized v2 observation additionally requires the authenticated product authority document and receipt-bound proofs. Recognized pending v2 journals report unknown installation with no installed version; unrecognized journals fail without repair.

Legacy check timestamps and HTTP cache documents do not populate the common authenticated candidate cache. Until the metadata adapter supplies that cache, this status route reports unknown release status and absent cache evidence rather than current. Local receipt ownership can still supply an installed version independently of release availability. Missing home configuration and observation failures emit one value-free JSON result with its matching exit code. Other native platforms return unsupported until their observation backends are qualified.

## Invariants

Status cannot initialize, retire state, recover journals, execute candidate health or retrieve metadata or artifacts. Missing initialized authority fails rather than importing legacy history. Legacy observational versions cannot establish installed receipt ownership. No new public mutation command or unsupported placeholder operation is exposed.

## Rejected alternatives

Mapping the six-hour legacy check time to common freshness would grant authority to an HTTP observation. Using the legacy verification helper would perform recovery during status. Routing self/product mutation to the new installation protocol before the common mutation adapter is complete would make recovery and activation inaccessible.

## Consequences and known limitations

Only the common status subcommand is exposed in this integration slice. Legacy self/product routes and ordinary automatic-update behavior are unchanged; removing implicit network access remains part of the full adapter cutover. Metadata refresh, candidate caching, mutation preparation, online/offline activation, rollback and legacy route compatibility remain incomplete. No released binary, dependency version or conformance level changes. This read-only adapter will be extended by the complete common adapter; it is not a second installation authority.

## Verification

`common_status_observes_absence_without_initializing` first failed because the public update subcommand was absent. It now verifies the v2 document and an unchanged empty home. `common_status_preserves_pending_cutover_and_requires_initialized_authority` exercises pending and initialized states without recovery or default-ledger recreation. `common_status_does_not_promote_legacy_observations_to_freshness` rejects legacy version/timestamp authority. `common_status_checks_legacy_receipt_bytes_without_repair` checks receipt-owned observation and missing-link rejection. `common_status_preserves_external_command_and_emits_one_error_document` and `common_status_missing_home_still_emits_json` protect external content and failure output. The existing Bash self-completion test also resolves the nested status JSON option.

## Runtime acceptance

Qualify the source-bound release binary outside a checkout with traced local-only status, managed and pending installations, hostile custody and cached-evidence expiry once the complete candidate adapter exists. Native non-Linux observation and the full common update contract remain separate gates.

## Supersession conditions

Supersede this record if local observation acquires mutation authority or freshness derives from a different accepted evidence contract. Preserve explicit recovery, failure output, unknown pending identity and the distinction between local receipt ownership and release authentication.
