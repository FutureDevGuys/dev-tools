---
authority: canonical
owner: dev-auth
---

# ADR 0056: Retained strong-generation documents

status: proposed
verification: pending

## Decision

The retained-generation document selector covers the fixed Linux system assets, shared administrator policy and both user-configuration versions for each desired and retiring native account. Selection does not acquire privilege, stop services, establish native account identity or enable the still-gated public strong restoration operation. The enclosing operation owns canonical layout, exact candidate executable and plan authority, native account revalidation, setup exclusion, stopped broker and absent workloads, durable restoration direction and complete inactive verification.

System assets are limited to the product's fixed asset inventory. For a prior installation, each original document must have root-owned ordinary 0644 single-link custody and exact retained bytes matching its approved snapshot and the original installation receipt's digest. The receipt's path set must equal the fixed inventory. Candidate bytes come from the executing candidate's compiled asset renderer; the enclosing operation must already have established that executable's exact retained identity. Unsupported destinations, unapproved original absence, unrelated receipt keys, changed bytes and unsafe metadata fail without adoption. [ADR 0064](0064-initial-strong-generation-withdrawal.md) separately admits original absence for every fixed asset when the complete initial activation/receipt inventory was approved absent.

The administrator policy remains at its fixed root-controlled path. Candidate policy publication is 0644; restoration preserves the exact original bytes and ordinary 0600 or 0644 mode. Each desired user's candidate-selected configuration has the approved candidate bytes and native-owner 0600 custody, while that user's alternate-version configuration remains unchanged. Both configuration versions of retiring accounts also remain unchanged. User documents retain their native owner and private mode; this selector does not silently adopt originally root-owned user files. Originally absent documents are handled by the existing retained absence boundary without creating absent parents.

Prior strong configuration validation uses the prior administrator policy's schema to select each prior allowed account's active configuration, independent of which schema the candidate selected. The prior allowed-user set must agree with desired and retiring-account coverage. Selected present configurations must resolve under that policy and retain valid workspace custody. Alternate-version and newly desired-account documents without authority under the prior policy are preserved as inactive bytes, not interpreted as active capabilities. An absent prior administrator policy grants no authority and cannot justify a retiring-account set.

All selected documents use the descriptor-bound publication/removal mechanism in ADR 0053, admitting exact prior or candidate content/permission pairs and restoring original bytes, custody or absence. Full retained installation construction also receives the original receipt mode from the approved snapshot, rather than inferring it from the candidate's default. Credentials and credential-action receipts are outside this document set.

## Evidence

The fixed-asset admission test failed at the missing operation before implementation. It covers every compiled asset and rejects unrelated paths, extra receipt ownership, wrong digest, changed bytes, wrong owner/mode and original absence. It does not write host system assets.

Configuration-selection and prior-policy tests each failed at their absent operation before implementation. They cover both candidate configuration versions, separate desired and retiring account identities, private prior administrator mode, exact document destinations/custody, all four prior/candidate policy-version combinations, invalid selected retiring configuration and missing retiring-account coverage. These are source component tests; the existing subordinate-UID namespace document fixture separately exercises descriptor-bound root publication into distinct account directories. Native fixed-path system-asset mutation, full root service teardown, signed installation and process-death/power-loss acceptance remain required before complete strong restoration is supported.
