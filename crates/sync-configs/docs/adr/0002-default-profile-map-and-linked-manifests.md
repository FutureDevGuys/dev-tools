# ADR 0002: Default profile maps and linked manifests

status: proposed
verification: pending

## Decision

An optional closed `default_profile_map` object supplies `path`, `host`, and an optional `field` to the existing profile-map resolver. Use it only without explicit CLI profile selection. Preserve profile order, deduplication, hook metadata, preconditions and all mutation/authorization boundaries. Invalid active selection stops before mutation. A valid explicit CLI selection does not read a dormant default map.

Resolve manifest-relative sources and hook working directories from the canonical target of a linked manifest. Discover its existing adjacent override beside the logical supplied path; that machine-local override can replace the default without changing the shared manifest or copying profile membership. Resolve a default map's relative path from the file that declares it. There is no new discovery service, configuration format, private-consumer knowledge or implicit privilege.

## Verification

Focused public fixtures must run the no-argument CLI with a linked default manifest and local override, verify profile-selected file/hook behavior and unchanged repeat, exercise explicit CLI replacement, and reject malformed defaults before writes. Until those native checks and normal product release/installation acceptance pass, this source is not an accepted release or installed behavior.
