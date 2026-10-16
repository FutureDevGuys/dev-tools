---
authority: canonical
owner: dev-tools
---

# ADR 0126: Owned version retention pins

status: proposed
verification: pending

## Decision

The Linux installation foundation adds a narrow typed pin for an already
published ordinary versioned artifact. The product supplies a validated
`VersionedLayout`, version component and exact `ArtifactIdentity`, establishes
release authentication and owns the encompassing serialized recovery transaction.
The pin API never chooses product policy, accepts a release, runs a command,
changes activation/previous receipts or supplies rollback permission.

Only the typed layout derives `retained-artifacts-v1/VERSION.json`; there is no
caller-supplied destination, glob, directory scan or arbitrary keep list.
The strict bounded private document binds the complete layout, version, length
and digest. Publication verifies the derived executable's owner, ordinary `0755`
mode, single regular-file link and exact bounded content, then durably publishes
the owner-only pin. An exact repeat rechecks custody and acknowledges durability.
Read-only pin observation creates nothing; malformed, foreign or drifting pins
are errors rather than absence. The API acquires no additional writer lease:
products own the outer release lease and existing cleanup owns its installation
lock, preserving their established lock ordering.

The common superseded-version retirement used by v1 and v2 checks this exact
pin before deleting an old artifact. Valid owned pins preserve content;
invalid pins block destructive cleanup. Rollback still requires the ordinary
authenticated previous-version receipt and does not interpret pins as activation
authority. The pin is persistent explicit retention, with no automatic age/size
eviction or implicit unpin route. Existing installation schemas and default
unpinned cleanup behavior remain unchanged. Explicit owned uninstall remains
outside pin protection and may remove pinned active/previous artifacts; this
slice changes ordinary update retirement, not uninstall policy or authority.

`ExistingDocumentDirectory::publish_new` is additive to ADR 0053. It uses the
same bounded ordinary-file and descriptor-relative durable publication but
requires absence even for equal bytes. A no-replace rename enforces the final
condition. Existing `write` retains its synchronized equal-byte no-op behavior.
An error after namespace publication remains uncertain progress and belongs to
the product's recovery journal, not an automatic rollback.

These primitives are unpublished source. Legacy binaries do not understand
pins and must be quiescent before a product claims retention protection. No
mixed-version fence, new generic transaction framework, root privilege, signed
historical acceptance or native support is implied. Update All ADR 0031 owns
authenticated creation, durable product intent and recovery. Native custody,
upgrade/rollback preservation, crash durability and existing conformance
qualification remain pending; no tests/builds were authorized for this slice.
