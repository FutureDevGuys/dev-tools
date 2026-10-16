---
authority: canonical
owner: update-all
---

# Update All offline signed bundles

The explicit product install and update commands can use an existing signed
release bundle without contacting the network. Native bundle intake initially
fails closed outside Linux x86-64; native release acceptance is still pending.
This is an additive source interface, not a claim that an older published Update
All binary provides these options.

## Invocation

```text
update-all product install dev-cache --offline --root-document /absolute/bundle/root.json --manifest /absolute/bundle/manifest.json --artifact /absolute/bundle/dev-cache --json
update-all product update dev-cache --offline --root-document /absolute/bundle/root.json --manifest /absolute/bundle/manifest.json --artifact /absolute/bundle/dev-cache --json
```

Replace the product and paths with the intended product and its original signed
bundle. The three paths must be absolute. All four bundle flags are required
together; JSON output is optional. Omitting all four preserves ordinary online
install/update behavior. Product status, check, update-if-installed and rollback,
self commands, and common update commands do not accept these bundle flags.

The bundle's version is explicit; offline intake cannot determine whether a
newer release exists online. Both install and update use the same offline
activation operation. An externally managed public command retains the existing
external/no-change outcome and is not replaced.

The unreleased Update All common-lifecycle integration routes explicit
`product install/update update-all` bundles through the same v2 transaction as
canonical common mutation. It preserves complete-input and fixed-trust admission;
legacy migration additionally needs local original accepted/active/previous
proofs. Missing proof blocks offline migration rather than downloading it or
inventing ownership. Other products retain their existing scoped adapters.

## Accepted inputs

- Supply the original signed root document, source-bound product-v2 manifest and
  exact native artifact. Root and manifest are each limited to 512 KiB; the
  artifact is limited to 256 MiB. Empty inputs are rejected.
- Paths cannot contain parent traversal or symlink components. Each input must
  be a single-link regular file owned by the invoking user or root, without
  group/other write permission or special mode bits. The adapter performs these
  checks without changing the supplied files.
- The root must authenticate under Update All's compiled trust key. The manifest
  must select the requested product, stable SemVer, source commit, actual native
  target and required protocol. Its artifact URL must satisfy the existing
  signed GitHub release authority, even though intake never contacts that URL.
- Length and SHA-256 must match exactly before installation recovery or candidate
  execution. Valid filenames, matching version output, and locally edited
  metadata are not substitutes for signed evidence. There is no trust override.

The existing product release-writer lease serializes intake with check, install,
update and rollback. A competing writer is rejected without waiting. Missing or
reset accepted history alongside managed receipts, journals, version storage or pointers fails closed without reconstruction from installed bytes. The
installation foundation retains receipt-owned activation, bounded candidate
health, crash recovery and retained rollback.

## Results, failure and retry

Success uses the existing activation result. An exact already-active bundle
returns `changed: false` when no managed repair or recovery is needed. Finishing
a journal or repairing receipt-owned links is managed change and returns
`changed: true`, even when the requested version was already recorded as active.
Authenticated cache writes and accepted-metadata updates alone do not mean the
installation changed.

Intake preserves the last successful online-check timestamp exactly, including
an unset timestamp. It does not refresh online status or assert that the supplied
version is the latest release.

After authentication, original signed bytes are cached through the shared
release cache and accepted root/generation/version/manifest/binary history is
persisted before candidate activation. Existing recovery uses the prior accepted
state; the active and previous version observations are synchronized from the
resulting installation receipt. A failed or uncertain state publication ends
its transaction instead of accepting a newly observed history as its retry base.

A health or activation failure may therefore leave newly accepted history and
authenticated cached bytes while the previous installation remains active.
Retry the same exact bundle to resume through normal recovery. An older candidate
still fails anti-rollback checks; the existing receipt-owned rollback command is
the separate supported route to an eligible retained version. Do not edit state,
manufacture receipts or replace signed bytes to force a retry.

The implementation and pending native acceptance contract are recorded in
[Update All ADR 0025](../crates/update-all/docs/adr/0025-explicit-offline-signed-bundle-intake.md).

## Retain a historical artifact without activation

The separate unreleased retention operation restores or retains one exact
historical native artifact in an existing managed product store:

```text
update-all product retain update-all --root-document /absolute/bundle/current-root.json --manifest /absolute/bundle/historical-manifest.json --artifact /absolute/bundle/update-all --json
```

The root must exactly match the product's **current accepted root**. Supply the
original historical stable source-bound manifest and artifact. An old release's
original root is insufficient when the accepted root has advanced. Current key
revocations, fixed product/target/URL policy, protocol, source identity, exact
length and digest are checked offline. This operation never downloads metadata
or bytes and never uses a raw key or destination supplied by the caller.

`retain` is explicit new retention authority, not proof that this historical
release was previously accepted. It does not activate the file, create rollback
eligibility, lower or advance accepted history, change trust or caches, invoke
setup or privilege, or execute the artifact. Active/previous versions and all
public pointers remain unchanged. Normal install/update still reject a
historical downgrade; rollback still requires the existing previous-version
receipt. Other registered products use the same retention contract.

The operation requires a valid existing managed installation and accepted
history. It fails closed for external/unknown installation state, unsafe inputs,
foreign or drifting storage, and any unowned destination, including equal-byte
files. The destination is derived only from the typed product layout and signed
version. Already owned active/previous bytes can gain separate explicit retention
ownership; the first request therefore changes retention state. A fully retained
exact repeat verifies custody and synchronizes without republishing.

A bounded product journal precedes publication. Private proof receipts and
content-bound ownership pins preserve explicitly retained files during ordinary
v1/v2 managed upgrades; pins grant no activation authority. Older updater writers
must be quiescent; explicit uninstall is outside pin protection. After
interruption, repeat the exact manifest/artifact inputs
with the then-current accepted root to resume the same intent. A pending other
bundle blocks rather than being discarded. Do not copy files into the managed
store, edit receipts or remove journals manually.

JSON uses `update-all-product-retention-v1`, fixed value-free errors and nullable
`changed`: false before established mutation, true for established retention
change, null for entered uncertain progress. Its successful identity describes
the retained artifact, not the running command. This implementation is source
only; native durability, interruption, collision and upgrade/rollback preservation
acceptance remain pending under [ADR 0031](../crates/update-all/docs/adr/0031-nonactivating-authenticated-artifact-retention.md).
