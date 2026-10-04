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
