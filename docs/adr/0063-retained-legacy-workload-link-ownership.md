---
authority: canonical
owner: dev-auth
---

# ADR 0063: Retained legacy workload-link ownership

status: proposed
verification: pending

## Decision

Linux strong-generation capture, when executed as effective root, may retain a root-owned workload symlink named by a native-user-owned workload receipt. Capture records its actual UID rather than rewriting it to the account UID. The original receipt remains bound to approved bytes; the link requires its exact raw receipted target, symlink type and single-link custody. User-only capture and non-Linux capture retain native-owner-only admission. This accommodates the historical publisher described in ADR 0061 without changing ownership on existing links or weakening new-link publication.

The retained strong integration selector admits UID 0 only for an original object selected by that account's retained receipt, exact account-relative name, target digest/bytes, ordinary symlink mode and single-link identity. It requires effective root. Live admission and removal preserve each permitted target/owner pair: the original target has its retained owner, while a candidate target has the native account owner. Permission to retire a root-owned original does not authorize a root-owned candidate, an unrelated name or a changed receipt. Absence retries preserve the retained generation. Selected directory and receipt custody remain native-user-owned.

Removal selects the explicit-owner descriptor boundary in ADR 0062. It does not chown a legacy link or touch its executable target. Default shared link APIs retain same-owner behavior; desktop entries and regular documents gain no root-owner exception. The enclosing setup owner retains approval validation, admission exclusion and durable recovery direction. This compatibility is product-owned, limited to receipt-owned original workload links, and remains required while retained generations from the historical publisher are supported. Removal requires closing that rollback/migration window and executable evidence that no supported source generation needs it.

No public command, receipt or retained-generation schema changes. The strong public restoration gate remains closed pending the remaining full acceptance requirements; recognizing a legacy owner is not signed-release or runtime support evidence.

## Evidence

The mapped-root product regression first rejected a retained UID-0 original during integration selection. It now removes selected native-owned and legacy-root-owned originals across desired and retiring accounts, preserves unrelated files and account directory custody, rejects unretained ownership drift and rejects crossed target/owner pairs before removal. A second regression failed when strong capture rejected the legacy link; it now retains UID 0 unchanged while user-only capture rejects it. Existing new-publication assertions still require a native-owned link and an untouched executable target.

The disposable systemd full-generation fixture includes a native-owned original for the desired account and a historical root-owned original for the retiring account. Its synthetic release identities, absence of credentials and active broker processes, and external container cleanup requirements remain as documented in ADR 0057. [ADR 0064](0064-initial-strong-generation-withdrawal.md) supplies the separate initial strong absence composition. Signed migration, interrupted restoration and other native platforms remain separate qualification gates.
