---
authority: canonical
owner: update-all
---

# ADR 0092: Preserve an owned public command directory mode

status: proposed
verification: pending

## Decision

Update All's shared versioned installer retains private product data directories at mode 0700 and selects the existing public command directory's exact mode when it is owned by the installation account and has mode 0700 or 0755. A fresh command directory uses mode 0755. The selected value is passed as the shared layout's explicit bin-directory mode, so the installation layer still verifies exact owner and permissions before publishing an alias. Other modes, links and wrong owners fail closed; installation never changes an existing directory's permissions to make it pass.

An existing managed product may be installed beneath a public 0755 command directory while its receipt, versions and state remain private. The old implicit 0700 selection incorrectly blocked an authenticated Dev Cache 0.1.9 installation on a machine whose otherwise owned command directory had mode 0755. This correction changes the layout selection, not release authentication, product ownership, binary content, alias targets or rollback policy. The signed Update All 0.1.8 artifact is immutable; a successor release is required to make the corrected installer available.

## Evidence and limits

The existing authenticated product installation reached shared directory preparation and returned `installation directory has unsafe filesystem authority` before publishing Dev Cache 0.1.9. The public directory was owned by the selected user at mode 0755, while the private product and versions directories were owned by the same user at mode 0700. Focused layout checks and a signed installed successor must establish fresh and retained mode selection, authenticated installation, repeat operation and rollback. Native Windows and macOS runtime acceptance remain separate from Linux qualification.
