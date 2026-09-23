---
authority: canonical
owner: dev-tools
---

# ADR 0090: Explicit empty-file custody

status: proposed
verification: pending

`dev-tools-installation` adds explicit raw-file reads and descriptor-bound write/replace/remove methods that permit an empty regular file. This is necessary to preserve and restore an empty native configuration such as sudo.conf. Existing document APIs retain their nonempty requirement; an empty JSON authority document does not become valid.

The file methods use the same owner/mode checks, held directory, named-object revalidation, expected content identity, staged publication, synchronization and owned removal as document operations. Empty content has its exact SHA-256 identity rather than representing absence. An absent file and an existing zero-byte file remain different states. No arbitrary pathname mutation, owner change, set-ID publication or separate transaction authority is introduced.

Tests cover empty create/read/no-op, replacement to and from nonempty bytes, stale-identity rejection, removal/repeat, and continued rejection by the original document methods. Native Dev Auth setup/restoration supplies the integrated consumer evidence; publication and other native targets remain separate gates.
