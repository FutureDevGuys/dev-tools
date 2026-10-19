---
authority: canonical
owner: dev-tools
---

# ADR 0129: Independent file publication contracts

status: proposed
verification: pending

## Decision

The unpublished installation 0.2.1 integration preserves three independent
contracts on an existing descriptor-bound directory. Document operations require
nonempty contents. `publish_new` additionally requires an absent destination;
matching existing bytes remain a collision. Explicit ordinary-file operations
permit empty contents without treating an empty file as an authority document.

The existing `read_file`, `write_file`, `replace_file` and `remove_file` methods
retain their `DocumentAuthority` inputs and behavior from ADR 0116. The additive
`read_file_with_group`, `write_file_with_group` and `remove_file_with_group`
methods select `FileAuthority`, including its exact native GID. These names
supersede only the colliding unpublished method names in ADR 0125. The explicit
group check applies to current, staged and acknowledged files; a caller cannot
replace it with a no-op byte comparison. SyncConfigs selects these methods for
its durable overlay transaction. DevAuth's existing callers need no authority
conversion or permission widening.

A private typed publication selection keeps nonempty document publication,
absent-only publication, ordinary empty-file publication and exact-group file
publication distinct. It replaces the conflicting private boolean arguments
from the independent source branches. The common reader retains both the empty
content selection and optional exact group, rechecking opened-file metadata
after reading. No product name, policy, path discovery or transaction is added
to the installation foundation.

All variants retain owner/mode/link/bound checks, descriptor-relative staging
and publication, no-replace initial rename, file-before-parent synchronization,
named-versus-held revalidation, caller-owned writer exclusion and uncertain
progress after an entered mutation. No accepted package, release artifact,
installation receipt or serialized authority changes.

## Verification

Public source regressions combine these interfaces on the same selected leaf.
They require empty-file support not to admit empty documents or adopt occupied
new-document destinations, and require wrong-group reads, replacement and
removal to preserve the original file. Existing empty-file, directory custody,
retained publication and SyncConfigs overlay coverage remains required.

This is source integration only. Compilation, focused regressions, matched
DevAuth helper/core construction, native overlay recovery, signed standalone
release and installed acceptance remain separate gates. Pending verification
does not qualify the complete merged repository or any additional platform.
