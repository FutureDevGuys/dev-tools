---
authority: canonical
owner: dev-auth
---

# ADR 0098: Linux private-authority filesystem custody

status: proposed
verification: pending

## Decision and scope

Dev Auth extends its existing Linux executable-filesystem deny-list to opened private runtime/configuration directories, opened private files, and opened policy documents. The classifier rejects recognized NFS, CIFS, SMB, 9P, CODA, AFS, Ceph, NCP, FUSE, VirtualBox shared-folder and VMware shared-folder filesystem types. The executable deny-list and its call boundary remain unchanged. Passing this negative classifier does not prove that an unknown filesystem is local or qualified.

Private runtime/configuration paths must be absolute. Directory validation opens the selected directory without following a final symlink, then checks directory type, current-user ownership, owner-only mode and, on Linux, filesystem type on that same opened object. Private-directory creation reuses this validation, including when another creator wins the race. Private-file reads preserve no-follow opening, regular-file, current-user ownership, single-link and owner-only-mode checks. Policy reads preserve their required owner, mode, size and before/open/after identity checks, adding filesystem classification before reading bytes. Filesystem observation errors fail closed.

These directory checks validate the opened directory object; they do not retain it across later pathname operations, walk every ancestor or establish immunity to replacement by the same user. No new authority schema, signing provider, binding, privileged lifecycle or non-Linux filesystem classifier is introduced.

## Compatibility

Existing XDG/default configuration and runtime selection remains unchanged. Previously accepted private authority on a recognized denied filesystem now fails custody validation; there is no fallback, automatic relocation or permission repair. Operators must deliberately select storage satisfying the existing absolute-path and native-custody contract before retrying. This record does not adopt a fixed native-account workstation configuration location.

## Verification and qualification

Source tests enumerate the complete unchanged executable deny-list, retain its accepted examples, and explicitly distinguish unknown types from qualification. Private-directory tests cover concurrent creation, final symlinks, regular-file substitution and unsafe modes. Private-file and policy tests cover absolute existing paths, relative-path rejection, owner/mode checks, final symlinks and retained metadata/link checks. Rejected relative directory creation leaves its target absent.

These are source regression tests. Actual mounted-filesystem rejection, including WSL host-shared mounts, and installed native filesystem custody remain separate acceptance gates. No Linux, WSL or other platform support is established by this change or its source test results.
