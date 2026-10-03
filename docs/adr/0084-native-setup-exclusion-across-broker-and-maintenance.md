---
authority: canonical
owner: dev-auth
---

# ADR 0084: Native setup exclusion across broker and maintenance

status: proposed
verification: pending

The strong broker runs as the dedicated `dev-auth` account. Requiring that process to call the root-only admission helper rejected every control registration. The privileged dispatcher now validates the private setup generation and transfers its shared installation-lock descriptor with the prepare/register request. The broker authenticates the root peer before reading the frame, requires exactly one close-on-exec descriptor for those operations, validates its root-owned private named lock identity, and retains it through pending/active registration and cleanup. Renew/revoke carry no descriptor. Control protocol 4 rejects older control envelopes; public broker protocol 3 is unchanged. Neither broker privilege nor lock/document permissions are widened.

The Linux installation foundation exposes checked shared-descriptor export/import. Shared lock destruction closes its descriptor without an explicit unlock, preserving exclusion until the last transferred copy closes. Exclusive and non-Linux lock behavior is unchanged. This follows Linux [open-file-description locking](https://man7.org/linux/man-pages/man2/flock.2.html) and [descriptor-transfer semantics](https://man7.org/linux/man-pages/man7/unix.7.html). The caller authenticates the sender and owns transaction authority; importing a descriptor does not authenticate product policy. No published archive is changed.

Direct system/user policy installation and update, user configuration installation and update, and v1 migration acquire the existing native setup exclusion before mutation and reject any retained full-generation marker. Full setup continues through its already-serialized internal interfaces, without reentrant lock acquisition. Strong configuration changes require the root-owned full-setup route; a non-root standalone command cannot bypass the private system lease. User-only legacy maintenance remains available without a retained generation. Credential revocation and service stopping retain their independent reducing-authority paths.

Regression evidence includes the native non-root broker control path, pending-generation denial, retained exclusion after client return, duplicate-registration rejection and release after revocation; descriptor custody, truncation, multiple-descriptor and close-order tests; and installed CLI policy/configuration rejection under a live admission lease or retained generation. The original native broker test failed with denied registration, and the original installed user-policy test succeeded incorrectly during an active lease. Source/native tests do not establish signed distribution, live-provider execution, full broker-crash containment or non-Linux runtime support.
