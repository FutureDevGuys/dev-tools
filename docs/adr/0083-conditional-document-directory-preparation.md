---
authority: canonical
owner: dev-tools
---

# ADR 0083: Conditional document-directory preparation

status: proposed
verification: pending

## Decision

The Linux installation foundation exposes `DocumentDirectoryPreparation` for bounded absolute destinations with a possibly absent parent suffix. Observation retains the nearest existing owner-controlled, non-symlink directory and the missing suffix without mutation or storage synchronization. The caller owns destination selection, ancestor trust, writer exclusion and higher-level recovery. An independently created first missing component invalidates the observation, even if its owner and permissions would be acceptable to a fresh observation.

Preparation publishes each absent directory through descriptor-relative exclusive staging, final owner and ordinary mode assignment, directory synchronization, no-clobber rename and parent synchronization. This prevents a restrictive umask or interruption before final permission assignment from exposing an incomplete final directory. Each newly published parent is retained before its child is prepared. Existing directories are never chmodded or adopted through stale absence evidence. Ancestor entries and the final directory are synchronized on mutating retries, including when a fresh observation finds a directory whose prior publication did not finish its parent sync. Read-only observation keeps its existing no-sync contract.

The result is an `ExistingDocumentDirectory` and a known-change boolean. Errors after publication may have uncertain progress; the enclosing retained transaction owns recovery. In-process cleanup removes only the still-named, empty staging directory held by that invocation. A process-death staging name is not ownership evidence and later calls neither adopt nor delete it. This is not a new directory journal, an all-writer fence, a recursive cleanup facility or a non-Linux support claim. The additive API remains in unpublished installation 0.2.1; frozen archives, schemas and release identities are unchanged.

Dev Auth strong recovery selects this mechanism only for the parents of its fixed compiled system definitions, with root ownership and new-directory mode 0755. It groups definitions by exact parent, admits every existing or absent leaf before mutation, and retains both directory and leaf observations across completion. Parent publication is followed by the existing exact-content document writer, stopped-service checks, manager reload and product receipt verification. A missing parent does not authorize an unknown file, enable a service or select another destination. The existing setup-generation boundary and binary/helper/launcher proofs still precede mutation.

## Evidence and remaining gates

The clean standalone native CLI fixture exposed an absent `/etc/sysusers.d` despite available systemd and polkit prerequisites; retained recovery rejected before mutation. Shared tests cover nested absence without creation, final owner/mode, unchanged fresh retry, stale valid-directory creation, unknown files and links, replaced ancestors, unsafe custody, invalid modes and preservation of existing permissions. Native syscall tests exercise final metadata before staged-directory sync, no-clobber descriptor-relative publication, parent sync afterward, read-only observation and recovery from injected sync failure before and after publication, under a restrictive umask.

The optimized standalone CLI passes initial staged and unstaged recovery in fresh disposable systemd roots without precreating the missing sysusers directory. These cases exercise absent fixed assets, policy/configuration publication with native account ownership, removal of original inputs, unchanged repeat, rejection of damaged accepted state and continuation from retained pending authority. A separate native component preserves a late valid parent before mutation and an independent leaf after known parent publication, then completes from a fresh proof. The subordinate-UID fixture checks root publication of a selected account's nested directories without granting root ownership to those directories.

Run the two ignored `setup_v3::recovery_native::native_disposable_public_strong_initial_{staged,unstaged}_recovery` fixtures with an optimized candidate at `/candidate/dev-auth`, and the ignored `setup::recovery_native::native_disposable_strong_missing_asset_parent_completion` fixture, under the network-free, mount-free disposable systemd contract in ADR 0078. Synthetic retained provenance does not establish signed release admission. The unoptimized binary can exceed the fixture's unchanged 90-second command deadline while executing repeated custody checks; its timing is not release performance evidence. Actual process death/power loss, all-writer coordination, active-broker teardown and native non-Linux acceptance remain separate delivery gates.
