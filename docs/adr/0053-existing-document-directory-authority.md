---
authority: canonical
owner: dev-tools
---

# ADR 0053: Descriptor-bound documents in an existing directory

status: proposed
verification: pending

## Decision

The Linux installation foundation exposes `ExistingDocumentDirectory` for callers that must retain one selected parent across bounded regular-document observation, publication and removal. Opening requires an existing non-symlink directory chain and an explicitly owned parent without group/world write access. Every operation revalidates named versus held directory identity. Document names are single ordinary leaf components; no operation creates directories or grants authority over another parent.

Staging creation, ownership assignment, final mode, content verification, rename, unlink and directory synchronization use the retained descriptor. A changing user-home pathname therefore cannot redirect a privileged caller's publication into a different directory. Existing same-owner leaf mutation is not atomically excluded; callers still own writer coordination, ancestor selection, content authority and higher-level recovery. The descriptor boundary prevents redirection, not hostile same-owner edits or a nonparticipating legacy writer.

Files require exact owner and ordinary permission bits, a single regular-file link and bounded nonempty content. Special permission bits are rejected rather than silently masked. Publication accepts matching bytes as a synchronized no-op; different bytes require the expected current identity. No-clobber initial publication uses descriptor-relative rename. Final file contents and metadata are synchronized before publication, followed by parent synchronization. Removal requires exact expected bytes and named file identity; already-absent retries synchronize the existing parent. Read-only observation never synchronizes or repairs storage.

Explicit `replace` accepts separately bounded current and target ordinary modes with the same native owner. It validates the exact current content/custody before publishing bytes and target metadata together. Matching contents with a different desired mode require publication, not an unchanged acknowledgement. This supports restoring private receipt permissions after a public-read candidate without in-place path-based chmod or a change of file owner.

Staging uses bounded exclusive creation attempts. Names and ages are not cleanup authority. In-process cleanup removes only the still-named file created by that invocation; process death can leave unmarked staging which later calls neither adopt nor delete. Errors after publication/removal carry uncertain progress and require the caller's retained recovery transaction. This boundary is not a new installation journal, permanent writer fence or set-ID executable publisher.

The additive interface belongs to unpublished installation 0.2.1. Existing document APIs, schemas, frozen registry packages and accepted release bytes remain unchanged. Dev Auth retained configuration restoration selects this boundary for its existing user directories and preserves originally absent parents without creation. Its retained binary-restoration component also selects it for receipt publication and permission restoration. Full native privileged restoration qualification remains separate; this primitive does not itself authorize root setup or restore configuration.

Dev Auth's retained document boundary admits each prior or candidate content/permission pair together. Restoration publishes the prior bytes and their original ordinary mode, and rejects crossed pairs even when the bytes alone are recognized. Setup's current-path identity retains all permission bits, including set-ID and sticky bits, so approval cannot conflate the privileged launcher with an ordinary executable. Document mutation still rejects special bits; recording an executable's full mode does not authorize document publication with that mode.

## Evidence

A public regression opens a selected directory, replaces its pathname with another directory and requires publication, reading and removal to reject without modifying either location. It failed against a path-resolving wrapper before descriptor retention was implemented. Source tests also cover exact replacement/removal and unchanged retries, absent-parent preservation, wrong owner, writable or symbolic parents, symbolic/hard-linked files, FIFO/directory leaves, unknown modes and special bits, empty/oversized bytes and traversing names.

The Dev Auth restoration boundary has its own directory-replacement regression, which failed before selecting this primitive; both native user-only restoration paths remain regression gates. A separate replacement test failed against the same-mode writer and now requires exact private/public mode transitions, unchanged repeat, and preservation on mismatched current permissions. A source-binary root user-namespace fixture exercises Dev Auth's strong receipt/history component restoring private prior permissions and retrying a stale product receipt after shared rollback, without operating on host system services or claiming full strong restoration.

Product regressions independently require setup identity to preserve special permission bits and retained document restoration to recover private prior permissions from a public-read candidate. Each failed at the corresponding pre-change permission assertion. The document regression also requires stable retry and preservation on either crossed byte/mode pair; it is component evidence, not full root-managed restoration acceptance.

The explicit `native_root_document_restoration_preserves_distinct_account_ownership` product fixture runs as namespace root with subordinate UID mappings, restores and removes documents in separate UID 1000 and UID 1001 directories, and checks owner/mode preservation, unchanged retries and rejection of a mismatched root document authority. It exercises the product-selected descriptor boundary without host account, policy or service changes. Run it with `cargo test -p dev-auth --lib setup_v3::restoration::tests::native_root_document_restoration_preserves_distinct_account_ownership --locked -- --ignored --exact`; subordinate mappings and Linux `unshare` are prerequisites, not a native system-service acceptance substitute.

The explicit native syscall fixture checks descriptor-relative exclusive staging and no-clobber rename, final mode before file sync, file sync before publication, and parent sync afterward. It also checks read-only observation, idempotent sync without republishing and recoverable failures before publication, after publication and after removal. These tests do not establish hardware power-loss, signed product, hostile same-owner atomic exclusion or non-Linux acceptance.
