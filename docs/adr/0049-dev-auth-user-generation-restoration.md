---
authority: canonical
owner: dev-auth
---

# ADR 0049: Retained user-generation restoration

status: proposed
verification: pending

## Decision

`dev-auth setup restore --mode user-only` selects the prior retained setup generation and leaves its integrations inactive. The Linux operation resolves the native non-root owner and canonical installation, holds the stable exclusive setup lease, requires legacy sessions to be absent and executes only the exact retained candidate bytes. It validates the transition digest, approved plan, native name/UID/GID/home, candidate inventory, retained receipt and configuration identities, prior policy/configuration pairing and native workspace authority. It never retrieves a release, reads discarded source documents, enrolls credentials or reverses credential-action receipts. [ADR 0052](0052-dev-auth-initial-installation-restoration.md) extends restoration to approved initial installation absence. Strong-mode restoration and non-Linux restoration remain explicitly blocked, not silently reduced to binary-only rollback.

Before mutation the operation establishes that each affected configuration path contains either the exact retained prior bytes or the exact approved candidate bytes. Alternate-version paths that the candidate did not write must still match the retained prior state. Retained user documents require native-owner private custody. Restoration durably selects `restoring` before deactivating receipt-owned integrations, restoring documents or changing executable authority. Prior absence is restored using identity-bound durable removal, not an unqualified unlink. The operation never recreates old workload or desktop launchers, and replacement files outside receipt ownership are preserved through failure.

Configuration and receipt publication retain their selected existing parents through [ADR 0053](0053-existing-document-directory-authority.md). Replacing a parent pathname after selection fails closed; publication and removal remain descriptor-relative. An originally absent configuration parent is never created by restoration. This also provides the bounded permission-restoration mechanism needed by the separate strong-mode implementation, without enabling that incomplete public operation.

The installation sub-operation derives the original, candidate and inactive target product/shared receipts from the retained original receipt and approved installation plan. This retains the original native Git/GitHub paths and release provenance, including across same-version configuration changes. An installed version change retains the candidate as the previous release after restoration. A never-committed candidate installation may instead recover the original history. The shared journal callback admits only those exact receipts and verifies bounded artifact custody before recovery. A committed shared rollback followed by an interrupted product-receipt write resumes toward the explicit old target; retry never swaps forward. Product receipt publication uses the shared durable compare-and-swap document boundary. No accepted 0.3.11 receipt schema is changed.

Transparent deactivation is bounded to the admitted product receipt and does not enter the legacy shared recovery path. It resumes after partial alias removal, synchronizes the alias directory and durably clears the receipt. An empty receipt alias list cannot by itself establish inactivity: unreceipted links to the retained product executables or active pointer fail closed without being deleted. Full setup owns native exclusion and user-integration deactivation; the installation sub-operation neither acquires native privilege nor authorizes arbitrary configuration writes.

User workload and desktop deactivation preserve directory/receipt durability ordering under [ADR 0050](0050-dev-auth-integration-retirement-durability.md). [ADR 0059](0059-retained-user-integration-retirement.md) binds restoration retirement to original and candidate generation authority, uses descriptor-relative entry and receipt operations, retires eligible unreceipted candidate publication and preserves unrelated candidate-name collisions. Synchronization failure prevents terminal restoration, including when a retry observes that the receipt is already absent.

Only a verified inactive configuration, installation and integration postcondition permits `restored_inactive`. Terminal retries verify the retained target without mutation. Both restoration phases reject forward recovery and successor admission. A different newly approved setup plan is required for activation; the original restored plan cannot reopen its own generation. Legacy executables that do not read this phase still require the independent inactive-integration and absent-session boundaries.

## Interface and evidence

Help, parsing and completion share one command definition. Restoration accepts mode and output format, not credential inputs or a replacement plan. `dev-auth-setup-restore-v1` reports verified status, fixed value-free error kind, exit category and tri-state changed status. Entered failures preserve unknown progress. Once validated, `retry_executable` identifies the immutable retained candidate because the public alias may already point to the older release, which may not implement restoration. This path identifies the existing local continuation executable, not new release approval.

Source tests exercise original native-program restoration, same-version preservation, repeat stability, both sides of shared-receipt commit, unrelated product/journal rejection and interrupted transparent alias deactivation. A disposable native-user installed CLI fixture retains a v2 configuration pair, stages v3 with missing credentials, removes original source inputs, rejects owner configuration drift without changing the transition, restores v2 while removing newly installed v3 documents, preserves credential-action receipts and retention, verifies an unchanged repeat and rejects forward recovery. The fixture's differently identified prior source executable is not an accepted signed 0.3.11 artifact or evidence of legacy runtime participation. Debug-build liveness bounds are not release-performance acceptance.

Strong native custody and helper restoration, process-death/power-loss qualification, full mutation coordination, live-provider and signed release acceptance remain independent requirements. Restoring configuration cannot undo provider rotation or revocation, and an inactive restored generation is not a credential-readiness claim.
