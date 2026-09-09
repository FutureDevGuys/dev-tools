---
authority: canonical
owner: dev-tools
---

# ADR 0033: Read-only legacy-adoption preflight

status: proposed
verification: pending

## Context and decision

Receipt-less legacy products need to authenticate an artifact and inspect its two-level layout before committing to adoption. The existing adopter is an explicit mutation: it hardens directories, creates the installation lock, publishes a journal and rewrites pointers. Calling it to obtain preflight evidence commits too early.

The additive Linux `verify_two_level_versioned_adoption` interface takes the existing typed adoption request and a nonzero artifact bound. It verifies the caller-supplied identity against the installed artifact, rejects unsafe directory/artifact custody and requires an absent receipt, journal and shared active/previous namespace. Present legacy aliases and the `current` pointer must match the existing adopter's exact topology. Missing legacy aliases and `current` remain admissible; this result does not assert that a public command is currently reachable.

The observer uses the existing nofollow directory traversal, artifact verification, pointer admission and typed-input validation. It accepts owned, non-group/other-writable legacy directories without changing their modes to the intended managed modes. It creates no directories or lock files, acquires no installation lock, executes no callback or artifact, and neither repairs nor publishes installation state.

## Authority and compatibility

The caller owns signed-release authentication, ancestor trust and product policy. Matching a supplied hash is not release authenticity, and successful preflight is neither a receipt nor mutation authority. Observation is not a transactional snapshot against same-owner concurrent writers. An explicit adoption transaction must independently revalidate custody and source observations at its writer boundary before making durable changes. A missing receipt does not authorize treating a conflicting journal or shared pointer as disposable.

Existing adoption writers, v1/v2 receipt and journal formats and public request types remain unchanged. This additive interface belongs to unpublished installation 0.2.1; no frozen package or released product bytes change. Update All's receipt-less product composition still needs proof selection, an authenticated journaled transfer, explicit interruption recovery and common-operation admission. This preflight does not turn those unfinished outcomes into support claims.

## Verification and remaining acceptance

`legacy_preflight_preserves_unhardened_layout_and_namespace` first applied the existing mutating adopter and rejected its changed modes, new lock/receipt and rewritten pointers. The read-only interface passes the same filesystem snapshot comparison. Other public API tests preserve absent pointers and reject existing authority, unsafe directories, symlink traversal, artifact symlinks/hardlinks/modes/bytes, incorrect ownership, pointer drift, missing artifacts, invalid typed paths and zero/insufficient bounds without repair.

`legacy_adoption_observation_has_no_write_sync_or_lock_syscalls` invokes the public interface in a traced child against a prepared layout. It rejects write-capable opens, creation, permission/ownership changes, link/rename/removal, truncation, synchronization and locking syscalls. The existing cutover-observation trace receives the same checks. This is Linux observation evidence, not signed product adoption, concurrent mutation exclusion, power-loss recovery or non-Linux acceptance.

Before releasing product adoption, qualify signed artifact/proof custody, mode hardening only inside explicit mutation, competing-writer rejection, interrupted publication/resumption and retained-version policy. Supersede this record if preflight gains mutation authority, topology admission changes or another native backend is introduced.
