---
authority: canonical
owner: dev-tools
---

# ADR 0010: Cancellable public command input

status: proposed
verification: pending

## Decision

The shared command runner accepts bounded explicit public bytes through additive direct and prepared-command APIs with caller-owned cancellation. Closed stdin remains the default. Existing input APIs delegate to the same controller without requiring callers to add cancellation. Product policy continues to own executable authority, environment, working directory, and admission.

Input is at most 16 MiB and uses the existing anonymous temporary-file staging implementation, avoiding a blocking writer task when the child never reads. Temporary-file storage is not secret custody; these APIs cannot accept credentials or promise secure erasure. Staging is synchronous and outside the child-execution timeout. Pre-cancellation prevents staging and spawn; cancellation is checked again after staging. On return from execution, the runner releases its staged input handle and resets the prepared command's stdin to closed.

The existing native process controller owns timeout, output limits, cancellation, cleanup, and primary/secondary failure reporting. Input selection does not widen its platform containment guarantee or add a private consumer-specific controller. Invalid requests and input bounds retain precedence over cancellation. Streaming, interactive input, secret projection, and caller-provided file handles are not part of this increment.

## Verification

Public-crate tests exercise pre-cancellation, exact binary input, empty and maximum-size input, oversized rejection, prepared-command reuse, and cancellation of nonreading children with owned descendants. Existing held-executable and closed-input tests preserve caller setup and default behavior. Native filesystem and process acceptance remains required per platform before claiming support.
