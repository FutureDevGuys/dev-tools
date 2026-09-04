---
authority: canonical
owner: dev-tools
---

# ADR 0004: Typed privilege operations and plan bundles

status: proposed
verification: pending

## Context

Several products need bounded privileged effects. Reusing ambient sudo timestamps or introducing a general root broker would make authorization broader than the work the user approved and would not translate safely across operating systems.

## Decision

The mandatory primitive authorizes one typed operation against one absolute identity-validated helper. A later optional plan-bundle session may authorize multiple fully prepared typed plans under one visible approval. A bundle binds plan and helper digests, caller operating-system identity, product and operation audiences, protocol versions, use limits, and expiry. It is memory-only, nonrenewable, and revocable.

Default bundle lifetime is 15 minutes idle and two hours hard. Administrative policy may lower either value or explicitly raise the hard limit to at most eight hours. An admitted operation may finish after expiry, but no new operation may begin. Unplanned work requires new approval.

## Invariants

- There is no generic root command, arbitrary write, shell, password, or unrestricted filesystem capability.
- Release authenticity and privilege authorization are independent.
- Each product owns a narrow receipt-bound helper and can operate without a separate broker product.
- Logout, authority loss, helper replacement, revocation, or policy change ends a bundle.

## Verification

Contract tests cover exact-plan admission, replay, audience confusion, identity replacement, expiry, use exhaustion, revocation, interruption, crash recovery, unplanned operations, and value-free audit output. Each platform backend additionally proves native caller identity and helper custody.

## Runtime acceptance

Linux, macOS, and Windows are accepted separately through their native approval and IPC boundaries. No platform claim follows from another platform's tests or a cross-compiled binary.
