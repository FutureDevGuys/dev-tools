---
authority: canonical
owner: dev-auth
---

# ADR 0095: Setup-owned mutable binding activation

status: proposed
verification: pending

## Decision

Dev Auth's Linux candidate admits an explicitly mutable normal-command binding only through a full setup generation. A v3 deployment names each native account, v3 binding-plan file and exact lowercase digest. The full setup plan uses v5 when this authority is selected, reads each canonical binding plan as a retained source document, proves its current binding receipt precondition, and requires its target to be the configured workload launcher. Alias collisions with a workload name, self-routing into the product, and known proxy layers fail before mutation. A v3 deployment with an empty binding list explicitly removes prior bindings; a v1/v2 deployment cannot silently abandon an existing binding generation.

The existing setup lock, source capture, retained previous generation and restoration direction remain the only transition authority. Setup deactivates old workload integrations, installs and verifies the candidate binary and policy, publishes an owner/mode-checked binding-set receipt bound to the installed executable, then activates only receipt-owned aliases. Strong receipts are root-owned readable documents under the product data root; user-only receipts are private to the native account. An alias routes through the installed Dev Auth executable, the alias receipt, the binding receipt and the configured workload name. It never treats an alias path, copied environment hint or arbitrary PID as admission authority. Structured fixed arguments are inserted into native caller arguments without shell parsing; workload policy still owns cwd, environment, credential admission, process lifetime and containment.

Mutable mode deliberately approves the configured executable location including later edits. Runtime checks the installed executable and binding receipt, the exact owned alias, the selected workload's current launcher path and native launcher custody; it does not silently rehash a mutable target or extend its admission. Refresh/rebind planning reads the current receipt, requires a new digest-bound plan, and conserves one prior generation. Pinned activation still fails closed because snapshot bytes cannot yet be projected through all required pathname, identity and strong native boundaries. Discovery and planning alone never activate a binding.

Setup-aware version update reuses accepted policy and binding source documents but refreshes a mutable binding plan against the current executable at the same approved location and active receipt. It records a new exact digest in the successor setup intent; it cannot redirect to another visible/canonical target or silently turn pinned into mutable trust. This permits an explicitly mutable script edit without requiring an obsolete original-byte digest during an otherwise preserving product update. The successor plan still revalidates bytes before activation and remains under the full setup transaction.

Restoration observes the candidate/retained binding pair before mutation, retires aliases first, then restores or removes only the exact binding receipt under the full-generation journal. A removed binding reveals the untouched original command; restoration leaves prior integrations inactive. The candidate does not copy or move the original executable. No separate binding mutator or provider dependency is introduced.

## Verification and remaining gates

Source tests cover schema cutover, explicit mutable choice, current-receipt refresh planning, collision and target validation, bound native arguments and exit status, later mutable edits, initial restoration, refresh rollback and explicit removal in a disposable installed user-only setup. Strong native setup/runtime, desktop/editor-child routing, nested shell and service entry points, signal/terminal fidelity, concurrent interruption, pinned byte custody and non-Linux implementations remain unqualified. This source capability is not a signed product release.
