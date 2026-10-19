---
authority: canonical
owner: dev-tools
---

# ADR 0124: Explicit pending update recovery

status: proposed
verification: pending

## Decision

The shared update snapshot gains an explicit pending-recovery constructor. Its
public installation observation remains `unknown` with no installed identity.
Only explicit install/apply/rollback may reach product preparation from this
snapshot; status/check never recover. The constructor is a classification, not
custody, authentication or mutation permission. Product preparation must validate
all original signed endpoint proof and use its admitted installation protocol.
Returning false while the initial snapshot is pending blocks continuation; true
requires the existing fresh read-only observation before further mutation.

The existing v2 installation module adds bounded read-only pending endpoint
metadata for product-owned proof selection. Strict schema/layout decoding is
repeated on the selected document. The API creates, locks, repairs and authenticates
nothing. Recovery still revalidates its exact journal, receipt, bounded artifact
custody and callback authority under the existing installation lock. Unknown
documents never become permission to infer a recovery direction.

Existing snapshot constructors, schemas and default adapter behavior are unchanged.
There is no generic recovery engine, new journal format, product-name branch or
runtime support claim. Changes are in unpublished foundation source; frozen
published packages remain immutable. Product integration and native recovery
qualification remain separate and pending; source integration does not establish
native recovery or platform support.
