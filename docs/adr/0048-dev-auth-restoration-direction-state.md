---
authority: canonical
owner: dev-auth
---

# ADR 0048: Durable setup restoration direction

status: proposed
verification: pending

## Decision

The retained setup transition recognizes `restoring` and `restored_inactive` in addition to `pending` and `accepted`. The exclusive setup owner may change a pending or accepted generation to restoring only with its exact plan digest and intact generation. It may acknowledge restored-inactive only after entering restoration and verifying the complete inactive restoration postcondition. Identical phase retries synchronize existing bytes. No transition within that generation may return to pending or accepted after restoration starts.

Both restoration states deny workload admission and forward `setup recover`. Restoring also excludes replacement by another setup plan. A restored-inactive generation cannot replay its own original plan; a newly approved plan with its own current-state snapshot may replace it through a new retained setup transaction. Even when that new plan's configuration already satisfies its desired postcondition, apply must create and complete the new transaction rather than treating the restored-inactive marker as accepted. Existing accepted generations retain the verified-equivalent-plan no-op contract.

These state controls do not themselves restore configuration, executable receipts, integration state or credentials. [ADR 0049](0049-dev-auth-user-generation-restoration.md) defines the user-only restoration operation that selects these phases. Every restoration implementation must bind its mutations to the retained generation, keep integrations inactive, verify completion and preserve resumability across binary/configuration publication boundaries before publishing the terminal state. Credential rotation and revocation remain irreversible through configuration restoration.

## Compatibility and evidence

Existing transition bytes are unchanged. Older successor readers reject the unfamiliar phase rather than treating it as accepted. Released legacy executables that do not read this marker still require the independent stopped-broker, inactive-integration and native-session checks; phase state cannot retrofit their participation.

Source tests exercise both pending and accepted origins, exact-digest rejection, one-way advancement, durable same-phase retry, forward-recovery exclusion, admission closure, preservation of retained bytes and replacement only after terminal restoration with a different plan. The installed native-user CLI fixture requires unchanged blocked recovery for both restoration phases. Strong and initial-installation absence restoration, signed acceptance, process-death recovery and non-Linux custody remain separate gates.
