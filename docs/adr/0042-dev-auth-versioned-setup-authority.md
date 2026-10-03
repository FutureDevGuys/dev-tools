---
authority: canonical
owner: dev-auth
---

# ADR 0042: Versioned setup authority and schema-bound destinations

status: proposed
verification: pending

## Decision

Setup discovery, planning, installation and verification select the same explicit administrator-policy version as the runtime. V3 requires a compatible 0.4.0-or-newer release. Discovery checks each named provider independently; an ambient global provider executable cannot satisfy a missing named provider. Native programs, launchers and sandbox adapters retain their existing ownership checks.

The full setup-plan-v3 document carries `authority_schema = "dev-auth-administrator-policy-v3"` for logical authority. Absence preserves the retained v2 plan encoding and destinations. Unknown values are rejected. Revalidation recomputes the schema from the digest-bound source document and checks that it matches the approved plan. V3 user policy and configuration occupy `policy-v3.toml` and `config-v3.toml`; v2 documents are not silently relabeled or overwritten. System authority retains the one root-owned system policy path and requires a stopped replacement.

A user-only policy may remove native accounts, resources, projection rights, operation scope and admission modes, shorten approved maximum duration, and narrow workspaces. It cannot redirect a provider executable, credential slot or logical resource binding, replace a pinned operation key, change the native-program authority, relax required sandboxing or cross authority versions. User configuration remains a separate narrowing layer. The implementation validates unused declarations as well as selected workloads.

Full setup inventories both v2 and v3 user configuration paths and, in user-only mode, both user policy paths, regardless of the candidate schema. Selecting a v2 candidate cannot omit existing v3 rollback inputs. The active and retained entries name distinct canonical paths and are each included exactly once. An older approved plan lacking this complete inventory requires replanning; revalidation cannot silently add authority to its digest. This retention rule does not authorize cross-version policy narrowing or automatic rollback activation.

Explicit v3 template names coexist with the retained v2 template names. The v3 examples require launch-time approval; generating a template never enables enrollment-authorized admission.

## Migration and remaining release gates

Schema-aware setup paths are not by themselves a complete migration transaction. Full setup must retain the prior policy and integration generation, prevent concurrent admission during replacement, and support receipt-owned recovery and rollback before the successor is activated in a production installation. Existing installation receipts and resumable credential actions do not establish complete configuration rollback. Credential rotation or revocation cannot be silently undone by restoring an older policy document.

Native tests cover schema-bound planning, legacy-runtime rejection, missing-credential staging and repeat operation through disposable native accounts. Signed public-binary activation, retained configuration rollback, live enrollment and operation evidence, cross-platform custody, and native workload teardown remain separate acceptance gates.
