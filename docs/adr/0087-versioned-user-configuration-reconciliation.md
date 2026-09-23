---
authority: canonical
owner: dev-auth
---

# ADR 0087: Versioned user-configuration reconciliation

status: proposed
verification: pending

The public user-configuration reconciler follows the same explicit installed-authority dispatch as setup and ordinary runtime operations. A present v3 user-only policy takes precedence over retained v2 policy; malformed v3 authority never falls back. The selected policy chooses the user parser and native config destination. V2 compatibility remains available only under v2 authority, and mixed schemas are rejected before effects. Strong installations continue to use the system policy and native account identity.

The existing `dev-auth-user-config-reconcile-plan-v1` envelope and digest format remain unchanged: their exact source/policy identities and installation/native-account fields already bind the authority needed for either source schema. Apply recomputes the complete plan from current installed authority instead of accepting submitted policy or destination paths as authority. Source, policy, current destination, installation, account or authority-selection drift rejects the approved plan before mutation.

A verified no-op remains read-only. Changed configuration acquires the existing native setup/admission exclusion, rejects retained full-setup generations that require transaction-aware maintenance, and revalidates after acquiring the lease. The lease remains held through publication and postcondition observation. The reconciler updates only the selected user configuration; workload/desktop integration, administrator policy, broker lifecycle, credential enrollment and product installation remain outside this interface. In particular, a configuration sync cannot create or replace same-name launchers.

Public tests run the installed CLI inside a disposable native-user filesystem boundary. They cover v2/v3 plan/apply/verify/repeat behavior, retained v2 files under v3 authority, mixed or malformed authority rejection, stale/retargeted plans, held maintenance locks and retained-generation denial, no-op observation during maintenance, value-free errors, and unchanged user-owned launchers without provider invocation. Signed distribution and consumer/native-platform acceptance remain separate gates.
