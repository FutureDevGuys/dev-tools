---
authority: canonical
owner: dev-auth
---

# ADR 0097: Versioned config-only reconciliation

status: proposed
verification: pending

## Decision and compatibility

The public `reconcile plan`, `apply`, and `verify` user-configuration interface follows the installed-authority dispatch already defined by [ADR0039](0039-dev-auth-versioned-workload-authority.md) and [ADR0042](0042-dev-auth-versioned-setup-authority.md). A present `policy-v3.toml` takes precedence over retained `policy-v2.toml` in user-only mode. An inaccessible, malformed, or incompatible v3 authority fails closed without falling back. Strong installations retain the system policy path and native account identity.

V2 authority accepts only `version = 2` user configuration at the native account's `config-v2.toml`; v3 authority accepts only `dev-auth-user-config-v3` at `config-v3.toml`. Both remain below the existing native-account `.config/dev-auth` directory. This does not relocate native configuration or relabel, migrate, or overwrite the other version's files. Dev Auth owns the retained v2 compatibility window already specified by ADR0039 and ADR0042; its removal remains subject to their setup and native acceptance gates.

The `dev-auth-user-config-reconcile-plan-v1` envelope, canonical encoding, approval digest, and `dev-tools-reconcile-result-v1` result protocol do not change. The existing source/policy identities and installation/native-account fields bind either supported schema. Apply recomputes the complete plan using current installed/native authority and requires exact equality with the approved plan. Source, policy, current destination, installation, native account, or selected authority drift rejects before mutation. Rehashing a caller-selected old policy or destination cannot make it authoritative. A v2 plan ceases to apply when v3 becomes present, even if its v2 input bytes remain unchanged.

## Inactive configuration-only mutation

A verified no-op remains read-only, before taking any configuration-maintenance lease. A changed apply takes the existing native setup/admission exclusion, revalidates after obtaining that lease, and holds it through publication and postcondition observation. The current maintenance-quiescence checks in [ADR0094](0094-reusable-bounded-maintenance-sessions.md) remain intact. Retained full-setup generations continue to reject standalone configuration mutation under [ADR0084](0084-native-setup-exclusion-across-broker-and-maintenance.md); the reconciler cannot accept, rewrite, or restore those generations.

Mutation uses the existing inactive configuration installer: policy narrowing, native ownership, document custody, source digest and destination compare-and-swap checks remain, while launcher/desktop preflight, publication, and rollback are excluded. "Inactive" describes that integration-free installer path, not new authority to change an admitted workload or a broker. The selected user configuration is the only mutation target. Administrator policy, workload/desktop integration, binding activation, broker lifecycle, credential enrollment, product installation, and privileged maintenance grants remain outside this interface. User-owned same-name launchers are neither created nor replaced.

## Conformance and release gates

Source conformance is the installed-CLI regression `installed_user_reconcile_preserves_versioned_authority_and_config_only_scope` in `crates/dev-auth/tests/cli.rs`, using the existing disposable native-user filesystem boundary. It covers v2/v3 plan/apply/verify/repeat, v3 precedence with retained v2 documents, explicit v2-to-present-v3 authority drift, malformed or mixed-schema rejection, source/policy drift, validly rehashed destination retargeting, held-lock and retained-generation denial, and no-op observation during maintenance. It checks unchanged user-owned launchers, absent alias receipts, no provider/native-tool invocation, and value-free errors. Existing reconciliation unit tests and public grammar/absence tests remain applicable.

These are source and disposable installed-fixture checks. Signed distribution, full-generation migration/recovery, strong native mutation, live enrolled-provider behavior, and native platform acceptance remain separate gates. Compilation or a cloud fixture pass does not establish those outcomes or non-Linux runtime support. The ADR remains proposed with verification pending until its required acceptance is established.
