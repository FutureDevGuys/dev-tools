---
authority: canonical
owner: dev-auth
---

# ADR 0039: Explicit v3 workload authority and native adaptation

status: proposed
verification: pending

## Decision

Administrator policy declares the exact schema `dev-auth-administrator-policy-v3`; its native-user configuration declares `dev-auth-user-config-v3`. Bounded, closed parsers reject mixed or unknown versions before native work. Installed runtime dispatch selects the explicit authority version; it never falls back to v2 after a v3 parse or resolution failure. The existing v2 parser and narrowing semantics remain available for the retained source-version compatibility window, not for silently translating an installation's authority.

Each administrator workload cap selects permitted native accounts, trusted launchers, a logical-resource cap, explicit admission modes and a positive maximum duration. It separately constrains operation scope, workspace selections and sandbox requirements. User profiles narrow resource rights; each workload narrows them again and explicitly selects its admission mode and duration. Empty or unknown admission modes are not automatic authorization. Duration arithmetic must fit the native clock; there is no product-wide hours maximum.

GitHub capabilities bind application identity, repository selection, installation IDs and maximum repository/permission scope to an operation-only logical resource. SSH authentication, Git signing and release signing likewise select operation-only logical names; administrator authority pins public keys, fingerprints and release-product scope. Workloads cannot substitute provider references or private key bytes. The common resource resolver fixes the provider instance and credential slot independently for every operation.

The retained native execution engine uses one resolved profile per workload, keyed by workload name. This prevents two workloads that share a user profile from sharing its unnarrowed resource superset. User-profile names are configuration composition, not broker admission identities. Each resolved operation retains its own credential slot; there is no v3 profile-wide slot or global provider fallback. The compatibility adapter carries provider references only inside the trusted existing operation engine, never as caller-selected CLI inputs. Exportable resource selections remain logical and are not passed through the legacy raw-reference execution path.

## Lifetime and protocol

Linux authority uses an absolute host `CLOCK_BOOTTIME` deadline, including suspension. Approval fixes the deadline before external workload startup. Activation preserves it; lease renewal and credential refresh do not modify it. Admission, capability execution, publication and supervision check the same deadline. Native time observations and these deadlines cannot cross hosts or grant Windows authority from WSL.

The changed native control and broker formats use protocol identity 3 and reject the retained identity 2. Exact 0.3.11 release verification remains separate and unchanged. A stopped-broker migration must preserve authenticated rollback inputs, deactivate affected launchers, validate and install the successor, verify integration, and activate last. Logical policy parsing, source tests or a service process alone do not authorize cutover.

## Verification

Policy tests cover explicit schema dispatch, bounded declarations, account/right/admission/duration expansion, workload-specific resource narrowing, workspace intent, all existing operation families and multiple provider slots. Native-adapter tests check slot selection through the actual session-grant constructor. Broker tests must additionally prove provider selection, expired-deadline denial before and after provider work, renewal without hard-deadline extension and native workload cleanup. Standalone signed setup, live enrolled provider use, projection custody and complete platform acceptance remain required release gates.
