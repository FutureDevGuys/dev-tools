# Dev Auth: complete the usable product

## Outcome and delivery boundary

Complete the independently installable Linux product: reusable administrator grants, ordinary sudo and Ansible integration, working normal-command bindings, provider-neutral credential workflows, and setup-aware update and recovery. Windows, WSL, and macOS implementations and runnable native acceptance suites remain deliverables. Missing native SDKs, signing inputs, or hosts do not block the Linux release; record unavailable artifacts and unrun acceptance separately. Use local just commands, with no GitHub CI or hosted-runner workaround.

Shared Rust foundations count toward a milestone only when integrated into its working public product interface. Keep ordinary setup/update privilege separate from the explicitly approved administrator-session exception. No sibling product, client SDK, MCP interface, public broker-protocol commitment, source checkout, or private consumer dependency is introduced.

## Approved contracts

A grant has an explicitly selected workload or OS-user scope and an explicitly approved finite duration within administrator policy. Workload identity comes from the retained native launch boundary, never arbitrary PID attachment or copied hints. Workload grants end with that workload or the hard deadline, whichever is earlier. User-wide grants also end on final interactive logout. Both scopes end on revocation, relevant policy/identity loss, or coordinator failure.

No idle timeout applies by default. Administrator policy may explicitly impose one. Duration may exceed eight hours; 12-hour and longer permitted requests work. Suspension counts toward hard expiry. Activity, keepalive, credential refresh, and delegation never extend that deadline. A new or replacement grant requires fresh native approval. Passwords are never handled or stored, and global sudo timestamps are never refreshed.

Keep ordinary workload lifetime separate from privilege lifetime. Expiry immediately denies new privileged execution and terminates managed privileged descendants; the non-root workload continues unless its own explicit lifetime policy ends it. Preserve existing enrollment, credential scopes, admission choices, and configured limits during migration.

Support typed, exact-plan, and separately policy-permitted unrestricted administrator authority. Delegation conserves and narrows authority, expiry, and any use budget. Failed cleanup is not successful revocation. User-wide authority is available to other processes under that account. Unrestricted authority is root/admin-equivalent: it cannot guarantee containment against commands deliberately disabling enforcement or undo completed effects.

Add privilege request, status, inspect, exec, delegate, revoke, and leave, and integrate launch-with-grant with workload launch. Control operations use versioned value-free JSON and common exit categories. Execution preserves native argv, streams, terminal behavior, signals, and child status; optional structured results have a separate destination. Noninteractive requests return promptly when approval is required. Fresh approval and recovery remain usable without an active grant.

Managed denial never falls back to a native cached authorization or a broader grant. Explicit privilege leave exits managed routing without granting authority. Unbound sudo retains native behavior.

Binding code trust and native containment are separate axes. Pinned mode retains approved launch bytes until explicit refresh/rebind, where custody and required pathname behavior can be enforced. Explicit mutable mode approves a configured script/package location including later edits, preserving normal paths and writable workspaces. Propose pinned mode when feasible; otherwise require a deliberate mutable choice. Never silently downgrade an existing pinned approval.

## Milestone 1: reusable Linux administrator access

Implement the native privileged coordinator, caller authentication, memory-only grants, execution ownership, bounded delegation, expiry, revocation, and teardown through focused shared Rust mechanisms and Dev Auth policy/approval/CLI integration. Retain root-owned, non-delegated execution boundaries separate from ordinary workloads. Coordinator failure invalidates grants and terminates their privileged descendants. Privilege-only setup requires neither 1Password nor Git/gh.

Use a product-owned native sudo bridge as the starting implementation: upstream Sudo audit preflight, conditional group-based authorization, and final command admission into the owned execution boundary. Retain native sudo parsing, run-as handling, environment policy, and terminals. Authenticate and receipt-own any bridge/helper in the product payload. Do not overwrite unrelated plugin configuration, replace the system sudo implementation, or leave active authorization dependent on later file cleanup.

Qualify cached-ticket behavior, atomic admission, and failure between authorization and execution before activating this integration. A failed native property reopens the mechanism rather than weakening the approved property. Unsupported sudo implementations produce actionable compatibility results.

The exit gate is one native approval followed by repeated ordinary and absolute-path sudo, a public Ansible become fixture, and explicit CLI execution, under both scopes. Expiry/revocation must stop privileged descendants while preserving the non-root workload. Package this as the first usable feature milestone.

## Milestone 2: normal-command bindings

Complete continuation, structured-command, and separately permitted pinned-shell execution and journaled activation. Preserve wrappers, adjacent resources, native argv, cwd, declared environment, full UID/GID identity, streams, terminals, signals, and writable workspaces. Use receipt-owned proxies and reversible desktop integration without moving or overwriting original programs.

Complete explicit refresh/rebind, cycle rejection, externally managed source proposals, owned removal, and verified prior-generation rollback through one desired-state model. Retain the parent-replacement counterexample as a regression; arbitrary user-writable original-path byte pinning is not a delivery prerequisite for an explicitly approved mutable binding.

The exit gate covers generic CLI, script, service, desktop, editor-child, and nested-shell launches through ordinary entry points. Removal reveals the untouched original, and repeat application changes nothing.

## Milestone 3: the complete Linux product

Close remaining credential/lifecycle gaps through production interfaces: logical resources, independent enrollment/admission, exportable secret operations, operation-only non-exportable keys, real 1Password and independent fake providers, native Git/gh/SSH, rotation, revocation, refresh, concurrency, and denied-session no-fallback. Keep doctor local and network-free; explicit provider validation reports independent component outcomes.

Complete setup-aware update status/check/install/apply/rollback using the existing shared installation/release primitives. Complete fresh setup, stopped-broker migration, writer coordination, interrupted installation, repair, authenticated rollback, and owned uninstall. Do not wait for unrelated product adapters.

The exit gate is a signed standalone Linux product passing public CLI, real-provider, installation/recovery, and full product conformance.

## Milestone 4: platform implementations and local verification

Implement native equivalents for Windows (approved service, tokens/IPC, credential store, controlled Job Objects, ConPTY, installation/recovery), WSL (Linux authority independent of Windows), and macOS (approved privileged service/helper, authenticated identity/IPC, Keychain, process/terminal handling, installation/recovery). Preserve native OS approval and signing/entitlement boundaries.

Provide just ci for noninteractive format/lint/tests/build/relevant conformance, just ci-target TARGET for target builds, just accept-native for explicitly invoked native integration, and just accept-overnight for long-duration acceptance. No hosted CI is authorized. Required operations must not be placeholder successes or silently skipped acceptance tests.

Build locally where possible. Report SDK/signing/entitlement/host blockers precisely and distinguish implemented, built, installed, released, and natively accepted evidence. Cross-compilation does not establish runtime support.

## Acceptance and rollout

Use discriminating tests before each behavior increment, followed by the relevant surrounding checks. Native fixtures belong to this public repository and never depend on private consumer state or configuration.

Acceptance covers both scopes, wrong identities, copied hints, delegated-budget conservation, concurrent admission, idle/suspend/hard expiry, revocation, logout, policy changes, coordinator crash, failed cleanup, and fresh approval after expiry. Native sudo coverage includes Ansible, scripts, pipelines, interactive shells, run-as options, cancellation, warm native timestamps, and no timestamp extension.

Execution/binding coverage includes binary streams, native argument edge cases, PTY/ConPTY resize and signals, detached descendants, bounded DAGs and output, wrapper-relative resources, mutable workspaces, pinned replacement, mutable updates, rollback, and collisions. Credential coverage exercises real/fake Git/gh/SSH/exportable secrets, operation-only key custody, rotation, revocation, and value-free diagnostics.

Release gates include signed standalone fresh install, upgrade, interruption, repair, repeat/no-op, offline rollback, owned uninstall, five-shell completions, existing performance limits, accelerated clock tests, and one real overnight grant through expiry.

Preserve unrelated dirty work and immutable accepted releases. Review/reuse the prepared readiness fix and existing duration work. New administrator authority stays disabled until explicitly configured and approved. For authority/protocol changes, stop affected brokers, retain authenticated rollback inputs, validate the complete candidate, and activate last. Keep setup/recovery and new approval independent of an active grant.

Update applicable ADRs, public interfaces, completion definitions, conformance tests, and documentation with each implemented capability. Keep state.md limited to incomplete work and active risks. Declare Linux delivered only after its complete signed independently installable product passes Linux acceptance; report other platform gates separately.
