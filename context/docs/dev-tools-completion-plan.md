# Dev Tools completion plan

## Objective and ownership

Complete the existing public product contracts in dependency order: current foundation and distribution cutovers, Artifact Update and common product updates, then Dev Auth advanced capabilities. Qualify Linux first without substituting cross-compilation for native macOS, Windows or WSL acceptance. The product standard and applicable ADRs define the requirements; vague backlog wording does not expand providers, packaging formats or platform commitments.

This work owns public Dev Tools products, shared crates, release tooling and product-level installation/rollback acceptance. Private Syscfg policy, plugin ownership, caller migration and consumer convergence belong to their separate owner. Contact that owner only for a concrete blocking interface dependency, material interface change, actual conflict or explicit user request; preserve the other task's edits and do not implement parallel private fixes.

## Repository and state cleanup

Recheck ancestry, unique commits, checkout ownership and working-tree cleanliness before removing a branch or worktree. Use normal merged-branch deletion for integrated topic branches. Keep main and do not force-delete unmerged branches, expire reflogs or prune unreachable objects. Retain the detached 46066ec source worktree until its exact signed registry transaction is resolved, then remove it through normal worktree removal after rechecking dependencies and cleanliness.

Keep context/state.md short and limited to unfinished outcomes, active risks and concrete external dependencies. Remove resolved items and private consumer execution tasks; consolidate duplicated recovery work. This document preserves the accepted sequence and gates, not a running changelog.

## Stage 1: current implementation and distribution

- Attribute the residual installed Dev Cache compiler-intercept cost before changing code. Add a discriminating regression for the supported cause, preserving exact compiler output/status, routing, activity accounting and the exclusion of automatic cache-tree maintenance from compiler calls.
- Resolve issue 40 through the admitted GitHub boundary: obtain its exact error, inspect issue/comment state before retry and avoid duplicate comments. If authority is insufficient, report the exact required authority without switching credential routes.
- Requalify installation and secret package archives against their known corrections before uploading; preserve original signed archives as evidence and never upload known-unfixed bytes or replace accepted version identities.
- Publish dependency-ready shared-crate batches from their correct clean source generations, including command, completion, release and update foundations. Verify registry checksums and downloaded bytes, configure Trusted Publishing and revoke the bootstrap token. A missing bootstrap input blocks publication, not independent source work.
- Port the incumbent release acceptance corpus and finish native release-tool parity. Remove Python release implementations only after parity and end-to-end release acceptance, rather than retaining two authorities.

Stage acceptance requires reproducible authenticated package bytes, registry-visible dependencies without neighboring checkouts, nonmutating publication repeats and replacement of the retired release implementation.

## Stage 2: Artifact Update and common product updates

- Audit the 14 declared Artifact Update source types against documented behavior and executable tests. Correct demonstrated gaps without inventing additional provider commitments.
- Finish interrupted-publication recovery, reservation lifecycle and native storage backends. Preserve unknown/unmarked files without independent ownership evidence; filename, age and PID are not deletion authority. Keep disposable caches, accepted release authority and installation receipts separate.
- Qualify authenticated online installation, offline reuse, retained rollback and crash recovery outside a checkout. Check-only sources remain unable to authorize installation.
- Complete product-owned dev-tools-update adapters in order: Update All, Dev Cache, Sync Configs, Skills Sync, then planned products and Dev Auth's setup-aware path. Products retain layout, health, policy and approval ownership without invoking sibling products for ordinary operations.
- Ship Skills Sync's explicit repair interface before making doctor read-only. Retire its bounded legacy online manifest exception only after an accepted source-bound successor exists.
- Complete the five-shell release-binary matrix, including identified Fish and Elvish grammar cases.
- Retire Update All's temporary package-authority bridge only after its separate owner provides an accepted replacement interface; do not implement that private replacement here.

Stage acceptance requires the common CLI/result contract against real release binaries, explicit schema migration, first-install and interruption recovery, offline behavior and retained rollback. Configuration-only health never claims installed-artifact or release authenticity.

## Stage 3: Dev Auth capabilities

1. Complete smart-binding native execution and journaled activation for continuation and structured targets, followed by explicitly authorized pinned-shell targets. Preserve wrapper/resource behavior, native arguments, streams, working directory, terminals, signals and exit status. Finish digest-bound refresh/rebind, proxy-cycle rejection, owned removal and retained-generation rollback under the binding-v2 contract.
2. Implement administrator-policy v3 logical names and typed secret read/public/exec operations through the provider-neutral foundation. Qualify the enrolled 1Password adapter and each projection independently. Operation-only keys remain nonexportable; private policy configuration remains outside this task.
3. Implement native privilege-session identity and authority backends beyond the lifecycle model: typed/exact-plan admission, conserved delegation, stream graphs, expiry/revocation termination and product integration. Unrestricted sessions require their separate administrator permission and visible approval.

Do not silently accept old draft-plan digests, widen ordinary helpers or activate private wrappers. Adversarial acceptance covers target replacement, altered receipts, collisions, recursion, secret leakage, cancellation, replay, audience confusion, budget conservation, expiry, broker failure and incomplete descendant termination. Native enforcement, not state-machine transitions, establishes support.

## Verification and execution gates

Each independently mergeable slice receives targeted regressions, relevant integration/conformance coverage, formatting checks and strict linting. Recheck the governing contract, exclusions, compatibility window and failure semantics before handoff. Bound build concurrency, preserve Dev Cache routing and clean up owned test processes and temporary outputs after retaining necessary evidence. Integrate completed signed slices promptly without accumulating speculative branches or worktrees.

Release gates require clean signed source, independent byte-identical builds, authenticated publication, anonymous verification, fresh installation, repeat operation and retained rollback. Local-only commands remain network-free and diagnostic paths nonmutating; custody-sensitive changes receive hostile-filesystem and interruption checks. Promote a product from build_info to full conformance only when its actual release binary passes the complete contract.

Native macOS, Windows and WSL acceptance additionally requires real hosts, SDKs, signing identities and entitlements. Missing access is an explicit per-platform gate and does not stop independent work or justify a support claim. Remove compatibility only when its declared rollback-window conditions are satisfied.

Completion means product and distribution gates passed, obsolete implementations and justified temporary worktrees removed, and external dependencies resolved rather than merely deferred in a list.
