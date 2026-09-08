# Skills Sync 0.2.0 and SyncConfigs 0.2.1 Linux acceptance

The source-bound releases [Skills Sync 0.2.0](https://github.com/FutureDevGuys/dev-tools/releases/tag/skills-sync%2Fv0.2.0) and [SyncConfigs 0.2.1](https://github.com/FutureDevGuys/dev-tools/releases/tag/sync-configs%2Fv0.2.1) derive from signed source commit `1ef64914b02bc2b21e825897cfd0a243a309af8e`. Native `release-admin` constructed two independent signed sets and compared their six release files byte-for-byte, including permissions. Both manifests authenticate under the tracked root. Native publication anonymously verified all public assets; a repeated publication reported `changed: false`.

| Product | Target | Generation | Bytes | SHA-256 |
| --- | --- | --- | --- | --- |
| Skills Sync 0.2.0 | linux-x86_64 | 6 | 2,035,032 | `b746327deb613309338f6699292b14f5c02b62164c4bbdfd005ab769e6f713a3` |
| SyncConfigs 0.2.1 | linux-x86_64 | 15 | 7,158,272 | `9cf4ecb042f122d7cdaedd46185edefe07909e46d988c71b20304a7656aeeceb` |

## Behavior and source evidence

Clean-source all-target tests, strict product Clippy and formatting checks passed. Skills Sync's native contracts cover tracked updates, missing restoration, source non-expansion, unrelated ownership, local link repair, explicit independent link policies, preview/status preservation, ambiguous names, deadline handling and interruption. SyncConfigs tests cover unchanged NaN values, genuine float conflicts, receipt-owned retirement, preserved suppression through repeat convergence and exclusion of comment-like multiline string contents.

The real-provider acceptance test ran with the installed Skills Sync 0.2.0 binary, Node 26.8.1 and the independently installed `skills` 1.5.25 CLI. It owns a disposable home/project and loopback synthetic source and proves actual global tracked updates, missing restoration, untracked/app-owned preservation, no source expansion, update-free repeated repair and project/global isolation. Selecting the retained 0.1.4 binary instead fails the missing-update assertion, demonstrating that the installed-binary selector reaches the artifact under test. Use the opt-in invocation in [Skills Sync documentation](skills-sync.md), including `SKILLS_SYNC_ACCEPTANCE_BINARY`, to repeat this acceptance without touching normal skill payloads.

`sync` requires the upstream 1.5.25 positional-name/scope interface and intentionally updates tracked installed payloads. `repair` is the update-free route. Explicit `--agent-link-policy reconcile` permits canonical local repairs while `--link-policy off` still disables upstream link-registration calls. The legacy mutating `doctor` alias remains during ADR 0014's compatibility window.

## Installation and rollback

Update All 0.1.8 installed the authenticated public releases into receipt-owned product layouts. Installed bytes matched the signed hashes above; repeat updates reported `changed: false`. The previous Skills Sync 0.1.4 and SyncConfigs 0.2.0 binaries remain retained.

A disposable copy of both managed layouts exercised rollback to each previous version and return to each new version with networking disabled and no external commands on `PATH`. A private mount at the original home path preserved receipt path authority while keeping the live layouts untouched. The sandbox needs a normal private `/dev` for the updater's closed-stdin `/dev/null`; omitting it fails before candidate execution and is not product rollback evidence. All four rollback operations and the resulting executable version checks passed. Live artifact hashes remained unchanged.

Binary rollback restores the executable, not upstream changes or configuration merges already applied. These results qualify the named Linux product changes; they do not claim full common doctor/update conformance, native Windows/macOS acceptance, or performance acceptance for unrelated commands.
