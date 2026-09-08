# ADR 0001: Tracked upstream updates and local global-link repair

status: proposed
verification: pending

## Decision

`sync` delegates updates of explicitly tracked, unambiguous canonical installations to the caller-selected upstream `skills` CLI before observing a fresh restore/link plan. The upstream runtime lock remains the update authority: global `~/.agents/.skill-lock.json` and project `./skills-lock.json`. Historical default lock discovery does not change; detached locks remain usable for repair, not native updates. All selected update scopes are checked before the first mutation. Stable upstream 1.x releases starting with 1.5.25 provide the required scope and positional-name interface; older or unrecognized versions fail before update. No private update engine, lock writer, source enumeration or hash implementation is added.

Only installed names present in the initially selected lock and physically under the canonical scope root are eligible. Ambiguous case/slug aliases, excessive selections and option-like names fail closed. External app-owned installations and untracked skills are preserved. Updates receive explicit names, never an all-source option. Fresh locks and inventories determine subsequent restoration and linking; newly introduced lock names are not adopted automatically. Applied update records mean the native command completed, not that every source changed or could be checked: upstream may report skipped sources while exiting successfully.

`repair` remains the update-free compatibility workflow of global ADR 0014. For installed global canonical payloads and recognized explicit agents, missing or broken links are repaired locally without reinstalling payloads. Missing payloads still require upstream `add`; broad adoption and unsupported-agent/project link registration retain the legacy provider boundary. Well-known global restoration uses `sourceBaseUrl` when recorded, because the individual file URL is not an equivalent installation source. Global link reconciliation becomes the `sync` default, scoped to tracked canonical names; broad legacy doctor/repair policy is unchanged.

Provider calls use shared `dev-tools-command` 0.1.2, direct native argv, captured caller environment and working directory, closed stdin, 16 MiB per-stream output bounds, a timeout (300 seconds by default, configurable from 1 through 86400), and Ctrl-C cancellation. Provider failure stops later restoration/link actions. Interruption exits 130 and preserves already-entered upstream effects; this is not rollback. Primary and cleanup categories are retained without captured provider diagnostics. The existing MIT/Apache-2.0 shared runner and already-locked MIT/Apache-2.0 `ctrlc` dependency supply these mechanisms without another runtime or supervisor. Legacy optional Git source inference is outside this provider-runtime increment.

Explicit `--agent-link-policy reconcile` permits these canonical local link repairs even with `--link-policy off`; the latter still disables upstream link-registration calls. This separation lets callers request local repair without reinstalling an existing payload.

Linux public inventory capture uses the anonymous regular-file stdout mode of global ADR 0022 to avoid Node early-exit pipe truncation. Its child-wide file-size limit also affects incidental cache writes, so the provider must already be installed and listing must tolerate the bound. Mutation/version calls use bounded pipes. Other targets retain bounded pipe capture but gain no native qualification claim from Linux tests.

## Verification and release

Public CLI fixtures cover selected updates, restoration, unrelated ownership, local/repeat/broken-link repair, lock mismatch, provider version rejection, ambiguous names, preview/status preservation, timeout and running interruption. Opt-in acceptance uses an independently installed pinned `skills` 1.5.25 release and a public synthetic loopback well-known source, checking actual payload changes, restoration, source non-expansion, update-free repeated global repair and project/global isolation. No downstream consumer data or checkout is used.

Signed source-bound release and installed-artifact acceptance remain required before consumer cutover. These changes do not claim common read-only doctor/update conformance or native Windows/macOS support. Binary rollback restores old sync behavior but does not revert upstream changes already applied.
