# Active work

- Update All structured item reporting and dashboard colors need a signed release and managed installation. Source changes are in #119, #120, #121 (colors) and the Claude review pass that follows it (shared item-role colors, magenta action, empty NO_COLOR). The installed release is still 0.1.20.

- Update All generic lock diagnostics, PR #116: source and controlled Linux CLI validation pass. One socket fixture remains blocked by the cloud sandbox and fails identically on baseline. Release and desktop installation remain pending; no installed product changed.

- **Dev Auth lifecycle gaps (#105)**, pull request #124 on branch `fix/dev-auth-lifecycle-105`, closes #105 and waits for review and a merge commit. Its six items and ADR 0144 are in the pull request. Native acceptance of the lifecycle edges is pending, and two tests fail identically on `main` on the development host: the managed Git clone credential test and the `grant_cli` template help test. Release 0.5.6 and installation wait on the owner.
- **Dev Auth 0.5.6**, after #105 merges.
  - Advance `crates/dev-auth` and `crates/dev-auth-sudo` to 0.5.6 with `Cargo.lock`.
  - Then build twice, compare, verify and publish through the approved release-builder workload; that step waits on the owner's approval. The newest published release is 0.5.5.
  - Releases through 0.5.5 judge a setup plan in the release that plans it (ADR 0140), so an upgrade from 0.5.5 or older must plan with the 0.5.6 executable itself.
- **Agent Plugins as a Dev Tools product**, after Dev Auth 0.5.6. The owner: "Do this task here: 'dev-tools: agent-plugins as an encapsulated, modular product'". Their wider direction: "it needs to be able to just work when given a config or just given arguments or flags. However, I think that there should be commands to generate default configurations too", "I think update all also does something similar, so that would need to change too", and "the finished tools themselves are encapsulated and hermetic". Not started. The work:
  - port the agent-tooling projector to Rust on shared crates;
  - add a command that writes the default configuration;
  - use the shared update and release crates, then release the product;
  - move Update All's similar logic onto the same shared crate.
- Skills Sync 0.2.1 is prepared in source and unpublished. The newest Skills Sync release is 0.2.0.
- Dev Cache's native container cache stays off by default, and native Docker acceptance has not run (#41).
- Native Windows, WSL and macOS acceptance has not run, so supported platforms are Linux only.
- **Windows readiness.** The owner: "dev tools things are definitely meant to be hermetic and non-bespoke to any OS or machine" and "Dev Tools: make Windows tests pass under Wine". The Windows test programs of the user-facing products now pass under Wine (1,107 passing; the 3 `update-all` package-authority tests need a Python helper and a source checkout, which Wine cannot supply). Nothing has run on native Windows, so no Windows support is claimed. Before any claim: native acceptance, an audited owner-only ACL for SyncConfigs transaction files, and a check that a file swapped between validation and replacement is never overwritten (the Windows publication path revalidates by identity but replaces by path). Windows release artifacts do not exist yet; consumers such as Syscfg's Windows apply defer the stages that need them.
- Branches `auric/generic-secret-projection-policy-20261022` (1,220 changed lines) and `feat/generic-workload-acceptance-20261022` (599) hold unmerged Dev Auth projection and acceptance work with no pull request. #75 may supersede them; compare before reusing or deleting them.
