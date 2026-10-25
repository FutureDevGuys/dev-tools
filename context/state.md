# Active work

- **Dev Auth lifecycle gaps (#105)** on branch `fix/dev-auth-lifecycle-edges-20261024`. The branch is one work-in-progress commit; rewrite it into reviewed commits before its pull request. It covers six items:
  - a PolicyKit restart must not end grants;
  - an abnormal coordinator exit restarts the coordinator;
  - a rollback keeps the binary and its unit in step;
  - per-job task limits and a systemd-oomd preference;
  - the flaky packet test;
  - a rerun message for `exec` while the coordinator drains.

  Remaining: the approval-classification test and the issue's unfinished items, then a merge-commit pull request.
- **Dev Auth 0.5.6**, after #105 merges.
  - Advance `crates/dev-auth` and `crates/dev-auth-sudo` to 0.5.6 with `Cargo.lock`.
  - Then build twice, compare, verify and publish through the approved release-builder workload; that step waits on the owner's approval. The newest published release is 0.5.5.
  - Releases through 0.5.5 judge a setup plan in the release that plans it (ADR 0140), so an upgrade from 0.5.5 or older must plan with the 0.5.6 executable itself.
- **Agent Plugins as a Dev Tools product**, after Dev Auth 0.5.6. The owner: "Do this task here: 'dev-tools: agent-plugins as an encapsulated, modular product'". Their wider direction: "it needs to be able to just work when given a config or just given arguments or flags. However, I think that there should be commands to generate default configurations too", "I think update all also does something similar, so that would need to change too", and "the finished tools themselves are encapsulated and hermetic". Not started. The work:
  - port the agent-tooling projector to Rust on shared crates;
  - add a command that writes the default configuration;
  - use the shared update and release crates, then release the product;
  - move Update All's similar logic onto the same shared crate.
- Update All 0.1.17 and Skills Sync 0.2.1 are prepared in source and unpublished. The newest releases are Update All 0.1.16 and Skills Sync 0.2.0.
- Dev Cache's native container cache stays off by default, and native Docker acceptance has not run (#41).
- Native Windows, WSL and macOS acceptance has not run, so supported platforms are Linux only.
- Branches `auric/generic-secret-projection-policy-20261022` (1,220 changed lines) and `feat/generic-workload-acceptance-20261022` (599) hold unmerged Dev Auth projection and acceptance work with no pull request. #75 may supersede them; compare before reusing or deleting them.
