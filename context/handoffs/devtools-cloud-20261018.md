# Dev Tools cloud handoff — 2026-10-18

Local implementation and native execution are paused for the requested Git transfer. This branch preserves the integration history, selected non-secret evidence, exact signed candidate inputs, and unfinished work. It does not claim product completion or authorize a workload on another machine.

Repository: <https://github.com/FutureDevGuys/dev-tools>. Handoff branch: `handoff/devtools-cloud-20261018`. Existing integration review: [draft PR 68](https://github.com/FutureDevGuys/dev-tools/pull/68). Leave the PR draft until its remaining acceptance gates pass.

## Exact source and transfer layout

The qualified source is commit `81338f23a8cf45c30caf3e95937b8d42c6ee8e0e`, tree `dfb53899dbe65bab8f5b9cc6a7a56b28cd928e6f`, source epoch `1792291519`. The handoff commit adds documentation and transport files; its new tree is **not** the source identity of the retained candidates. Use a separate clean checkout of the qualified commit when qualifying those exact candidates. Preserve the integration history and frozen local checkout.

`handoff/cloud-20261018/MANIFEST.json` records each transported file's length, SHA-256, class, and original digest. `SHA256SUMS` covers the transport files and manifest. Signed binaries, manifests, public keys, and the matching sudo payload are copied byte for byte. Evidence exports normalize local paths; their original and derivative digests are recorded separately. They are historical evidence, not newly reproduced results or current acceptance ledgers.

The transfer excludes credentials, private signing keys, enrollment/policy material, raw user terminal logs, home directories, Cargo targets/caches, and the guest image. Candidate A and B byte equality is preserved by evidence; copying one accepted byte set does not reproduce an independent build. Transported binaries have non-executable Git modes. Verify their hashes and current product trust through the normal route before deliberate use. Do not install or load the sudo payload merely because it is present.

Task-runner snapshots are deliberately named `*.review.txt`. Their local paths, inodes, tools, admission records, units and clocks are not portable. Do not execute them as a cloud allocation or resurrect consumed runs. Rebind only the necessary task-local paths and inputs through the existing supported route, preserving the resource controls and original failure records.

## Actual completed work

The integration source is signed, clean and already pushed. Independent A/B construction produced five identical outputs totaling 58,623,464 bytes. Direct CLI/ABI qualification and the recorded signing, comparison and both-bundle verifications passed. These results remain distinct from installed or Strong-native support.

| Product/input | Exact artifact SHA-256 | Current result |
| --- | --- | --- |
| Dev Auth 0.5.3, generation 29 | `f6116a325e1e434c04f2195bc07b65363c700034fc2ef606ad62c37be79f1756` | Signed A/B and public intake passed. Strong native acceptance, publication and host upgrade remain open. |
| Dev Cache 0.1.13, generation 14 | `45aa2b5c6a17c197c4897225cf3b22ad61af597de930b81d1c9be0ec3cfbe758` | Signed A/B and private user-store lifecycle passed. Remaining native coordination, live upgrade and publication remain open. |
| Sync Configs 0.3.2, generation 18 | `692b3cf53325bbbe1474d2181c9a328ecfcd21669516c161a08f9cc20c0f8e65` | Private lifecycle, twelve native recovery cases, live install/repeat, publication and exact public download verification passed. |
| Matching sudo payload | `24c7fa052de58efdfd8624ea4722c2a3921bbaea0e5bcff7effc3cbad306727b` | A/B matched. Retained as a Dev Auth fixture input; no new host installation. |

Sync's public release is <https://github.com/FutureDevGuys/dev-tools/releases/tag/sync-configs/v0.3.2>. Its annotated signed tag dereferences the qualified source. All three downloaded assets equal the accepted signed bundle; fresh Release Admin verification passed. The native publication client and descendants are settled, its unit/cgroup is absent, and all five known foreground/native PID paths were freshly absent. The outer Kitty exit was not retained; do not invent an exit code. No publication prompt or uncertain publication remains.

The installed UpdateAll 0.1.14 is a different, already released source: `7d7bcb1e04c08183aa8dfe0c9854870fe4b114e8`, artifact SHA-256 `544a3ac13f0bbaeebeda6495e3d00ebde6cf9d216554086bf72201b9881de7b5`. The integration-only 0.1.14 output (`71ff6a04…`) must never be reissued under the released identity, installed as that release, or substituted in the user-run audit. It is intentionally excluded from this transport.

## First unfinished investigation: UpdateAll runner

Austin reported immediate failures in a real 0.1.14 run. Investigate whether UpdateAll's runner launched, coordinated, timed, cancelled or reported them incorrectly **before** treating every updater as an unrelated defect. The audit is unfinished; the current evidence does not clear the runner.

The sanitized `evidence/updateall-user-run-audit.json` records the run identity, selected builtin task results, source-blob correspondence, and open questions. The actual process matched the installed 0.1.14 bytes. Its inherited PATH began with the existing Dev Cache intercept directory. No selected Dev Cache config/root/mode override was observed. No user task was replayed, stopped or altered.

Observed child results include Dev Cache exclusive-maintenance busy refusals for NPM/UV and nested UV calls under Pipx; a Sync offered-generation-16/version-0.3.0 rollback refusal after generation 18/version 0.3.2 was accepted; and separate caller-owned failures. Why release discovery offered the older Sync manifest is unproven. The later routing task reported an activation no-op, after the first busy refusal. Neither fact establishes the runner's innocence or the cause of maintenance occupancy.

Inspect the exact installed-source scheduler, resource-lock enforcement, inherited environment/routing, command ownership, timeout/cancellation/settlement and report aggregation. Relevant UpdateAll Rust blobs match the integration source; the export records the compared blob IDs. Investigate recurring Dev Cache behavior after the runner assessment. Do not read or make the public products depend on private caller implementations, and do not repair unrelated individual updaters as a substitute for this causal investigation. Raw logs remain local and are not published.

## Dev Cache: smallest remaining native path

Two consumed native attempts stopped in the task observer, not in a demonstrated product defect. The first wrongly required the installed executable's link count to be one despite its legitimate intercept hardlinks. The second wrongly treated the generic temporary path as a routed adapter instead of checking `effective_paths.temp`. Preserve both failures and their original clocks.

The corrected remaining-only preparation is frozen and **unrun**. It inherits exactly seven successful steps: signature verification, candidate identity, private installation, idempotent activation, root initialization, configuration check and status. Still required: actual C compilation/link/run and expected compiler failure; active nested leases; exclusive maintenance busy exit 12; nonmutating preview; and automatic post-workload plus normal explicit maintenance after full settlement. Existing budget is 600 seconds plus 60 settlement with one job, fixed resource/PSI/shared-lock/cgroup/pidfd controls and first failure stop.

The last conditional binder refused before mutation because another exact allocation had advanced the shared record. Parent subsequently held Cache until its reservation was explicitly released. No corrected Cache clock or target command started. Transfer does not release that hold. Historical machine scheduling metadata is not a product input or cloud admission.

After required native acceptance, complete supported live 0.1.13 installation and normal signed publication while preserving 0.1.12 rollback/configuration. Current host Cache remains 0.1.12. Do not infer acceptance from A/B construction or the private user-store lifecycle.

## Dev Auth: exact fixture path and remaining native gates

0.5.3 is signed and independently reproduced; the local host remains on 0.5.2. An authenticated official Ubuntu image was downloaded and its QCOW2 metadata read without booting or mounting it. The 621,284,352-byte image is excluded from Git. Redownload the immutable source and verify it against the exported authenticated metadata:

- URL: <https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img>
- SHA-256: `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`
- Ubuntu documented signing-key fingerprint: `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`.

The exact fixture harness has **not** been built. Its Cargo target is the binary, not the stale `--lib` spelling:

```text
cargo test -p dev-auth --bin dev-auth --release --locked --offline -j1 --no-run
```

The preparation pins source 81338f23, epoch 1792291519, the matching sudo payload, a cleared real-toolchain PATH, a separate target/tmp and 440 checksum-verified registry archives. No Cargo resolver or harness build ran during that readback. A different machine must provide its own verified dependencies/toolchain; a local cache observation does not transport those archives. Check the actual new harness's ELF/GLIBC requirements against the guest before execution.

First existing native case: `setup_v3::recovery_native::signed::native_disposable_signed_fresh_install_workload_and_restore`, using the built harness with `--ignored --exact --nocapture` and `DEV_AUTH_NATIVE_SYSTEMD_FIXTURE=disposable`. This requires an actual owned rootful disposable systemd environment with the required private namespaces, native identity and cgroup capabilities. A marker alone, ordinary user namespace container, or host invocation is not that environment. No host credentials, policy, enrollment, home mount or sudo helper should be exposed to the guest. Any guest `gh`/other prerequisite must itself have a grounded source; the image does not supply every fixture dependency.

That first case does not close all Strong-native support. Signed fresh/legacy/patch/maintenance lifecycle, repeat/no-op, repair/interruption/recovery/restoration/uninstall, full-identity projection, enrolled real-provider workload admission, callback/bridge/continuation and separately required privilege fixtures remain to be accounted for. Follow the repository acceptance documents and applicable ADRs, particularly 0115, 0116, 0121 and 0122. Only after their actual native gates pass should 0.5.3 be published and installed through the supported Strong route, preserving 0.5.2 and all existing policy/enrollment choices.

## Broader requested completion inventory

The accepted source of the full outcome remains `context/docs/dev-auth-delivery-plan.md`; this handoff does not reduce it to the next release checkpoint. Track each requirement against source, native, installed and released evidence:

- Standalone Rust credential and reusable privilege product; explicit component/provider checks separate from admitted workloads; local network-free doctor and truthful versioned outcomes.
- Complete V3 logical-resource operation families, cross-slot provider selection, enrollment, rotation/revocation/refresh, captured-byte projection custody and cleanup, using the existing real 1Password Service Account and an independent fake. No MCP, sibling product service, new client SDK or private consumer dependency.
- Authoritative native Git/gh route preserving upstream syntax and human passthrough, session/resource authority, API/subprocess behavior and denied-session no-fallback; no diagnostic version/hash subprocess on ordinary hot paths.
- Continuation, structured and separately permitted pinned-shell bindings; native UID/GID/supplementary groups, arguments, streams, terminals, signals, wrappers and nested/service/desktop/editor callers; explicit refresh/rebind/cycle rejection/owned removal/rollback.
- Native privilege sessions and explicit CLI integration, finite hard deadlines, conserved narrowed delegation, DAG/pipes/PTY execution, expiry/revocation/logout/policy or broker-loss cleanup and sudo no-fallback. Source foundations alone do not establish the complete administrator-facing product.
- Stopped-broker migration and activate-last signed lifecycle preserving enrollment/scope/admission, including interrupted writers and active-broker teardown.
- Linux runtime acceptance and released independent installation, plus Windows/WSL/macOS implementation, build artifacts and runnable native acceptance for the user's later qualification. Unrun platform suites do not establish support. A real overnight grant and vendor-controlled approvals require the appropriate actual environment.

Broader provider adapters, unrelated product portfolio work and crate publication remain deferred unless a concrete delivery dependency requires them. Do not launch broad test/lint/CI campaigns in place of the requested working behavior. Required native product qualification remains an acceptance gate.

## Resume and local-only boundaries

1. Verify the Git branch/commit and transport hashes; inspect this inventory and the retained original-vs-export digests. Product source identity remains 81338f23.
2. Resume the UpdateAll causal audit source-only first. Preserve existing user work, failed/consumed clocks, anti-rollback history and genuine signatures.
3. Reconcile the parent's current resource disposition before a heavy/native launch. No old local release receipt, idle lock or handoff note grants a new reservation.
4. Perform the smallest concrete remaining native work in a suitable verified environment, then supported delivery. Cloud findings cannot certify the original workstation's installed routing, kernel/systemd/TTY custody, real provider approval or retained private state.
5. Keep private credentials and local acceptance ledgers on their owning machine. Read-only review and non-secret preparation can move; actual attended authentication remains human-controlled.

No new hosted CI workflow is introduced. The qualified source and transfer branch contain no `.github/workflows` files. Normal hooks and SSH commit signing remain enabled. This transfer does not merge main, promote PR 68, change trust/policy/authentication, or rerun any native product operation.
