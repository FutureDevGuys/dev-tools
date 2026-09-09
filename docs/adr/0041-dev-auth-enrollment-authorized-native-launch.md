---
authority: canonical
owner: dev-auth
---

# ADR 0041: Enrollment-authorized native workload launch

status: proposed
verification: pending

## Decision

The unreleased Dev Auth 0.4 successor separates policy-selected enrollment-authorized launch from launch-time interactive approval. On Linux, the existing receipt-owned workload launcher copy gains a narrow set-user-ID entry point. The public product executable, setup helper and versioned source executable remain ordinary mode-0755 files. Only the workload launcher copy for authenticated releases at or after 0.4.0 uses mode 04755. Retained earlier releases remain mode 0755, including during interrupted-transition recovery and rollback; their entry points do not carry this guard contract.

Every invocation with different real/effective user or group IDs enters the enrolled dispatcher before inspecting frontend names, subcommands or environment hints. It cannot select setup, secret, broker, privilege, shell or another public command by changing argv[0]. The entry point accepts only the existing exact workload-dispatch grammar and emits fixed value-free failure diagnostics. It verifies effective root, the kernel real caller UID, the fixed dedicated executable path, receipt custody, source/copy identity, root-owned policy and the fully resolved native-user workload. Only an explicit `enrolled_noninteractive` choice within administrator caps permits this route. Legacy policy and `approval_required` workloads are denied without prompting. Copied environment markers and a caller-supplied `PKEXEC_UID` are not enrolled-launch authority.

After those checks the dispatcher normalizes its own root infrastructure identity, retains the original native workload owner as explicit state, and uses the existing bounded handoff, gated systemd boundary, broker registration and user-identity execution path. Workload arguments remain native argv after the fixed command boundary; they never become root shell input. The workload itself runs as its owning user, not as administrator. General administrator grants remain a separate explicitly approved authority under ADR 0004.

Interactive workload approval continues through the existing polkit path. A prompt-free invocation never enters pkexec or uses absence of a prompt as authorization. Explicit nested launches reuse their verified existing authority without widening it. When a separate execution result is selected, a retained native child now allows result finalization while preserving arguments, streams, terminal behavior, signal status and the existing hard deadline.

## Installation and compatibility

The receipt-owned launcher remains a separate verified copy, never a hardlink to the public executable. Permission publication follows content verification; unchanged permissions are a no-op. A partially installed new copy cannot authorize through an old receipt whose source identity differs. Recovery and rollback recompute launcher permissions from the retained authenticated release identity. Set-group-ID, sticky and unexpected executable modes are not accepted as the enrolled-helper contract. This source change does not alter installed files or silently enable automatic admission in existing policy.

The 0.3.11 release's exact verification compatibility remains unchanged. Source version 0.4.0 distinguishes the successor from those accepted bytes; this version has not been published or release-qualified. The stopped-broker policy migration and signed setup qualification remain necessary before activation.

## Verification

Routing tests reject implicit and approval-required automatic admission and select the explicit enrolled route. Setup tests distinguish guarded successor permissions from retained older versions and exercise recovery against the existing setup-helper transition suite. Native acceptance must additionally launch the protected copy under a real non-root caller, reject forged argv[0]/environment and wrong-account requests, prove no interactive agent is contacted, exercise absent enrollment and changed policy, and verify owner-identity execution, terminal streams, whole-domain teardown, repeat setup and rollback. Unit routing and mode tests are not proof of that native set-user-ID acceptance.
