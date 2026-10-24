---
authority: canonical
owner: dev-auth
---

# ADR 0140: Only the release that a setup plan installs renders and judges it

status: proposed
verification: source tests pass under `just test`; signed cross-release upgrade acceptance pending

## Context

A setup plan names the release it installs, its candidate. Every release derives part of a plan from its own code rather than from native observation:

- the action list, from `planned_action_contract`;
- the current-state inventory, which grows when a release starts to own a new path;
- the grant payload, the identities of the sudo library, service unit, polkit action, sudoers file and sudo bridge that the release embeds. The embedded library carries its release version and source commit, so the payload differs in every release.

`setup plan` rendered these parts in whatever executable ran it, and the candidate validated them against its own code. An installed 0.5.2 planned an upgrade to 0.5.4, and the 0.5.4 candidate rejected the plan with `privilege setup plan has an incompatible closed authority contract`. A 0.4.0 planner had failed the same way for 0.5.2 on the current-state inventory. The diagnostic for that case named only the maintenance paths that 0.5.0 added, so the next contract change would fail opaquely again.

The handoff ran the other way too. `setup apply`, the setup helper and `setup verify --plan` parsed and validated the whole plan in the running executable before they ran the candidate. An installed release therefore rejected any plan that a newer candidate rendered for itself. It also could not parse a plan that carries a field it does not know. Planning in the candidate alone would have moved the failure from the candidate to the installed release.

The privilege-only builder and the setup-owned update worker already rendered in the candidate. [ADR 0120](0120-setup-owned-updates-and-preserving-maintenance.md) records that a plan built by the old executable cannot supply the new release's sudo bridge digest. Recovery, restoration and maintenance already require the exact retained candidate.

## Decision

### The candidate renders its own plan

`setup plan` selects and verifies the release as before: online selection, an explicit bundle with `--offline`, or the accepted release with `--offline`. It then compares the running executable with the selected release's artifact by length and SHA-256.

- If they match, the running executable renders the plan.
- Otherwise `setup plan` reloads the exact accepted release from its canonical cache entry, checks the cached artifact's identity, and executes that artifact as `dev-auth` with the original arguments plus `--accepted-release`, a cleared environment and `/` as its working directory. This is the same handoff that `setup apply` uses. The candidate parses the arguments and the deployment document itself and renders every part of the plan.
- A selected release older than 0.5.6 cannot accept the handoff. The planner refuses with a version-skew error that names that release and says to run that release's own `setup plan`.

`--accepted-release` resolves the release without network access, from the explicit bundle when one is given and from the accepted-release ledger otherwise. The running executable must be that release, or planning fails and says to plan again. The plan records the deployment's `offline` choice unchanged. The candidate never selects a release over the network, so one `setup plan` makes at most one network selection and plans exactly the release that it selected and accepted.

`build_setup_plan_v3_for_verified_release` refuses with a version-skew error unless the running executable is the release, before it reads any input. Every plan build for an installation that names a verified release, including the rebuilds that apply and recovery use to revalidate a plan, refuses the same way. This covers `setup plan`, the update worker and any later caller.

### Any release hands a plan to its candidate before judging it

`setup apply`, the setup helper's `apply-v3` and `setup verify --plan` first read only the fields that name and authenticate the candidate:

- `intent.mode` and `intent.purpose`;
- `installation.request.mode` and `installation.request.source_executable`;
- `installation.source_length`, `installation.source_sha256` and `installation.verified_release`;
- the `name` and `uid` of each entry in `accounts`.

This read ignores every other field. It checks the approved digest over the canonical JSON of the whole document, the native identity that may apply the plan, the exact accepted release in its canonical cache and the candidate's identity. The setup helper reads the plan only from root-owned private custody, as before, and accepts only strong plans. When the candidate is another executable, the running release executes it with the same arguments, a cleared environment and `/` as its working directory. Only the candidate parses and validates the full plan.

The handoff view also refuses a plan whose installation mode differs from its deployment mode.

These fields are a contract between releases, together with the strict shape of `VerifiedDevAuthRelease`, the accepted-release ledger and cache layout, `--accepted-release`, the setup helper's canonical arguments, and the `setup apply` and `setup verify` flags that the running release parses before the handoff. A release keeps them readable by its predecessors, or those predecessors cannot hand its plans to it.

### The candidate names the parts it does not render

Full validation compares the parts that releases render differently with what the validating release renders for the plan's own inputs: the action list, the current-state inventory and, for a plan with the grant component, the grant payload. If any part differs, validation fails with `PlanVersionSkew::Rendered`. Its message names each differing part, the validating release and the remedy: regenerate the plan with that release's `setup plan` and approve the new digest. The message names only the validating release's own version, kinds and counts, never plan text. This check replaces the special case for the 0.5.0 maintenance paths and the grant component's separate payload and action comparison. A difference in any other part fails with that part's existing error.

A component that adds a part that a release derives from its own code adds that part to this comparison. A plan does not record the release that rendered it. Releases up to 0.5.5 reject unknown plan fields, so a new field would break every apply through such a release, including credential-only applies that work today.

Validation runs only in the release that a plan installs. Recovery and restoration already check the exact retained candidate first. Maintenance (`setup repair` and `setup uninstall` on a full generation) now checks it before validating too, so another release reports `run_retained_candidate_for_maintenance` and the retry executable instead of a contract error.

### What changes for trust

Release selection and signature verification, the exact accepted-release ledger and canonical cache, the approved digest, root custody of the executed candidate and of the helper's plan, native apply identity and recovery are unchanged. The candidate still validates the full plan and revalidates its documents, current state and release before any mutation. A running executable that is not the candidate no longer judges the plan's contracts, because the candidate repeats that judgment before it acts.

`setup plan` now executes the selected release before anyone approves a plan. For a strong installation it runs as root, because strong planning requires root. Before, a new release's code first ran as root in `setup apply`, after its plan digest was approved. The release is the exact signed release that the ledger accepted, and planning changes no installed state. Only the candidate can render a plan that it accepts, so this is the cost of the fix. The update worker in ADR 0120 already runs the selected release before it applies.

## Consequences

Releases up to 0.5.5 neither hand planning to the selected release nor hand a plan to its candidate before judging it. To upgrade from one of them, run `setup plan` and `setup apply` with the new release's own executable, such as its release asset after `setup verify-release` accepts it. For a strong installation, run that `setup apply` directly as root. `--authorize sudo|polkit` runs the installed setup helper, which validates the plan with its own contracts. A plan that such a planner rendered reaches a 0.5.6 or later candidate as a version-skew error that names the release to plan with. Later upgrades work from the installed `dev-auth`.

0.5.6 is the first release after 0.5.5, the last release without this change. A source build planning for a released candidate older than 0.5.6 refuses instead of rendering a plan that the candidate may reject.

An apply or verify of a plan that is not valid now reports a candidate error, such as a digest or native identity mismatch, before a contract error. A non-root user therefore no longer sees the contract diagnostic for a strong plan.

The running release still parses the `setup plan` arguments and the deployment document under its own grammar before it hands planning off. A flag or deployment schema that only a newer release knows therefore needs that release's own executable.

`setup recover`, `setup restore` and maintenance still parse the retained plan in full before they check the candidate. An older release that runs them on a newer candidate's retained plan with a field it does not know reports a parse error instead of the retry executable.

## Verification

Source tests cover the following. The grant cases need the embedded native sudo payload, so they are ignored by a plain `cargo test` and `just test` runs them. The command-line cases plan for the effective native account, which must not be root, like the existing user-only setup tests.

- an older planner's grant payload, action list and current-state inventory, each reported as version skew that names the candidate;
- a plan rendered by the candidate itself, for credentials alone and with the grant component, which validates unchanged;
- `setup apply` and `setup verify --plan` handing a newer release's plan, which carries an unknown component and action, to its candidate unjudged, with the exact arguments, a cleared environment and `/` as the working directory;
- the running release naming itself as the release to plan with for an older planner's plan;
- the choice between rendering, delegating to a 0.5.6 or later release and refusing an older one;
- the render entry refusing a release that is not the running executable;
- `setup apply` and `setup verify --plan` refusing, without running any candidate, a plan with another digest, a changed candidate identity, mismatched modes or a strong deployment without a verified release.

The planning handoff's execution needs a release that the embedded release root signed and the fixed native release storage, so no hermetic test executes it. Signed cross-release upgrade acceptance for credential-only, privilege-only and combined setups remains pending.
