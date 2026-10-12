---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0029: Implementation-first Linux sudo delivery

status: proposed
verification: pending

## Decision and supersession

Deliver the complete implemented Update All correction before expanding its qualification campaign. This record supersedes only ADR 0028's requirement to finish every native sudo-policy lane before the immediate Linux delivery. It does not change sudo invocation, privilege admission, replay prevention, task input, cancellation, credential handling, or any release authentication mechanism.

The initial Linux delivery is qualified against the actual native user's existing sudo policy. Administrator permission to execute commands, such as a password-required `(ALL : ALL) ALL` listing, is not proof of a NOPASSWD rule or of terminal/parent timestamp semantics. Record the observed policy and executed behavior without inferring the missing profiles. Neither source changes nor test intent authorize changes to production sudoers, timestamp settings, accounts, credentials or host security configuration.

## Essential current-policy acceptance

Use the exact final source and its candidate binary with an isolated catalog, configuration, state and a harmless fixed-argv disposable protected command. Automatic product updates and unrelated catalog tasks must be disabled. Native credential entry belongs to the user in the visible native prompt and must not enter chat, saved transcripts or fixture files.

One bounded end-to-end journey must establish successful task-terminal authentication/launch under the existing policy, exact argv, exactly one protected effect, visible completion and agreement with the saved task/run result. Exercise cancellation after submitted input while the harmless command is still running and establish owned-child cleanup. A harmless command failure after its one recorded effect must remain failure with zero automatic protected replay. Reuse the existing behavior driver and synthetic evidence where they already establish the unchanged retry/masking/timeout contracts; do not create a new policy-matrix framework for this delivery.

The task-terminal sudo invocation remains distinct from startup preflight or keepalive. Count the protected command's launches and effects, rather than incorrectly requiring the entire application to invoke sudo only once. A failed native journey is a real blocker to activation and must be diagnosed. Successful `sudo -l`, compilation, a controlled fake sudo process or an empty/filtered test selection is not a substitute for the journey.

Retain applicable existing formatting, strict lint, changed-product behavior and source-policy checks. Carry unchanged-source evidence with its original source identity; qualify the actual integrated tree for changed behavior. Do not bypass hooks, disable checks or relabel a prior failed aggregate as passed.

## Explicitly deferred coverage

The terminal-scoped, parent-scoped, no-cache and NOPASSWD matrix remains useful follow-on qualification. Each unexecuted policy lane is recorded as NOT RUN; a current-host pass qualifies only the observed policy and exercised paths. The 31 controlled-executable scenarios remain synthetic sudo evidence. There is no claim that those scenarios run real sudo, nor that a native four-policy environment has already been provisioned.

Other operating-system native execution, broad version/policy combinations, exhaustive fault schedules and large performance campaigns do not delay completing this implementation-first Linux correction. No additional platform or policy guarantee follows from their deferral. Existing required release identity, authenticated artifacts, managed installation and retained rollback remain intact.

## Source, release and installed state

A merged source change is not an installed fix. Use the normal task PR and signed-source workflow, combine accepted baseline corrections without weakening their behavior, then use the existing authenticated Linux release constructor and publisher. Select an unused version/generation from actual accepted release history; never reissue accepted identifiers with different bytes. Release Admin's independent-candidate comparison, source/artifact verification and signing boundary remain the existing release contract.

Activate through the product's managed install/update path, retaining the prior accepted rollback candidate. Verify the live command's version, source identity, digest, doctor/update status and harmless corrected behavior. Report source-built, source-merged, released and installed as distinct milestones. This record itself proves none of those outcomes and grants no additional system authority.
