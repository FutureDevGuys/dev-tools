---
authority: canonical
owner: dev-tools
---

# ADR 0004: Attributable AUR failure containment

status: superseded
verification: pending
replacement: 0005-verified-repository-retirement.md

## Context

A single AUR package build or source failure can terminate a full `yay` update
before unrelated repository and AUR updates finish. Treating every such failure
as fatal leaves known-safe work incomplete, but package-specific exceptions or
automatic uninstalls would make the multi-system updater encode local policy.
Recovery is safe only when the failed package is exact, the exclusion boundary
is complete, and the original bulk transaction can finish successfully.

## Decision

An exactly attributed AUR source/checksum or build failure receives one isolated
package retry. Source/checksum failures first clear only that package's yay
cache/worktree; build-only failures preserve their cache. The exclusion set is
expanded through parsed yay dependency groups. The original bulk command is then
resumed with every handled or unresolved target passed to `--ignore`.

A successful resumed command completes the task. Isolated successes are reported
as updated. Unresolved exclusions are reported as skipped with a non-blocking
warning. The resumed command's report rows are authoritative over matching rows
from the failed attempt. Complete subprocess evidence remains in `task-yay.log`.

Recovery fails closed when attribution is ambiguous, another transaction-level
blocker exists, a safe exclusion set cannot be constructed, or the resumed
command fails. Health dependents run only after successful resumption.

## Invariants

- Recovery contains package identities, never package-name policy.
- Build-only failures never authorize cache/worktree deletion.
- Source/checksum cleanup remains scoped to the exactly attributed yay package.
- Dependency-coupled packages are excluded together.
- AUR source/build containment never uninstalls a package. ADR 0005 defines the
  distinct, proof-gated repository-retirement exception for exact pacman
  conflict-removal questions.
- A successful isolated retry does not substitute for successful bulk
  resumption.
- Ambiguous or transaction-level failures block health dependents.
- Structured evidence stays bounded while the task log retains complete command
  output.

## Rejected alternatives

- A package allowlist or PolyMC-specific branch would make shared updater
  behavior depend on one host's installed software.
- Automatic uninstall would turn build failure handling into destructive package
  policy.
- Deleting cache for every build failure discards useful build state without
  evidence of source corruption.
- Splitting official repository and AUR updates into unrelated transactions could
  weaken Arch full-upgrade semantics.
- Treating isolated retry success as task success could skip unrelated updates
  that the original bulk command had not completed.

## Consequences and known limitations

Recovery depends on stable, exact package attribution in yay output. Dependency
group expansion is conservative and can exclude a coupled package that did not
itself fail. Excluded packages remain pending for a later run and require manual
attention when their isolated retry fails. New yay output shapes must fail closed
until the parser can prove the same boundary.

## Verification

Named regression tests:

- `yay_package_recovery_plan_accepts_attributed_build_failure_without_cleanup`
- `yay_attributed_build_failure_retries_then_resumes_without_cache_cleanup`
- `yay_source_recovery_ignores_mixed_build_failures_and_dependents`
- `yay_package_recovery_plan_rejects_unattributed_build_failure`
- `yay_transaction_blocker_prevents_package_recovery_and_preserves_evidence`
- `structured_failure_evidence_is_bounded_while_task_log_retains_full_output`

## Runtime acceptance

Repair the installed command, run
`update-all --plain --only=yay,arch-update-services` twice on the live Arch host,
and inspect the resulting task artifacts. Acceptance requires both runs to
succeed, no package updates to remain, no unexplained second-run mutation, and
service-restart behavior consistent with the observed update outcome.

## Supersession conditions

ADR 0005 supersedes only the blanket prohibition on every automatic removal.
The attributable AUR source/build containment and exclusion rules in this
record remain in force. Revisit them if yay exposes a stronger machine-readable
failure and dependency protocol or package recovery moves to an external
authority with equivalent attribution, exclusion, and health-gating guarantees.
