---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0041: Terminal reported NPM authority failure

status: proposed
verification: pending

## Context

A user-owned NPM prefix can pass the preflight authority check and still report
an installation denial. Configured command retries previously replayed that
mutation before the NPM task saw its failure. The outer classifier inspected a
concise display message, losing stdout diagnostics and output after the excerpt
limit. Denials first seen in individual or root-health recovery did not stop
later package mutations.

## Decision

An explicit NPM-install replay policy checks complete captured failure channels
before configured retry or capture fallback. Positive reported EACCES/EPERM or
supported explicit denial messages stop replay. Capture guards retain only the
classified observation when disposing output. Executable names, path components,
negative marker names and successful command text are not denial evidence.

Every NPM installation path uses that policy: batch, individual, isolated
root-health reinstall and registry-only lifecycle retry. Recovery carries its
terminal classification separately from display/health text. An observed denial
stops further automatic NPM installs or recovery for that task, preserves already
observed report rows and leaves unverified planned roots with unknown post-state.
The blocking authority advisory remains a rich completed task with an incomplete
run, following ADR0040. No ownership change, elevation, cleanup, repair, restore
or rollback is inferred or attempted.

## Invariants

- Successful command output cannot turn a success into an authority failure.
- The policy is selected by the actual NPM installation call, not a program name
  or arbitrary task identifier.
- Full captured stdout and stderr are considered before automatic replay.
- Storage and cancellation handling retain their existing precedence; generic
  non-NPM retry and sudo authentication/fallback policies remain unchanged.
- No further NPM mutation occurs after a terminal reported installation denial.
- Earlier effects remain; stopping replay does not establish a transaction,
  unchanged filesystem or definitive filesystem-ownership diagnosis.
- Verified observations survive; requested targets do not become observations.
- Ordinary package-specific recovery and bounded lifecycle trust remain intact.

## Rejected alternatives

Globally disabling retries on permission prose would change independent provider
and sudo contracts. Matching npm in an executable path would confuse identity
with operation authority. Parsing formatted errors discards causal evidence.
Classifying arbitrary health-check strings could mistake a package or path name
for a new installation denial. Rechecking ownership cannot establish rollback or
safe replay after a provider has partially modified files.

## Consequences and known limitations

An explicit future retry remains the operator's decision after reviewing the
denial and package state. Reported output is not a measured filesystem diagnosis;
a failed provider quoting a standalone historical denial can remain ambiguous
and is conservatively stopped. Direct-TTY output without capture cannot be
classified this way. Actual built-in NPM installs are noninteractive; capture
fallback protection is exercised through the same command-policy boundary.
Independent tasks retain the scheduler's existing policy. Native platform,
real-package, installed-release and user-operated elevation acceptance remain
separate from disposable native Rust fixture evidence.

## Verification

- `npm_authority_diagnostics_stop_configured_replays_from_complete_channels`
- `npm_authority_during_individual_and_health_recovery_stops_later_mutation`
- `npm_authority_controls_preserve_success_recovery_and_non_npm_retry`
- `authority_failure_classification_requires_captured_diagnostics_not_names`
- `captured_npm_authority_failure_stops_guard_fallback_without_replaying`

## Runtime acceptance

Run the exact standalone candidate with disposable Rust providers, user-owned
prefixes and retries above zero in sync/plain and async/plain. Exercise initial,
individual, both root-health stages and lifecycle-triggered installation denials,
including full stdout, stderr beyond the excerpt limit and retained partial
effects. Compare process and run-artifact exits, mutation counts and package rows.
Require one attempted mutation for initial denial and no mutation after later
denial; preserve a prior verified row and null unverified targets. Exercise
ordinary retries/recovery, success containing historical diagnostics, path and
marker negatives, non-NPM permission retries and combined storage precedence.
Exercise a real capture guard at the NPM policy boundary before direct-TTY
fallback. Repeat supported native platform acceptance without real package,
privilege, trust or user-configuration changes.

## Supersession conditions

Supersede if a provider transaction/capability protocol replaces reported text,
NPM gains a separately authorized recovery transaction, or the rich incomplete
run contract changes. ADR0002's bounded lifecycle trust, ADR0007's preflight
mutation authority and ADR0038's terminal storage handling remain in force.
