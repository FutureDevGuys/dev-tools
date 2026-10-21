---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0039: Preserve unclassified NPM directories

status: proposed
verification: pending

## Context

An interrupted global NPM installation can leave package data under a hidden,
hyphenated directory while the canonical package path is absent. Update All's
previous pre-install cleanup deleted every directory matching that naming shape.
The name did not prove that the directory was disposable, and cleanup could
destroy the only retained package copy before an installation failed.

## Decision

Update All does not delete or restore NPM tree entries based on temporary-looking
names. Canonical package presence, absence, or manifest contents are not cleanup
authority. NPM itself still owns the effects of an authorized provider update;
preservation by Update All does not promise that NPM will leave an entry intact.

Before planned installs, Update All may make a read-only, non-recursive
observation of hidden, hyphenated directories in the global root and one scope
level. It reports a bounded sample as unclassified data, without asserting
ownership, staleness, integrity, or recoverability. Observed symlink roots,
candidate entries and scope directories are not followed. It does not open
package contents for this observation. Inspection failure is reported as
incomplete, not an empty observation, and causes no cleanup or automatic repair.

Preservation and incomplete-inspection advisories are non-blocking, retained in
terminal NPM task results, and do not alter ordinary update/recovery behavior.
ADR0007's mutation-authority gate and ADR0038's terminal storage handling remain
in force. No new command, automatic migration or provider configuration is added.

## Invariants

- A name is never authority to remove potentially retained package data.
- Scoped, unscoped and unrelated hidden entries remain untouched by Update All,
  whether or not a canonical package exists.
- Observation never restores a canonical package or guesses a rollback source.
- The observer examines only directory-entry metadata at the two allowed levels;
  samples remain bounded independently of the number of entries.
- Unavailable inspection evidence is reported truthfully and does not block an
  otherwise authorized provider operation.
- Ordinary success stays successful; storage failure still stops further
  automatic mutation and leaves unknown post-state unknown.

## Rejected alternatives

Deleting only when a canonical directory exists still cannot prove whether the
retained copy contains unique data or the only functioning executable. Reading
package manifests cannot establish ownership, completeness or safe removal.
Automatic restoration would invent transaction/rollback authority. Blocking all
updates because of unrelated hidden entries would broaden this repair into an
unreliable installation-health policy.

## Consequences and known limitations

Hidden entries can consume disk space or cause an NPM-owned conflict; the
operator must review that state explicitly. The observer does not perform a
complete tree inventory or measure capacity. Its sampled names are directory
observations, not a consistent filesystem snapshot or hostile concurrent-path
replacement defense. Provider mutation remains governed by the existing NPM
authority contract. Native platform and real-package acceptance remain pending;
the automated tests use only disposable Rust provider fixtures.

## Verification

- `npm_preserves_scoped_unscoped_and_unrelated_hidden_directories`
- `npm_ordinary_success_does_not_report_retained_staging`
- `npm_hidden_directory_observation_is_bounded_and_never_recursive`
- `npm_hidden_directory_observation_skips_symlinks_and_reports_unreadable_roots`
- `storage_exhaustion_stops_common_and_npm_retries_without_losing_effects`
- `successful_and_recoverable_npm_paths_still_work`

## Runtime acceptance

Run the standalone executable with a harmless native Rust provider in a
disposable, user-owned global prefix. Exercise scoped and unscoped retained
copies, both present and absent canonical packages, unrelated hidden entries,
symlink candidates and scopes, and normal successful updates. Require exact
retained bytes after both success and reported storage exhaustion, no automatic
restoration, bounded non-blocking notices, and no further install after the
storage failure. Repeat default and no-default builds and native platform
acceptance without touching real packages or deleting user data.

## Supersession conditions

Supersede this record only if a provider supplies an explicit, verifiable
transaction/cleanup protocol that establishes ownership and safe removal, or
Update All adopts a separately authorized retained-state recovery contract.
