---
authority: canonical
owner: dev-tools
---

# ADR 0002: NPM lifecycle-script attribution and recovery

status: accepted
verification: verified

## Context

A successful batched npm install updated every planned global root, but
unattributed lifecycle warnings erased all successes. A warning identifies a
possible health risk; it is not authoritative evidence that every planned root
failed.

## Decision

Post-install `npm outdated -g --json` is authoritative for each planned root's
update result. Lifecycle findings are deduplicated by package, version, and
command. Exact-root findings remain associated with that root; transitive and
unattributed findings are diagnostics.

A current root is healthy only when its installed version and manifest match the
target, declared global bin targets exist, and the primary executable passes a
bounded non-interactive version/help probe. Packages without binaries use
install/version integrity.

An unhealthy root gets one normal isolated reinstall to reveal its blocked
script closure. Automatic recovery stops if any closure member exposes a local,
git, directory, or arbitrary URL dependency source. Otherwise one ephemeral
`--allow-scripts` retry authorizes only the observed registry closure, followed
by fresh version and executable checks. Trust configuration is never persisted.

## Invariants

- One root's warning cannot erase another root's verified post-state.
- Warnings alone never authorize lifecycle scripts.
- Automatic authorization is root-triggered, isolated, registry-only, and
  single-use.
- No maintained package allowlist controls lifecycle trust.
- A root that cannot be verified remains blocked with an actionable cause.

## Rejected alternatives

- Treating all lifecycle warnings as failed roots repeats the accounting defect.
- Persisting npm script permissions expands trust beyond the observed run.
- Maintaining known-safe package names becomes stale policy and is not a
  substitute for closure inspection and health verification.
- Running every warned script optimizes for installation success over host
  integrity.

## Consequences and known limitations

Executable probes are intentionally bounded and may need revision if a healthy
CLI exposes no safe version/help surface. Registry metadata or installed
manifests that cannot be read fail closed. Post-state verification adds a small
number of read-only npm and filesystem probes.

## Verification

Named regression tests:

- `blocked_install_scripts_parser_deduplicates_package_version_and_lifecycle`
- `scoped_allow_scripts_retry_targets_only_the_blocked_desired_package`
- `command_output_diagnostics_surface_npm_allow_scripts_warning`
- `npm_advisories_dedupe_deprecated_warnings`

## Runtime acceptance

Run npm and `skills` against the live global npm installation, inspect per-root
counts and artifacts, confirm no npm policy file changed, then run the same lane
again. Acceptance requires `skills` after npm, verified root outcomes, complete
logs, and no false updates on the second run.

## Supersession conditions

Supersede this record if npm provides a stronger machine-readable lifecycle
closure and root-health protocol, global package execution no longer uses
manifest `bin`, or lifecycle trust moves to an external signed policy authority.
