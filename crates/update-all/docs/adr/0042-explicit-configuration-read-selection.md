---
authority: canonical
owner: dev-tools/update-all
---

# ADR 0042: Explicit configuration read selection

status: proposed
verification: pending

## Context

A missing nonempty UPDATE_ALL_CONFIG path silently selected a discovered
configuration, or runtime defaults. A zero-argument invocation could therefore
run unrelated detected tasks after its intended configuration was lost or
mistyped. Explicit non-regular files could also block startup during reading.

## Decision

For operations that read configuration, select the CLI path first, then the
nonempty native UPDATE_ALL_CONFIG path. Only an unset or exactly empty variable
permits ordinary default discovery. An explicit selection is not a hint: missing
paths and metadata, read, parse or semantic validation errors fail without
selecting another configuration. Both CLI and environment paths must identify a
regular file before reading. Configuration validation uses the same selection.

Preserve relative paths against the invocation's working directory, literal
whitespace, native non-Unicode paths and symlinks to regular files. Do not add
canonicalization, tilde expansion, a new size limit or changes to discovered
default candidates. Read selection remains separate from configuration-writing
operations, which may create an explicitly named absent file.

## Invariants

- CLI selection wins even if the environment names a missing or invalid file.
- Startup rejection precedes task execution, elevation and journal creation;
  no invented run artifact claims that a run occurred.
- Ordinary startup and config-validation errors retain InvalidPlan exit 3.
- Empty/unset environment selection preserves existing XDG/HOME discovery and
  runtime defaults when no file is discovered.
- Default Dashboard, configured Plain, non-TTY detach, completion, release and
  self-update behavior are not changed by this decision.
- Configuration-writing destinations retain their existing creation semantics.

## Rejected alternatives

Silent fallback can widen the selected work. Trimming a path changes the meaning
of a legitimate filename. Converting a native path to UTF-8 can discard an
explicit selection. Reading a FIFO as ordinary configuration can hang startup.
Changing the UI default or task-run exit taxonomy does not repair selection.

## Consequences and known limitations

Callers that used an absent explicit path as a discovery hint must unset it or
set it to the empty string. Explicit directory, FIFO and device inputs are no
longer read as configuration. Metadata admission follows ordinary file symlinks;
it is not protection against hostile replacement between metadata and reading.
Discovered-default admission, read-size bounds and platform-native qualification
remain outside this slice. Disposable Linux executable fixtures do not establish
signed-release, installed-successor or native macOS/Windows acceptance.

## Verification

- `zero_argument_missing_explicit_environment_config_never_runs_discovered_fallback`
- `zero_argument_valid_environment_config_precedes_discovered_defaults`
- `cli_config_precedes_valid_or_missing_environment_selection`
- `zero_argument_empty_or_unset_environment_preserves_xdg_and_home_discovery`
- `zero_argument_default_dashboard_keeps_non_tty_detach_and_truthful_completion`
- `absent_configuration_keeps_read_only_runtime_default_validation`
- `explicit_environment_paths_preserve_whitespace_relative_and_non_unicode_names`
- `explicit_config_directories_and_fifos_are_rejected_before_reading`
- `explicit_config_symlink_to_regular_file_remains_supported`
- `malformed_explicit_environment_config_never_uses_valid_fallback`
- `configuration_creation_still_accepts_an_explicit_absent_target`
- `configuration_writer_preserves_legacy_destination_selection_in_isolated_processes`

## Runtime acceptance

Run the exact standalone candidate with zero arguments in disposable roots and
an environment cleared of ambient overrides. PATH contains only the native Rust
marker provider, with no installed update-all alias, managers or sudo. Exercise
missing and valid environment selections, CLI precedence, exactly empty/unset
discovery, literal and native paths, non-file refusal and regular-file symlinks.
Keep configured Plain and default Dashboard non-TTY controls. Compare actual
markers, process exits, selected tasks, final artifacts and journal completion
where startup permits; rejected startup must not fabricate artifacts. Preserve
the failing pre-fix invocation and run the same contract against the candidate.
Verify authoring commands can still create absent explicit targets. Native
supported-platform and installed-release gates remain separate.

## Supersession conditions

Supersede this record if explicit selection becomes optional, streamed inputs are
introduced, configuration-writing authority changes, or descriptor-held reading
replaces the existing ordinary file boundary.
