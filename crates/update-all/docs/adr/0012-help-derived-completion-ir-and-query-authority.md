---
authority: canonical
owner: dev-tools
---

# ADR 0012: Help-derived completion IR and query authority

status: proposed
verification: pending

## Context

ADR 0011 makes a valid native completion authoritative and leaves help as the terminal fallback boundary when native support is unavailable or invalid. The legacy fallback generated one Zsh script directly from ad hoc help parsing, reran commands when parser behavior changed, treated uncertain positionals as files, and could not share completion semantics with other shells. Replacing native output with inferred help would reduce completion quality, while independently parsing and rendering help in five adapters would create five inconsistent policy engines.

## Decision

A conservative, shell-neutral completion IR is the canonical help-derived artifact. Help planning is entered only after native planning reports unavailable or invalid. A valid native result returns before any help fallback probe, parse, query, or render step, and help never scores, augments, or replaces it.

Raw help is captured once per exact candidate identity, exact resolved executable, and exact direct argv. Captures include bounded stdout and stderr, exit status, and truncation markers. They are encoded as versioned content-addressed objects with owner-only files and directories; exact-key references permit parser upgrades to reprocess existing evidence without invoking the command. The evidence cache is a sibling of the managed publication root so evidence memoization does not create immutable completion snapshots or alter managed-root publication semantics. Content objects use no-clobber publication and existing objects are accepted only when their bytes, regular-file type, and owner-only mode match.

The versioned IR records canonical command paths, aliases, descriptions and evidence references; option spellings, value arity, value name, choices, repeatability, scope, and confidence; positionals with explicit value hints; subcommands; end-of-options behavior; and completeness markers. Unknown information stays unknown. In particular, an unknown positional never receives file or directory completion. Command sections are recognized only from a small allow-list and only when usage exposes a command slot or multiple command-like rows corroborate the section. Environment, Configuration, Examples, and Exit Codes are never command sections.

The planner traverses root help plus two subcommand levels by default, rejects requested depth above three, permits at most sixteen child probes and twenty aggregate help attempts, enforces a 12-second default and 15-second hard total budget, bounds both output streams, detects cycles, deduplicates aliases, and marks nodes partial when depth, budget, cycles, truncation, or parsing prevent completeness. Nonzero help output may remain evidence when it contains parseable help.

One dependency-free Rust query engine interprets the canonical IR for Bash, Zsh, Fish, Elvish, and PowerShell. Its versioned transport uses direct argv for request words and lowercase hexadecimal UTF-8 response fields, rather than delimiter-sensitive shell interpolation. It preserves candidate values, descriptions, explicit file or directory behavior, append/no-space directives, choices, repeatability, and end-of-options semantics. Thin shell adapters only collect shell state, invoke the shared engine, decode records, and register candidates. Deterministic static renderers exist for every shell as the release fallback; no daemon is introduced. Release measurements must use warm and cold p95 samples, with limits of 100 ms and 250 ms respectively, and a shell that exceeds either limit must ship its deterministic static renderer instead of the query adapter.

Help traversal retains its own evidence, recursion, attempt, output, per-probe, and total-budget accounting rather than inheriting native recipe ordering or trust policy. Its bounded process runner executes the exact resolved executable with direct argv, closed stdin, and a controlled environment. Process-tree termination delegates to the repository's existing `crate::util::process::terminate_process_group` abstraction, the same boundary used by ADR 0011's native runner. This decision adds no second FFI or unsafe process boundary.

The strong resolution fingerprint separates native protocol identity from help-fallback implementation identity. An unchanged healthy help-derived candidate reuses its artifact without probes or publication mutation. A parser or transport version change can reprocess cached evidence without rerunning help. When changed executable identity yields byte-identical canonical IR, the active adapter is unchanged, only the identity memo is updated, and the outcome is `probed_unchanged` under ADR 0010.

## Invariants

- Valid native completion is terminal authority; no help fallback work runs afterward.
- Raw help probes use planner-local bounded accounting and the same repository process-tree termination authority as native probes.
- Raw evidence is bounded, immutable, content-addressed, owner-only, and keyed by exact candidate identity plus exact executable and argv.
- Parser upgrades can reprocess healthy evidence without rerunning the target command.
- Unknown value behavior remains unknown and cannot silently become filesystem completion.
- Non-command headings cannot become subcommand sections.
- Recursion, nodes, output, memory, attempts, and elapsed time have hard bounds and produce explicit partial markers instead of unbounded probing.
- All five adapters query one Rust semantic engine through a versioned character-safe transport.
- No daemon, checkout path, syscfg, Shellrc loader, platform capsule, browser, Firejail, agent-tooling, or release/version authority is introduced.
- Managed provider publication remains on its existing Zsh binding until the separate five-shell activation and loader migration is authorized.

## Rejected alternatives

Running help after successful native generation would subordinate authoritative shell-specific behavior to incomplete inference. Storing only parsed output would require rerunning commands after parser fixes and would discard evidence needed to audit uncertainty. Treating every indented row as a command would promote environment variables, examples, and prose into false subcommands. Treating unknown positionals as paths would create surprising and incorrect filesystem behavior. Five shell-specific parsers would drift in semantics and trust. JSON over shell strings would add quoting and dependency complexity; a daemon would add lifecycle and security authority not justified by completion latency. A second handwritten signal FFI would duplicate ADR 0011's unsafe boundary; coupling help traversal to native recipe-session semantics would conflate separate planning budgets and policies.

## Consequences and known limitations

[ADR 0013](0013-five-shell-immutable-completion-activation.md) supplies the reserved five-shell provider publication boundary. This record remains authoritative for IR, query, renderer, uncertainty, and performance semantics.

The evidence cache records a new exact-key reference when executable identity changes even if the resulting raw bytes are already present. That reference is outside the managed publication root; immutable snapshots, views, `current`, and pruning remain unchanged when canonical IR and adapter bytes are identical.

Latency thresholds are release gates, not claims established by unit tests. Until measured on supported targets, query-adapter mode is provisional. The deterministic renderers are present so a failing shell can be switched without introducing a daemon, but runtime acceptance must select and record the shipping mode per shell.

## Verification

The executable regression contract is covered by `valid_native_is_authoritative_and_runs_zero_help_probes`, `exact_identity_reuses_raw_evidence_without_process_probe`, `native_root_help_is_persisted_without_a_second_process_probe`, `recursion_is_bounded_and_marks_partial_nodes`, `evidence_is_captured_once_per_exact_identity`, `evidence_streams_are_bounded`, `evidence_files_and_directories_are_owner_only`, `content_addressed_object_publication_never_clobbers_existing_bytes`, `content_addressed_object_is_owner_only`, `canonical_ir_round_trip_is_deterministic`, `adversarial_headings_do_not_create_commands`, `unknown_positionals_remain_unknown`, `ansi_wrapping_and_nonzero_evidence_are_parseable`, `help_ir_clap_fixture_preserves_arity_choices_repeatability_and_positionals`, `help_ir_cobra_and_go_style_fixture_preserves_global_scope_and_commands`, `help_ir_click_typer_fixture_preserves_aliases_and_choices`, `help_ir_argparse_fixture_does_not_invent_file_semantics`, `help_ir_commander_oclif_fixture_handles_uppercase_sections_and_wrapping`, `adversarial_sections_ansi_and_nonzero_help_evidence_are_conservative`, `command_section_requires_usage_or_multiple_command_rows`, `query_asserts_end_of_options_and_explicit_directives`, `confidence_and_partial_markers_are_explicit`, `parser_is_deterministic_bounded_and_does_not_panic_on_adversarial_input`, `transport_round_trips_arbitrary_shell_characters`, `query_preserves_choices_descriptions_and_append_directives`, `unknown_positional_does_not_invent_file_completion`, `end_of_options_stops_option_candidates`, `every_shell_has_query_and_static_adapter`, `all_five_adapters_preserve_candidate_descriptions_and_explicit_directives`, `arbitrary_shell_characters_survive_query_candidate_transport`, `real_shell_candidates_are_syntax_checked_when_shells_are_available`, `latency_miss_selects_static_without_daemon`, `render_is_deterministic`, `identity_change_with_identical_artifact_updates_only_memo_then_reuses`, `changed_help_identity_with_identical_canonical_ir_is_probed_unchanged_then_reused`, and `second_unchanged_run_performs_zero_probes_and_zero_managed_root_mutation`.

## Runtime acceptance

Exercise representative Clap, Cobra, Click or Typer, argparse, Commander or oclif, and Go-style executables. Confirm one raw capture per exact identity and argv, owner-only object and reference modes, parser-version reprocessing with zero command probes, bounded partial traversal, and identical canonical bytes across repeated parsing. Run candidate queries containing whitespace, quotes, tabs, newlines, metacharacters, and Unicode through every available real shell. Record warm and cold p95 samples for each supported shell; select static rendering for every threshold miss. Change an executable without changing its help semantics and confirm `probed_unchanged`, no new snapshot or view, no `current` movement or pruning, then confirm the next unchanged run performs zero probes and zero managed-root mutation before marking this record accepted.

## Supersession conditions

Supersede this record if help evidence moves to another persistence authority, the IR or query transport requires a backward-incompatible public contract, five-shell activation changes the current publication boundary, a daemon is authorized, process-tree termination moves away from the repository process abstraction, or benchmark policy adopts different release thresholds or mode-selection authority.
