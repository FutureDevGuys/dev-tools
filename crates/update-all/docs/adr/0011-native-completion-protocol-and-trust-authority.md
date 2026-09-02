---
authority: canonical
owner: dev-tools
---

# ADR 0011: Native completion protocol and trust authority

status: proposed
verification: pending

## Context

The managed completion engine already separates provider inventory, candidate identity, binding selection, and immutable publication, but native generation was a Zsh-only list of a few argv guesses with an independent timeout. It could run help after receiving usable native output, had no reusable recipe identity, and had no shell-specific registration, syntax, or dynamic-execution trust boundary. Extending that behavior by adding more guesses would weaken native authority and make one candidate's probes unbounded in aggregate.

## Decision

A versioned, provider-generic native planner owns generation attempts for Bash, Zsh, Fish, Elvish, and PowerShell. Registry version 1 contains the evidence-backed completion, completions, generate-completion, generate-completions, and gen-completion subcommands; positional shell names; separated and joined shell flags; top-level completion, completions, and show-completion flags; the powershell and pwsh spellings; and Click or Typer environment-source generation. Provider catalogs may add nonstandard direct-argv recipes and provider-owned relative static artifacts without adding product-specific code.

The planner probes in this order: provider-owned bundled static artifact, the previously successful current recipe for the same candidate and shell, explicit catalog recipes, safe high-yield stdout protocols, help-evidenced protocols, then framework environment protocols. A valid native result is authoritative and ends all probing; help is not run afterward to compare, enrich, or replace it. Existing help-derived Zsh generation remains only the terminal fallback after the native planner reports no completion. A dynamic-output policy rejection is a hard error rather than permission to cross that fallback boundary.

Every process attempt executes the already resolved executable with its configured launch argv and direct additional argv. Standard input is closed; the working directory and inherited environment are controlled; stdout and stderr have independent byte limits; and one session enforces a per-attempt timeout, total deadline, and attempt budget across command selection, native recipes, syntax checks, help evidence, and the existing fallback. Timeout, cancellation, capture overflow, and incomplete pipe shutdown terminate the child process tree.

Native bytes are preserved except for removal of a UTF-8 byte-order mark, normalization of CRLF or bare CR to LF, and exactly one terminal newline. The planner rejects leading diagnostic banners, validates registration for the requested command, and invokes the target shell's syntax checker when available. Accepted output is recorded as static or dynamic. Static classification is fail-closed: only narrowly declarative Bash `complete` and Fish `complete` registration shapes qualify; function bodies, Zsh function definitions, Elvish closure assignments, PowerShell scriptblocks, and every other opaque executable shape are dynamic. The classification-policy version participates in strong candidate resolution identity so a policy change cannot use an older unchanged memo without re-evaluation. Dynamic output is allowed for provider-managed candidates and explicit catalog or provider-bundled sources; an ambient generic probe requires the catalog's explicit dynamic-trust grant.

## Invariants

- A valid native completion stops all later native, help-evidence, framework, and help-fallback probes.
- No built-in or declarative recipe may invoke an install-completion mutation form.
- Every process probe uses the exact selected executable and direct argv under one bounded session; shell interpolation is not a protocol mechanism.
- Registration for another command, a leading banner, invalid syntax, capture overflow, timeout, or budget exhaustion cannot become an active native artifact.
- Ambient dynamic output without explicit trust is reported as a policy rejection and cannot silently become help-derived output.
- Dynamic trust is never inferred from the absence of a short list of command tokens; payloads are static only when the complete shell-specific shape is on the narrow declarative allow-list.
- A successful recipe memo is versioned and reused only when its candidate, command, shell, and current registry or catalog definition still match.
- Strong unchanged candidate identity remains probe-free and mutation-free under ADR 0010.
- The planner and catalog schema contain no checkout, syscfg, browser, Firejail, shell-startup, or platform-capsule authority.

## Rejected alternatives

Running help after every native result would make native authority contingent on a lower-quality parser and could replace complete shell-specific logic with incomplete inferred flags. Invoking install-completion forms would let discovery mutate user state. Inheriting the full parent environment or executing recipe strings through a shell would make results depend on unrelated local state and create interpolation authority. Treating all dynamic output as unsafe would reject normal native protocols, while trusting all ambient dynamic output would let an unowned PATH executable install runtime behavior without an explicit decision. Giving each probe an independent timeout without a shared budget would still permit excessive aggregate work.

## Consequences and known limitations

The protocol planner and validators are shell-neutral and callable for all five shells. [ADR 0013](0013-five-shell-immutable-completion-activation.md) supplies the later five-shell provider activation authority and extends the already-approved conservative help fallback to each selected shell without changing native precedence or trust.

Syntax validation is conditional on the corresponding shell executable being available. Registration validators are intentionally conservative and may require a catalog recipe or validator extension for unusual but valid registration styles. Process runtime obeys the shared deadline, followed by a fixed bounded cleanup grace needed to close inherited pipes and terminate descendants. Windows batch entry points continue to use the repository's existing direct batch compatibility wrapper and tree termination mechanism.

## Verification

The regression contract is covered by `native_protocol_positional_shell_names_cover_all_five_shells`, `native_protocol_completion_family_is_supported`, `native_protocol_completions_family_is_supported`, `native_protocol_generate_completion_family_is_supported`, `native_protocol_generate_completions_family_is_supported`, `native_protocol_gen_completion_family_is_supported`, `native_protocol_top_level_completion_family_is_supported`, `native_protocol_top_level_completions_family_is_supported`, `native_protocol_top_level_show_completion_family_is_supported`, `native_protocol_top_level_flags_accept_positional_shell_arguments`, `native_protocol_shell_flag_separate_and_joined_forms_require_help_evidence`, `powershell_protocol_accepts_powershell_and_pwsh_synonyms`, `click_typer_framework_environment_source_protocol_is_supported`, `declarative_catalog_recipe_supports_nonstandard_generator`, `declarative_catalog_native_schema_deserializes_and_validates`, `provider_bundled_static_artifact_precedes_process_recipes`, `previous_successful_recipe_precedes_catalog_and_registry_probes`, `wrong_command_registration_is_rejected_for_all_five_shells`, `leading_banner_is_rejected_without_rewriting_payload`, `bom_crlf_and_terminal_newline_are_canonicalized`, `provider_managed_dynamic_native_output_is_allowed`, `explicit_catalog_dynamic_native_output_is_allowed`, `narrowly_declarative_bash_payload_is_static_without_dynamic_trust`, `ambient_evasive_function_body_requires_dynamic_trust`, `ambient_dynamic_native_output_requires_explicit_trust`, `ambient_dynamic_policy_rejection_never_falls_back_to_help`, `ambient_dynamic_native_output_is_allowed_with_explicit_trust`, `completion_dynamic_trust_survives_runtime_config_parsing`, `path_completion_merge_marks_new_tool_as_ambient`, `shell_syntax_failure_rejects_native_output`, `bounded_runner_uses_exact_executable_direct_argv_closed_stdin_and_controlled_environment`, `native_probe_timeout_is_bounded`, `native_total_deadline_bounds_all_attempts`, `native_attempt_budget_bounds_protocol_search`, `native_stdout_and_stderr_limits_are_enforced`, `native_probe_timeout_terminates_descendants`, `mutating_install_completion_forms_are_never_invoked`, `valid_native_completion_stops_before_richer_help`, and `second_unchanged_run_performs_zero_probes_and_zero_managed_root_mutation`.

## Runtime acceptance

Use controlled fixture executables for all five shells and confirm the recorded recipe, registration, normalized bytes, and static or dynamic classification. Confirm PowerShell probes try both powershell and pwsh spellings, a remembered recipe precedes catalog and generic discovery, and a valid native artifact leaves a help marker untouched. Exercise an ambient dynamic fixture with and without explicit trust, then exceed timeout, total deadline, attempt count, stdout, and stderr limits while confirming descendant processes do not survive. Repeat an unchanged catalog sync and confirm no fixture probe runs and neither the managed root nor legacy overlay changes before marking this record accepted.

## Supersession conditions

Supersede this record if native generation moves to another authority, the protocol registry requires a backward-incompatible recipe identity, process execution adopts a different bounded-runner contract, dynamic trust becomes capability-based rather than source-based, registration or syntax validation becomes a versioned public interface, or five-shell provider publication changes the planner's current shell-neutral boundary.
