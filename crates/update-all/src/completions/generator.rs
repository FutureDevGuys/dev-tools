use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::native::{
    plan_native_completion, NativeCandidateOrigin, NativeCompletionRequest, NativePlannerOutcome,
    NativeProbeSession, NativeRecipeMemo,
};
use super::registry::{
    RegistryBundledCompletion, RegistryCommandCandidate, RegistryCompletionRecipe,
};
use super::{CompletionArtifactClassification, CompletionShell};
use crate::util::process::which;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompletionCommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CompletionCommandPlan {
    pub command: CompletionCommandSpec,
    pub selection_probe_args: Vec<String>,
}

pub(super) struct CompletionGenerationRequest<'a> {
    pub provider: &'a str,
    pub tool: &'a str,
    pub shell: CompletionShell,
    pub rc_root: &'a Path,
    pub command: &'a CompletionCommandSpec,
    pub provider_bin_dir: &'a Path,
    pub bundled_completions: &'a [RegistryBundledCompletion],
    pub catalog_recipes: &'a [RegistryCompletionRecipe],
    pub previous_recipe: Option<&'a NativeRecipeMemo>,
    pub origin: NativeCandidateOrigin,
    pub trust_dynamic: bool,
}

pub(super) struct GeneratedCompletion {
    pub path: PathBuf,
    pub changed: bool,
    pub classification: CompletionArtifactClassification,
    pub native_recipe: Option<NativeRecipeMemo>,
}

pub(super) fn completion_command_plans(
    provider: &str,
    tool: &str,
    provider_bin_dir: &Path,
    command: Option<&str>,
    command_candidates: &[RegistryCommandCandidate],
) -> Vec<CompletionCommandPlan> {
    resolve_command_plans(
        provider,
        tool,
        provider_bin_dir,
        command,
        command_candidates,
    )
}

pub(super) fn select_completion_command_plan(
    plans: &[CompletionCommandPlan],
    session: &mut NativeProbeSession,
) -> std::result::Result<Option<CompletionCommandPlan>, String> {
    for (index, plan) in plans.iter().enumerate() {
        if plan.selection_probe_args.is_empty() {
            return Ok(Some(plan.clone()));
        }
        let output = session.run_process(
            &plan.command,
            &plan.selection_probe_args,
            &BTreeMap::new(),
            &format!("command-selection-{index}"),
        )?;
        if output.success {
            return Ok(Some(plan.clone()));
        }
    }
    Ok(None)
}

pub(super) fn generate_tool_completion(
    request: CompletionGenerationRequest<'_>,
    session: &mut NativeProbeSession,
) -> std::result::Result<Option<GeneratedCompletion>, String> {
    static VALID_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    let valid_re = VALID_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]*$"));
    let valid_re = valid_re
        .as_ref()
        .map_err(|_| "internal_error: completion validator failed to initialize".to_string())?;
    if !valid_re.is_match(request.tool) || !valid_re.is_match(request.provider) {
        return Err("invalid_identifier".to_string());
    }

    let (bytes, classification, native_recipe) = match plan_native_completion(
        NativeCompletionRequest {
            shell: request.shell,
            command_name: request.tool,
            command: request.command,
            provider_bin_dir: request.provider_bin_dir,
            bundled_completions: request.bundled_completions,
            catalog_recipes: request.catalog_recipes,
            previous_recipe: request.previous_recipe,
            origin: request.origin,
            trust_dynamic: request.trust_dynamic,
        },
        session,
    )? {
        NativePlannerOutcome::Completion(completion) => (
            completion.bytes,
            completion.classification,
            Some(completion.recipe),
        ),
        NativePlannerOutcome::NotFound {
            root_help,
            diagnostics,
        } if request.shell == CompletionShell::Zsh => {
            if let Some(fallback) = generate_help_fallback_completion(
                request.tool,
                request.command,
                session,
                root_help,
            )? {
                (
                    fallback.into_bytes(),
                    CompletionArtifactClassification::Static,
                    None,
                )
            } else if diagnostics.is_empty() {
                return Ok(None);
            } else {
                return Err(format!("native_output_rejected:{}", diagnostics.summary()));
            }
        }
        NativePlannerOutcome::NotFound { diagnostics, .. } => {
            if diagnostics.is_empty() {
                return Ok(None);
            }
            return Err(format!("native_output_rejected:{}", diagnostics.summary()));
        }
    };

    let managed_dir = request.rc_root.join("shell").join("completions");
    let managed_path = managed_dir.join(format!("_managed_{}_{}", request.provider, request.tool));
    fs::create_dir_all(&managed_dir).map_err(|error| error.to_string())?;
    let changed =
        write_bytes_if_changed(&managed_path, &bytes).map_err(|error| error.to_string())?;
    Ok(Some(GeneratedCompletion {
        path: managed_path,
        changed,
        classification,
        native_recipe,
    }))
}

pub(super) fn write_bytes_if_changed(path: &Path, content: &[u8]) -> io::Result<bool> {
    if let Ok(existing) = fs::read(path) {
        if existing == content {
            return Ok(false);
        }
    }

    fs::write(path, content)?;
    Ok(true)
}

fn generate_help_fallback_completion(
    tool: &str,
    command_spec: &CompletionCommandSpec,
    session: &mut NativeProbeSession,
    root_help: Option<String>,
) -> std::result::Result<Option<String>, String> {
    let max_depth = env::var("UPDATE_ALL_COMPLETION_HELP_DEPTH")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(4);
    let max_probes = env::var("UPDATE_ALL_COMPLETION_HELP_PROBE_LIMIT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(32)
        .max(1);
    let mut visited = HashSet::new();
    let mut probe_budget = HelpProbeBudget::new(max_probes);
    let root = probe_help_node(
        command_spec,
        Vec::new(),
        session,
        max_depth,
        &mut visited,
        &mut probe_budget,
        root_help.as_deref(),
    )?;
    Ok(root.map(|node| build_help_completion_payload(tool, &node)))
}

fn build_help_completion_payload(tool: &str, root: &HelpNode) -> String {
    let function_name = format!("_{}", tool.replace('-', "_"));
    let mut payload = String::new();
    payload.push_str(&format!("#compdef {tool}\n\n"));
    payload.push_str(&format!("{function_name}() {{\n"));
    payload.push_str("  local context state line\n");
    payload.push_str("  typeset -A opt_args\n");
    payload.push_str("  local node_path='root'\n");
    payload.push_str("  local depth=0\n");
    payload.push_str("  local idx=2\n");
    payload.push_str("  while (( idx < CURRENT )); do\n");
    payload.push_str("    local word=\"${words[idx]}\"\n");
    payload.push_str("    [[ \"$word\" == -* ]] && { ((idx++)); continue; }\n");
    payload.push_str("    case \"$node_path:$word\" in\n");
    append_transition_cases(&mut payload, root);
    payload.push_str("      *)\n");
    payload.push_str("        break\n");
    payload.push_str("        ;;\n");
    payload.push_str("    esac\n");
    payload.push_str("    ((idx++))\n");
    payload.push_str("  done\n");
    payload.push_str("  local -a rebased_words\n");
    payload.push_str("  rebased_words=(\"${words[1]}\" \"${(@)words[@]:$((depth + 2))}\")\n");
    payload.push_str("  local rebased_current=$(( CURRENT - depth ))\n");
    payload.push_str("  (( rebased_current < 2 )) && rebased_current=2\n");
    payload.push_str("  local -a words\n");
    payload.push_str("  local CURRENT\n");
    payload.push_str("  words=(\"${rebased_words[@]}\")\n");
    payload.push_str("  CURRENT=$rebased_current\n");
    payload.push_str("  case \"$node_path\" in\n");
    append_node_cases(&mut payload, tool, root);
    payload.push_str("  esac\n");
    payload.push_str("}\n\n");
    payload.push_str(&format!("{function_name} \"$@\"\n"));
    payload
}

fn probe_help_node(
    command_spec: &CompletionCommandSpec,
    path_args: Vec<String>,
    session: &mut NativeProbeSession,
    depth_left: usize,
    visited: &mut HashSet<String>,
    probe_budget: &mut HelpProbeBudget,
    preloaded_help: Option<&str>,
) -> std::result::Result<Option<HelpNode>, String> {
    let path_key = path_args.join("\x1f");
    if !visited.insert(path_key) {
        return Ok(None);
    }
    if !probe_budget.take() {
        return Ok(None);
    }

    let merged = if let Some(preloaded_help) = preloaded_help {
        preloaded_help.to_string()
    } else {
        let mut probe_args = path_args.clone();
        probe_args.push("--help".to_string());
        let help_probe =
            session.run_process(command_spec, &probe_args, &BTreeMap::new(), "help_fallback")?;
        if !help_probe.success {
            return Ok(None);
        }

        let mut merged = String::from_utf8_lossy(&help_probe.stdout).to_string();
        let stderr = String::from_utf8_lossy(&help_probe.stderr);
        if !stderr.trim().is_empty() {
            if !merged.is_empty() {
                merged.push('\n');
            }
            merged.push_str(&stderr);
        }
        merged
    };

    let stripped = strip_ansi(&merged);
    let command_rows = parse_help_command_rows(&stripped);
    let options = parse_help_options(&stripped);
    let section_options = parse_help_option_sections(&stripped);
    if command_rows.is_empty() && options.is_empty() {
        return Ok(None);
    }

    let mut resolved_commands = Vec::new();
    for row in command_rows {
        let normalized_names = row
            .names
            .iter()
            .map(|value| normalize_help_section_name(value))
            .collect::<Vec<_>>();
        for name in &row.names {
            let mut child_path = path_args.clone();
            child_path.push(name.clone());
            let mut child = if depth_left > 0 {
                probe_help_node(
                    command_spec,
                    child_path.clone(),
                    session,
                    depth_left.saturating_sub(1),
                    visited,
                    probe_budget,
                    None,
                )?
                .map(Box::new)
            } else {
                None
            };
            if child.is_none() {
                if let Some(child_options) = normalized_names
                    .iter()
                    .find_map(|normalized| section_options.get(normalized))
                {
                    child = Some(Box::new(HelpNode {
                        path: child_path,
                        commands: Vec::new(),
                        options: child_options.clone(),
                    }));
                }
            }
            resolved_commands.push(HelpCommand {
                name: name.clone(),
                description: row.description.clone(),
                child,
            });
        }
    }

    Ok(Some(HelpNode {
        path: path_args,
        commands: resolved_commands,
        options,
    }))
}

fn append_transition_cases(payload: &mut String, node: &HelpNode) {
    for command in &node.commands {
        if node.path.iter().any(|part| part == &command.name) {
            continue;
        }
        let parent_key = help_node_key(&node.path);
        let child_key = help_child_key(&node.path, &command.name);
        payload.push_str(&format!(
            "      '{}:{}')\n        node_path='{}'\n        depth=$((depth + 1))\n        ;;\n",
            zsh_single_quote(&parent_key),
            zsh_single_quote(&command.name),
            zsh_single_quote(&child_key),
        ));
        if let Some(child) = command.child.as_ref() {
            append_transition_cases(payload, child);
        }
    }
}

fn append_node_cases(payload: &mut String, tool: &str, node: &HelpNode) {
    append_single_node_case(payload, tool, node);
    for command in &node.commands {
        if node.path.iter().any(|part| part == &command.name) {
            continue;
        }
        if let Some(child) = command.child.as_ref() {
            append_node_cases(payload, tool, child);
        } else {
            append_empty_leaf_case(payload, &node.path, &command.name);
        }
    }
}

fn append_single_node_case(payload: &mut String, tool: &str, node: &HelpNode) {
    let node_key = help_node_key(&node.path);
    let commands = node
        .commands
        .iter()
        .filter(|command| !node.path.iter().any(|part| part == &command.name))
        .map(|command| (command.name.as_str(), command.description.as_str()))
        .collect::<Vec<_>>();
    payload.push_str(&format!("    '{}')\n", zsh_single_quote(&node_key)));
    if !commands.is_empty() {
        payload.push_str("      local -a commands\n");
        payload.push_str("      commands=(\n");
        for (name, description) in &commands {
            payload.push_str(&format!(
                "        '{}:{}'\n",
                zsh_single_quote(name),
                zsh_single_quote(description)
            ));
        }
        payload.push_str("      )\n");
    }
    payload.push_str("      _arguments -s -C \\\n");
    for option in &node.options {
        payload.push_str("        ");
        payload.push_str(&render_option_spec(option));
        payload.push_str(" \\\n");
    }
    if !commands.is_empty() {
        payload.push_str("        '1:command:->command' \\\n");
        payload.push_str("        '*::args:->args'\n");
        payload.push_str("      case \"$state\" in\n");
        payload.push_str("        command)\n");
        payload.push_str(&format!(
            "          _describe -t {}-commands '{} command' commands\n",
            tool, tool
        ));
        payload.push_str("          return\n");
        payload.push_str("          ;;\n");
        payload.push_str("        args)\n");
        payload.push_str("          _files\n");
        payload.push_str("          return\n");
        payload.push_str("          ;;\n");
        payload.push_str("      esac\n");
    } else {
        payload.push_str("        '*::args:_files'\n");
    }
    payload.push_str("      return\n");
    payload.push_str("      ;;\n");
}

fn append_empty_leaf_case(payload: &mut String, parent_path: &[String], command: &str) {
    let node_key = help_child_key(parent_path, command);
    payload.push_str(&format!(
        "    '{}')\n      _arguments -s -C '*::args:_files'\n      return\n      ;;\n",
        zsh_single_quote(&node_key)
    ));
}

fn help_node_key(path: &[String]) -> String {
    if path.is_empty() {
        "root".to_string()
    } else {
        path.join("__")
    }
}

fn help_child_key(path: &[String], child: &str) -> String {
    if path.is_empty() {
        child.to_string()
    } else {
        format!("{}__{}", path.join("__"), child)
    }
}

fn parse_help_commands(help_text: &str) -> Vec<(String, String)> {
    let mut commands = Vec::new();
    for row in parse_help_command_rows(help_text) {
        for name in row.names {
            push_unique_entry(&mut commands, name, row.description.clone());
        }
    }
    commands
}

fn parse_help_command_rows(help_text: &str) -> Vec<HelpCommandRow> {
    let mut commands = Vec::new();
    let mut in_command_section = false;
    let mut pending: Option<(Vec<String>, usize)> = None;
    for line in help_text.lines() {
        let trimmed = line.trim();
        if parse_help_section_heading(trimmed).is_some() {
            pending = None;
            in_command_section = is_help_command_section(trimmed);
            continue;
        }
        if !in_command_section {
            continue;
        }
        if trimmed.is_empty()
            || trimmed.starts_with('-')
            || trimmed.starts_with('$')
            || trimmed.starts_with("http")
        {
            pending = None;
            continue;
        }
        let indent = leading_whitespace_count(line);
        if let Some((pending_names, pending_indent)) = pending.take() {
            if indent > pending_indent {
                commands.push(HelpCommandRow {
                    names: pending_names,
                    description: trimmed.to_string(),
                });
                continue;
            }
            pending = Some((pending_names, pending_indent));
        }
        let Some((left, description)) = split_help_columns(line) else {
            if let Some((pending_names, pending_indent)) = pending.take() {
                if indent > pending_indent {
                    commands.push(HelpCommandRow {
                        names: pending_names,
                        description: trimmed.to_string(),
                    });
                    continue;
                }
            }
            let names = extract_help_command_names(trimmed);
            if !names.is_empty() {
                pending = Some((names, indent));
            }
            continue;
        };
        if description.is_empty() {
            continue;
        }
        pending = None;
        let names = extract_help_command_names(&left);
        if names.is_empty() {
            continue;
        }
        commands.push(HelpCommandRow {
            names,
            description: description.to_string(),
        });
    }
    commands
}

fn parse_help_options(help_text: &str) -> Vec<HelpOption> {
    let mut options = Vec::new();
    for line in help_text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('-') {
            continue;
        }
        let Some((left, description)) = split_help_columns(line) else {
            continue;
        };
        let mut shorts = Vec::new();
        let mut longs = Vec::new();
        for token in left.split(',').map(str::trim) {
            let token = token.split_whitespace().next().unwrap_or("");
            if token.starts_with("--") {
                longs.push(token.to_string());
            } else if token.starts_with('-') {
                shorts.push(token.to_string());
            }
        }
        if shorts.is_empty() && longs.is_empty() {
            continue;
        }
        push_unique_option(
            &mut options,
            HelpOption {
                shorts,
                longs,
                description: description.to_string(),
            },
        );
    }
    options
}

fn parse_help_option_sections(help_text: &str) -> BTreeMap<String, Vec<HelpOption>> {
    let mut sections = BTreeMap::new();
    let mut active_section: Option<String> = None;

    for line in help_text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(section_name) = parse_help_option_section_heading(trimmed) {
            active_section = Some(section_name);
            continue;
        }
        if parse_help_section_heading(trimmed).is_some() {
            active_section = None;
            continue;
        }
        if !trimmed.starts_with('-') {
            continue;
        }
        let Some((left, description)) = split_help_columns(line) else {
            continue;
        };
        let Some(section) = active_section.as_ref() else {
            continue;
        };
        let mut shorts = Vec::new();
        let mut longs = Vec::new();
        for token in left.split(',').map(str::trim) {
            let token = token.split_whitespace().next().unwrap_or("");
            if token.starts_with("--") {
                longs.push(token.to_string());
            } else if token.starts_with('-') {
                shorts.push(token.to_string());
            }
        }
        if shorts.is_empty() && longs.is_empty() {
            continue;
        }
        let entry = sections.entry(section.clone()).or_insert_with(Vec::new);
        push_unique_option(
            entry,
            HelpOption {
                shorts,
                longs,
                description: description.to_string(),
            },
        );
    }

    sections
}

fn parse_help_option_section_heading(line: &str) -> Option<String> {
    let heading = parse_help_section_heading(line)?;
    let section_name = heading.strip_suffix(" Options")?;
    let normalized = normalize_help_section_name(section_name);
    if normalized.is_empty() || normalized == "options" {
        return None;
    }
    Some(normalized)
}

fn parse_help_section_heading(line: &str) -> Option<&str> {
    let heading = line.strip_suffix(':')?.trim();
    if heading.is_empty() || heading.len() > 64 {
        return None;
    }
    if !heading
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch.is_ascii_whitespace() || ch == '-')
    {
        return None;
    }
    Some(heading)
}

fn normalize_help_section_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn is_help_command_section(line: &str) -> bool {
    let Some(heading) = parse_help_section_heading(line) else {
        return false;
    };
    let heading = heading.to_ascii_lowercase();
    matches!(heading.as_str(), "commands" | "updates" | "project")
        || heading.starts_with("manage ")
        || (!matches!(
            heading.as_str(),
            "usage" | "options" | "arguments" | "examples" | "description"
        ) && !heading.ends_with(" options"))
}

fn split_help_columns(line: &str) -> Option<(String, String)> {
    static COL_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    let col_re = COL_RE.get_or_init(|| Regex::new(r"^\s*(.+?)\s{2,}(.+?)\s*$"));
    let col_re = col_re.as_ref().ok()?;
    let caps = col_re.captures(line)?;
    let left = caps.get(1)?.as_str().trim().to_string();
    let right = caps.get(2)?.as_str().trim().to_string();
    Some((left, right))
}

fn leading_whitespace_count(line: &str) -> usize {
    line.chars().take_while(|ch| ch.is_whitespace()).count()
}

fn extract_help_command_names(left: &str) -> Vec<String> {
    let mut names = Vec::new();
    for raw_name in left.split(',') {
        let Some(name) = raw_name.split_whitespace().next() else {
            continue;
        };
        let name = name.trim_matches(|ch| matches!(ch, '`' | '[' | ']'));
        if !is_help_command_name(name) {
            continue;
        }
        if !names.iter().any(|existing| existing == name) {
            names.push(name.to_string());
        }
    }
    names
}

fn strip_ansi(input: &str) -> String {
    static ANSI_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    let ansi_re = ANSI_RE.get_or_init(|| Regex::new(r"\x1B\[[0-9;]*[A-Za-z]"));
    let Ok(ansi_re) = ansi_re else {
        return input.to_string();
    };
    ansi_re.replace_all(input, "").to_string()
}

fn extract_flags_from_text(input: &str) -> BTreeSet<String> {
    static LONG_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    static SHORT_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    let long_re = match LONG_RE
        .get_or_init(|| Regex::new(r"(?:^|[^A-Za-z0-9_])(--[A-Za-z0-9][A-Za-z0-9-]*)"))
    {
        Ok(value) => value,
        Err(_) => return BTreeSet::new(),
    };
    let short_re = match SHORT_RE
        .get_or_init(|| Regex::new(r"(?:^|[^A-Za-z0-9_])(-[A-Za-z])(?:$|[^A-Za-z0-9-])"))
    {
        Ok(value) => value,
        Err(_) => return BTreeSet::new(),
    };

    let mut flags = BTreeSet::new();
    for capture in long_re.captures_iter(input) {
        if let Some(name) = capture.get(1) {
            flags.insert(name.as_str().to_string());
        }
    }
    for capture in short_re.captures_iter(input) {
        if let Some(name) = capture.get(1) {
            flags.insert(name.as_str().to_string());
        }
    }
    flags
}

fn is_help_command_name(name: &str) -> bool {
    name.chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_'))
}

fn zsh_single_quote(value: &str) -> String {
    value.replace('\'', "'\\''")
}

fn render_option_spec(option: &HelpOption) -> String {
    let desc = zsh_single_quote(&option.description);
    match (option.shorts.first(), option.longs.first()) {
        (Some(short), Some(long)) => {
            format!("'({} {})'{{{},{}}}'[{}]'", short, long, short, long, desc)
        }
        (Some(short), None) => format!("'{}[{}]'", short, desc),
        (None, Some(long)) => format!("'{}[{}]'", long, desc),
        (None, None) => "'*::args:_files'".to_string(),
    }
}

fn resolve_command_plans(
    provider: &str,
    tool: &str,
    provider_bin_dir: &Path,
    command: Option<&str>,
    command_candidates: &[RegistryCommandCandidate],
) -> Vec<CompletionCommandPlan> {
    if let Some(command) = command.and_then(resolve_configured_command) {
        return vec![CompletionCommandPlan {
            command,
            selection_probe_args: Vec::new(),
        }];
    }

    if provider == "npm" {
        if let Some(command) = resolve_npm_exec_path(provider_bin_dir, tool)
            .or_else(|| which(tool))
            .map(|path| CompletionCommandSpec {
                program: path,
                args: Vec::new(),
            })
        {
            return vec![CompletionCommandPlan {
                command,
                selection_probe_args: Vec::new(),
            }];
        }
        return resolve_command_candidates(command_candidates);
    }

    if provider == "path" {
        if let Some(command) = which(tool).map(|path| CompletionCommandSpec {
            program: path,
            args: Vec::new(),
        }) {
            return vec![CompletionCommandPlan {
                command,
                selection_probe_args: Vec::new(),
            }];
        }
        return resolve_command_candidates(command_candidates);
    }

    let candidates = resolve_command_candidates(command_candidates);
    if !candidates.is_empty() {
        return candidates;
    }

    which(tool)
        .map(|program| CompletionCommandPlan {
            command: CompletionCommandSpec {
                program,
                args: Vec::new(),
            },
            selection_probe_args: Vec::new(),
        })
        .into_iter()
        .collect()
}

fn resolve_configured_command(program: &str) -> Option<CompletionCommandSpec> {
    let program = program.trim();
    if program.is_empty() {
        return None;
    }
    Some(CompletionCommandSpec {
        program: resolve_existing_program(program)?,
        args: Vec::new(),
    })
}

fn resolve_command_candidates(
    candidates: &[RegistryCommandCandidate],
) -> Vec<CompletionCommandPlan> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let program = resolve_existing_program(candidate.program.trim())?;
            Some(CompletionCommandPlan {
                command: CompletionCommandSpec {
                    program,
                    args: candidate.args.clone(),
                },
                selection_probe_args: candidate.probe_args.clone(),
            })
        })
        .collect()
}

fn resolve_existing_program(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    let path = Path::new(program);
    if path.components().count() > 1 || path.is_absolute() {
        return path.is_file().then(|| path.to_path_buf());
    }
    which(program)
}

struct HelpProbeBudget {
    remaining: usize,
}

impl HelpProbeBudget {
    fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    fn take(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HelpOption {
    shorts: Vec<String>,
    longs: Vec<String>,
    description: String,
}

#[derive(Clone, Debug)]
struct HelpNode {
    path: Vec<String>,
    commands: Vec<HelpCommand>,
    options: Vec<HelpOption>,
}

#[derive(Clone, Debug)]
struct HelpCommand {
    name: String,
    description: String,
    child: Option<Box<HelpNode>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HelpCommandRow {
    names: Vec<String>,
    description: String,
}

fn push_unique_entry(entries: &mut Vec<(String, String)>, name: String, description: String) {
    if entries.iter().any(|(existing, _)| existing == &name) {
        return;
    }
    entries.push((name, description));
}

fn push_unique_option(options: &mut Vec<HelpOption>, option: HelpOption) {
    if options.iter().any(|existing| {
        existing.shorts == option.shorts
            && existing.longs == option.longs
            && existing.description == option.description
    }) {
        return;
    }
    options.push(option);
}

fn resolve_npm_exec_path(npm_bin_dir: &Path, tool: &str) -> Option<PathBuf> {
    let candidates = [
        tool.to_string(),
        format!("{tool}.cmd"),
        format!("{tool}.ps1"),
        format!("{tool}.exe"),
        format!("{tool}.bat"),
    ];
    for candidate in candidates {
        let path = npm_bin_dir.join(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_help_command_rows_ignores_non_command_sections() {
        let help = r#"
Usage: example [command]

Arguments:
  package    Package to install

Commands:
  add        Add a package
  list, ls   List packages

Examples:
  example add foo
"#;

        let rows = parse_help_command_rows(help);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].names, vec!["add"]);
        assert_eq!(rows[1].names, vec!["list", "ls"]);
    }

    #[test]
    fn parse_help_command_rows_accepts_generic_manage_sections() {
        let help = r#"
Usage: pluggy [command]

Manage plugins:
  install    Install a plugin
  remove, rm  Remove a plugin

Options:
  --help     Show help
"#;

        let rows = parse_help_command_rows(help);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].names, vec!["install"]);
        assert_eq!(rows[1].names, vec!["remove", "rm"]);
    }

    #[test]
    fn parse_help_command_rows_keeps_wrapped_descriptions_out_of_commands() {
        let help = r#"
Usage: just [OPTIONS] [ARGUMENTS]...

Options:
      --ceiling <CEILING>
          Do not ascend above <CEILING> directory when searching for a justfile. [env:
          JUST_CEILING=]
      --indentation <INDENTATION>
          Indent recipes bodies with <INDENTATION> [env: JUST_INDENTATION=] [default: "    "]
      --list-prefix <TEXT>
          Print <TEXT> before each list item [env: JUST_LIST_PREFIX=] [default: "    "]

Commands:
      --changelog             Print changelog
      --choose                Select one or more recipes to run using a binary chooser. If
                              `--chooser` is not passed the chooser defaults to fzf
  -c, --command <COMMAND>...  Run an arbitrary command
      --completions <SHELL>   Print shell completion script for <SHELL>
"#;

        let rows = parse_help_command_rows(help);
        assert!(rows.is_empty(), "{rows:#?}");
    }

    #[test]
    fn parse_help_command_rows_accepts_continuation_descriptions() {
        let help = r#"
Usage: skills <command> [options]

Manage Skills:
  add <package>        Add a skill package
  use <package>@<skill>
                       Generate a prompt for using one skill without installing it
  list, ls             List installed skills
"#;

        let rows = parse_help_command_rows(help);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].names, vec!["add"]);
        assert_eq!(rows[1].names, vec!["use"]);
        assert_eq!(
            rows[1].description,
            "Generate a prompt for using one skill without installing it"
        );
        assert_eq!(rows[2].names, vec!["list", "ls"]);
    }

    #[test]
    fn build_help_completion_payload_skips_recursive_child_command_loops() {
        let child = Box::new(HelpNode {
            path: vec!["config".to_string()],
            commands: vec![HelpCommand {
                name: "config".to_string(),
                description: "Manage configuration".to_string(),
                child: Some(Box::new(HelpNode {
                    path: vec!["config".to_string(), "config".to_string()],
                    commands: Vec::new(),
                    options: Vec::new(),
                })),
            }],
            options: Vec::new(),
        });
        let root = HelpNode {
            path: Vec::new(),
            commands: vec![HelpCommand {
                name: "config".to_string(),
                description: "Manage configuration".to_string(),
                child: Some(child),
            }],
            options: Vec::new(),
        };

        let payload = build_help_completion_payload("pnpm", &root);
        assert!(payload.contains("'root:config'"));
        assert!(!payload.contains("'config:config'"), "{payload}");
        assert!(!payload.contains("'config__config'"), "{payload}");
    }

    #[test]
    fn parse_help_option_sections_normalizes_section_names() {
        let help = r#"
Add Options:
  -s, --source <name>    Select skill source

Experimental Sync Options:
  -a, --agent <name>     Filter agents
"#;

        let sections = parse_help_option_sections(help);
        assert!(sections.contains_key("add"));
        assert!(sections.contains_key("experimental_sync"));
        assert_eq!(sections["add"][0].longs, vec!["--source".to_string()]);
        assert_eq!(
            sections["experimental_sync"][0].longs,
            vec!["--agent".to_string()]
        );
    }

    #[test]
    fn build_help_completion_payload_inherits_section_options_for_aliases() {
        let root = HelpNode {
            path: Vec::new(),
            options: Vec::new(),
            commands: vec![
                HelpCommand {
                    name: "list".to_string(),
                    description: "List packages".to_string(),
                    child: Some(Box::new(HelpNode {
                        path: vec!["list".to_string()],
                        commands: Vec::new(),
                        options: vec![HelpOption {
                            shorts: vec!["-a".to_string()],
                            longs: vec!["--agent".to_string()],
                            description: "Filter by agent".to_string(),
                        }],
                    })),
                },
                HelpCommand {
                    name: "ls".to_string(),
                    description: "List packages".to_string(),
                    child: Some(Box::new(HelpNode {
                        path: vec!["ls".to_string()],
                        commands: Vec::new(),
                        options: vec![HelpOption {
                            shorts: vec!["-a".to_string()],
                            longs: vec!["--agent".to_string()],
                            description: "Filter by agent".to_string(),
                        }],
                    })),
                },
            ],
        };

        let payload = build_help_completion_payload("skills", &root);
        assert!(payload.contains("'list')"));
        assert!(payload.contains("'ls')"));
        assert!(payload.contains("'(-a --agent)'{-a,--agent}'[Filter by agent]'"));
    }
}
