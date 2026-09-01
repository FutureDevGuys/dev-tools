use regex::Regex;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env;
use std::fs;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::Duration;
use wait_timeout::ChildExt;

use crate::completions::registry::RegistryCommandCandidate;
use crate::util::process::{command_for_executable, resolve_executable, which};

const GENERATOR_PROBE_TIMEOUT: &str = "generator_probe_timeout";

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

pub(super) struct GeneratedCompletion {
    pub path: PathBuf,
    pub changed: bool,
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
) -> Option<CompletionCommandPlan> {
    plans.iter().find_map(|plan| {
        if plan.selection_probe_args.is_empty() {
            return Some(plan.clone());
        }
        let probe = run_probe(
            &plan.command,
            plan.selection_probe_args.iter().map(String::as_str),
            Duration::from_secs(5),
        )
        .ok()?;
        probe.success.then(|| plan.clone())
    })
}

pub(super) fn generate_tool_completion(
    provider: &str,
    tool: &str,
    rc_root: &Path,
    command_spec: &CompletionCommandSpec,
) -> std::result::Result<Option<GeneratedCompletion>, String> {
    static VALID_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    let valid_re = VALID_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]*$"));
    let valid_re = valid_re
        .as_ref()
        .map_err(|_| "internal_error: completion validator failed to initialize".to_string())?;
    if !valid_re.is_match(tool) {
        return Err("invalid_identifier".to_string());
    }

    let managed_dir = rc_root.join("shell").join("completions");
    let managed_path = managed_dir.join(format!("_managed_{provider}_{tool}"));

    let hard_timeout = env::var("UPDATE_ALL_COMPLETION_PROBE_HARD_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(15);

    let timeout = Duration::from_secs(hard_timeout);
    let output = select_completion_payload(tool, command_spec, timeout)?;
    let Some(output) = output else {
        return Ok(None);
    };

    fs::create_dir_all(&managed_dir).map_err(|e| e.to_string())?;
    let changed =
        write_bytes_if_changed(&managed_path, output.as_bytes()).map_err(|e| e.to_string())?;
    Ok(Some(GeneratedCompletion {
        path: managed_path,
        changed,
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

fn select_completion_payload(
    tool: &str,
    command_spec: &CompletionCommandSpec,
    timeout: Duration,
) -> std::result::Result<Option<String>, String> {
    let mut unsafe_native = false;
    let mut native_probe_timeout = false;
    let native = match probe_completion_generator(command_spec, timeout) {
        Ok(native) => native,
        Err(e) if e == GENERATOR_PROBE_TIMEOUT => {
            native_probe_timeout = true;
            String::new()
        }
        Err(e) => return Err(e),
    };
    let native = if native.trim().is_empty() {
        None
    } else if !native.contains("#compdef") {
        None
    } else if is_unsafe_completion_payload(&native) {
        unsafe_native = true;
        None
    } else {
        Some(native)
    };

    if let Some(native) = native {
        let native_needs_fallback =
            native_payload_missing_help_flags(command_spec, &native, timeout).unwrap_or(false);
        if !native_needs_fallback {
            return Ok(Some(native));
        }
        return match generate_help_fallback_completion(tool, command_spec, timeout) {
            Ok(Some(fallback)) => Ok(Some(fallback)),
            Ok(None) | Err(_) => Ok(Some(native)),
        };
    }

    match generate_help_fallback_completion(tool, command_spec, timeout)? {
        Some(fallback) => Ok(Some(fallback)),
        None if unsafe_native => Err("unsafe_output".to_string()),
        None if native_probe_timeout => Err(GENERATOR_PROBE_TIMEOUT.to_string()),
        None => Ok(None),
    }
}

fn is_unsafe_completion_payload(payload: &str) -> bool {
    static UNSAFE_RE: OnceLock<std::result::Result<Regex, regex::Error>> = OnceLock::new();
    let unsafe_re = UNSAFE_RE.get_or_init(|| {
        Regex::new(
            r#"(?mx)
(?:^|[;\n])\s*eval(?:\s|["'])    # eval with whitespace or quoted arg
|(?:^|[;\n])\s*(?:source|\.)\s+   # source or dot command invocation
"#,
        )
    });
    let Ok(unsafe_re) = unsafe_re else {
        return true;
    };
    unsafe_re.is_match(payload) || contains_executable_substitution(payload)
}

fn contains_executable_substitution(payload: &str) -> bool {
    let mut in_single_quote = false;
    let mut escaped = false;

    for (idx, ch) in payload.char_indices() {
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            }
            continue;
        }

        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '\'' => in_single_quote = true,
            '`' => return true,
            '$' => {
                let after = idx + ch.len_utf8();
                if payload[after..].starts_with('(')
                    && !payload[after + '('.len_utf8()..].starts_with('(')
                {
                    return true;
                }
            }
            _ => {}
        }
    }

    false
}

fn probe_completion_generator(
    command_spec: &CompletionCommandSpec,
    timeout: Duration,
) -> std::result::Result<String, String> {
    let patterns: &[&[&str]] = &[
        &["completion", "zsh"],
        &["completion", "--shell", "zsh"],
        &["completions", "zsh"],
        &["--completions", "zsh"],
    ];

    for argv in patterns {
        let probe = run_probe(command_spec, argv.iter().copied(), timeout)?;
        if probe.success {
            if let Some(out) = native_completion_payload(&probe.stdout) {
                return Ok(out);
            }
        }
    }

    Ok(String::new())
}

fn native_completion_payload(stdout: &[u8]) -> Option<String> {
    let output = String::from_utf8_lossy(stdout).to_string();
    let mut offset = 0usize;
    for line in output.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#compdef") {
            let leading = line.len().saturating_sub(trimmed.len());
            return Some(output[offset + leading..].to_string());
        }
        offset += line.len();
    }
    None
}

fn generate_help_fallback_completion(
    tool: &str,
    command_spec: &CompletionCommandSpec,
    timeout: Duration,
) -> std::result::Result<Option<String>, String> {
    let max_depth = env::var("UPDATE_ALL_COMPLETION_HELP_DEPTH")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4);
    let max_probes = env::var("UPDATE_ALL_COMPLETION_HELP_PROBE_LIMIT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32)
        .max(1);
    let mut visited = HashSet::new();
    let mut probe_budget = HelpProbeBudget::new(max_probes);
    let root = probe_help_node(
        command_spec,
        Vec::new(),
        timeout,
        max_depth,
        &mut visited,
        &mut probe_budget,
    )?;
    Ok(root.map(|node| build_help_completion_payload(tool, &node)))
}

fn native_payload_missing_help_flags(
    command_spec: &CompletionCommandSpec,
    payload: &str,
    timeout: Duration,
) -> std::result::Result<bool, String> {
    let help_probe = run_probe(command_spec, ["--help"], timeout)?;
    if !help_probe.success {
        return Ok(false);
    }

    let mut help_text = String::from_utf8_lossy(&help_probe.stdout).to_string();
    let stderr = String::from_utf8_lossy(&help_probe.stderr);
    if !stderr.trim().is_empty() {
        if !help_text.is_empty() {
            help_text.push('\n');
        }
        help_text.push_str(&stderr);
    }

    let help_flags = extract_flags_from_text(&strip_ansi(&help_text));
    if help_flags.is_empty() {
        return Ok(false);
    }
    let completion_flags = extract_flags_from_text(payload);
    Ok(help_flags
        .iter()
        .any(|flag| !completion_flags.contains(flag)))
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
    timeout: Duration,
    depth_left: usize,
    visited: &mut HashSet<String>,
    probe_budget: &mut HelpProbeBudget,
) -> std::result::Result<Option<HelpNode>, String> {
    let path_key = path_args.join("\x1f");
    if !visited.insert(path_key) {
        return Ok(None);
    }
    if !probe_budget.take() {
        return Ok(None);
    }

    let mut probe_args = path_args.clone();
    probe_args.push("--help".to_string());
    let help_probe = run_probe(command_spec, probe_args.iter().map(String::as_str), timeout)?;
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
                    timeout,
                    depth_left.saturating_sub(1),
                    visited,
                    probe_budget,
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

struct ProbeOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
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

fn run_probe<I, S>(
    command_spec: &CompletionCommandSpec,
    args: I,
    timeout: Duration,
) -> std::result::Result<ProbeOutput, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let resolved_program = command_spec
        .program
        .to_str()
        .map(resolve_executable)
        .unwrap_or_else(|| command_spec.program.clone());
    let mut cmd = command_for_executable(&resolved_program);
    cmd.args(command_spec.args.iter().map(String::as_str));
    cmd.args(args.into_iter().map(|arg| arg.as_ref().to_string()));
    cmd.current_dir(std::env::temp_dir());
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }

    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let mut stdout_reader = child.stdout.take().map(read_pipe_thread);
    let mut stderr_reader = child.stderr.take().map(read_pipe_thread);

    let status = match child.wait_timeout(timeout).map_err(|e| e.to_string())? {
        Some(status) => status,
        None => {
            crate::util::process::terminate_process_group(child.id());
            #[cfg(not(unix))]
            {
                let _ = child.kill();
            }
            let _ = child.wait();
            if let Some(handle) = stdout_reader.take() {
                let _ = handle.join();
            }
            if let Some(handle) = stderr_reader.take() {
                let _ = handle.join();
            }
            return Err(GENERATOR_PROBE_TIMEOUT.to_string());
        }
    };

    Ok(ProbeOutput {
        success: status.success(),
        stdout: stdout_reader
            .take()
            .map(join_pipe_reader)
            .unwrap_or_default(),
        stderr: stderr_reader
            .take()
            .map(join_pipe_reader)
            .unwrap_or_default(),
    })
}

fn read_pipe_thread<R: Read + Send + 'static>(mut reader: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = reader.read_to_end(&mut bytes);
        bytes
    })
}

fn join_pipe_reader(handle: JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
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
    fn unsafe_completion_payload_allows_arithmetic_expansion() {
        let payload = r#"#compdef arith
_arith() {
  local depth=$((CURRENT - 1))
  _arguments '--count[Use arithmetic state]'
}
"#;

        assert!(!is_unsafe_completion_payload(payload));
        assert!(is_unsafe_completion_payload(
            "#compdef dyn\n_dyn() { reply=($(dyn completion-server)); }\n"
        ));
    }

    #[test]
    fn unsafe_completion_payload_allows_quoted_description_substitution_tokens() {
        let payload = r#"#compdef docs
_docs() {
  _arguments '--save-dev[Save package to your `devDependencies`]' \
    '--manual[Run $(tool) yourself when needed]'
}
"#;

        assert!(!is_unsafe_completion_payload(payload));
        assert!(is_unsafe_completion_payload(
            "#compdef dyn\n_dyn() { reply=(`dyn completion-server`); }\n"
        ));
        assert!(is_unsafe_completion_payload(
            "#compdef dyn\n_dyn() { reply=(\"$(dyn completion-server)\"); }\n"
        ));
    }

    #[test]
    fn native_completion_payload_strips_leading_status_banner() {
        let payload = native_completion_payload(
            b"tool: config=/tmp/example.toml status=ready\n  #compdef tool\n_tool() {}\n",
        )
        .unwrap();

        assert_eq!(payload, "#compdef tool\n_tool() {}\n");
    }

    #[test]
    fn native_probe_timeout_uses_help_fallback_when_available() {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(windows)]
        let script = temp.path().join("sleepy.cmd");
        #[cfg(not(windows))]
        let script = temp.path().join("sleepy");
        std::fs::write(
            &script,
            #[cfg(windows)]
            r#"@echo off
if "%~1"=="completion" if "%~2"=="zsh" (
  powershell -NoProfile -Command "Start-Sleep -Milliseconds 500"
  exit /b 1
)
if "%~1"=="--help" (
  echo Usage: sleepy [options]
  echo.
  echo Options:
  echo   --alpha    Alpha mode
  exit /b 0
)
exit /b 1
"#,
            #[cfg(not(windows))]
            r#"#!/bin/sh
set -eu
if [ "${1:-}" = "completion" ] && [ "${2:-}" = "zsh" ]; then
  sleep 1
  exit 1
fi
if [ "${1:-}" = "--help" ]; then
  printf '%s\n' \
    'Usage: sleepy [options]' \
    '' \
    'Options:' \
    '  --alpha    Alpha mode'
  exit 0
fi
exit 1
"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let payload = select_completion_payload(
            "sleepy",
            &CompletionCommandSpec {
                program: script,
                args: Vec::new(),
            },
            Duration::from_millis(100),
        )
        .unwrap()
        .unwrap();

        assert!(payload.contains("#compdef sleepy"), "{payload}");
        assert!(payload.contains("--alpha"), "{payload}");
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

    #[test]
    fn native_payload_missing_help_flags_detects_drift() {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(windows)]
        let script = temp.path().join("flaggy.cmd");
        #[cfg(not(windows))]
        let script = temp.path().join("flaggy");
        std::fs::write(
            &script,
            #[cfg(windows)]
            r#"@echo off
if "%~1"=="--help" (
  echo Usage: flaggy [options]
  echo.
  echo Options:
  echo   --alpha    Alpha mode
  echo   --beta     Beta mode
  exit /b 0
)
if "%~1"=="completion" if "%~2"=="zsh" (
  echo #compdef flaggy
  echo _flaggy^(^) {
  echo   _arguments '--alpha[Alpha mode]'
  echo }
  exit /b 0
)
exit /b 1
"#,
            #[cfg(not(windows))]
            r#"#!/bin/sh
set -eu
if [ "${1:-}" = "--help" ]; then
  printf '%s\n' \
    'Usage: flaggy [options]' \
    '' \
    'Options:' \
    '  --alpha    Alpha mode' \
    '  --beta     Beta mode'
  exit 0
fi
if [ "${1:-}" = "completion" ] && [ "${2:-}" = "zsh" ]; then
  printf '%s\n' \
    '#compdef flaggy' \
    '_flaggy() {' \
    "  _arguments '--alpha[Alpha mode]'" \
    '}'
  exit 0
fi
exit 1
"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).unwrap();
        }

        let missing = native_payload_missing_help_flags(
            &CompletionCommandSpec {
                program: script,
                args: Vec::new(),
            },
            "#compdef flaggy\n_flaggy() { _arguments '--alpha[Alpha mode]' }\n",
            Duration::from_secs(2),
        )
        .unwrap();

        assert!(missing);
    }
}
