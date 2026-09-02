//! Conservative, shell-neutral completion IR derived from bounded help evidence.
//!
//! Parsing is intentionally fail-closed. Text that is not explicitly described by
//! the source remains unknown, and unknown positionals never acquire filesystem
//! semantics. The binary encoding is canonical and dependency-free so the IR can
//! be used as the content-addressed fallback artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;

pub(crate) const IR_MAGIC: &[u8; 8] = b"UACIR\0\x01\0";
pub(crate) const IR_VERSION: u16 = 1;
pub(crate) const HELP_PARSER_VERSION: u16 = 1;
pub(crate) const IR_STORE_DIRECTORY: &str = "help-ir";
pub(crate) const IR_OBJECT_EXTENSION: &str = "uacir";
pub(crate) const MAX_IR_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_NODES: usize = 256;
pub(crate) const MAX_OPTIONS_PER_NODE: usize = 512;
pub(crate) const MAX_POSITIONALS_PER_NODE: usize = 128;
pub(crate) const MAX_CHOICES_PER_VALUE: usize = 512;
pub(crate) const MAX_TEXT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct EvidenceRef {
    pub(crate) digest: String,
    pub(crate) argv: Vec<String>,
    pub(crate) exit_code: Option<i32>,
    pub(crate) truncated_stdout: bool,
    pub(crate) truncated_stderr: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Confidence {
    Explicit,
    Corroborated,
    Inferred,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Completeness {
    Complete,
    PartialBudget,
    PartialDepth,
    PartialCycle,
    PartialParse,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum ValueArity {
    None,
    Required,
    Optional,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Repeatability {
    Once,
    Repeatable,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum OptionScope {
    Command,
    Inherited,
    Global,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum ValueHint {
    None,
    File,
    Directory,
    Command,
    User,
    Host,
    Choice,
    Opaque(String),
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Description {
    pub(crate) text: String,
    pub(crate) evidence: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValueSpec {
    pub(crate) arity: ValueArity,
    pub(crate) name: Option<String>,
    pub(crate) choices: Vec<String>,
    pub(crate) hint: ValueHint,
    pub(crate) confidence: Confidence,
}

impl Default for ValueSpec {
    fn default() -> Self {
        Self {
            arity: ValueArity::Unknown,
            name: None,
            choices: Vec::new(),
            hint: ValueHint::Unknown,
            confidence: Confidence::Unknown,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OptionSpec {
    pub(crate) spellings: Vec<String>,
    pub(crate) description: Option<Description>,
    pub(crate) value: ValueSpec,
    pub(crate) repeatability: Repeatability,
    pub(crate) scope: OptionScope,
    pub(crate) confidence: Confidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PositionalSpec {
    pub(crate) name: String,
    pub(crate) description: Option<Description>,
    pub(crate) value: ValueSpec,
    pub(crate) required: Option<bool>,
    pub(crate) repeatability: Repeatability,
    pub(crate) confidence: Confidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CommandNode {
    pub(crate) canonical_path: Vec<String>,
    pub(crate) aliases: Vec<String>,
    pub(crate) description: Option<Description>,
    pub(crate) options: Vec<OptionSpec>,
    pub(crate) positionals: Vec<PositionalSpec>,
    pub(crate) subcommands: Vec<CommandNode>,
    pub(crate) accepts_end_of_options: Option<bool>,
    pub(crate) completeness: BTreeSet<Completeness>,
    pub(crate) evidence: Vec<usize>,
}

impl CommandNode {
    pub(crate) fn new(path: Vec<String>) -> Self {
        let mut completeness = BTreeSet::new();
        completeness.insert(Completeness::Unknown);
        Self {
            canonical_path: path,
            aliases: Vec::new(),
            description: None,
            options: Vec::new(),
            positionals: Vec::new(),
            subcommands: Vec::new(),
            accepts_end_of_options: None,
            completeness,
            evidence: Vec::new(),
        }
    }

    pub(crate) fn normalize(&mut self) {
        normalize_strings(&mut self.aliases);
        for option in &mut self.options {
            normalize_strings(&mut option.spellings);
            normalize_strings(&mut option.value.choices);
        }
        for positional in &mut self.positionals {
            normalize_strings(&mut positional.value.choices);
        }
        for child in &mut self.subcommands {
            child.normalize();
        }
        self.options.sort_by(|left, right| {
            left.spellings
                .first()
                .cmp(&right.spellings.first())
                .then_with(|| left.spellings.cmp(&right.spellings))
        });
        self.positionals
            .sort_by(|left, right| left.name.cmp(&right.name));
        self.subcommands.sort_by(|left, right| {
            left.canonical_path
                .cmp(&right.canonical_path)
                .then_with(|| left.aliases.cmp(&right.aliases))
        });
        self.options.dedup_by(|left, right| left == right);
        self.positionals.dedup_by(|left, right| left == right);
        self.subcommands
            .dedup_by(|left, right| left.canonical_path == right.canonical_path);
        if self.completeness.len() > 1 {
            self.completeness.remove(&Completeness::Unknown);
        }
    }

    pub(crate) fn find_child(&self, name: &str) -> Option<&Self> {
        self.subcommands.iter().find(|child| {
            child.canonical_path.last().is_some_and(|part| part == name)
                || child.aliases.iter().any(|alias| alias == name)
        })
    }

    pub(crate) fn find_child_mut(&mut self, name: &str) -> Option<&mut Self> {
        self.subcommands.iter_mut().find(|child| {
            child.canonical_path.last().is_some_and(|part| part == name)
                || child.aliases.iter().any(|alias| alias == name)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompletionIr {
    pub(crate) version: u16,
    pub(crate) command_name: String,
    pub(crate) aliases: Vec<String>,
    pub(crate) description: Option<Description>,
    pub(crate) evidence: Vec<EvidenceRef>,
    pub(crate) root: CommandNode,
}

impl CompletionIr {
    pub(crate) fn new(command_name: String, evidence: EvidenceRef) -> Self {
        Self {
            version: IR_VERSION,
            command_name: command_name.clone(),
            aliases: Vec::new(),
            description: None,
            evidence: vec![evidence],
            root: CommandNode::new(vec![command_name]),
        }
    }

    pub(crate) fn normalize(&mut self) {
        normalize_strings(&mut self.aliases);
        self.evidence.sort();
        self.evidence.dedup();
        self.root.normalize();
    }

    pub(crate) fn encode_canonical(&self) -> io::Result<Vec<u8>> {
        let mut normalized = self.clone();
        normalized.normalize();
        let mut writer = WireWriter::new(MAX_IR_BYTES);
        writer.bytes(IR_MAGIC)?;
        writer.u16(normalized.version)?;
        writer.string(&normalized.command_name)?;
        writer.strings(&normalized.aliases)?;
        writer.description(normalized.description.as_ref())?;
        writer.usize(normalized.evidence.len())?;
        for evidence in &normalized.evidence {
            writer.evidence(evidence)?;
        }
        writer.node(&normalized.root, 0)?;
        Ok(writer.finish())
    }

    pub(crate) fn encode_behavior_canonical(&self) -> io::Result<Vec<u8>> {
        let mut behavior = self.clone();
        behavior.evidence.clear();
        if let Some(description) = &mut behavior.description {
            description.evidence.clear();
        }
        clear_evidence_references(&mut behavior.root);
        behavior.encode_canonical()
    }

    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_IR_BYTES {
            return Err(invalid("completion IR exceeds the hard byte bound"));
        }
        let mut reader = WireReader::new(bytes);
        if reader.take(IR_MAGIC.len())? != IR_MAGIC {
            return Err(invalid("completion IR magic/version family mismatch"));
        }
        let version = reader.u16()?;
        if version != IR_VERSION {
            return Err(invalid("unsupported completion IR version"));
        }
        let command_name = reader.string()?;
        let aliases = reader.strings()?;
        let description = reader.description()?;
        let evidence_len = reader.usize_bounded(1024)?;
        let mut evidence = Vec::with_capacity(evidence_len);
        for _ in 0..evidence_len {
            evidence.push(reader.evidence()?);
        }
        let mut node_count = 0usize;
        let root = reader.node(0, &mut node_count)?;
        reader.finish()?;
        let mut result = Self {
            version,
            command_name,
            aliases,
            description,
            evidence,
            root,
        };
        result.normalize();
        Ok(result)
    }

    pub(crate) fn merge_node(&mut self, node: CommandNode) {
        if node.canonical_path.len() <= 1 {
            self.root = node;
            return;
        }
        let relative = node.canonical_path[1..].to_vec();
        merge_at_path(&mut self.root, &relative, node);
        self.normalize();
    }
}

fn merge_at_path(parent: &mut CommandNode, relative: &[String], node: CommandNode) {
    let Some((head, tail)) = relative.split_first() else {
        *parent = node;
        return;
    };
    if tail.is_empty() {
        if let Some(existing) = parent.find_child_mut(head) {
            *existing = node;
        } else {
            parent.subcommands.push(node);
        }
        return;
    }
    if parent.find_child(head).is_none() {
        let mut path = parent.canonical_path.clone();
        path.push(head.clone());
        parent.subcommands.push(CommandNode::new(path));
    }
    if let Some(child) = parent.find_child_mut(head) {
        merge_at_path(child, tail, node);
    }
}

fn clear_evidence_references(node: &mut CommandNode) {
    node.evidence.clear();
    if let Some(description) = &mut node.description {
        description.evidence.clear();
    }
    for option in &mut node.options {
        if let Some(description) = &mut option.description {
            description.evidence.clear();
        }
    }
    for positional in &mut node.positionals {
        if let Some(description) = &mut positional.description {
            description.evidence.clear();
        }
    }
    for child in &mut node.subcommands {
        clear_evidence_references(child);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionKind {
    None,
    Options(OptionScope),
    Positionals,
    CandidateCommands,
    RejectedCommands,
    Other,
}

#[derive(Clone, Debug)]
struct LogicalRow {
    left: String,
    right: String,
    evidence_line: usize,
}

pub(crate) fn parse_help(
    bytes: &[u8],
    command_path: &[String],
    evidence_index: usize,
) -> CommandNode {
    let text = normalize_help_text(bytes);
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let usage = collect_usage(&lines);
    let usage_words = usage_words(&usage);
    let usage_has_subcommand_slot = usage.iter().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("<command>")
            || lower.contains("[command]")
            || lower.contains("<subcommand>")
            || lower.contains("[subcommand]")
            || lower.contains(" commands")
    });

    let mut node = CommandNode::new(command_path.to_vec());
    node.evidence.push(evidence_index);
    node.accepts_end_of_options = usage
        .iter()
        .any(|line| tokenized(line).iter().any(|token| token == "--"))
        .then_some(true);

    if let Some(description) = first_description(&lines) {
        node.description = Some(Description {
            text: description,
            evidence: vec![evidence_index],
        });
    }

    let command_row_count = count_command_like_rows(&lines);
    let command_sections_allowed = usage_has_subcommand_slot || command_row_count >= 2;
    let mut section = SectionKind::None;
    let mut rows: Vec<(SectionKind, LogicalRow)> = Vec::new();
    let mut current_row: Option<(SectionKind, LogicalRow)> = None;

    for (line_index, raw) in lines.iter().enumerate() {
        let line = raw.trim_end();
        if let Some(next) = classify_heading(line, command_sections_allowed) {
            if let Some(row) = current_row.take() {
                rows.push(row);
            }
            section = next;
            continue;
        }
        if line.trim().is_empty() {
            if let Some(row) = current_row.take() {
                rows.push(row);
            }
            continue;
        }
        if matches!(
            section,
            SectionKind::None | SectionKind::Other | SectionKind::RejectedCommands
        ) {
            continue;
        }
        if let Some((left, right)) = split_columns(line) {
            if matches!(section, SectionKind::CandidateCommands)
                && right.is_empty()
                && current_row.is_some()
            {
                if let Some((_, row)) = &mut current_row {
                    if !row.right.is_empty() {
                        row.right.push(' ');
                    }
                    row.right.push_str(left.trim());
                }
                continue;
            }
            if let Some(row) = current_row.take() {
                rows.push(row);
            }
            current_row = Some((
                section,
                LogicalRow {
                    left,
                    right,
                    evidence_line: line_index,
                },
            ));
        } else if let Some((_, row)) = &mut current_row {
            let continuation = line.trim();
            if !continuation.is_empty() {
                if !row.right.is_empty() {
                    row.right.push(' ');
                }
                row.right.push_str(continuation);
            }
        }
    }
    if let Some(row) = current_row {
        rows.push(row);
    }

    let mut aliases_seen = BTreeSet::new();
    for (kind, row) in rows {
        match kind {
            SectionKind::Options(scope) => {
                if let Some(option) = parse_option_row(&row, scope, evidence_index) {
                    merge_option(&mut node.options, option);
                }
            }
            SectionKind::Positionals => {
                if let Some(positional) = parse_positional_row(&row, &usage_words, evidence_index) {
                    merge_positional(&mut node.positionals, positional);
                }
            }
            SectionKind::CandidateCommands if command_sections_allowed => {
                if let Some(child) = parse_command_row(&row, command_path, evidence_index) {
                    let name = child.canonical_path.last().cloned().unwrap_or_default();
                    if !name.is_empty()
                        && node.subcommands.len() < MAX_NODES.saturating_sub(1)
                        && aliases_seen.insert(name)
                    {
                        for alias in &child.aliases {
                            aliases_seen.insert(alias.clone());
                        }
                        node.subcommands.push(child);
                    }
                }
            }
            _ => {}
        }
    }

    parse_usage_positionals(&usage, command_path, evidence_index, &mut node.positionals);
    if node.options.is_empty() && node.positionals.is_empty() && node.subcommands.is_empty() {
        node.completeness.clear();
        node.completeness.insert(Completeness::PartialParse);
    } else {
        node.completeness.clear();
        node.completeness.insert(Completeness::Complete);
    }
    node.normalize();
    node
}

fn first_description(lines: &[String]) -> Option<String> {
    let mut saw_usage = false;
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_usage_line(trimmed) {
            saw_usage = true;
            continue;
        }
        if heading_name(trimmed).is_some() {
            continue;
        }
        if !saw_usage && !trimmed.starts_with('-') && trimmed.len() <= 512 {
            return Some(trimmed.to_owned());
        }
    }
    None
}

fn collect_usage(lines: &[String]) -> Vec<String> {
    let mut usage = Vec::new();
    let mut collecting = false;
    for line in lines {
        let trimmed = line.trim();
        if is_usage_line(trimmed) {
            collecting = true;
            usage.push(trimmed.to_owned());
            continue;
        }
        if collecting {
            if trimmed.is_empty() || heading_name(trimmed).is_some() {
                collecting = false;
            } else if line.starts_with(' ') || line.starts_with('\t') {
                usage.push(trimmed.to_owned());
            } else {
                collecting = false;
            }
        }
    }
    usage
}

fn is_usage_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("usage:")
        || lower.starts_with("usage ")
        || lower.starts_with("usages:")
        || lower.starts_with("syntax:")
}

fn usage_words(usage: &[String]) -> BTreeSet<String> {
    usage
        .iter()
        .flat_map(|line| tokenized(line))
        .map(|token| trim_metavar(&token).to_ascii_lowercase())
        .collect()
}

fn tokenized(line: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|token| {
            token
                .trim_matches(|ch: char| ch == ',' || ch == ';')
                .to_owned()
        })
        .collect()
}

fn classify_heading(line: &str, command_sections_allowed: bool) -> Option<SectionKind> {
    let heading = heading_name(line)?;
    let lower = heading.to_ascii_lowercase();
    let normalized = lower.split_whitespace().collect::<Vec<_>>().join(" ");
    if matches!(
        normalized.as_str(),
        "environment"
            | "environment variables"
            | "configuration"
            | "config"
            | "examples"
            | "example"
            | "exit codes"
            | "exit status"
            | "files"
            | "see also"
            | "notes"
    ) {
        return Some(SectionKind::RejectedCommands);
    }
    if matches!(
        normalized.as_str(),
        "options" | "option" | "flags" | "optional arguments" | "optional options"
    ) {
        return Some(SectionKind::Options(OptionScope::Command));
    }
    if matches!(normalized.as_str(), "global flags" | "global options") {
        return Some(SectionKind::Options(OptionScope::Global));
    }
    if matches!(normalized.as_str(), "inherited flags" | "inherited options") {
        return Some(SectionKind::Options(OptionScope::Inherited));
    }
    if matches!(
        normalized.as_str(),
        "arguments" | "positional arguments" | "positionals" | "operands"
    ) {
        return Some(SectionKind::Positionals);
    }
    if matches!(
        normalized.as_str(),
        "commands" | "subcommands" | "available commands" | "command groups"
    ) {
        return Some(if command_sections_allowed {
            SectionKind::CandidateCommands
        } else {
            SectionKind::RejectedCommands
        });
    }
    Some(SectionKind::Other)
}

fn heading_name(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.len() < 2 || trimmed.len() > 80 {
        return None;
    }
    if let Some(without) = trimmed.strip_suffix(':') {
        if without.chars().any(char::is_alphabetic)
            && !without.starts_with('-')
            && !without.contains("  ")
        {
            return Some(without.trim());
        }
    }
    let alpha: Vec<char> = trimmed.chars().filter(|ch| ch.is_alphabetic()).collect();
    if alpha.len() >= 2
        && alpha.iter().all(|ch| ch.is_uppercase())
        && !trimmed.starts_with('-')
        && !trimmed.contains("  ")
    {
        return Some(trimmed);
    }
    None
}

fn count_command_like_rows(lines: &[String]) -> usize {
    let mut section_candidate = false;
    let mut count = 0usize;
    for line in lines {
        if let Some(name) = heading_name(line) {
            let lower = name.to_ascii_lowercase();
            section_candidate = matches!(
                lower.as_str(),
                "commands" | "subcommands" | "available commands" | "command groups"
            );
            continue;
        }
        if !section_candidate {
            continue;
        }
        if let Some((left, right)) = split_columns(line) {
            if command_name(&left).is_some() && !right.is_empty() {
                count += 1;
            }
        }
    }
    count
}

fn split_columns(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let mut index = 0usize;
    while index + 1 < bytes.len() {
        if bytes[index].is_ascii_whitespace() && bytes[index + 1].is_ascii_whitespace() {
            let left = trimmed[..index].trim();
            let right = trimmed[index..].trim();
            if !left.is_empty() {
                return Some((left.to_owned(), right.to_owned()));
            }
        }
        index += 1;
    }
    if trimmed.starts_with('-') {
        return Some((trimmed.to_owned(), String::new()));
    }
    let mut split = trimmed.splitn(2, char::is_whitespace);
    let left = split.next()?.trim();
    let right = split.next().unwrap_or("").trim();
    (!left.is_empty()).then(|| (left.to_owned(), right.to_owned()))
}

fn parse_option_row(
    row: &LogicalRow,
    scope: OptionScope,
    evidence_index: usize,
) -> Option<OptionSpec> {
    let mut spellings = Vec::new();
    let tokens = split_option_declaration(&row.left);
    let mut value = ValueSpec {
        arity: ValueArity::None,
        name: None,
        choices: Vec::new(),
        hint: ValueHint::None,
        confidence: Confidence::Explicit,
    };
    for token in tokens {
        if token.starts_with('-') {
            let (spelling, attached) = split_attached_value(&token);
            let spelling = spelling.trim_end_matches("...");
            if valid_option_spelling(spelling) {
                spellings.push(spelling.to_owned());
            }
            if let Some(metavar) = attached {
                apply_metavar(&mut value, metavar, ValueArity::Required);
            }
        } else if looks_like_metavar(&token) {
            let arity = if token.starts_with('[') {
                ValueArity::Optional
            } else {
                ValueArity::Required
            };
            apply_metavar(&mut value, &token, arity);
        } else if is_explicit_go_value_type(&token) {
            value.arity = ValueArity::Required;
            value.name = Some(token.clone());
            value.hint = ValueHint::Unknown;
            value.confidence = Confidence::Explicit;
        }
    }
    normalize_strings(&mut spellings);
    if spellings.is_empty() {
        return None;
    }
    apply_choices(&mut value, &row.left);
    apply_choices(&mut value, &row.right);
    apply_explicit_hint(&mut value, &row.left, &row.right);
    if value.arity == ValueArity::None && description_says_value(&row.right) {
        value.arity = ValueArity::Unknown;
        value.hint = ValueHint::Unknown;
        value.confidence = Confidence::Inferred;
    }
    let repeatability = detect_repeatability(&row.left, &row.right);
    let confidence = if row.evidence_line == usize::MAX {
        Confidence::Unknown
    } else {
        Confidence::Explicit
    };
    Some(OptionSpec {
        spellings,
        description: description(&row.right, evidence_index),
        value,
        repeatability,
        scope,
        confidence,
    })
}

fn split_option_declaration(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    for ch in input.chars() {
        match ch {
            '<' | '[' | '{' => depth += 1,
            '>' | ']' | '}' => depth = (depth - 1).max(0),
            ',' | ' ' | '\t' if depth == 0 => {
                if !current.trim().is_empty() {
                    result.push(current.trim().to_owned());
                }
                current.clear();
                continue;
            }
            _ => {}
        }
        current.push(ch);
    }
    if !current.trim().is_empty() {
        result.push(current.trim().to_owned());
    }
    result
}

fn split_attached_value(token: &str) -> (&str, Option<&str>) {
    if let Some((left, right)) = token.split_once('=') {
        return (left, (!right.is_empty()).then_some(right));
    }
    if let Some(index) = token.find('<') {
        return (&token[..index], Some(&token[index..]));
    }
    if let Some(index) = token.find('[') {
        return (&token[..index], Some(&token[index..]));
    }
    (token, None)
}

fn valid_option_spelling(spelling: &str) -> bool {
    spelling.len() >= 2
        && spelling.starts_with('-')
        && spelling != "--"
        && !spelling.chars().any(char::is_whitespace)
}

fn is_explicit_go_value_type(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "string"
            | "strings"
            | "bool"
            | "int"
            | "int32"
            | "int64"
            | "uint"
            | "uint32"
            | "uint64"
            | "float"
            | "duration"
            | "bytes"
            | "count"
    )
}

fn looks_like_metavar(token: &str) -> bool {
    (token.starts_with('<') && token.ends_with('>'))
        || (token.starts_with('[') && token.ends_with(']'))
        || (token.starts_with('{') && token.ends_with('}'))
        || (token
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch == '_' || ch == '-')
            && token.chars().any(char::is_alphabetic)
            && !token.starts_with('-'))
}

fn trim_metavar(input: &str) -> String {
    input
        .trim()
        .trim_matches(|ch| matches!(ch, '<' | '>' | '[' | ']' | '{' | '}' | ','))
        .trim_end_matches("...")
        .to_owned()
}

fn apply_metavar(value: &mut ValueSpec, metavar: &str, arity: ValueArity) {
    let name = trim_metavar(metavar);
    if !name.is_empty() {
        value.name = Some(name.clone());
        value.arity = arity;
        value.hint = hint_from_name(&name);
        value.confidence = Confidence::Explicit;
    }
    apply_choices(value, metavar);
}

fn apply_choices(value: &mut ValueSpec, text: &str) {
    for (open, close) in [('{', '}'), ('[', ']')] {
        let mut rest = text;
        while let Some(start) = rest.find(open) {
            let after = &rest[start + open.len_utf8()..];
            let Some(end) = after.find(close) else { break };
            let inside = &after[..end];
            let lower_inside = inside.to_ascii_lowercase();
            let contains_choice_marker =
                ["possible values:", "possible value:", "one of:", "choices:"]
                    .iter()
                    .any(|marker| lower_inside.contains(marker));
            let candidates: Vec<String> = if contains_choice_marker {
                Vec::new()
            } else {
                inside
                    .split([',', '|'])
                    .map(str::trim)
                    .filter(|part| !part.is_empty() && part.len() <= 256)
                    .map(str::to_owned)
                    .collect()
            };
            if candidates.len() >= 2 && candidates.len() <= MAX_CHOICES_PER_VALUE {
                value.choices.extend(candidates);
                value.hint = ValueHint::Choice;
                value.confidence = Confidence::Explicit;
            }
            rest = &after[end + close.len_utf8()..];
        }
    }
    let lower = text.to_ascii_lowercase();
    for marker in ["possible values:", "possible value:", "one of:", "choices:"] {
        if let Some(index) = lower.find(marker) {
            let tail = &text[index + marker.len()..];
            let tail = tail
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim_end_matches('.')
                .trim();
            let candidates: Vec<String> = tail
                .split([',', '|'])
                .map(|part| part.trim().trim_matches('`').trim_matches('\''))
                .filter(|part| !part.is_empty() && part.len() <= 256)
                .take(MAX_CHOICES_PER_VALUE)
                .map(str::to_owned)
                .collect();
            if candidates.len() >= 2 {
                value.choices.extend(candidates);
                value.hint = ValueHint::Choice;
                value.confidence = Confidence::Explicit;
            }
        }
    }
    normalize_strings(&mut value.choices);
}

fn apply_explicit_hint(value: &mut ValueSpec, declaration: &str, description: &str) {
    if matches!(value.hint, ValueHint::Choice) {
        return;
    }
    let combined = format!("{declaration} {description}").to_ascii_lowercase();
    let explicit = [
        (
            ["<file>", "[file]", " file path", "path to a file"].as_slice(),
            ValueHint::File,
        ),
        (
            [
                "<dir>",
                "<directory>",
                "[dir]",
                "[directory]",
                "directory path",
            ]
            .as_slice(),
            ValueHint::Directory,
        ),
        (["<command>", "[command]"].as_slice(), ValueHint::Command),
        (
            ["<user>", "<username>", "[user]"].as_slice(),
            ValueHint::User,
        ),
        (
            ["<host>", "<hostname>", "[host]"].as_slice(),
            ValueHint::Host,
        ),
    ];
    for (needles, hint) in explicit {
        if needles.iter().any(|needle| combined.contains(needle)) {
            value.hint = hint;
            value.confidence = Confidence::Explicit;
            return;
        }
    }
}

fn hint_from_name(name: &str) -> ValueHint {
    match name.to_ascii_lowercase().as_str() {
        "file" | "filepath" | "file_path" | "filename" => ValueHint::File,
        "dir" | "directory" | "dirpath" | "directory_path" => ValueHint::Directory,
        "command" | "cmd" => ValueHint::Command,
        "user" | "username" => ValueHint::User,
        "host" | "hostname" => ValueHint::Host,
        _ => ValueHint::Unknown,
    }
}

fn description_says_value(description: &str) -> bool {
    let lower = description.to_ascii_lowercase();
    lower.contains("value") || lower.contains("path") || lower.contains("name")
}

fn detect_repeatability(left: &str, right: &str) -> Repeatability {
    let combined = format!("{left} {right}").to_ascii_lowercase();
    if combined.contains("...")
        || combined.contains("repeatable")
        || combined.contains("multiple times")
        || combined.contains("more than once")
        || combined.contains("may be repeated")
    {
        Repeatability::Repeatable
    } else {
        Repeatability::Unknown
    }
}

fn parse_positional_row(
    row: &LogicalRow,
    usage_words: &BTreeSet<String>,
    evidence_index: usize,
) -> Option<PositionalSpec> {
    let raw = row.left.trim();
    if raw.is_empty() || raw.starts_with('-') {
        return None;
    }
    let name = trim_metavar(raw.split_whitespace().next()?);
    if name.is_empty() || name.len() > 256 {
        return None;
    }
    let mut value = ValueSpec {
        arity: ValueArity::Required,
        name: Some(name.clone()),
        choices: Vec::new(),
        hint: hint_from_name(&name),
        confidence: Confidence::Explicit,
    };
    apply_choices(&mut value, raw);
    apply_choices(&mut value, &row.right);
    apply_explicit_hint(&mut value, raw, &row.right);
    let lower = name.to_ascii_lowercase();
    let corroborated = usage_words.contains(&lower);
    Some(PositionalSpec {
        name,
        description: description(&row.right, evidence_index),
        value,
        required: if raw.starts_with('[') {
            Some(false)
        } else if raw.starts_with('<') || corroborated {
            Some(true)
        } else {
            None
        },
        repeatability: detect_repeatability(raw, &row.right),
        confidence: if corroborated {
            Confidence::Corroborated
        } else {
            Confidence::Explicit
        },
    })
}

fn parse_usage_positionals(
    usage: &[String],
    command_path: &[String],
    evidence_index: usize,
    positionals: &mut Vec<PositionalSpec>,
) {
    let command_tokens: BTreeSet<String> = command_path
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    for line in usage {
        for token in tokenized(line) {
            let unwrapped = token.trim_start_matches(['<', '[']);
            if token.starts_with('-')
                || unwrapped.starts_with('-')
                || command_tokens.contains(&token.to_ascii_lowercase())
            {
                continue;
            }
            let wrapped = (token.starts_with('<') && token.ends_with('>'))
                || (token.starts_with('[') && token.ends_with(']'));
            if !wrapped {
                continue;
            }
            let name = trim_metavar(&token);
            let lower = name.to_ascii_lowercase();
            if name.is_empty()
                || matches!(
                    lower.as_str(),
                    "options" | "flags" | "command" | "subcommand" | "args" | "arguments"
                )
                || positionals
                    .iter()
                    .any(|item| item.name.eq_ignore_ascii_case(&name))
            {
                continue;
            }
            let hint = hint_from_name(&name);
            positionals.push(PositionalSpec {
                name: name.clone(),
                description: None,
                value: ValueSpec {
                    arity: ValueArity::Required,
                    name: Some(name),
                    choices: Vec::new(),
                    hint,
                    confidence: Confidence::Explicit,
                },
                required: Some(token.starts_with('<')),
                repeatability: if token.contains("...") {
                    Repeatability::Repeatable
                } else {
                    Repeatability::Unknown
                },
                confidence: Confidence::Explicit,
            });
            if positionals.len() >= MAX_POSITIONALS_PER_NODE {
                return;
            }
        }
    }
    let _ = evidence_index;
}

fn parse_command_row(
    row: &LogicalRow,
    parent_path: &[String],
    evidence_index: usize,
) -> Option<CommandNode> {
    let (name, aliases) = command_name_and_aliases(&row.left)?;
    if name.starts_with('-') || name.len() > 256 || row.right.is_empty() {
        return None;
    }
    let mut path = parent_path.to_vec();
    path.push(name);
    let mut child = CommandNode::new(path);
    child.aliases = aliases;
    child.description = description(&row.right, evidence_index);
    child.evidence.push(evidence_index);
    child.completeness.clear();
    child.completeness.insert(Completeness::Unknown);
    Some(child)
}

fn command_name(input: &str) -> Option<String> {
    command_name_and_aliases(input).map(|pair| pair.0)
}

fn command_name_and_aliases(input: &str) -> Option<(String, Vec<String>)> {
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.starts_with('-') {
        return None;
    }
    let mut head = trimmed;
    let mut aliases = Vec::new();
    if let Some(index) = trimmed.find(['(', '[']) {
        head = trimmed[..index].trim();
        let tail = &trimmed[index..];
        let lower = tail.to_ascii_lowercase();
        if lower.contains("alias") {
            let values = tail
                .trim_matches(|ch| matches!(ch, '(' | ')' | '[' | ']'))
                .split_once(':')
                .map(|pair| pair.1)
                .unwrap_or("");
            aliases.extend(
                values
                    .split([',', '|'])
                    .map(str::trim)
                    .filter(|value| valid_command_name(value))
                    .map(str::to_owned),
            );
        }
    }
    let mut parts = head
        .split([',', '|'])
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let name = parts.next()?.split_whitespace().next()?.to_owned();
    aliases.extend(
        parts
            .filter(|part| valid_command_name(part))
            .map(str::to_owned),
    );
    if !valid_command_name(&name) {
        return None;
    }
    normalize_strings(&mut aliases);
    aliases.retain(|alias| alias != &name);
    Some((name, aliases))
}

fn valid_command_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.starts_with('-')
        && value
            .chars()
            .all(|ch| ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.' | ':' | '+'))
}

fn merge_option(options: &mut Vec<OptionSpec>, incoming: OptionSpec) {
    if let Some(existing) = options.iter_mut().find(|existing| {
        existing
            .spellings
            .iter()
            .any(|spelling| incoming.spellings.contains(spelling))
    }) {
        existing.spellings.extend(incoming.spellings);
        normalize_strings(&mut existing.spellings);
        if existing.description.is_none() {
            existing.description = incoming.description;
        }
        if existing.value.arity == ValueArity::Unknown {
            existing.value = incoming.value;
        } else {
            existing.value.choices.extend(incoming.value.choices);
            normalize_strings(&mut existing.value.choices);
        }
        if existing.repeatability == Repeatability::Unknown {
            existing.repeatability = incoming.repeatability;
        }
        return;
    }
    if options.len() < MAX_OPTIONS_PER_NODE {
        options.push(incoming);
    }
}

fn merge_positional(positionals: &mut Vec<PositionalSpec>, incoming: PositionalSpec) {
    if let Some(existing) = positionals
        .iter_mut()
        .find(|existing| existing.name.eq_ignore_ascii_case(&incoming.name))
    {
        if existing.description.is_none() {
            existing.description = incoming.description;
        }
        if existing.value.hint == ValueHint::Unknown && incoming.value.hint != ValueHint::Unknown {
            existing.value.hint = incoming.value.hint;
        }
        existing.value.choices.extend(incoming.value.choices);
        normalize_strings(&mut existing.value.choices);
        return;
    }
    if positionals.len() < MAX_POSITIONALS_PER_NODE {
        positionals.push(incoming);
    }
}

fn description(text: &str, evidence_index: usize) -> Option<Description> {
    let normalized = collapse_whitespace(text);
    (!normalized.is_empty()).then(|| Description {
        text: normalized,
        evidence: vec![evidence_index],
    })
}

fn normalize_help_text(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    let mut text = String::from_utf8_lossy(bytes)
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    text = strip_ansi(&text);
    text
}

fn strip_ansi(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == 0x1b {
            if index + 1 < bytes.len() && bytes[index + 1] == b'[' {
                index += 2;
                while index < bytes.len() {
                    let byte = bytes[index];
                    index += 1;
                    if (0x40..=0x7e).contains(&byte) {
                        break;
                    }
                }
                continue;
            }
            if index + 1 < bytes.len() && bytes[index + 1] == b']' {
                index += 2;
                while index < bytes.len() {
                    if bytes[index] == 0x07 {
                        index += 1;
                        break;
                    }
                    if bytes[index] == 0x1b && index + 1 < bytes.len() && bytes[index + 1] == b'\\'
                    {
                        index += 2;
                        break;
                    }
                    index += 1;
                }
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn collapse_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_strings(values: &mut Vec<String>) {
    values.retain(|value| !value.is_empty() && value.len() <= MAX_TEXT_BYTES);
    values.sort();
    values.dedup();
}

#[derive(Debug)]
pub(crate) struct DecodeError(&'static str);

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for DecodeError {}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, DecodeError(message))
}

struct WireWriter {
    bytes: Vec<u8>,
    max: usize,
}

impl WireWriter {
    fn new(max: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn reserve(&self, extra: usize) -> io::Result<()> {
        if self.bytes.len().saturating_add(extra) > self.max {
            Err(invalid(
                "completion IR encoding exceeds the hard byte bound",
            ))
        } else {
            Ok(())
        }
    }

    fn bytes(&mut self, value: &[u8]) -> io::Result<()> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> io::Result<()> {
        self.bytes(&[value])
    }

    fn u16(&mut self, value: u16) -> io::Result<()> {
        self.bytes(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> io::Result<()> {
        self.bytes(&value.to_be_bytes())
    }

    fn usize(&mut self, value: usize) -> io::Result<()> {
        self.u32(u32::try_from(value).map_err(|_| invalid("wire collection is too large"))?)
    }

    fn bool_option(&mut self, value: Option<bool>) -> io::Result<()> {
        self.u8(match value {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        })
    }

    fn string(&mut self, value: &str) -> io::Result<()> {
        if value.len() > MAX_TEXT_BYTES {
            return Err(invalid("wire string exceeds the hard text bound"));
        }
        self.usize(value.len())?;
        self.bytes(value.as_bytes())
    }

    fn optional_string(&mut self, value: Option<&str>) -> io::Result<()> {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1)?;
                self.string(value)
            }
        }
    }

    fn strings(&mut self, values: &[String]) -> io::Result<()> {
        self.usize(values.len())?;
        for value in values {
            self.string(value)?;
        }
        Ok(())
    }

    fn description(&mut self, value: Option<&Description>) -> io::Result<()> {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1)?;
                self.string(&value.text)?;
                self.usize(value.evidence.len())?;
                for index in &value.evidence {
                    self.usize(*index)?;
                }
                Ok(())
            }
        }
    }

    fn evidence(&mut self, value: &EvidenceRef) -> io::Result<()> {
        self.string(&value.digest)?;
        self.strings(&value.argv)?;
        match value.exit_code {
            None => self.u8(0)?,
            Some(code) => {
                self.u8(1)?;
                self.u32(code as u32)?;
            }
        }
        self.u8(u8::from(value.truncated_stdout))?;
        self.u8(u8::from(value.truncated_stderr))
    }

    fn value(&mut self, value: &ValueSpec) -> io::Result<()> {
        self.u8(encode_arity(value.arity))?;
        self.optional_string(value.name.as_deref())?;
        self.strings(&value.choices)?;
        self.value_hint(&value.hint)?;
        self.u8(encode_confidence(value.confidence))
    }

    fn value_hint(&mut self, value: &ValueHint) -> io::Result<()> {
        match value {
            ValueHint::None => self.u8(0),
            ValueHint::File => self.u8(1),
            ValueHint::Directory => self.u8(2),
            ValueHint::Command => self.u8(3),
            ValueHint::User => self.u8(4),
            ValueHint::Host => self.u8(5),
            ValueHint::Choice => self.u8(6),
            ValueHint::Opaque(value) => {
                self.u8(7)?;
                self.string(value)
            }
            ValueHint::Unknown => self.u8(8),
        }
    }

    fn node(&mut self, node: &CommandNode, depth: usize) -> io::Result<()> {
        if depth > 16 {
            return Err(invalid("completion IR nesting exceeds the hard bound"));
        }
        self.strings(&node.canonical_path)?;
        self.strings(&node.aliases)?;
        self.description(node.description.as_ref())?;
        self.usize(node.options.len())?;
        for option in &node.options {
            self.strings(&option.spellings)?;
            self.description(option.description.as_ref())?;
            self.value(&option.value)?;
            self.u8(encode_repeatability(option.repeatability))?;
            self.u8(encode_scope(option.scope))?;
            self.u8(encode_confidence(option.confidence))?;
        }
        self.usize(node.positionals.len())?;
        for positional in &node.positionals {
            self.string(&positional.name)?;
            self.description(positional.description.as_ref())?;
            self.value(&positional.value)?;
            self.bool_option(positional.required)?;
            self.u8(encode_repeatability(positional.repeatability))?;
            self.u8(encode_confidence(positional.confidence))?;
        }
        self.bool_option(node.accepts_end_of_options)?;
        self.usize(node.completeness.len())?;
        for value in &node.completeness {
            self.u8(encode_completeness(*value))?;
        }
        self.usize(node.evidence.len())?;
        for index in &node.evidence {
            self.usize(*index)?;
        }
        self.usize(node.subcommands.len())?;
        for child in &node.subcommands {
            self.node(child, depth + 1)?;
        }
        Ok(())
    }
}

struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> io::Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid("trailing bytes in completion IR"))
        }
    }

    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| invalid("completion IR offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated completion IR"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| invalid("truncated u16"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> io::Result<u32> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| invalid("truncated u32"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn usize_bounded(&mut self, max: usize) -> io::Result<usize> {
        let value = usize::try_from(self.u32()?).map_err(|_| invalid("wire size overflow"))?;
        if value > max {
            Err(invalid("wire collection exceeds a hard bound"))
        } else {
            Ok(value)
        }
    }

    fn bool_option(&mut self) -> io::Result<Option<bool>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(false)),
            2 => Ok(Some(true)),
            _ => Err(invalid("invalid optional boolean tag")),
        }
    }

    fn string(&mut self) -> io::Result<String> {
        let len = self.usize_bounded(MAX_TEXT_BYTES)?;
        String::from_utf8(self.take(len)?.to_vec())
            .map_err(|_| invalid("completion IR text is not UTF-8"))
    }

    fn optional_string(&mut self) -> io::Result<Option<String>> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.string().map(Some),
            _ => Err(invalid("invalid optional string tag")),
        }
    }

    fn strings(&mut self) -> io::Result<Vec<String>> {
        let count = self.usize_bounded(MAX_OPTIONS_PER_NODE.max(MAX_CHOICES_PER_VALUE))?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.string()?);
        }
        Ok(values)
    }

    fn description(&mut self) -> io::Result<Option<Description>> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let text = self.string()?;
                let count = self.usize_bounded(1024)?;
                let mut evidence = Vec::with_capacity(count);
                for _ in 0..count {
                    evidence.push(self.usize_bounded(1024)?);
                }
                Ok(Some(Description { text, evidence }))
            }
            _ => Err(invalid("invalid description tag")),
        }
    }

    fn evidence(&mut self) -> io::Result<EvidenceRef> {
        let digest = self.string()?;
        let argv = self.strings()?;
        let exit_code = match self.u8()? {
            0 => None,
            1 => Some(self.u32()? as i32),
            _ => return Err(invalid("invalid exit-code tag")),
        };
        let truncated_stdout = decode_bool(self.u8()?)?;
        let truncated_stderr = decode_bool(self.u8()?)?;
        Ok(EvidenceRef {
            digest,
            argv,
            exit_code,
            truncated_stdout,
            truncated_stderr,
        })
    }

    fn value(&mut self) -> io::Result<ValueSpec> {
        Ok(ValueSpec {
            arity: decode_arity(self.u8()?)?,
            name: self.optional_string()?,
            choices: self.strings()?,
            hint: self.value_hint()?,
            confidence: decode_confidence(self.u8()?)?,
        })
    }

    fn value_hint(&mut self) -> io::Result<ValueHint> {
        match self.u8()? {
            0 => Ok(ValueHint::None),
            1 => Ok(ValueHint::File),
            2 => Ok(ValueHint::Directory),
            3 => Ok(ValueHint::Command),
            4 => Ok(ValueHint::User),
            5 => Ok(ValueHint::Host),
            6 => Ok(ValueHint::Choice),
            7 => self.string().map(ValueHint::Opaque),
            8 => Ok(ValueHint::Unknown),
            _ => Err(invalid("invalid value-hint tag")),
        }
    }

    fn node(&mut self, depth: usize, count: &mut usize) -> io::Result<CommandNode> {
        if depth > 16 {
            return Err(invalid("completion IR nesting exceeds the hard bound"));
        }
        *count = count.saturating_add(1);
        if *count > MAX_NODES {
            return Err(invalid("completion IR node count exceeds the hard bound"));
        }
        let canonical_path = self.strings()?;
        let aliases = self.strings()?;
        let description = self.description()?;
        let option_count = self.usize_bounded(MAX_OPTIONS_PER_NODE)?;
        let mut options = Vec::with_capacity(option_count);
        for _ in 0..option_count {
            options.push(OptionSpec {
                spellings: self.strings()?,
                description: self.description()?,
                value: self.value()?,
                repeatability: decode_repeatability(self.u8()?)?,
                scope: decode_scope(self.u8()?)?,
                confidence: decode_confidence(self.u8()?)?,
            });
        }
        let positional_count = self.usize_bounded(MAX_POSITIONALS_PER_NODE)?;
        let mut positionals = Vec::with_capacity(positional_count);
        for _ in 0..positional_count {
            positionals.push(PositionalSpec {
                name: self.string()?,
                description: self.description()?,
                value: self.value()?,
                required: self.bool_option()?,
                repeatability: decode_repeatability(self.u8()?)?,
                confidence: decode_confidence(self.u8()?)?,
            });
        }
        let accepts_end_of_options = self.bool_option()?;
        let completeness_count = self.usize_bounded(16)?;
        let mut completeness = BTreeSet::new();
        for _ in 0..completeness_count {
            completeness.insert(decode_completeness(self.u8()?)?);
        }
        let evidence_count = self.usize_bounded(1024)?;
        let mut evidence = Vec::with_capacity(evidence_count);
        for _ in 0..evidence_count {
            evidence.push(self.usize_bounded(1024)?);
        }
        let child_count = self.usize_bounded(MAX_NODES)?;
        let mut subcommands = Vec::with_capacity(child_count);
        for _ in 0..child_count {
            subcommands.push(self.node(depth + 1, count)?);
        }
        Ok(CommandNode {
            canonical_path,
            aliases,
            description,
            options,
            positionals,
            subcommands,
            accepts_end_of_options,
            completeness,
            evidence,
        })
    }
}

fn decode_bool(value: u8) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("invalid boolean tag")),
    }
}

fn encode_arity(value: ValueArity) -> u8 {
    match value {
        ValueArity::None => 0,
        ValueArity::Required => 1,
        ValueArity::Optional => 2,
        ValueArity::Unknown => 3,
    }
}
fn decode_arity(value: u8) -> io::Result<ValueArity> {
    match value {
        0 => Ok(ValueArity::None),
        1 => Ok(ValueArity::Required),
        2 => Ok(ValueArity::Optional),
        3 => Ok(ValueArity::Unknown),
        _ => Err(invalid("invalid arity tag")),
    }
}
fn encode_repeatability(value: Repeatability) -> u8 {
    match value {
        Repeatability::Once => 0,
        Repeatability::Repeatable => 1,
        Repeatability::Unknown => 2,
    }
}
fn decode_repeatability(value: u8) -> io::Result<Repeatability> {
    match value {
        0 => Ok(Repeatability::Once),
        1 => Ok(Repeatability::Repeatable),
        2 => Ok(Repeatability::Unknown),
        _ => Err(invalid("invalid repeatability tag")),
    }
}
fn encode_scope(value: OptionScope) -> u8 {
    match value {
        OptionScope::Command => 0,
        OptionScope::Inherited => 1,
        OptionScope::Global => 2,
        OptionScope::Unknown => 3,
    }
}
fn decode_scope(value: u8) -> io::Result<OptionScope> {
    match value {
        0 => Ok(OptionScope::Command),
        1 => Ok(OptionScope::Inherited),
        2 => Ok(OptionScope::Global),
        3 => Ok(OptionScope::Unknown),
        _ => Err(invalid("invalid scope tag")),
    }
}
fn encode_confidence(value: Confidence) -> u8 {
    match value {
        Confidence::Explicit => 0,
        Confidence::Corroborated => 1,
        Confidence::Inferred => 2,
        Confidence::Unknown => 3,
    }
}
fn decode_confidence(value: u8) -> io::Result<Confidence> {
    match value {
        0 => Ok(Confidence::Explicit),
        1 => Ok(Confidence::Corroborated),
        2 => Ok(Confidence::Inferred),
        3 => Ok(Confidence::Unknown),
        _ => Err(invalid("invalid confidence tag")),
    }
}
fn encode_completeness(value: Completeness) -> u8 {
    match value {
        Completeness::Complete => 0,
        Completeness::PartialBudget => 1,
        Completeness::PartialDepth => 2,
        Completeness::PartialCycle => 3,
        Completeness::PartialParse => 4,
        Completeness::Unknown => 5,
    }
}
fn decode_completeness(value: u8) -> io::Result<Completeness> {
    match value {
        0 => Ok(Completeness::Complete),
        1 => Ok(Completeness::PartialBudget),
        2 => Ok(Completeness::PartialDepth),
        3 => Ok(Completeness::PartialCycle),
        4 => Ok(Completeness::PartialParse),
        5 => Ok(Completeness::Unknown),
        _ => Err(invalid("invalid completeness tag")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> EvidenceRef {
        EvidenceRef {
            digest: "00".repeat(32),
            argv: vec!["tool".into(), "--help".into()],
            exit_code: Some(0),
            truncated_stdout: false,
            truncated_stderr: false,
        }
    }

    #[test]
    fn canonical_ir_round_trip_is_deterministic() {
        let bytes = b"tool description\n\nUsage: tool [OPTIONS] <FILE>\n\nOptions:\n  -v, --verbose...  increase detail\n  --mode <MODE>     possible values: fast, safe\n";
        let root = parse_help(bytes, &["tool".into()], 0);
        let mut ir = CompletionIr::new("tool".into(), evidence());
        ir.root = root;
        let first = ir.encode_canonical().unwrap();
        let decoded = CompletionIr::decode(&first).unwrap();
        let second = decoded.encode_canonical().unwrap();
        assert_eq!(first, second);
        assert_eq!(decoded.root.positionals[0].value.hint, ValueHint::File);
        let verbose = decoded
            .root
            .options
            .iter()
            .find(|option| {
                option
                    .spellings
                    .iter()
                    .any(|spelling| spelling == "--verbose")
            })
            .unwrap();
        assert_eq!(verbose.repeatability, Repeatability::Repeatable);
    }

    #[test]
    fn adversarial_headings_do_not_create_commands() {
        let bytes = b"Usage: tool [OPTIONS]\n\nEnvironment:\n  PROD  production mode\n\nConfiguration:\n  init  initialize config\n\nExamples:\n  run   run an example\n\nExit Codes:\n  1  failed\n";
        let node = parse_help(bytes, &["tool".into()], 0);
        assert!(node.subcommands.is_empty());
    }

    #[test]
    fn unknown_positionals_remain_unknown() {
        let bytes = b"usage: tool THING\n\npositional arguments:\n  THING  opaque input\n";
        let node = parse_help(bytes, &["tool".into()], 0);
        assert_eq!(node.positionals[0].value.hint, ValueHint::Unknown);
    }

    #[test]
    fn ansi_wrapping_and_nonzero_evidence_are_parseable() {
        let bytes = b"\x1b[1mUsage:\x1b[0m tool [OPTIONS]\r\n\r\nOptions:\r\n  --output <FILE>  write output to a\r\n                   file path\r\n";
        let node = parse_help(bytes, &["tool".into()], 0);
        assert_eq!(node.options.len(), 1);
        assert_eq!(node.options[0].value.hint, ValueHint::File);
    }
}
