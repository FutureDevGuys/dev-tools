//! Comment-aware TOML overlays that preserve local-only configuration.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use toml_edit::{ArrayOfTables, DocumentMut, Item, TableLike, Value};

use super::ownership;
use super::{OverlayResult, PathKey};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TomlConflictPolicy {
    #[default]
    Source,
    Target,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CommentedTargetPolicy {
    #[default]
    Respect,
    Activate,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExclusiveSiblingGroup {
    pub parent_pattern: PathKey,
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct TomlOverlayOptions {
    pub dry_run: bool,
    pub conflict_policy: TomlConflictPolicy,
    pub preserve_target_layout: bool,
    pub reconcile_removed_keys: bool,
    pub managed_overlay_id: Option<String>,
    pub state_root: Option<PathBuf>,
    pub commented_target_policy: CommentedTargetPolicy,
    pub exclusive_sibling_groups: Vec<ExclusiveSiblingGroup>,
}

pub fn overlay_toml_text(
    source_text: &str,
    target_text: &str,
    options: &TomlOverlayOptions,
    retired_paths: &BTreeSet<PathKey>,
) -> Result<OverlayResult> {
    let mut source_document = parse_document(source_text, "source")?;
    let original_target = parse_document(target_text, "target")?;
    let source_paths = assignment_paths(&source_document);
    let (commented_assignments, commented_tables) = commented_target_paths(target_text);
    let mut suppressed = source_paths
        .iter()
        .filter(|path| {
            commented_assignments.contains(*path)
                || commented_tables
                    .iter()
                    .any(|prefix| path.starts_with(prefix))
        })
        .cloned()
        .collect::<Vec<_>>();
    suppressed.sort();

    match options.commented_target_policy {
        CommentedTargetPolicy::Error if !suppressed.is_empty() => {
            bail!(
                "commented target paths suppress source keys: {}",
                suppressed
                    .iter()
                    .map(|path| render_toml_key_path(path))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        CommentedTargetPolicy::Activate => suppressed.clear(),
        CommentedTargetPolicy::Respect | CommentedTargetPolicy::Error => {}
    }

    let mut preserve_target_layout = options.preserve_target_layout;
    if !suppressed.is_empty() {
        for path in &suppressed {
            remove_path(source_document.as_table_mut(), path);
        }
        preserve_target_layout = true;
    }

    let source_semantic = SemanticValue::Object(table_semantic(source_document.as_table()));
    let mut all_retired = retired_paths.clone();
    all_retired.extend(exclusive_retired_paths(
        &source_semantic,
        &options.exclusive_sibling_groups,
    )?);

    let mut target_document = original_target.clone();
    let mut removed = 0;
    for path in &all_retired {
        removed += usize::from(remove_path(target_document.as_table_mut(), path));
    }

    let target_semantic = SemanticValue::Object(table_semantic(target_document.as_table()));
    let added = count_missing(&source_semantic, &target_semantic);
    let overwritten = if options.conflict_policy == TomlConflictPolicy::Source {
        count_conflicts(&source_semantic, &target_semantic)
    } else {
        0
    };

    let mut merged = match options.conflict_policy {
        TomlConflictPolicy::Target => {
            let mut merged = target_document;
            merge_missing(merged.as_table_mut(), source_document.as_table());
            merged
        }
        TomlConflictPolicy::Source if preserve_target_layout => {
            let mut merged = target_document;
            merge_source_wins(merged.as_table_mut(), source_document.as_table());
            merged
        }
        TomlConflictPolicy::Source => {
            if source_document.is_empty() {
                target_document
            } else {
                let mut merged = source_document;
                merge_missing(merged.as_table_mut(), target_document.as_table());
                merged
            }
        }
    };

    // Materialize decor and key ordering into a stable owned string before validating.
    let rendered = merged.to_string();
    merged = parse_document(&rendered, "merged output")?;
    let merged_semantic = SemanticValue::Object(table_semantic(merged.as_table()));
    let expected = match options.conflict_policy {
        TomlConflictPolicy::Source => semantic_source_wins(&source_semantic, &target_semantic),
        TomlConflictPolicy::Target => semantic_target_wins(&source_semantic, &target_semantic),
    };
    if merged_semantic != expected {
        bail!("merged TOML output did not match the expected semantic overlay");
    }

    Ok(OverlayResult {
        changed: rendered != target_text,
        added,
        overwritten,
        removed,
        text: rendered,
        suppressed,
        ..OverlayResult::default()
    })
}

pub fn overlay_toml_file(
    source_path: &Path,
    target_path: &Path,
    options: &TomlOverlayOptions,
) -> Result<OverlayResult> {
    let source_text = fs::read_to_string(source_path)
        .with_context(|| format!("cannot read TOML overlay source {}", source_path.display()))?;
    let (target_text, materialize_symlink) = read_optional_target(target_path)?;

    let mut ownership_path = None;
    let mut prior_paths = BTreeSet::new();
    let mut current_paths = BTreeSet::new();
    if options.reconcile_removed_keys {
        let managed_id = options.managed_overlay_id.as_deref().ok_or_else(|| {
            anyhow!("managed_overlay_id is required when reconcile_removed_keys is enabled")
        })?;
        let path = ownership::receipt_path(managed_id, options.state_root.as_deref())?;
        prior_paths = ownership::load_paths(&path, managed_id)?;
        current_paths = assignment_paths(&parse_document(&source_text, "source")?);
        ownership_path = Some(path);
    }

    let retired_paths = prior_paths
        .difference(&current_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut result = overlay_toml_text(&source_text, &target_text, options, &retired_paths)?;
    for suppressed in &result.suppressed {
        current_paths.remove(suppressed);
    }
    let ownership_changed = ownership_path.is_some() && prior_paths != current_paths;
    result.materialized_symlink = materialize_symlink;
    result.ownership_changed = ownership_changed;
    result.changed |= materialize_symlink || ownership_changed;

    if options.dry_run || !result.changed {
        return Ok(result);
    }

    let target_snapshot = ownership::snapshot_file(target_path)?;
    let write_target = result.text != target_text || materialize_symlink;
    if write_target {
        ownership::atomic_write_preserving_target(target_path, result.text.as_bytes())?;
    }
    if let Some(path) = ownership_path {
        let managed_id = options
            .managed_overlay_id
            .as_deref()
            .expect("validated managed overlay id");
        if let Err(error) = ownership::write_paths_atomic(&path, managed_id, &current_paths) {
            if write_target {
                ownership::restore_file(target_path, &target_snapshot).with_context(|| {
                    format!(
                        "ownership receipt update failed and target rollback also failed: {error:#}"
                    )
                })?;
            }
            return Err(error);
        }
    }
    Ok(result)
}

/// Parse a TOML dotted key or table path using the same parser as the document.
pub fn parse_toml_key_path(raw: &str) -> Result<PathKey> {
    if raw.contains(['\n', '\r']) {
        bail!("TOML key path must occupy one line");
    }
    let mut parsed = Vec::new();
    for component in split_key_components(raw)? {
        if component == "*" {
            parsed.push(component.to_owned());
            continue;
        }
        let synthetic = format!("{component} = 0\n");
        let document = parse_document(&synthetic, "key path")?;
        let paths = assignment_paths(&document);
        if paths.len() != 1 {
            bail!("TOML key path must identify exactly one key");
        }
        let path = paths.into_iter().next().expect("one parsed key component");
        if path.len() != 1 {
            bail!("TOML key path contains an invalid component");
        }
        parsed.extend(path);
    }
    if parsed.is_empty() {
        bail!("TOML key path must not be empty");
    }
    Ok(parsed)
}

pub fn render_toml_key_path(path: &[String]) -> String {
    path.iter()
        .map(|component| {
            if !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'*'))
            {
                component.clone()
            } else {
                serde_json::to_string(component).expect("a Rust string always serializes to JSON")
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn parse_document(text: &str, label: &str) -> Result<DocumentMut> {
    text.parse::<DocumentMut>()
        .map_err(|_| anyhow!("failed to parse TOML {label}"))
}

fn split_key_components(raw: &str) -> Result<Vec<&str>> {
    let mut components = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut start = 0;
    for (index, character) in raw.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some('"') if character == '"' => quote = None,
            Some('\'') if character == '\'' => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == '.' => {
                let component = raw[start..index].trim();
                if component.is_empty() {
                    bail!("TOML key path contains an empty component");
                }
                components.push(component);
                start = index + character.len_utf8();
            }
            None => {}
        }
    }
    if quote.is_some() {
        bail!("TOML key path contains an unterminated quoted component");
    }
    let component = raw[start..].trim();
    if component.is_empty() {
        bail!("TOML key path contains an empty component");
    }
    components.push(component);
    Ok(components)
}

fn assignment_paths(document: &DocumentMut) -> BTreeSet<PathKey> {
    let mut paths = BTreeSet::new();
    collect_assignment_paths(document.as_table(), &mut Vec::new(), &mut paths);
    paths
}

fn collect_assignment_paths(
    table: &dyn TableLike,
    path: &mut PathKey,
    output: &mut BTreeSet<PathKey>,
) {
    for (key, item) in table.iter() {
        path.push(key.to_owned());
        if let Item::Table(child) = item {
            collect_assignment_paths(child, path, output);
        } else if !item.is_none() {
            output.insert(path.clone());
        }
        path.pop();
    }
}

fn commented_target_paths(text: &str) -> (BTreeSet<PathKey>, BTreeSet<PathKey>) {
    let mut assignments = BTreeSet::new();
    let mut tables = BTreeSet::new();
    let mut active_table = Vec::new();
    for line in text.lines() {
        if let Some(path) = extract_table_header_path(line) {
            active_table = path;
            continue;
        }
        let stripped = line.trim_start();
        let Some(candidate) = stripped.strip_prefix('#') else {
            continue;
        };
        let candidate = candidate.trim_start();
        if let Some(path) = extract_table_header_path(candidate) {
            tables.insert(path);
            continue;
        }
        let Some(separator) = assignment_separator(candidate) else {
            continue;
        };
        let raw_key = candidate[..separator].trim();
        if raw_key.is_empty() {
            continue;
        }
        if let Ok(mut path) = parse_toml_key_path(raw_key) {
            let mut full = active_table.clone();
            full.append(&mut path);
            assignments.insert(full);
        }
    }
    (assignments, tables)
}

fn extract_table_header_path(line: &str) -> Option<PathKey> {
    let stripped = line.trim();
    let array_table = stripped.starts_with("[[");
    let start = if array_table {
        2
    } else if stripped.starts_with('[') {
        1
    } else {
        return None;
    };
    let end_token = if array_table { "]]" } else { "]" };
    let mut quote = None;
    let mut escaped = false;
    let mut index = start;
    let bytes = stripped.as_bytes();
    while index < bytes.len() {
        let character = bytes[index] as char;
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some('"') if character == '"' => quote = None,
            Some('\'') if character == '\'' => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if stripped[index..].starts_with(end_token) => {
                let trailer = stripped[index + end_token.len()..].trim();
                if !trailer.is_empty() && !trailer.starts_with('#') {
                    return None;
                }
                return parse_toml_key_path(stripped[start..index].trim()).ok();
            }
            None => {}
        }
        index += 1;
    }
    None
}

fn assignment_separator(line: &str) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some('"') if character == '"' => quote = None,
            Some('\'') if character == '\'' => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if character == '#' => return None,
            None if character == '=' => return Some(index),
            None => {}
        }
    }
    None
}

fn remove_path(table: &mut dyn TableLike, path: &[String]) -> bool {
    if path.is_empty() {
        return false;
    }
    if path.len() == 1 {
        return table.remove(&path[0]).is_some();
    }
    let Some(child) = table.get_mut(&path[0]).and_then(Item::as_table_like_mut) else {
        return false;
    };
    let removed = remove_path(child, &path[1..]);
    let empty = child.is_empty();
    if removed && empty {
        table.remove(&path[0]);
    }
    removed
}

fn merge_missing(target: &mut dyn TableLike, source: &dyn TableLike) {
    let entries = source
        .iter()
        .map(|(key, item)| (key.to_owned(), item.clone()))
        .collect::<Vec<_>>();
    for (key, source_item) in entries {
        let Some(target_item) = target.get_mut(&key) else {
            target.insert(&key, source_item);
            continue;
        };
        if let (Some(target_table), Some(source_table)) =
            (target_item.as_table_like_mut(), source_item.as_table_like())
        {
            merge_missing(target_table, source_table);
        }
    }
}

fn merge_source_wins(target: &mut dyn TableLike, source: &dyn TableLike) {
    let entries = source
        .iter()
        .map(|(key, item)| (key.to_owned(), item.clone()))
        .collect::<Vec<_>>();
    for (key, source_item) in entries {
        let Some(target_item) = target.get_mut(&key) else {
            target.insert(&key, source_item);
            continue;
        };
        if target_item.is_table_like() && source_item.is_table_like() {
            let target_table = target_item
                .as_table_like_mut()
                .expect("checked target table-like item");
            let source_table = source_item
                .as_table_like()
                .expect("checked source table-like item");
            merge_source_wins(target_table, source_table);
        } else {
            *target_item = source_item;
        }
    }
}

fn exclusive_retired_paths(
    source: &SemanticValue,
    groups: &[ExclusiveSiblingGroup],
) -> Result<BTreeSet<PathKey>> {
    let mut retired = BTreeSet::new();
    for group in groups {
        let unique = group.keys.iter().collect::<BTreeSet<_>>();
        if group.keys.len() < 2 || unique.len() != group.keys.len() {
            bail!("mutually exclusive sibling groups require at least two unique keys");
        }
        let mut matches = Vec::new();
        nested_objects_at_pattern(source, &group.parent_pattern, &mut Vec::new(), &mut matches);
        for (parent_path, object) in matches {
            let present = group
                .keys
                .iter()
                .filter(|key| object.contains_key(*key))
                .cloned()
                .collect::<Vec<_>>();
            if present.len() > 1 {
                let mut names = present;
                names.sort();
                let location = if parent_path.is_empty() {
                    "<root>".to_owned()
                } else {
                    render_toml_key_path(&parent_path)
                };
                bail!(
                    "mutually exclusive source keys are both active at {location}: {}",
                    names.join(", ")
                );
            }
            if let Some(active) = present.first() {
                for key in &group.keys {
                    if key != active {
                        let mut path = parent_path.clone();
                        path.push(key.clone());
                        retired.insert(path);
                    }
                }
            }
        }
    }
    Ok(retired)
}

fn nested_objects_at_pattern<'a>(
    value: &'a SemanticValue,
    pattern: &[String],
    path: &mut PathKey,
    output: &mut Vec<(PathKey, &'a BTreeMap<String, SemanticValue>)>,
) {
    if pattern.is_empty() {
        if let SemanticValue::Object(object) = value {
            output.push((path.clone(), object));
        }
        return;
    }
    let SemanticValue::Object(object) = value else {
        return;
    };
    if pattern[0] == "*" {
        for (key, child) in object {
            path.push(key.clone());
            nested_objects_at_pattern(child, &pattern[1..], path, output);
            path.pop();
        }
    } else if let Some(child) = object.get(&pattern[0]) {
        path.push(pattern[0].clone());
        nested_objects_at_pattern(child, &pattern[1..], path, output);
        path.pop();
    }
}

#[derive(Clone, Debug)]
enum SemanticValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Datetime(String),
    Array(Vec<SemanticValue>),
    Object(BTreeMap<String, SemanticValue>),
}

impl PartialEq for SemanticValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Integer(left), Self::Integer(right)) => left == right,
            (Self::Float(left), Self::Float(right)) => {
                left.partial_cmp(right) == Some(std::cmp::Ordering::Equal)
            }
            (Self::Boolean(left), Self::Boolean(right)) => left == right,
            (Self::Datetime(left), Self::Datetime(right)) => left == right,
            (Self::Array(left), Self::Array(right)) => left == right,
            (Self::Object(left), Self::Object(right)) => left == right,
            _ => false,
        }
    }
}

fn table_semantic(table: &dyn TableLike) -> BTreeMap<String, SemanticValue> {
    table
        .iter()
        .filter_map(|(key, item)| item_semantic(item).map(|value| (key.to_owned(), value)))
        .collect()
}

fn item_semantic(item: &Item) -> Option<SemanticValue> {
    match item {
        Item::None => None,
        Item::Value(value) => Some(value_semantic(value)),
        Item::Table(table) => Some(SemanticValue::Object(table_semantic(table))),
        Item::ArrayOfTables(tables) => Some(array_of_tables_semantic(tables)),
    }
}

fn value_semantic(value: &Value) -> SemanticValue {
    match value {
        Value::String(value) => SemanticValue::String(value.value().clone()),
        Value::Integer(value) => SemanticValue::Integer(*value.value()),
        Value::Float(value) => SemanticValue::Float(*value.value()),
        Value::Boolean(value) => SemanticValue::Boolean(*value.value()),
        Value::Datetime(value) => SemanticValue::Datetime(value.value().to_string()),
        Value::Array(array) => SemanticValue::Array(array.iter().map(value_semantic).collect()),
        Value::InlineTable(table) => SemanticValue::Object(
            table
                .iter()
                .map(|(key, value)| (key.to_owned(), value_semantic(value)))
                .collect(),
        ),
    }
}

fn array_of_tables_semantic(tables: &ArrayOfTables) -> SemanticValue {
    SemanticValue::Array(
        tables
            .iter()
            .map(|table| SemanticValue::Object(table_semantic(table)))
            .collect(),
    )
}

fn count_missing(source: &SemanticValue, target: &SemanticValue) -> usize {
    let (SemanticValue::Object(source), SemanticValue::Object(target)) = (source, target) else {
        return 0;
    };
    source
        .iter()
        .map(|(key, source_value)| match target.get(key) {
            None => leaf_count(source_value),
            Some(target_value) => count_missing(source_value, target_value),
        })
        .sum()
}

fn count_conflicts(source: &SemanticValue, target: &SemanticValue) -> usize {
    let (SemanticValue::Object(source), SemanticValue::Object(target)) = (source, target) else {
        return usize::from(source != target) * leaf_count(source);
    };
    source
        .iter()
        .map(|(key, source_value)| match target.get(key) {
            None => 0,
            Some(target_value) => count_conflicts(source_value, target_value),
        })
        .sum()
}

fn leaf_count(value: &SemanticValue) -> usize {
    match value {
        SemanticValue::Object(object) if !object.is_empty() => {
            object.values().map(leaf_count).sum()
        }
        _ => 1,
    }
}

fn semantic_source_wins(source: &SemanticValue, target: &SemanticValue) -> SemanticValue {
    match (source, target) {
        (SemanticValue::Object(source), SemanticValue::Object(target)) => {
            let mut merged = source.clone();
            for (key, target_value) in target {
                match merged.get_mut(key) {
                    None => {
                        merged.insert(key.clone(), target_value.clone());
                    }
                    Some(source_value) => {
                        *source_value = semantic_source_wins(source_value, target_value);
                    }
                }
            }
            SemanticValue::Object(merged)
        }
        _ => source.clone(),
    }
}

fn semantic_target_wins(source: &SemanticValue, target: &SemanticValue) -> SemanticValue {
    match (source, target) {
        (SemanticValue::Object(source), SemanticValue::Object(target)) => {
            let mut merged = target.clone();
            for (key, source_value) in source {
                match merged.get_mut(key) {
                    None => {
                        merged.insert(key.clone(), source_value.clone());
                    }
                    Some(target_value) => {
                        *target_value = semantic_target_wins(source_value, target_value);
                    }
                }
            }
            SemanticValue::Object(merged)
        }
        _ => target.clone(),
    }
}

fn read_optional_target(path: &Path) -> Result<(String, bool)> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let text = match fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot read TOML overlay target {}", path.display())
                    })
                }
            };
            Ok((text, true))
        }
        Ok(metadata) if metadata.is_file() => Ok((
            fs::read_to_string(path)
                .with_context(|| format!("cannot read TOML overlay target {}", path.display()))?,
            false,
        )),
        Ok(_) => bail!(
            "TOML overlay target must be a file path: {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((String::new(), false)),
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect TOML overlay target {}", path.display())),
    }
}
