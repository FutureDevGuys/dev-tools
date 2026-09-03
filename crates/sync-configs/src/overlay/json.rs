//! Source-authoritative JSON overlays with optional exact-subtree replacement.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Number, Value};

use super::ownership;
use super::{OverlayResult, PathKey};

#[derive(Clone, Debug, Default)]
pub struct JsonOverlayOptions {
    pub dry_run: bool,
    pub replace_json_pointers: Vec<String>,
    pub reconcile_removed_keys: bool,
    pub managed_overlay_id: Option<String>,
    pub state_root: Option<PathBuf>,
}

pub fn load_json_object_text(text: &str, label: &str) -> Result<Map<String, Value>> {
    if text.trim().is_empty() {
        return Ok(Map::new());
    }
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|error| anyhow!("failed to parse JSON {label}: {error}"))?
        .0;
    deserializer
        .end()
        .map_err(|error| anyhow!("failed to parse JSON {label}: {error}"))?;
    match value {
        Value::Object(object) => Ok(object),
        _ => bail!("JSON {label} must contain a top-level object"),
    }
}

pub fn overlay_json_text(
    source_text: &str,
    target_text: &str,
    replace_json_pointers: &[String],
    retired_paths: &BTreeSet<PathKey>,
) -> Result<OverlayResult> {
    let source = load_json_object_text(source_text, "source")?;
    let target = load_json_object_text(target_text, "target")?;
    let mut pruned_target = target.clone();
    let mut removed = 0;
    for path in retired_paths {
        removed += usize::from(remove_object_path(&mut pruned_target, path));
    }

    let added = count_missing(&source, &pruned_target);
    let overwritten = count_conflicts(&source, &pruned_target);
    let mut merged = Value::Object(source_wins(&source, &pruned_target));
    let source_value = Value::Object(source);
    let mut replaced = 0;
    for pointer in replace_json_pointers {
        let replacement = get_pointer_value(&source_value, pointer)?.clone();
        if get_pointer_value(&merged, pointer)? != &replacement {
            replaced += 1;
        }
        set_pointer_value(&mut merged, pointer, replacement)?;
    }

    let target_value = Value::Object(target);
    let text = if merged == target_value {
        target_text.to_owned()
    } else {
        let mut rendered =
            serde_json::to_string_pretty(&merged).context("cannot render merged JSON")?;
        rendered.push('\n');
        rendered
    };
    Ok(OverlayResult {
        changed: text != target_text,
        added,
        overwritten,
        replaced,
        removed,
        text,
        ..OverlayResult::default()
    })
}

pub fn overlay_json_file(
    source_path: &Path,
    target_path: &Path,
    options: &JsonOverlayOptions,
) -> Result<OverlayResult> {
    let source_text = fs::read_to_string(source_path)
        .with_context(|| format!("cannot read JSON overlay source {}", source_path.display()))?;
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
        let source = load_json_object_text(&source_text, "source")?;
        collect_leaf_paths(&Value::Object(source), &mut Vec::new(), &mut current_paths);
        ownership_path = Some(path);
    }

    let retired_paths = prior_paths
        .difference(&current_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut result = overlay_json_text(
        &source_text,
        &target_text,
        &options.replace_json_pointers,
        &retired_paths,
    )?;
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

/// Resolve an RFC 6901 pointer. Missing is distinct from an explicit JSON null.
pub fn get_pointer_value<'a>(data: &'a Value, pointer: &str) -> Result<&'a Value> {
    let mut current = data;
    for component in parse_json_pointer(pointer)? {
        current = match current {
            Value::Object(object) => object
                .get(&component)
                .ok_or_else(|| anyhow!("JSON pointer not found in source: {pointer}"))?,
            Value::Array(items) => {
                let index = parse_array_index(&component, pointer)?;
                items
                    .get(index)
                    .ok_or_else(|| anyhow!("JSON pointer not found in source: {pointer}"))?
            }
            _ => bail!("JSON pointer traverses a non-container value: {pointer}"),
        };
    }
    Ok(current)
}

fn set_pointer_value(data: &mut Value, pointer: &str, value: Value) -> Result<()> {
    let path = parse_json_pointer(pointer)?;
    if path.is_empty() {
        if !value.is_object() {
            bail!("replacing the JSON document root requires an object value");
        }
        *data = value;
        return Ok(());
    }

    let mut current = data;
    for component in &path[..path.len() - 1] {
        current = match current {
            Value::Object(object) => object
                .get_mut(component)
                .ok_or_else(|| anyhow!("JSON pointer not found in merged output: {pointer}"))?,
            Value::Array(items) => {
                let index = parse_array_index(component, pointer)?;
                items
                    .get_mut(index)
                    .ok_or_else(|| anyhow!("JSON pointer not found in merged output: {pointer}"))?
            }
            _ => bail!("JSON pointer traverses a non-container value: {pointer}"),
        };
    }

    let final_component = path.last().expect("non-empty pointer path");
    match current {
        Value::Object(object) => {
            if !object.contains_key(final_component) {
                bail!("JSON pointer not found in merged output: {pointer}");
            }
            object.insert(final_component.clone(), value);
        }
        Value::Array(items) => {
            let index = parse_array_index(final_component, pointer)?;
            let slot = items
                .get_mut(index)
                .ok_or_else(|| anyhow!("JSON pointer not found in merged output: {pointer}"))?;
            *slot = value;
        }
        _ => bail!("JSON pointer parent is not a container: {pointer}"),
    }
    Ok(())
}

fn parse_json_pointer(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    if !pointer.starts_with('/') {
        bail!("JSON pointer must be empty or start with '/': {pointer}");
    }
    pointer[1..]
        .split('/')
        .map(|raw| {
            let mut decoded = String::with_capacity(raw.len());
            let mut chars = raw.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => bail!("JSON pointer contains an invalid '~' escape: {pointer}"),
                }
            }
            Ok(decoded)
        })
        .collect()
}

fn parse_array_index(component: &str, pointer: &str) -> Result<usize> {
    if component.is_empty()
        || component == "-"
        || (component.len() > 1 && component.starts_with('0'))
        || !component.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("JSON pointer has an invalid array index: {pointer}");
    }
    component
        .parse::<usize>()
        .map_err(|_| anyhow!("JSON pointer array index is too large: {pointer}"))
}

fn count_missing(source: &Map<String, Value>, target: &Map<String, Value>) -> usize {
    source
        .iter()
        .map(|(key, source_value)| match target.get(key) {
            None => leaf_count(source_value),
            Some(Value::Object(target_object)) => match source_value {
                Value::Object(source_object) => count_missing(source_object, target_object),
                _ => 0,
            },
            Some(_) => 0,
        })
        .sum()
}

fn count_conflicts(source: &Map<String, Value>, target: &Map<String, Value>) -> usize {
    source
        .iter()
        .map(|(key, source_value)| match target.get(key) {
            None => 0,
            Some(target_value) => conflict_count(source_value, target_value),
        })
        .sum()
}

fn conflict_count(source: &Value, target: &Value) -> usize {
    match (source, target) {
        (Value::Object(source), Value::Object(target)) => count_conflicts(source, target),
        _ if source != target => leaf_count(source),
        _ => 0,
    }
}

fn leaf_count(value: &Value) -> usize {
    match value {
        Value::Object(object) if !object.is_empty() => object.values().map(leaf_count).sum(),
        _ => 1,
    }
}

fn source_wins(source: &Map<String, Value>, target: &Map<String, Value>) -> Map<String, Value> {
    let mut merged = source.clone();
    for (key, target_value) in target {
        match merged.get_mut(key) {
            None => {
                merged.insert(key.clone(), target_value.clone());
            }
            Some(Value::Object(source_object)) => {
                if let Value::Object(target_object) = target_value {
                    *source_object = source_wins(source_object, target_object);
                }
            }
            Some(_) => {}
        }
    }
    merged
}

fn collect_leaf_paths(value: &Value, path: &mut PathKey, output: &mut BTreeSet<PathKey>) {
    if let Value::Object(object) = value {
        if !object.is_empty() {
            for (key, child) in object {
                path.push(key.clone());
                collect_leaf_paths(child, path, output);
                path.pop();
            }
            return;
        }
    }
    if !path.is_empty() {
        output.insert(path.clone());
    }
}

fn remove_object_path(data: &mut Map<String, Value>, path: &[String]) -> bool {
    if path.is_empty() {
        return false;
    }
    remove_object_path_inner(data, path).0
}

fn remove_object_path_inner(data: &mut Map<String, Value>, path: &[String]) -> (bool, bool) {
    if path.len() == 1 {
        let removed = data.remove(&path[0]).is_some();
        return (removed, data.is_empty());
    }
    let Some(Value::Object(child)) = data.get_mut(&path[0]) else {
        return (false, data.is_empty());
    };
    let (removed, child_empty) = remove_object_path_inner(child, &path[1..]);
    if removed && child_empty {
        data.remove(&path[0]);
    }
    (removed, data.is_empty())
}

fn read_optional_target(path: &Path) -> Result<(String, bool)> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let text = match fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot read JSON overlay target {}", path.display())
                    })
                }
            };
            Ok((text, true))
        }
        Ok(metadata) if metadata.is_file() => Ok((
            fs::read_to_string(path)
                .with_context(|| format!("cannot read JSON overlay target {}", path.display()))?,
            false,
        )),
        Ok(_) => bail!(
            "JSON overlay target must be a file path: {}",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok((String::new(), false)),
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect JSON overlay target {}", path.display())),
    }
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueValueVisitor)
    }
}

struct UniqueValueVisitor;

impl<'de> Visitor<'de> for UniqueValueVisitor {
    type Value = UniqueValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueValue>()? {
            values.push(value.0);
        }
        Ok(UniqueValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result = Map::new();
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate JSON key {key:?}")));
            }
            let value = map.next_value::<UniqueValue>()?;
            result.insert(key, value.0);
        }
        Ok(UniqueValue(Value::Object(result)))
    }
}
