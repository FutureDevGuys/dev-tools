//! Public operations backing the standalone structured-overlay and managed-path commands.

use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use toml_edit::{DocumentMut, TableLike};

use crate::overlay::json::{overlay_json_file, JsonOverlayOptions};
use crate::overlay::ownership;
use crate::overlay::toml::{
    overlay_toml_file, parse_toml_key_path, CommentedTargetPolicy, TomlConflictPolicy,
    TomlOverlayOptions,
};
use crate::overlay::{OverlayResult, PathKey};
use crate::paths::{lexical_normalize, PathPlatform};

/// Inputs for the standalone JSON overlay operation.
#[derive(Clone, Debug)]
pub struct JsonOverlayRequest {
    pub source: PathBuf,
    pub target: PathBuf,
    pub dry_run: bool,
    pub check: bool,
    pub replace_json_pointers: Vec<String>,
    pub reconcile_removed_keys: bool,
    pub managed_overlay_id: Option<String>,
    pub state_root: Option<PathBuf>,
}

impl JsonOverlayRequest {
    pub fn new(source: PathBuf, target: PathBuf) -> Self {
        Self {
            source,
            target,
            dry_run: false,
            check: false,
            replace_json_pointers: Vec::new(),
            reconcile_removed_keys: false,
            managed_overlay_id: None,
            state_root: None,
        }
    }

    fn overlay_options(&self) -> JsonOverlayOptions {
        JsonOverlayOptions {
            dry_run: self.dry_run || self.check,
            replace_json_pointers: self.replace_json_pointers.clone(),
            reconcile_removed_keys: self.reconcile_removed_keys,
            managed_overlay_id: self.managed_overlay_id.clone(),
            state_root: self.state_root.clone(),
        }
    }
}

/// Which standalone TOML operation to perform.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TomlOperation {
    #[default]
    Overlay,
    Remove,
}

/// Inputs for the standalone TOML overlay or source-owned-key removal operation.
#[derive(Clone, Debug)]
pub struct TomlRequest {
    pub source: PathBuf,
    pub target: PathBuf,
    pub operation: TomlOperation,
    pub dry_run: bool,
    pub check: bool,
    pub conflict_policy: TomlConflictPolicy,
    pub reconcile_removed_keys: bool,
    pub managed_overlay_id: Option<String>,
    pub state_root: Option<PathBuf>,
    pub commented_target_policy: CommentedTargetPolicy,
}

impl TomlRequest {
    pub fn new(source: PathBuf, target: PathBuf) -> Self {
        Self {
            source,
            target,
            operation: TomlOperation::Overlay,
            dry_run: false,
            check: false,
            conflict_policy: TomlConflictPolicy::Source,
            reconcile_removed_keys: false,
            managed_overlay_id: None,
            state_root: None,
            commented_target_policy: CommentedTargetPolicy::Respect,
        }
    }

    fn overlay_options(&self) -> TomlOverlayOptions {
        TomlOverlayOptions {
            dry_run: self.dry_run || self.check,
            conflict_policy: self.conflict_policy,
            reconcile_removed_keys: self.reconcile_removed_keys,
            managed_overlay_id: self.managed_overlay_id.clone(),
            state_root: self.state_root.clone(),
            commented_target_policy: self.commented_target_policy,
            ..TomlOverlayOptions::default()
        }
    }
}

/// Value-free outcome shared by standalone overlay operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayCommandOutcome {
    pub overlay: OverlayResult,
    pub check_failed: bool,
}

impl OverlayCommandOutcome {
    pub fn exit_code(&self) -> i32 {
        i32::from(self.check_failed)
    }

    fn new(overlay: OverlayResult, check: bool) -> Self {
        Self {
            check_failed: check && overlay.changed,
            overlay,
        }
    }
}

pub fn execute_json_overlay(request: &JsonOverlayRequest) -> Result<OverlayCommandOutcome> {
    let overlay = overlay_json_file(&request.source, &request.target, &request.overlay_options())?;
    Ok(OverlayCommandOutcome::new(overlay, request.check))
}

pub fn execute_toml(request: &TomlRequest) -> Result<OverlayCommandOutcome> {
    let overlay = match request.operation {
        TomlOperation::Overlay => {
            overlay_toml_file(&request.source, &request.target, &request.overlay_options())?
        }
        TomlOperation::Remove => remove_source_owned_toml(request)?,
    };
    Ok(OverlayCommandOutcome::new(overlay, request.check))
}

/// Adoption policy for a pre-existing managed path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPathPolicy {
    #[default]
    Safe,
    Strict,
    Takeover,
}

impl ManagedPathPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Strict => "strict",
            Self::Takeover => "takeover",
        }
    }
}

impl fmt::Display for ManagedPathPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Observed relationship between the source and target paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPathState {
    Absent,
    ManagedLink,
    IdenticalSource,
    SkeletonDefault,
    Conflict,
}

impl ManagedPathState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::ManagedLink => "managed_link",
            Self::IdenticalSource => "identical_source",
            Self::SkeletonDefault => "skeleton_default",
            Self::Conflict => "conflict",
        }
    }
}

impl fmt::Display for ManagedPathState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Recommended action for the requested managed-path policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedPathAction {
    None,
    Create,
    Adopt,
    Replace,
    Block,
}

impl ManagedPathAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Create => "create",
            Self::Adopt => "adopt",
            Self::Replace => "replace",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for ManagedPathAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Inputs for standalone managed-path classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedPathRequest {
    pub source: PathBuf,
    pub target: PathBuf,
    pub policy: ManagedPathPolicy,
    pub skeleton: Option<PathBuf>,
}

impl ManagedPathRequest {
    pub fn new(source: PathBuf, target: PathBuf) -> Self {
        Self {
            source,
            target,
            policy: ManagedPathPolicy::Safe,
            skeleton: None,
        }
    }
}

/// Stable, serializable managed-path classification result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ManagedPathClassification {
    pub source: PathBuf,
    pub target: PathBuf,
    pub policy: ManagedPathPolicy,
    pub state: ManagedPathState,
    pub action: ManagedPathAction,
    pub backup_required: bool,
}

pub fn classify_managed_path(request: &ManagedPathRequest) -> ManagedPathClassification {
    let state = classify_state(request);
    let (action, backup_required) = choose_managed_path_action(request.policy, state);
    ManagedPathClassification {
        source: request.source.clone(),
        target: request.target.clone(),
        policy: request.policy,
        state,
        action,
        backup_required,
    }
}

fn remove_source_owned_toml(request: &TomlRequest) -> Result<OverlayResult> {
    ownership::validate_real_parent_chain(&request.target, "TOML removal target")?;
    let target_metadata = optional_metadata(&request.target)?;
    let Some(metadata) = target_metadata else {
        return Ok(OverlayResult::default());
    };
    let source_text = fs::read_to_string(&request.source).with_context(|| {
        format!(
            "cannot read TOML removal source {}",
            request.source.display()
        )
    })?;
    if !metadata.is_file() && !is_link_or_reparse(&metadata) {
        return Err(anyhow!(
            "TOML removal target must be a regular file path: {}",
            request.target.display()
        ));
    }
    ownership::validate_real_parent_chain(&request.target, "TOML removal target")?;
    let target_text = fs::read_to_string(&request.target).with_context(|| {
        format!(
            "cannot read TOML removal target {}",
            request.target.display()
        )
    })?;

    let source_paths = assignment_paths_from_text(&source_text, "source")?;
    let result = prune_toml_assignments(&target_text, &source_paths)?;
    validate_toml_prune_semantics(&source_text, &target_text, &result.text)?;
    let mut result = result;
    result.materialized_symlink = result.changed && is_link_or_reparse(&metadata);

    if !result.changed || request.dry_run || request.check {
        return Ok(result);
    }
    if result.text.is_empty() {
        ownership::remove_existing_leaf(&request.target, "TOML removal target")?;
    } else {
        ownership::atomic_write_preserving_target(&request.target, result.text.as_bytes())?;
    }
    Ok(result)
}

fn optional_metadata(path: &Path) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("cannot inspect TOML target {}", path.display()))
        }
    }
}

fn assignment_paths_from_text(text: &str, label: &str) -> Result<BTreeSet<PathKey>> {
    text.parse::<DocumentMut>()
        .map_err(|_| anyhow!("failed to parse TOML {label}"))?;
    let mut paths = BTreeSet::new();
    let mut table_path = Vec::new();
    for line in text.lines() {
        if let Some(path) = table_header_path(line)? {
            table_path = path;
            continue;
        }
        let Some(separator) = assignment_separator(line) else {
            continue;
        };
        let raw_key = line[..separator].trim();
        if raw_key.is_empty() {
            continue;
        }
        let mut path = table_path.clone();
        path.extend(parse_toml_key_path(raw_key)?);
        paths.insert(path);
    }
    Ok(paths)
}

fn assignment_line_paths(text: &str) -> Result<Vec<(usize, PathKey)>> {
    let mut paths = Vec::new();
    let mut table_path = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if let Some(path) = table_header_path(line)? {
            table_path = path;
            continue;
        }
        let Some(separator) = assignment_separator(line) else {
            continue;
        };
        let raw_key = line[..separator].trim();
        if raw_key.is_empty() {
            continue;
        }
        let mut path = table_path.clone();
        path.extend(parse_toml_key_path(raw_key)?);
        paths.push((index, path));
    }
    Ok(paths)
}

fn prune_toml_assignments(
    target_text: &str,
    source_paths: &BTreeSet<PathKey>,
) -> Result<OverlayResult> {
    target_text
        .parse::<DocumentMut>()
        .map_err(|_| anyhow!("failed to parse TOML target"))?;
    let removed_indexes = assignment_line_paths(target_text)?
        .into_iter()
        .filter_map(|(index, path)| source_paths.contains(&path).then_some(index))
        .collect::<BTreeSet<_>>();
    if removed_indexes.is_empty() {
        return Ok(OverlayResult {
            text: target_text.to_owned(),
            ..OverlayResult::default()
        });
    }

    let mut lines = target_text
        .split_inclusive('\n')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for index in &removed_indexes {
        lines
            .get_mut(*index)
            .ok_or_else(|| anyhow!("TOML assignment index was outside the parsed document"))?
            .clear();
    }
    remove_empty_table_headers(&mut lines)?;
    let text = normalize_pruned_toml(lines);
    text.parse::<DocumentMut>()
        .map_err(|_| anyhow!("failed to parse TOML pruned output"))?;
    Ok(OverlayResult {
        changed: text != target_text,
        removed: removed_indexes.len(),
        text,
        ..OverlayResult::default()
    })
}

fn remove_empty_table_headers(lines: &mut [String]) -> Result<()> {
    loop {
        let mut headers = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if !line.is_empty() && table_header_path(line)?.is_some() {
                headers.push(index);
            }
        }
        let mut changed = false;
        for offset in (0..headers.len()).rev() {
            let start = headers[offset];
            let end = headers.get(offset + 1).copied().unwrap_or(lines.len());
            let body_has_active_content = lines[start + 1..end]
                .iter()
                .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));
            if !body_has_active_content {
                lines[start].clear();
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
    }
}

fn normalize_pruned_toml(lines: Vec<String>) -> String {
    let mut compact = Vec::new();
    let mut previous_blank = true;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let blank = line.trim().is_empty();
        if blank && previous_blank {
            continue;
        }
        compact.push(line);
        previous_blank = blank;
    }
    while compact.last().is_some_and(|line| line.trim().is_empty()) {
        compact.pop();
    }
    let mut text = compact.concat();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

fn table_header_path(line: &str) -> Result<Option<PathKey>> {
    let stripped = line.trim();
    let (start, end_token) = if stripped.starts_with("[[") {
        (2, "]]")
    } else if stripped.starts_with('[') {
        (1, "]")
    } else {
        return Ok(None);
    };
    let mut quote = None;
    let mut escaped = false;
    let mut index = start;
    while index < stripped.len() {
        let character = stripped.as_bytes()[index] as char;
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if character == '\\' => escaped = true,
            Some('"') if character == '"' => quote = None,
            Some('\'') if character == '\'' => quote = None,
            Some(_) => {}
            None if matches!(character, '\'' | '"') => quote = Some(character),
            None if stripped.as_bytes()[index..].starts_with(end_token.as_bytes()) => {
                let trailer = stripped[index + end_token.len()..].trim();
                if !trailer.is_empty() && !trailer.starts_with('#') {
                    return Ok(None);
                }
                return parse_toml_key_path(stripped[start..index].trim()).map(Some);
            }
            None => {}
        }
        index += 1;
    }
    Ok(None)
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

fn validate_toml_prune_semantics(
    source_text: &str,
    target_text: &str,
    updated_text: &str,
) -> Result<()> {
    let source = source_text
        .parse::<DocumentMut>()
        .map_err(|_| anyhow!("failed to parse TOML source"))?;
    let mut expected = target_text
        .parse::<DocumentMut>()
        .map_err(|_| anyhow!("failed to parse TOML target"))?;
    prune_source_keys(source.as_table(), expected.as_table_mut());
    let actual = updated_text
        .parse::<DocumentMut>()
        .map_err(|_| anyhow!("failed to parse TOML pruned output"))?;
    if semantic_table(expected.as_table()) != semantic_table(actual.as_table()) {
        return Err(anyhow!(
            "pruned TOML output did not match source-owned key removal; normalize the target structure before retrying"
        ));
    }
    Ok(())
}

fn prune_source_keys(source: &dyn TableLike, target: &mut dyn TableLike) {
    for (key, source_item) in source.iter() {
        let remove_key = {
            let Some(target_item) = target.get_mut(key) else {
                continue;
            };
            if let (Some(source_table), Some(target_table)) =
                (source_item.as_table_like(), target_item.as_table_like_mut())
            {
                prune_source_keys(source_table, target_table);
                target_table.is_empty()
            } else {
                true
            }
        };
        if remove_key {
            target.remove(key);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SemanticToml {
    Table(Vec<(String, SemanticToml)>),
    Value(String),
}

fn semantic_table(table: &dyn TableLike) -> SemanticToml {
    let mut entries = table
        .iter()
        .filter_map(|(key, item)| {
            if let Some(child) = item.as_table_like() {
                Some((key.to_owned(), semantic_table(child)))
            } else if !item.is_none() {
                Some((key.to_owned(), SemanticToml::Value(item.to_string())))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    SemanticToml::Table(entries)
}

fn classify_state(request: &ManagedPathRequest) -> ManagedPathState {
    let target_metadata = match fs::symlink_metadata(&request.target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ManagedPathState::Absent,
        Err(_) => return ManagedPathState::Conflict,
    };
    if is_link_or_reparse(&target_metadata) {
        return if link_resolves_to(&request.target, &request.source) {
            ManagedPathState::ManagedLink
        } else {
            ManagedPathState::Conflict
        };
    }
    if paths_equal(&request.source, &request.target) {
        return ManagedPathState::IdenticalSource;
    }
    if request.skeleton.as_deref().is_some_and(|skeleton| {
        path_exists_without_following(skeleton) && paths_equal(skeleton, &request.target)
    }) {
        return ManagedPathState::SkeletonDefault;
    }
    ManagedPathState::Conflict
}

fn choose_managed_path_action(
    policy: ManagedPathPolicy,
    state: ManagedPathState,
) -> (ManagedPathAction, bool) {
    match state {
        ManagedPathState::ManagedLink => (ManagedPathAction::None, false),
        ManagedPathState::Absent => (ManagedPathAction::Create, false),
        _ if policy == ManagedPathPolicy::Takeover => (ManagedPathAction::Replace, true),
        _ if policy == ManagedPathPolicy::Strict => (ManagedPathAction::Block, false),
        ManagedPathState::IdenticalSource => (ManagedPathAction::Adopt, false),
        ManagedPathState::SkeletonDefault => (ManagedPathAction::Replace, true),
        ManagedPathState::Conflict => (ManagedPathAction::Block, false),
    }
}

fn link_resolves_to(link: &Path, source: &Path) -> bool {
    let Ok(raw_target) = fs::read_link(link) else {
        return false;
    };
    let joined = if raw_target.is_absolute() {
        raw_target
    } else {
        link.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(raw_target)
    };
    normalized_absolute(&joined)
        .is_some_and(|target| normalized_absolute(source).is_some_and(|source| source == target))
}

fn normalized_absolute(path: &Path) -> Option<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Some(canonical);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir().ok()?.join(path)
    };
    Some(lexical_normalize(&absolute, PathPlatform::current()))
}

fn path_exists_without_following(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TreeNode {
    Directory,
    File(Vec<u8>),
    Link(PathBuf),
    Other,
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    matches!(
        (tree_snapshot(left), tree_snapshot(right)),
        (Ok(Some(left)), Ok(Some(right))) if left == right
    )
}

fn tree_snapshot(root: &Path) -> io::Result<Option<Vec<(PathBuf, TreeNode)>>> {
    let metadata = fs::symlink_metadata(root)?;
    if is_link_or_reparse(&metadata) {
        return Ok(None);
    }
    if metadata.is_file() {
        return Ok(Some(vec![(
            PathBuf::from("."),
            TreeNode::File(fs::read(root)?),
        )]));
    }
    if !metadata.is_dir() {
        return Ok(None);
    }
    let mut records = Vec::new();
    snapshot_directory(root, root, &mut records)?;
    Ok(Some(records))
}

fn snapshot_directory(
    root: &Path,
    directory: &Path,
    records: &mut Vec<(PathBuf, TreeNode)>,
) -> io::Result<()> {
    let mut children = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let path = child.path();
        let relative = path
            .strip_prefix(root)
            .map_err(io::Error::other)?
            .to_path_buf();
        let metadata = fs::symlink_metadata(&path)?;
        if is_link_or_reparse(&metadata) {
            records.push((relative, TreeNode::Link(fs::read_link(path)?)));
        } else if metadata.is_dir() {
            records.push((relative, TreeNode::Directory));
            snapshot_directory(root, &path, records)?;
        } else if metadata.is_file() {
            records.push((relative, TreeNode::File(fs::read(path)?)));
        } else {
            records.push((relative, TreeNode::Other));
        }
    }
    Ok(())
}

fn is_link_or_reparse(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}
