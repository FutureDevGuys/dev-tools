//! Public operations backing the standalone structured-overlay and managed-path commands.

use std::env;
use std::fmt;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

use crate::overlay::json::{overlay_json_file, JsonOverlayOptions};
use crate::overlay::ownership;
use crate::overlay::toml::{
    overlay_toml_file, remove_source_owned_text, CommentedTargetPolicy, TomlConflictPolicy,
    TomlOverlayOptions,
};
use crate::overlay::OverlayResult;
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
    #[cfg(target_os = "linux")]
    if !request.dry_run && !request.check {
        use crate::overlay::transaction::{Operation, Transaction};
        // Remove is target-only, irrespective of inactive receipt flags.
        let mut transaction = Transaction::begin(
            &request.source,
            &request.target,
            Operation::TomlRemove,
            None,
        )?;
        if transaction.is_missing() {
            return Ok(OverlayResult {
                changed: transaction.recovered(),
                ..OverlayResult::default()
            });
        }
        let source_text = transaction.source_text()?.to_owned();
        let target_text = transaction.target_text()?;
        let mut result = remove_source_owned_text(&source_text, &target_text)?;
        result.materialized_symlink = result.changed && transaction.is_symlink();
        transaction.publish(&mut result, true, None)?;
        return Ok(result);
    }
    #[cfg(target_os = "linux")]
    crate::overlay::transaction::ensure_no_pending(&request.target)?;
    ownership::validate_real_parent_chain(&request.target, "TOML removal target")?;
    let Some(metadata) = optional_metadata(&request.target)? else {
        return Ok(OverlayResult::default());
    };
    if !metadata.is_file() && !is_link_or_reparse(&metadata) {
        return Err(anyhow!("TOML removal target must be a regular file path"));
    }
    let source_text =
        fs::read_to_string(&request.source).context("cannot read TOML removal source")?;
    let target_text =
        fs::read_to_string(&request.target).context("cannot read TOML removal target")?;
    let mut result = remove_source_owned_text(&source_text, &target_text)?;
    result.materialized_symlink = result.changed && is_link_or_reparse(&metadata);
    if request.dry_run || request.check || !result.changed {
        return Ok(result);
    }
    Err(anyhow!(
        "durable overlay publication is currently available only on Linux"
    ))
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
