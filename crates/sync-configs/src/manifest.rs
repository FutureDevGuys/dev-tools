use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value as JsonValue;
use serde_yaml_ng::Value as YamlValue;
use thiserror::Error;
use walkdir::WalkDir;

use crate::paths::{
    candidate_source_override, canonical_target_key, contains_glob, contains_parent_component,
    is_absolute_for, manifest_override_path, normalize_user_path, resolve_against,
    resolve_config_path, PathContext, PathError, PathPlatform,
};

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const PROFILE_MAP_SCHEMA_VERSION: u32 = 1;
pub const CLIENT_CAPABILITY_PRECONDITION_SCHEMA_VERSION: u32 = 1;
pub const RECONCILER_PROTOCOL: &str = "dev-tools-reconcile-v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    ManifestSchemaV1,
    EntriesDirectoryV1,
    StructuredOverlaysV1,
    TrustedHooksV1,
    PrivilegedRegularFileTargetsV1,
    ExternalReconcilerV1,
    ClientCapabilitiesPreconditionV1,
}

impl Capability {
    pub const ALL: [Self; 7] = [
        Self::ManifestSchemaV1,
        Self::EntriesDirectoryV1,
        Self::StructuredOverlaysV1,
        Self::TrustedHooksV1,
        Self::PrivilegedRegularFileTargetsV1,
        Self::ExternalReconcilerV1,
        Self::ClientCapabilitiesPreconditionV1,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ManifestSchemaV1 => "manifest-schema-v1",
            Self::EntriesDirectoryV1 => "entries-directory-v1",
            Self::StructuredOverlaysV1 => "structured-overlays-v1",
            Self::TrustedHooksV1 => "trusted-hooks-v1",
            Self::PrivilegedRegularFileTargetsV1 => "privileged-regular-file-targets-v1",
            Self::ExternalReconcilerV1 => "external-reconciler-v1",
            Self::ClientCapabilitiesPreconditionV1 => "client-capabilities-precondition-v1",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|capability| capability.as_str() == raw)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Symlink,
    Copy,
    JsonOverlay,
    TomlOverlay,
}

impl fmt::Display for Mode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Symlink => "symlink",
            Self::Copy => "copy",
            Self::JsonOverlay => "json_overlay",
            Self::TomlOverlay => "toml_overlay",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryStrategy {
    AsDirectory,
    Children,
    Recursive,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Privilege {
    User,
    Sudo,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ScriptFailurePolicy {
    Abort,
    Skip,
    Continue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CommentedTargetPolicy {
    Respect,
    Activate,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FileMode(u32);

impl FileMode {
    pub fn new(mode: u32) -> Result<Self, String> {
        if mode <= 0o7777 {
            Ok(Self(mode))
        } else {
            Err(format!(
                "permission mode must be between 0000 and 7777, got {mode:o}"
            ))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for FileMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:04o}", self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionPolicy {
    pub file: Option<FileMode>,
    pub dir: Option<FileMode>,
    pub recursive: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExclusiveSiblingGroup {
    pub under: Vec<String>,
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub name: String,
    pub source: PathBuf,
    pub target: PathBuf,
    pub mode: Mode,
    pub directory_strategy: DirectoryStrategy,
    pub profiles: Vec<String>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub ignore_files: Vec<String>,
    pub discover_ignore_files: bool,
    pub use_default_filters: bool,
    pub group: Option<String>,
    pub subgroup: Option<String>,
    pub permissions: Option<PermissionPolicy>,
    pub source_permissions: Option<PermissionPolicy>,
    pub pre_script: Option<String>,
    pub pre_script_on_fail: ScriptFailurePolicy,
    pub pre_script_privilege: Privilege,
    pub post_script: Option<String>,
    pub post_script_on_fail: ScriptFailurePolicy,
    pub post_script_privilege: Privilege,
    pub target_privilege: Privilege,
    pub target_owner: Option<String>,
    pub target_group: Option<String>,
    pub target_parent_mode: Option<FileMode>,
    pub reconcile_existing: bool,
    pub reconcile_removed_keys: bool,
    pub managed_overlay_id: Option<String>,
    pub commented_target_policy: CommentedTargetPolicy,
    pub exclusive_sibling_groups: Vec<ExclusiveSiblingGroup>,
}

impl Entry {
    pub fn scope_label(&self) -> String {
        match (&self.group, &self.subgroup) {
            (Some(group), Some(subgroup)) => format!("{group} / {subgroup}"),
            (Some(group), None) => group.clone(),
            (None, Some(subgroup)) => subgroup.clone(),
            (None, None) => "root".to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ReconcilerScope {
    User,
    System,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciler {
    pub name: String,
    pub executable: PathBuf,
    pub source: PathBuf,
    pub scope: ReconcilerScope,
    pub privilege: Privilege,
    pub protocol: String,
    pub profiles: Vec<String>,
    pub group: Option<String>,
    pub subgroup: Option<String>,
}

impl Reconciler {
    pub fn scope_label(&self) -> String {
        match (&self.group, &self.subgroup) {
            (Some(group), Some(subgroup)) => format!("{group} / {subgroup}"),
            (Some(group), None) => group.clone(),
            (None, Some(subgroup)) => subgroup.clone(),
            (None, None) => "root".to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum StatePrecondition {
    JsonFields {
        path: PathBuf,
        fields: BTreeMap<String, JsonValue>,
        remediation: String,
    },
    ClientCapabilities {
        schema_version: u32,
        required_capabilities: Vec<Capability>,
        remediation: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Manifest {
    pub path: PathBuf,
    pub override_path: Option<PathBuf>,
    pub schema_version: u32,
    pub required_capabilities: Vec<Capability>,
    pub default_mode: Mode,
    pub entries: Vec<Entry>,
    pub reconcilers: Vec<Reconciler>,
    pub state_preconditions: Vec<StatePrecondition>,
}

#[derive(Clone, Debug)]
pub struct LoadOptions {
    pub mode_override: Option<Mode>,
    pub include_manifest_override: bool,
    pub prefer_source_overrides: bool,
    pub path_context: PathContext,
}

impl LoadOptions {
    pub fn from_current_environment() -> Result<Self, ManifestError> {
        Ok(Self {
            mode_override: None,
            include_manifest_override: true,
            prefer_source_overrides: true,
            path_context: PathContext::from_current_environment()?,
        })
    }

    pub fn with_path_context(mut self, path_context: PathContext) -> Self {
        self.path_context = path_context;
        self
    }
}

impl Default for LoadOptions {
    fn default() -> Self {
        let path_context = PathContext::from_current_environment().unwrap_or_else(|_| {
            PathContext::new(
                PathPlatform::current(),
                PathBuf::from("."),
                None,
                std::env::temp_dir(),
                std::env::vars_os().collect(),
            )
        });
        Self {
            mode_override: None,
            include_manifest_override: true,
            prefer_source_overrides: true,
            path_context,
        }
    }
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error(transparent)]
    Path(#[from] PathError),
    #[error("cannot read {kind} {path}: {source}")]
    Read {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse {kind} {path}: {source}")]
    Yaml {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },
    #[error("invalid {kind} {path}: {message}")]
    Validation {
        kind: &'static str,
        path: PathBuf,
        message: String,
    },
    #[error("required state is absent or invalid at {path}. {remediation}")]
    InvalidState { path: PathBuf, remediation: String },
    #[error("required state at {path} does not match fields: {fields}. {remediation}")]
    StateMismatch {
        path: PathBuf,
        fields: String,
        remediation: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(default)]
    schema_version: Option<u32>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(default)]
    default_mode: Option<Mode>,
    #[serde(default)]
    entries_dir: Option<String>,
    #[serde(default)]
    entries: Vec<RawEntry>,
    #[serde(default)]
    reconcilers: Vec<RawReconciler>,
    #[serde(default)]
    state_preconditions: Vec<RawStatePrecondition>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntryFragment {
    entries: Vec<RawEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    #[serde(default)]
    name: Option<String>,
    source: String,
    target: String,
    #[serde(default)]
    mode: Option<Mode>,
    #[serde(default)]
    directory_strategy: Option<DirectoryStrategy>,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    ignore_files: Vec<String>,
    #[serde(default)]
    discover_ignore_files: Option<bool>,
    #[serde(default)]
    use_default_filters: Option<bool>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    subgroup: Option<String>,
    #[serde(default)]
    permissions: Option<RawPermissionPolicy>,
    #[serde(default)]
    source_permissions: Option<RawPermissionPolicy>,
    #[serde(default)]
    pre_script: Option<String>,
    #[serde(default)]
    pre_script_on_fail: Option<ScriptFailurePolicy>,
    #[serde(default)]
    pre_script_privilege: Option<Privilege>,
    #[serde(default)]
    post_script: Option<String>,
    #[serde(default)]
    post_script_on_fail: Option<ScriptFailurePolicy>,
    #[serde(default)]
    post_script_privilege: Option<Privilege>,
    #[serde(default)]
    target_privilege: Option<Privilege>,
    #[serde(default)]
    target_owner: Option<String>,
    #[serde(default)]
    target_group: Option<String>,
    #[serde(default)]
    target_parent_mode: Option<RawFileMode>,
    #[serde(default)]
    reconcile_existing: Option<bool>,
    #[serde(default)]
    reconcile_removed_keys: Option<bool>,
    #[serde(default)]
    managed_overlay_id: Option<String>,
    #[serde(default)]
    commented_target_policy: Option<CommentedTargetPolicy>,
    #[serde(default)]
    mutually_exclusive_sibling_keys: Vec<RawExclusiveSiblingGroup>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPermissionPolicy {
    #[serde(default)]
    file: Option<RawFileMode>,
    #[serde(default)]
    dir: Option<RawFileMode>,
    #[serde(default)]
    recursive: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum RawFileMode {
    String(String),
    Integer(i64),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExclusiveSiblingGroup {
    under: String,
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReconciler {
    name: String,
    executable: String,
    source: String,
    #[serde(default)]
    scope: Option<ReconcilerScope>,
    #[serde(default)]
    privilege: Option<Privilege>,
    protocol: String,
    #[serde(default)]
    profiles: Vec<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    subgroup: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RawStatePrecondition {
    JsonFields {
        path: String,
        fields: BTreeMap<String, JsonValue>,
        remediation: String,
    },
    ClientCapabilities {
        schema_version: u32,
        required_capabilities: Vec<String>,
        remediation: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfileMap {
    #[serde(default)]
    schema_version: Option<u32>,
    profiles: BTreeMap<String, YamlValue>,
}

struct PartialManifest {
    schema_version: u32,
    required_capabilities: Vec<Capability>,
    default_mode: Mode,
    entries: Vec<Entry>,
    reconcilers: Vec<Reconciler>,
    state_preconditions: Vec<StatePrecondition>,
}

fn read_yaml<T>(path: &Path, kind: &'static str) -> Result<T, ManifestError>
where
    T: for<'de> Deserialize<'de>,
{
    let text = fs::read_to_string(path).map_err(|source| ManifestError::Read {
        kind,
        path: path.to_path_buf(),
        source,
    })?;
    serde_yaml_ng::from_str(&text).map_err(|source| ManifestError::Yaml {
        kind,
        path: path.to_path_buf(),
        source,
    })
}

fn invalid(path: &Path, kind: &'static str, message: impl Into<String>) -> ManifestError {
    ManifestError::Validation {
        kind,
        path: path.to_path_buf(),
        message: message.into(),
    }
}

fn require_schema(
    path: &Path,
    kind: &'static str,
    actual: Option<u32>,
    supported: u32,
) -> Result<u32, ManifestError> {
    let actual = actual.unwrap_or(supported);
    if actual != supported {
        return Err(invalid(
            path,
            kind,
            format!("schema_version must be {supported}, got {actual}"),
        ));
    }
    Ok(actual)
}

fn parse_capabilities(
    path: &Path,
    kind: &'static str,
    raw: Vec<String>,
) -> Result<Vec<Capability>, ManifestError> {
    let mut seen = BTreeSet::new();
    let mut capabilities = Vec::with_capacity(raw.len());
    for token in raw {
        let token = token.trim();
        let Some(capability) = Capability::parse(token) else {
            return Err(invalid(
                path,
                kind,
                format!("unsupported required capability '{token}'"),
            ));
        };
        if !seen.insert(capability) {
            return Err(invalid(
                path,
                kind,
                format!("duplicate required capability '{token}'"),
            ));
        }
        capabilities.push(capability);
    }
    Ok(capabilities)
}

fn nonempty(
    path: &Path,
    kind: &'static str,
    field: &str,
    value: String,
) -> Result<String, ManifestError> {
    let value = value.trim();
    if value.is_empty() {
        Err(invalid(path, kind, format!("'{field}' must not be empty")))
    } else {
        Ok(value.to_owned())
    }
}

fn optional_nonempty(
    path: &Path,
    kind: &'static str,
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, ManifestError> {
    value
        .map(|value| nonempty(path, kind, field, value))
        .transpose()
}

fn normalized_strings(
    path: &Path,
    kind: &'static str,
    field: &str,
    values: Vec<String>,
) -> Result<Vec<String>, ManifestError> {
    let mut normalized = Vec::with_capacity(values.len());
    for value in values {
        let value = value.trim();
        if !value.is_empty() {
            normalized.push(value.to_owned());
        }
    }
    if field == "keys" && normalized.is_empty() {
        return Err(invalid(path, kind, "'keys' must not be empty"));
    }
    Ok(normalized)
}

fn parse_file_mode(
    path: &Path,
    kind: &'static str,
    field: &str,
    raw: RawFileMode,
) -> Result<FileMode, ManifestError> {
    let raw = match raw {
        RawFileMode::String(raw) => nonempty(path, kind, field, raw)?,
        RawFileMode::Integer(raw) if raw >= 0 => raw.to_string(),
        RawFileMode::Integer(raw) => {
            return Err(invalid(
                path,
                kind,
                format!("'{field}' must be a non-negative octal permission, got {raw}"),
            ))
        }
    };
    let mode = u32::from_str_radix(&raw, 8).map_err(|_| {
        invalid(
            path,
            kind,
            format!("'{field}' must be a valid octal permission, got {raw:?}"),
        )
    })?;
    FileMode::new(mode).map_err(|message| invalid(path, kind, format!("'{field}': {message}")))
}

fn parse_permission_policy(
    path: &Path,
    field: &str,
    raw: Option<RawPermissionPolicy>,
) -> Result<Option<PermissionPolicy>, ManifestError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let file = raw
        .file
        .map(|mode| parse_file_mode(path, "entry", &format!("{field}.file"), mode))
        .transpose()?;
    let dir = raw
        .dir
        .map(|mode| parse_file_mode(path, "entry", &format!("{field}.dir"), mode))
        .transpose()?;
    if file.is_none() && dir.is_none() {
        return Err(invalid(
            path,
            "entry",
            format!("'{field}' must define at least one of 'file' or 'dir'"),
        ));
    }
    Ok(Some(PermissionPolicy {
        file,
        dir,
        recursive: raw.recursive.unwrap_or(false),
    }))
}

fn parse_toml_key_path(raw: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut index = 0;
    let bytes = raw.as_bytes();
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index == bytes.len() {
            break;
        }
        let part = match bytes[index] {
            b'"' => {
                let start = index;
                index += 1;
                let mut escaped = false;
                loop {
                    if index >= bytes.len() {
                        return Err("unterminated TOML basic string key".to_owned());
                    }
                    let byte = bytes[index];
                    index += 1;
                    if escaped {
                        escaped = false;
                    } else if byte == b'\\' {
                        escaped = true;
                    } else if byte == b'"' {
                        break;
                    }
                }
                serde_json::from_str::<String>(&raw[start..index])
                    .map_err(|error| format!("invalid TOML basic string key: {error}"))?
            }
            b'\'' => {
                index += 1;
                let start = index;
                while index < bytes.len() && bytes[index] != b'\'' {
                    index += 1;
                }
                if index == bytes.len() {
                    return Err("unterminated TOML literal string key".to_owned());
                }
                let part = raw[start..index].to_owned();
                index += 1;
                part
            }
            _ => {
                let start = index;
                while index < bytes.len() && bytes[index] != b'.' {
                    index += 1;
                }
                let part = raw[start..index].trim();
                if part.is_empty() {
                    return Err("empty TOML key segment".to_owned());
                }
                part.to_owned()
            }
        };
        parts.push(part);
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index < bytes.len() {
            if bytes[index] != b'.' {
                return Err("expected '.' in TOML key path".to_owned());
            }
            index += 1;
            if index == bytes.len() {
                return Err("empty TOML key segment".to_owned());
            }
        }
    }
    if parts.is_empty() {
        Err("empty TOML key path".to_owned())
    } else {
        Ok(parts)
    }
}

fn parse_exclusive_groups(
    path: &Path,
    groups: Vec<RawExclusiveSiblingGroup>,
) -> Result<Vec<ExclusiveSiblingGroup>, ManifestError> {
    groups
        .into_iter()
        .enumerate()
        .map(|(index, group)| {
            let under = nonempty(path, "entry", "mutually_exclusive_sibling_keys.under", group.under)?;
            let under = parse_toml_key_path(&under).map_err(|message| {
                invalid(
                    path,
                    "entry",
                    format!("mutually exclusive sibling group {index} has invalid 'under': {message}"),
                )
            })?;
            let keys = normalized_strings(path, "entry", "keys", group.keys)?;
            let unique: BTreeSet<_> = keys.iter().collect();
            if keys.len() < 2 || unique.len() != keys.len() {
                return Err(invalid(
                    path,
                    "entry",
                    format!("mutually exclusive sibling group {index} requires at least two unique keys"),
                ));
            }
            if keys.iter().any(|key| key.contains('.') || key == "*") {
                return Err(invalid(
                    path,
                    "entry",
                    format!("mutually exclusive sibling group {index} keys must be direct siblings"),
                ));
            }
            Ok(ExclusiveSiblingGroup { under, keys })
        })
        .collect()
}

fn parse_entry(
    raw: RawEntry,
    manifest_path: &Path,
    config_dir: &Path,
    default_mode: Mode,
    context: &PathContext,
) -> Result<Entry, ManifestError> {
    let source_raw = nonempty(manifest_path, "entry", "source", raw.source)?;
    let target_raw = nonempty(manifest_path, "entry", "target", raw.target)?;
    if contains_glob(&target_raw) {
        return Err(invalid(
            manifest_path,
            "entry",
            "'target' does not support glob patterns; only 'source' may include globs",
        ));
    }
    let mode = raw.mode.unwrap_or(default_mode);
    let directory_strategy = raw
        .directory_strategy
        .unwrap_or(DirectoryStrategy::AsDirectory);
    let profiles = normalized_strings(manifest_path, "entry", "profiles", raw.profiles)?;
    let include = normalized_strings(manifest_path, "entry", "include", raw.include)?;
    let exclude = normalized_strings(manifest_path, "entry", "exclude", raw.exclude)?;
    let ignore_files =
        normalized_strings(manifest_path, "entry", "ignore_files", raw.ignore_files)?;
    let discover_ignore_files = raw.discover_ignore_files.unwrap_or(true);
    let use_default_filters = raw.use_default_filters.unwrap_or(true);
    let permissions = parse_permission_policy(manifest_path, "permissions", raw.permissions)?;
    let source_permissions =
        parse_permission_policy(manifest_path, "source_permissions", raw.source_permissions)?;
    let target_privilege = raw.target_privilege.unwrap_or(Privilege::User);
    let target_owner = optional_nonempty(manifest_path, "entry", "target_owner", raw.target_owner)?;
    let target_group = optional_nonempty(manifest_path, "entry", "target_group", raw.target_group)?;
    let target_parent_mode = raw
        .target_parent_mode
        .map(|mode| parse_file_mode(manifest_path, "entry", "target_parent_mode", mode))
        .transpose()?;
    let pre_script = optional_nonempty(manifest_path, "entry", "pre_script", raw.pre_script)?;
    let pre_script_on_fail = raw.pre_script_on_fail.unwrap_or(ScriptFailurePolicy::Abort);
    let pre_script_privilege = raw.pre_script_privilege.unwrap_or(Privilege::User);
    let post_script = optional_nonempty(manifest_path, "entry", "post_script", raw.post_script)?;
    let post_script_on_fail = raw
        .post_script_on_fail
        .unwrap_or(ScriptFailurePolicy::Continue);
    let post_script_privilege = raw.post_script_privilege.unwrap_or(Privilege::User);
    if pre_script.is_none() && pre_script_privilege != Privilege::User {
        return Err(invalid(
            manifest_path,
            "entry",
            "'pre_script_privilege' requires pre_script",
        ));
    }
    if post_script.is_none() && post_script_privilege != Privilege::User {
        return Err(invalid(
            manifest_path,
            "entry",
            "'post_script_privilege' requires post_script",
        ));
    }
    let reconcile_existing = raw.reconcile_existing.unwrap_or(false);
    if reconcile_existing && mode != Mode::Copy {
        return Err(invalid(
            manifest_path,
            "entry",
            "'reconcile_existing' is supported only for copy mode",
        ));
    }
    let reconcile_removed_keys = raw.reconcile_removed_keys.unwrap_or(false);
    let managed_overlay_id = optional_nonempty(
        manifest_path,
        "entry",
        "managed_overlay_id",
        raw.managed_overlay_id,
    )?;
    if reconcile_removed_keys {
        if !matches!(mode, Mode::JsonOverlay | Mode::TomlOverlay) {
            return Err(invalid(
                manifest_path,
                "entry",
                "'reconcile_removed_keys' is supported only for overlay modes",
            ));
        }
        if managed_overlay_id.is_none() {
            return Err(invalid(
                manifest_path,
                "entry",
                "'managed_overlay_id' is required when reconcile_removed_keys is enabled",
            ));
        }
    }
    let comment_policy_was_explicit = raw.commented_target_policy.is_some();
    let commented_target_policy = raw
        .commented_target_policy
        .unwrap_or(CommentedTargetPolicy::Respect);
    let exclusive_sibling_groups =
        parse_exclusive_groups(manifest_path, raw.mutually_exclusive_sibling_keys)?;
    if (comment_policy_was_explicit || !exclusive_sibling_groups.is_empty())
        && mode != Mode::TomlOverlay
    {
        return Err(invalid(
            manifest_path,
            "entry",
            "comment and mutually-exclusive-key policies are supported only for toml_overlay",
        ));
    }

    let source = resolve_against(&source_raw, config_dir, context)?;
    let target = normalize_user_path(&target_raw, context)?;
    let privileged_metadata =
        target_owner.is_some() || target_group.is_some() || target_parent_mode.is_some();
    if target_privilege == Privilege::User && privileged_metadata {
        return Err(invalid(
            manifest_path,
            "entry",
            "target_owner, target_group, and target_parent_mode require target_privilege: sudo",
        ));
    }
    if target_privilege == Privilege::Sudo {
        if context.platform == PathPlatform::Windows {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo is unavailable on Windows",
            ));
        }
        if mode != Mode::Copy {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo initially supports only mode: copy",
            ));
        }
        if contains_glob(&source_raw) {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo requires a literal source path",
            ));
        }
        if !is_absolute_for(&target, context.platform) || contains_parent_component(&target_raw) {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo requires a literal absolute target path",
            ));
        }
        let uses_filters = !include.is_empty()
            || !exclude.is_empty()
            || !ignore_files.is_empty()
            || !discover_ignore_files
            || !use_default_filters;
        if directory_strategy != DirectoryStrategy::AsDirectory || uses_filters {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo does not support directory expansion or filters",
            ));
        }
        let Some(permission_policy) = permissions.as_ref() else {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo requires permissions.file",
            ));
        };
        if permission_policy.file.is_none() {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo requires permissions.file",
            ));
        }
        if permission_policy.dir.is_some() || permission_policy.recursive {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo supports only permissions.file",
            ));
        }
        if source_permissions.is_some() {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo does not support source_permissions",
            ));
        }
        if target_owner.is_none() || target_group.is_none() {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo requires target_owner and target_group",
            ));
        }
        if target_parent_mode.is_none() {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo requires target_parent_mode",
            ));
        }
        if pre_script.is_some() || post_script.is_some() {
            return Err(invalid(
                manifest_path,
                "entry",
                "target_privilege: sudo does not support per-entry scripts",
            ));
        }
    }
    if matches!(mode, Mode::Symlink | Mode::JsonOverlay | Mode::TomlOverlay)
        && permissions.is_some()
    {
        return Err(invalid(
            manifest_path,
            "entry",
            "'permissions' is only supported for copy mode; use 'source_permissions' for a symlinked source",
        ));
    }
    let group = optional_nonempty(manifest_path, "entry", "group", raw.group)?;
    let subgroup = optional_nonempty(manifest_path, "entry", "subgroup", raw.subgroup)?;
    let name = match raw.name {
        Some(name) => nonempty(manifest_path, "entry", "name", name)?,
        None => target.to_string_lossy().into_owned(),
    };
    Ok(Entry {
        name,
        source,
        target,
        mode,
        directory_strategy,
        profiles,
        include,
        exclude,
        ignore_files,
        discover_ignore_files,
        use_default_filters,
        group,
        subgroup,
        permissions,
        source_permissions,
        pre_script,
        pre_script_on_fail,
        pre_script_privilege,
        post_script,
        post_script_on_fail,
        post_script_privilege,
        target_privilege,
        target_owner,
        target_group,
        target_parent_mode,
        reconcile_existing,
        reconcile_removed_keys,
        managed_overlay_id,
        commented_target_policy,
        exclusive_sibling_groups,
    })
}

fn parse_reconciler(
    raw: RawReconciler,
    manifest_path: &Path,
    config_dir: &Path,
    context: &PathContext,
) -> Result<Reconciler, ManifestError> {
    let name = nonempty(manifest_path, "reconciler", "name", raw.name)?;
    let executable_raw = nonempty(manifest_path, "reconciler", "executable", raw.executable)?;
    let executable = normalize_user_path(&executable_raw, context)?;
    if !is_absolute_for(&executable, context.platform) {
        return Err(invalid(
            manifest_path,
            "reconciler",
            format!("'{name}' requires an absolute executable path"),
        ));
    }
    let source_raw = nonempty(manifest_path, "reconciler", "source", raw.source)?;
    let source = resolve_against(&source_raw, config_dir, context)?;
    if raw.protocol != RECONCILER_PROTOCOL {
        return Err(invalid(
            manifest_path,
            "reconciler",
            format!("'{name}' has unsupported protocol '{}'", raw.protocol),
        ));
    }
    let privilege = raw.privilege.unwrap_or(Privilege::User);
    if privilege == Privilege::Sudo && context.platform == PathPlatform::Windows {
        return Err(invalid(
            manifest_path,
            "reconciler",
            "reconciler privilege: sudo is unavailable on Windows",
        ));
    }
    Ok(Reconciler {
        name,
        executable,
        source,
        scope: raw.scope.unwrap_or(ReconcilerScope::User),
        privilege,
        protocol: raw.protocol,
        profiles: normalized_strings(manifest_path, "reconciler", "profiles", raw.profiles)?,
        group: optional_nonempty(manifest_path, "reconciler", "group", raw.group)?,
        subgroup: optional_nonempty(manifest_path, "reconciler", "subgroup", raw.subgroup)?,
    })
}

fn parse_precondition(
    raw: RawStatePrecondition,
    manifest_path: &Path,
    context: &PathContext,
) -> Result<StatePrecondition, ManifestError> {
    match raw {
        RawStatePrecondition::JsonFields {
            path,
            fields,
            remediation,
        } => {
            if fields.is_empty() {
                return Err(invalid(
                    manifest_path,
                    "state precondition",
                    "json_fields requires non-empty fields",
                ));
            }
            Ok(StatePrecondition::JsonFields {
                path: normalize_user_path(
                    &nonempty(manifest_path, "state precondition", "path", path)?,
                    context,
                )?,
                fields,
                remediation: nonempty(
                    manifest_path,
                    "state precondition",
                    "remediation",
                    remediation,
                )?,
            })
        }
        RawStatePrecondition::ClientCapabilities {
            schema_version,
            required_capabilities,
            remediation,
        } => {
            if schema_version != CLIENT_CAPABILITY_PRECONDITION_SCHEMA_VERSION {
                return Err(invalid(
                    manifest_path,
                    "state precondition",
                    format!(
                        "client_capabilities schema_version must be {}, got {schema_version}",
                        CLIENT_CAPABILITY_PRECONDITION_SCHEMA_VERSION
                    ),
                ));
            }
            let capabilities = parse_capabilities(
                manifest_path,
                "client capability precondition",
                required_capabilities,
            )?;
            if capabilities.is_empty() {
                return Err(invalid(
                    manifest_path,
                    "client capability precondition",
                    "required_capabilities must not be empty",
                ));
            }
            Ok(StatePrecondition::ClientCapabilities {
                schema_version,
                required_capabilities: capabilities,
                remediation: nonempty(
                    manifest_path,
                    "client capability precondition",
                    "remediation",
                    remediation,
                )?,
            })
        }
    }
}

fn load_fragment_entries(
    entries_dir: &Path,
    root_path: &Path,
    config_dir: &Path,
    default_mode: Mode,
    context: &PathContext,
) -> Result<Vec<Entry>, ManifestError> {
    if !entries_dir.exists() {
        return Err(invalid(
            root_path,
            "manifest",
            format!("entries_dir does not exist: {}", entries_dir.display()),
        ));
    }
    if !entries_dir.is_dir() {
        return Err(invalid(
            root_path,
            "manifest",
            format!("entries_dir is not a directory: {}", entries_dir.display()),
        ));
    }
    let mut files = Vec::new();
    for item in WalkDir::new(entries_dir).follow_links(false) {
        let item = item.map_err(|source| {
            invalid(
                root_path,
                "manifest",
                format!(
                    "cannot traverse entries_dir {}: {source}",
                    entries_dir.display()
                ),
            )
        })?;
        if !item.file_type().is_file() {
            continue;
        }
        if matches!(
            item.path().extension().and_then(|value| value.to_str()),
            Some("yaml" | "yml")
        ) {
            files.push(item.into_path());
        }
    }
    files.sort();
    let mut entries = Vec::new();
    for path in files {
        let fragment: RawEntryFragment = read_yaml(&path, "entry fragment")?;
        for raw in fragment.entries {
            entries.push(parse_entry(raw, &path, config_dir, default_mode, context)?);
        }
    }
    Ok(entries)
}

fn load_partial(path: &Path, options: &LoadOptions) -> Result<PartialManifest, ManifestError> {
    let raw: RawManifest = read_yaml(path, "manifest")?;
    let schema_version = require_schema(
        path,
        "manifest",
        raw.schema_version,
        MANIFEST_SCHEMA_VERSION,
    )?;
    let required_capabilities = parse_capabilities(path, "manifest", raw.required_capabilities)?;
    let default_mode = options
        .mode_override
        .or(raw.default_mode)
        .unwrap_or(Mode::Symlink);
    let config_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut entries = Vec::new();
    for raw in raw.entries {
        entries.push(parse_entry(
            raw,
            path,
            config_dir,
            default_mode,
            &options.path_context,
        )?);
    }
    if let Some(entries_dir) = raw.entries_dir {
        let entries_dir = resolve_against(&entries_dir, config_dir, &options.path_context)?;
        entries.extend(load_fragment_entries(
            &entries_dir,
            path,
            config_dir,
            default_mode,
            &options.path_context,
        )?);
    }
    let mut reconciler_names = BTreeSet::new();
    let mut reconcilers = Vec::new();
    for raw in raw.reconcilers {
        let reconciler = parse_reconciler(raw, path, config_dir, &options.path_context)?;
        if !reconciler_names.insert(reconciler.name.clone()) {
            return Err(invalid(
                path,
                "manifest",
                format!("duplicate reconciler name: {}", reconciler.name),
            ));
        }
        reconcilers.push(reconciler);
    }
    let state_preconditions = raw
        .state_preconditions
        .into_iter()
        .map(|raw| parse_precondition(raw, path, &options.path_context))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PartialManifest {
        schema_version,
        required_capabilities,
        default_mode,
        entries,
        reconcilers,
        state_preconditions,
    })
}

fn entries_equivalent(left: &Entry, right: &Entry) -> bool {
    left.source == right.source
        && left.target == right.target
        && left.mode == right.mode
        && left.permissions == right.permissions
        && left.source_permissions == right.source_permissions
        && left.target_privilege == right.target_privilege
        && left.target_owner == right.target_owner
        && left.target_group == right.target_group
        && left.target_parent_mode == right.target_parent_mode
        && left.reconcile_existing == right.reconcile_existing
        && left.reconcile_removed_keys == right.reconcile_removed_keys
        && left.managed_overlay_id == right.managed_overlay_id
        && left.commented_target_policy == right.commented_target_policy
        && left.exclusive_sibling_groups == right.exclusive_sibling_groups
}

pub fn deduplicate_and_validate_targets(
    entries: Vec<Entry>,
    context: &PathContext,
    manifest_path: &Path,
) -> Result<Vec<Entry>, ManifestError> {
    let mut positions: BTreeMap<PathBuf, usize> = BTreeMap::new();
    let mut deduplicated: Vec<Entry> = Vec::new();
    for entry in entries {
        let key = canonical_target_key(&entry.target, context);
        if let Some(position) = positions.get(&key).copied() {
            if entries_equivalent(&deduplicated[position], &entry) {
                continue;
            }
            return Err(invalid(
                manifest_path,
                "manifest",
                format!(
                    "duplicate target conflict for {} between '{}' and '{}'",
                    entry.target.display(),
                    deduplicated[position].name,
                    entry.name
                ),
            ));
        }
        positions.insert(key, deduplicated.len());
        deduplicated.push(entry);
    }
    Ok(deduplicated)
}

fn merge_manifest_entries(
    base: Vec<Entry>,
    overrides: Vec<Entry>,
    manifest_path: &Path,
) -> Result<Vec<Entry>, ManifestError> {
    let mut override_positions = BTreeMap::new();
    for (index, entry) in overrides.iter().enumerate() {
        if override_positions
            .insert(entry.source.clone(), index)
            .is_some()
        {
            return Err(invalid(
                manifest_path,
                "manifest override",
                format!("duplicate override source: {}", entry.source.display()),
            ));
        }
    }
    let mut consumed = BTreeSet::new();
    let mut merged = Vec::with_capacity(base.len() + overrides.len());
    for entry in base {
        if let Some(index) = override_positions.get(&entry.source).copied() {
            if consumed.insert(index) {
                merged.push(overrides[index].clone());
                continue;
            }
        }
        merged.push(entry);
    }
    for (index, entry) in overrides.into_iter().enumerate() {
        if !consumed.contains(&index) {
            merged.push(entry);
        }
    }
    Ok(merged)
}

fn apply_source_overrides(entries: &mut [Entry]) {
    let selected: BTreeSet<PathBuf> = entries.iter().map(|entry| entry.source.clone()).collect();
    for entry in entries {
        if entry.target_privilege != Privilege::User {
            continue;
        }
        let candidate = candidate_source_override(&entry.source);
        if candidate != entry.source && candidate.exists() && !selected.contains(&candidate) {
            entry.source = candidate;
        }
    }
}

fn resolve_input_path(path: &Path, context: &PathContext) -> Result<PathBuf, ManifestError> {
    if let Some(path) = path.to_str() {
        return Ok(resolve_config_path(path, context)?);
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(context.cwd.join(path))
    }
}

pub fn load_manifest(path: &Path, options: &LoadOptions) -> Result<Manifest, ManifestError> {
    let path = resolve_input_path(path, &options.path_context)?;
    let base = load_partial(&path, options)?;
    let mut required_capabilities = base.required_capabilities;
    let mut entries = base.entries;
    let mut reconcilers = base.reconcilers;
    let mut state_preconditions = base.state_preconditions;
    let override_candidate = manifest_override_path(&path);
    let override_path = if options.include_manifest_override && override_candidate.exists() {
        let override_manifest = load_partial(&override_candidate, options)?;
        entries = merge_manifest_entries(entries, override_manifest.entries, &override_candidate)?;
        let mut names: BTreeSet<String> = reconcilers
            .iter()
            .map(|reconciler| reconciler.name.clone())
            .collect();
        for reconciler in override_manifest.reconcilers {
            if !names.insert(reconciler.name.clone()) {
                return Err(invalid(
                    &override_candidate,
                    "manifest override",
                    format!(
                        "reconciler names must be unique across manifests: {}",
                        reconciler.name
                    ),
                ));
            }
            reconcilers.push(reconciler);
        }
        for capability in override_manifest.required_capabilities {
            if !required_capabilities.contains(&capability) {
                required_capabilities.push(capability);
            }
        }
        state_preconditions.extend(override_manifest.state_preconditions);
        Some(override_candidate)
    } else {
        None
    };
    if options.prefer_source_overrides {
        apply_source_overrides(&mut entries);
    }
    Ok(Manifest {
        path,
        override_path,
        schema_version: base.schema_version,
        required_capabilities,
        default_mode: base.default_mode,
        entries,
        reconcilers,
        state_preconditions,
    })
}

fn profile_list(
    value: &YamlValue,
    profile_map_path: &Path,
    host_profile: &str,
) -> Result<Vec<String>, ManifestError> {
    let sequence = value.as_sequence().ok_or_else(|| {
        invalid(
            profile_map_path,
            "profile map",
            format!("selection '{host_profile}' must be a list of strings"),
        )
    })?;
    let mut profiles = Vec::new();
    let mut seen = BTreeSet::new();
    for value in sequence {
        let Some(profile) = value.as_str() else {
            return Err(invalid(
                profile_map_path,
                "profile map",
                format!("selection '{host_profile}' must be a list of strings"),
            ));
        };
        let profile = profile.trim();
        if !profile.is_empty() && seen.insert(profile.to_owned()) {
            profiles.push(profile.to_owned());
        }
    }
    Ok(profiles)
}

pub fn load_profile_map(
    path: &Path,
    host_profile: &str,
    selection_field: Option<&str>,
    context: &PathContext,
) -> Result<Vec<String>, ManifestError> {
    let path = resolve_input_path(path, context)?;
    let raw: RawProfileMap = read_yaml(&path, "profile map")?;
    require_schema(
        &path,
        "profile map",
        raw.schema_version,
        PROFILE_MAP_SCHEMA_VERSION,
    )?;
    let selected = raw.profiles.get(host_profile).ok_or_else(|| {
        invalid(
            &path,
            "profile map",
            format!("unknown profile-map selection: {host_profile}"),
        )
    })?;
    let selected = if let Some(field) = selection_field {
        let mapping = selected.as_mapping().ok_or_else(|| {
            invalid(
                &path,
                "profile map",
                format!("selection '{host_profile}' has no '{field}' field"),
            )
        })?;
        mapping
            .get(YamlValue::String(field.to_owned()))
            .ok_or_else(|| {
                invalid(
                    &path,
                    "profile map",
                    format!("selection '{host_profile}' has no '{field}' field"),
                )
            })?
    } else {
        selected
    };
    profile_list(selected, &path, host_profile)
}

pub fn select_entries_for_profiles<'a>(
    entries: &'a [Entry],
    active_profiles: &[String],
) -> Vec<&'a Entry> {
    let active: BTreeSet<&str> = active_profiles
        .iter()
        .map(String::as_str)
        .filter(|profile| !profile.trim().is_empty())
        .collect();
    entries
        .iter()
        .filter(|entry| {
            if active.is_empty() {
                entry.profiles.is_empty()
            } else {
                entry
                    .profiles
                    .iter()
                    .any(|profile| active.contains(profile.as_str()))
            }
        })
        .collect()
}

pub fn select_reconcilers_for_profiles<'a>(
    reconcilers: &'a [Reconciler],
    active_profiles: &[String],
) -> Vec<&'a Reconciler> {
    let active: BTreeSet<&str> = active_profiles
        .iter()
        .map(String::as_str)
        .filter(|profile| !profile.trim().is_empty())
        .collect();
    reconcilers
        .iter()
        .filter(|reconciler| {
            if active.is_empty() {
                reconciler.profiles.is_empty()
            } else {
                reconciler
                    .profiles
                    .iter()
                    .any(|profile| active.contains(profile.as_str()))
            }
        })
        .collect()
}

pub fn collect_profile_names(manifest: &Manifest) -> Vec<String> {
    manifest
        .entries
        .iter()
        .flat_map(|entry| entry.profiles.iter())
        .chain(
            manifest
                .reconcilers
                .iter()
                .flat_map(|reconciler| reconciler.profiles.iter()),
        )
        .filter(|profile| !profile.trim().is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub fn check_state_preconditions(manifest: &Manifest) -> Result<(), ManifestError> {
    for precondition in &manifest.state_preconditions {
        match precondition {
            StatePrecondition::JsonFields {
                path,
                fields,
                remediation,
            } => {
                let text = fs::read_to_string(path).map_err(|_| ManifestError::InvalidState {
                    path: path.clone(),
                    remediation: remediation.clone(),
                })?;
                let payload: JsonValue =
                    serde_json::from_str(&text).map_err(|_| ManifestError::InvalidState {
                        path: path.clone(),
                        remediation: remediation.clone(),
                    })?;
                let Some(payload) = payload.as_object() else {
                    return Err(ManifestError::InvalidState {
                        path: path.clone(),
                        remediation: remediation.clone(),
                    });
                };
                let mismatches: Vec<&str> = fields
                    .iter()
                    .filter_map(|(field, expected)| {
                        if payload.get(field).is_some_and(|actual| actual == expected) {
                            None
                        } else {
                            Some(field.as_str())
                        }
                    })
                    .collect();
                if !mismatches.is_empty() {
                    return Err(ManifestError::StateMismatch {
                        path: path.clone(),
                        fields: mismatches.join(", "),
                        remediation: remediation.clone(),
                    });
                }
            }
            StatePrecondition::ClientCapabilities {
                required_capabilities,
                remediation,
                ..
            } => {
                if let Some(missing) = required_capabilities
                    .iter()
                    .find(|required| !Capability::ALL.contains(required))
                {
                    return Err(invalid(
                        &manifest.path,
                        "client capability precondition",
                        format!("missing capability '{missing}'. {remediation}"),
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod platform_tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn windows_manifest_rejects_a_sudo_reconciler() {
        let raw: RawReconciler = serde_yaml_ng::from_str(
            r#"
name: system-owner
executable: 'C:\Program Files\owner\owner.exe'
source: 'C:\desired\owner.toml'
privilege: sudo
protocol: dev-tools-reconcile-v1
"#,
        )
        .expect("reconciler fixture");
        let context = PathContext::new(
            PathPlatform::Windows,
            PathBuf::from(r"C:\workspace"),
            Some(PathBuf::from(r"C:\Users\operator")),
            PathBuf::from(r"D:\Temp"),
            BTreeMap::new(),
        );

        let error = parse_reconciler(
            raw,
            Path::new(r"C:\workspace\manifest.yaml"),
            Path::new(r"C:\workspace"),
            &context,
        )
        .expect_err("sudo reconciler must be rejected on Windows");

        assert!(
            error
                .to_string()
                .contains("reconciler privilege: sudo is unavailable on Windows"),
            "{error}"
        );
    }
}
