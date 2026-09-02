use crate::cli::{EngineMode, UiMode};
use crate::completions::registry::{Registry, RegistryProvider, RegistryTool};
use crate::updaters::{
    builtin_catalog, builtin_windows_foundations, BuiltinReportParser, HostOs, PrivilegeMode,
};
use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    pub enabled: bool,
    pub windows_foundations: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct TaskPolicy {
    pub timeout: Duration,
    pub retries: u32,
    pub retry_backoff: Duration,
}

impl TaskPolicy {
    pub fn new(timeout_secs: u64, retries: u32, retry_backoff_secs: u64) -> Self {
        Self {
            timeout: Duration::from_secs(timeout_secs.max(1)),
            retries,
            retry_backoff: Duration::from_secs(retry_backoff_secs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoggingConfig {
    pub run_dir: PathBuf,
    pub max_in_memory_lines: usize,
    pub filter_progress_noise: bool,
    pub timestamps: bool,
    pub task_colors: bool,
}

#[derive(Clone, Debug)]
pub struct UiConfig {
    pub mode: UiMode,
    pub persist_until_exit: bool,
    pub show_global_log: bool,
    pub max_events_per_frame: usize,
    pub dashboard_quit_behavior: DashboardQuitBehavior,
    pub quit_cancel_grace_ms: u64,
    pub mouse_row_stride: MouseRowStrideMode,
    pub note_verbosity: NoteVerbosity,
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    pub mode: EngineMode,
    pub jobs: String,
    pub fail_fast: bool,
}

#[derive(Clone, Debug)]
pub struct InstallConfig {
    pub auto_update: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InteractiveExecutionMode {
    AutoFallback,
    Capture,
    DirectTty,
}

impl InteractiveExecutionMode {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "auto_fallback" | "auto" => Some(Self::AutoFallback),
            "capture" => Some(Self::Capture),
            "direct_tty" | "direct" => Some(Self::DirectTty),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct InteractiveRuntimeConfig {
    pub mode: InteractiveExecutionMode,
    pub stall_seconds: u64,
    pub max_line_bytes: usize,
    pub max_capture_bytes: usize,
    pub retry_once: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DashboardQuitBehavior {
    CancelAll,
    Detach,
}

impl DashboardQuitBehavior {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "cancel_all" | "cancel" => Some(Self::CancelAll),
            "detach" => Some(Self::Detach),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseRowStrideMode {
    Auto,
    One,
    Two,
}

impl MouseRowStrideMode {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "1" | "one" => Some(Self::One),
            "2" | "two" => Some(Self::Two),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteVerbosity {
    Failures,
    All,
    None,
}

impl NoteVerbosity {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "failures" | "failure_only" | "failure" => Some(Self::Failures),
            "all" => Some(Self::All),
            "none" | "off" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UpdaterTaskConfig {
    pub id: String,
    pub label: String,
    pub os: Vec<String>,
    pub detect_mode: UpdaterDetectionMode,
    pub detect_any: Vec<String>,
    pub detect_all: Vec<String>,
    pub detect_all_windows: Vec<String>,
    pub skip_if_any: Vec<String>,
    pub skip_if_any_windows: Vec<String>,
    pub depends_on: Vec<String>,
    pub after: Vec<String>,
    pub requires_selected_any: Vec<String>,
    pub depends_on_selected: bool,
    pub depends_on_selected_exclude: Vec<String>,
    pub after_selected: bool,
    pub after_selected_exclude: Vec<String>,
    pub resource_locks: Vec<String>,
    pub authority: Option<String>,
    pub result_protocol: Option<u32>,
    pub command: String,
    pub args: Vec<String>,
    pub mode: Option<String>,
    pub command_candidates: Vec<UpdaterCommandCandidateConfig>,
    pub pre_commands: Vec<UpdaterPreCommandConfig>,
    pub report_commands: Vec<UpdaterReportCommandConfig>,
    pub report_patterns: Vec<UpdaterReportPatternConfig>,
    pub report_scoped_deltas: Vec<UpdaterScopedDeltaConfig>,
    pub enabled: bool,
    pub requires_elevation: bool,
    pub needs_sudo_session: bool,
    pub interactive: bool,
    pub external_window: bool,
    pub shell: bool,
    pub policy_key: String,
    pub category: String,
    pub report_parser: Option<BuiltinReportParser>,
    pub plain_header: Option<String>,
    pub plain_start: Option<String>,
    pub success_details: Vec<String>,
    pub external_manager_skip: bool,
}

#[derive(Clone, Debug)]
pub struct UpdaterCommandCandidateConfig {
    pub program: String,
    pub args: Vec<String>,
    pub probe_args: Vec<String>,
    pub mode: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UpdaterPreCommandConfig {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct UpdaterReportCommandConfig {
    pub program: String,
    pub args: Vec<String>,
    pub when: UpdaterReportCommandWhen,
    pub allow_exit_codes: Vec<i32>,
    pub state_pattern: Option<UpdaterStateReportPatternConfig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdaterReportCommandWhen {
    Before,
    After,
    BeforeAfter,
}

impl UpdaterReportCommandWhen {
    fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "before" => Some(Self::Before),
            "after" => Some(Self::After),
            "before_after" | "before-after" | "before+after" | "both" => Some(Self::BeforeAfter),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct UpdaterStateReportPatternConfig {
    pub pattern: String,
    pub section_key: String,
    pub section_title: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub include_unchanged: bool,
}

#[derive(Clone, Debug)]
pub struct UpdaterReportPatternConfig {
    pub pattern: String,
    pub section_key: String,
    pub section_title: String,
    pub status: String,
    pub name: Option<String>,
    pub before: Option<String>,
    pub after: Option<String>,
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
pub struct UpdaterScopedDeltaConfig {
    pub scope_pattern: String,
    pub before_pattern: String,
    pub after_pattern: String,
    pub section_key: String,
    pub section_title: String,
    pub row_name: String,
    pub scope_section_key: Option<String>,
    pub scope_section_title: Option<String>,
    pub scope_row_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdaterDetectionMode {
    AnyPresent,
    Always,
    CommandAvailable,
}

impl UpdaterDetectionMode {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "any_present" | "any" => Some(Self::AnyPresent),
            "always" => Some(Self::Always),
            "command_available" | "command" => Some(Self::CommandAvailable),
            _ => None,
        }
    }

    fn supported_values() -> &'static str {
        "any_present|always|command_available"
    }
}

#[derive(Clone, Debug)]
pub struct UpdaterConfig {
    pub run_all_detected: bool,
    pub include: BTreeSet<String>,
    pub exclude: BTreeSet<String>,
    pub privilege_mode: PrivilegeMode,
    pub custom_tasks: BTreeMap<String, UpdaterTaskConfig>,
    pub bootstrap: BootstrapConfig,
}

#[derive(Clone, Debug)]
pub struct CompletionConfig {
    pub tools: Vec<CompletionToolConfig>,
    /// Empty selects installed-shell detection. Non-empty values are
    /// normalized by the completion CLI/task boundary.
    pub shells: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CompletionToolConfig {
    pub name: String,
    pub provider: String,
    pub enabled: bool,
    pub managed_required: bool,
    pub priority: Option<i64>,
    pub trust_dynamic: bool,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub ui: UiConfig,
    pub engine: EngineConfig,
    pub install: InstallConfig,
    pub interactive: InteractiveRuntimeConfig,
    pub logging: LoggingConfig,
    pub tasks: BTreeMap<String, TaskPolicy>,
    pub updaters: UpdaterConfig,
    pub completions: CompletionConfig,
    pub source_path: Option<PathBuf>,
}

impl RuntimeConfig {
    pub fn policy_or_default(&self, key: &str, fallback: TaskPolicy) -> TaskPolicy {
        self.tasks.get(key).cloned().unwrap_or(fallback)
    }

    pub fn policy_or_default_any(&self, keys: &[&str], fallback: TaskPolicy) -> TaskPolicy {
        keys.iter()
            .find_map(|key| self.tasks.get(*key).cloned())
            .unwrap_or(fallback)
    }
}

#[derive(Default, Deserialize)]
struct FileConfig {
    ui: Option<FileUiConfig>,
    engine: Option<FileEngineConfig>,
    install: Option<FileInstallConfig>,
    runtime: Option<FileRuntimeConfig>,
    logging: Option<FileLoggingConfig>,
    tasks: Option<BTreeMap<String, FileTaskPolicy>>,
    updaters: Option<FileUpdaterConfig>,
    bootstrap: Option<FileBootstrapConfig>,
    completions: Option<FileCompletionConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUiConfig {
    mode: Option<String>,
    persist_until_exit: Option<bool>,
    show_global_log: Option<bool>,
    max_events_per_frame: Option<usize>,
    dashboard: Option<FileUiDashboardConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUiDashboardConfig {
    quit_behavior: Option<String>,
    quit_cancel_grace_ms: Option<u64>,
    mouse_row_stride: Option<String>,
    note_verbosity: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEngineConfig {
    mode: Option<String>,
    jobs: Option<String>,
    fail_fast: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInstallConfig {
    auto_update: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRuntimeConfig {
    interactive: Option<FileInteractiveConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileInteractiveConfig {
    mode: Option<String>,
    stall_seconds: Option<u64>,
    max_line_bytes: Option<usize>,
    max_capture_bytes: Option<usize>,
    retry_once: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileLoggingConfig {
    run_dir: Option<PathBuf>,
    max_in_memory_lines: Option<usize>,
    filter_progress_noise: Option<bool>,
    timestamps: Option<bool>,
    task_colors: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileTaskPolicy {
    timeout_secs: Option<u64>,
    retries: Option<u32>,
    retry_backoff_secs: Option<u64>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterConfig {
    run_all_detected: Option<bool>,
    include: Option<Vec<String>>,
    exclude: Option<Vec<String>>,
    privilege_mode: Option<String>,
    catalogs: Option<Vec<PathBuf>>,
    tasks: Option<BTreeMap<String, FileUpdaterTaskConfig>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterCatalog {
    schema_version: Option<u32>,
    engine_api: Option<u32>,
    adapter_api: Option<u32>,
    tasks: Option<BTreeMap<String, FileUpdaterTaskConfig>>,
}

struct CollectedUpdaterTaskConfigs {
    tasks: BTreeMap<String, FileUpdaterTaskConfig>,
    sources: BTreeMap<String, String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterTaskConfig {
    label: Option<String>,
    os: Option<Vec<String>>,
    detect_mode: Option<String>,
    detect: Option<Vec<String>>,
    detect_all: Option<Vec<String>>,
    detect_all_windows: Option<Vec<String>>,
    skip_if_any: Option<Vec<String>>,
    skip_if_any_windows: Option<Vec<String>>,
    depends_on: Option<Vec<String>>,
    after: Option<Vec<String>>,
    requires_selected_any: Option<Vec<String>>,
    depends_on_selected: Option<bool>,
    depends_on_selected_exclude: Option<Vec<String>>,
    after_selected: Option<bool>,
    after_selected_exclude: Option<Vec<String>>,
    resource_locks: Option<Vec<String>>,
    authority: Option<String>,
    result_protocol: Option<u32>,
    command: Option<String>,
    args: Option<Vec<String>>,
    mode: Option<String>,
    command_candidates: Option<Vec<FileUpdaterCommandCandidateConfig>>,
    pre_commands: Option<Vec<FileUpdaterPreCommandConfig>>,
    report_commands: Option<Vec<FileUpdaterReportCommandConfig>>,
    report_patterns: Option<Vec<FileUpdaterReportPatternConfig>>,
    report_scoped_deltas: Option<Vec<FileUpdaterScopedDeltaConfig>>,
    enabled: Option<bool>,
    requires_elevation: Option<bool>,
    needs_sudo_session: Option<bool>,
    interactive: Option<bool>,
    external_window: Option<bool>,
    shell: Option<bool>,
    policy_key: Option<String>,
    category: Option<String>,
    report_parser: Option<String>,
    plain_header: Option<String>,
    plain_start: Option<String>,
    success_details: Option<Vec<String>>,
    external_manager_skip: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterCommandCandidateConfig {
    program: Option<String>,
    args: Option<Vec<String>>,
    probe_args: Option<Vec<String>>,
    mode: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterPreCommandConfig {
    program: Option<String>,
    args: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterReportCommandConfig {
    program: Option<String>,
    args: Option<Vec<String>>,
    when: Option<String>,
    allow_exit_codes: Option<Vec<i32>>,
    state_pattern: Option<String>,
    state_name: Option<String>,
    state_version: Option<String>,
    state_section_key: Option<String>,
    state_section_title: Option<String>,
    state_include_unchanged: Option<bool>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterReportPatternConfig {
    pattern: Option<String>,
    section_key: Option<String>,
    section_title: Option<String>,
    status: Option<String>,
    name: Option<String>,
    before: Option<String>,
    after: Option<String>,
    note: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileUpdaterScopedDeltaConfig {
    scope_pattern: Option<String>,
    before_pattern: Option<String>,
    after_pattern: Option<String>,
    section_key: Option<String>,
    section_title: Option<String>,
    row_name: Option<String>,
    scope_section_key: Option<String>,
    scope_section_title: Option<String>,
    scope_row_name: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileBootstrapConfig {
    enabled: Option<bool>,
    windows_foundations: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCompletionConfig {
    tools: Option<Vec<FileCompletionToolConfig>>,
    shells: Option<Vec<String>>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileCompletionToolConfig {
    name: Option<String>,
    provider: Option<String>,
    enabled: Option<bool>,
    managed_required: Option<bool>,
    priority: Option<i64>,
    trust_dynamic: Option<bool>,
}

pub struct ConfigValidationReport {
    pub path: Option<PathBuf>,
    pub warnings: Vec<String>,
}

fn parse_updater_command_candidates(
    id: &str,
    raw_candidates: Vec<FileUpdaterCommandCandidateConfig>,
) -> Result<Vec<UpdaterCommandCandidateConfig>> {
    raw_candidates
        .into_iter()
        .enumerate()
        .map(|(idx, raw)| {
            let Some(program) = raw.program else {
                bail!(
                    "updaters.tasks.{id}.command_candidates[{idx}].program is required; add program = \"fallback-updater\""
                );
            };
            if program.trim().is_empty() {
                bail!(
                    "invalid updaters.tasks.{id}.command_candidates[{idx}].program ''; expected non-empty command name"
                );
            }
            validate_non_empty_list(
                &format!("updaters.tasks.{id}.command_candidates[{idx}].args"),
                raw.args.as_deref(),
            )?;
            validate_non_empty_list(
                &format!("updaters.tasks.{id}.command_candidates[{idx}].probe_args"),
                raw.probe_args.as_deref(),
            )?;
            Ok(UpdaterCommandCandidateConfig {
                program,
                args: raw.args.unwrap_or_default(),
                probe_args: raw.probe_args.unwrap_or_default(),
                mode: raw.mode,
            })
        })
        .collect()
}

fn parse_updater_report_commands(
    id: &str,
    raw_commands: Vec<FileUpdaterReportCommandConfig>,
) -> Result<Vec<UpdaterReportCommandConfig>> {
    raw_commands
        .into_iter()
        .enumerate()
        .map(|(idx, raw)| {
            let Some(program) = raw.program.clone() else {
                bail!(
                    "updaters.tasks.{id}.report_commands[{idx}].program is required; add program = \"reporter\""
                );
            };
            if program.trim().is_empty() {
                bail!(
                    "invalid updaters.tasks.{id}.report_commands[{idx}].program ''; expected non-empty command name"
                );
            }
            validate_non_empty_list(
                &format!("updaters.tasks.{id}.report_commands[{idx}].args"),
                raw.args.as_deref(),
            )?;
            let when = parse_updater_report_command_when(
                id,
                idx,
                raw.when.as_deref(),
                raw.state_pattern.is_some(),
            )?;
            let state_pattern = parse_updater_state_report_pattern(id, idx, &raw)?;
            let allow_exit_codes = parse_updater_report_command_allow_exit_codes(
                id,
                idx,
                raw.allow_exit_codes.unwrap_or_default(),
            )?;
            Ok(UpdaterReportCommandConfig {
                program,
                args: raw.args.unwrap_or_default(),
                when,
                allow_exit_codes,
                state_pattern,
            })
        })
        .collect()
}

fn parse_updater_report_command_allow_exit_codes(
    id: &str,
    idx: usize,
    codes: Vec<i32>,
) -> Result<Vec<i32>> {
    for code in &codes {
        if *code < 0 || *code > 255 {
            bail!(
                "invalid updaters.tasks.{id}.report_commands[{idx}].allow_exit_codes entry {code}; expected 0..255"
            );
        }
    }
    Ok(codes)
}

fn parse_updater_report_command_when(
    id: &str,
    idx: usize,
    raw: Option<&str>,
    has_state_pattern: bool,
) -> Result<UpdaterReportCommandWhen> {
    let when = match raw {
        Some(value) => UpdaterReportCommandWhen::parse(value).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid updaters.tasks.{id}.report_commands[{idx}].when '{}'; expected before|after|before_after",
                value
            )
        })?,
        None if has_state_pattern => UpdaterReportCommandWhen::BeforeAfter,
        None => UpdaterReportCommandWhen::After,
    };
    if has_state_pattern && when != UpdaterReportCommandWhen::BeforeAfter {
        bail!(
            "updaters.tasks.{id}.report_commands[{idx}].state_pattern requires when = \"before_after\""
        );
    }
    Ok(when)
}

fn parse_updater_state_report_pattern(
    id: &str,
    idx: usize,
    raw: &FileUpdaterReportCommandConfig,
) -> Result<Option<UpdaterStateReportPatternConfig>> {
    let Some(pattern) = raw.state_pattern.clone() else {
        return Ok(None);
    };
    if pattern.trim().is_empty() {
        bail!(
            "invalid updaters.tasks.{id}.report_commands[{idx}].state_pattern ''; expected non-empty regex"
        );
    }
    Regex::new(&pattern).with_context(|| {
        format!("invalid updaters.tasks.{id}.report_commands[{idx}].state_pattern")
    })?;
    let section_key = raw
        .state_section_key
        .clone()
        .unwrap_or_else(|| "state_packages".to_string());
    validate_optional_non_empty_scalar(
        &format!("updaters.tasks.{id}.report_commands[{idx}].state_section_key"),
        Some(section_key.as_str()),
        "section key",
    )?;
    let section_title = raw
        .state_section_title
        .clone()
        .unwrap_or_else(|| "State Package Results".to_string());
    validate_optional_non_empty_scalar(
        &format!("updaters.tasks.{id}.report_commands[{idx}].state_section_title"),
        Some(section_title.as_str()),
        "section title",
    )?;
    for (field, value) in [
        ("state_name", raw.state_name.as_deref()),
        ("state_version", raw.state_version.as_deref()),
    ] {
        validate_optional_non_empty_scalar(
            &format!("updaters.tasks.{id}.report_commands[{idx}].{field}"),
            value,
            "template",
        )?;
    }
    Ok(Some(UpdaterStateReportPatternConfig {
        pattern,
        section_key,
        section_title,
        name: raw.state_name.clone(),
        version: raw.state_version.clone(),
        include_unchanged: raw.state_include_unchanged.unwrap_or(false),
    }))
}

fn parse_updater_report_patterns(
    id: &str,
    raw_patterns: Vec<FileUpdaterReportPatternConfig>,
) -> Result<Vec<UpdaterReportPatternConfig>> {
    raw_patterns
        .into_iter()
        .enumerate()
        .map(|(idx, raw)| {
            let Some(pattern) = raw.pattern else {
                bail!(
                    "updaters.tasks.{id}.report_patterns[{idx}].pattern is required; add pattern = \"...\""
                );
            };
            if pattern.trim().is_empty() {
                bail!(
                    "invalid updaters.tasks.{id}.report_patterns[{idx}].pattern ''; expected non-empty regex"
                );
            }
            Regex::new(&pattern).with_context(|| {
                format!("invalid updaters.tasks.{id}.report_patterns[{idx}].pattern")
            })?;

            let section_key = raw
                .section_key
                .unwrap_or_else(|| "custom_report".to_string());
            validate_optional_non_empty_scalar(
                &format!("updaters.tasks.{id}.report_patterns[{idx}].section_key"),
                Some(section_key.as_str()),
                "section key",
            )?;
            let section_title = raw
                .section_title
                .unwrap_or_else(|| "Custom Report Results".to_string());
            validate_optional_non_empty_scalar(
                &format!("updaters.tasks.{id}.report_patterns[{idx}].section_title"),
                Some(section_title.as_str()),
                "section title",
            )?;
            let status = raw.status.unwrap_or_else(|| "updated".to_string());
            validate_report_pattern_status(id, idx, &status)?;

            for (field, value) in [
                ("name", raw.name.as_deref()),
                ("before", raw.before.as_deref()),
                ("after", raw.after.as_deref()),
                ("note", raw.note.as_deref()),
            ] {
                validate_optional_non_empty_scalar(
                    &format!("updaters.tasks.{id}.report_patterns[{idx}].{field}"),
                    value,
                    "template",
                )?;
            }

            Ok(UpdaterReportPatternConfig {
                pattern,
                section_key,
                section_title,
                status,
                name: raw.name,
                before: raw.before,
                after: raw.after,
                note: raw.note,
            })
        })
        .collect()
}

fn parse_updater_scoped_deltas(
    id: &str,
    raw_deltas: Vec<FileUpdaterScopedDeltaConfig>,
) -> Result<Vec<UpdaterScopedDeltaConfig>> {
    raw_deltas
        .into_iter()
        .enumerate()
        .map(|(idx, raw)| {
            let prefix = format!("updaters.tasks.{id}.report_scoped_deltas[{idx}]");
            let scope_pattern = required_scoped_delta_pattern(
                &prefix,
                "scope_pattern",
                raw.scope_pattern,
                &["scope"],
            )?;
            let before_pattern = required_scoped_delta_pattern(
                &prefix,
                "before_pattern",
                raw.before_pattern,
                &["name", "version"],
            )?;
            let after_pattern = required_scoped_delta_pattern(
                &prefix,
                "after_pattern",
                raw.after_pattern,
                &["name", "version"],
            )?;
            let section_key = required_scoped_delta_scalar(
                &prefix,
                "section_key",
                raw.section_key,
                "section key",
            )?;
            let section_title = required_scoped_delta_scalar(
                &prefix,
                "section_title",
                raw.section_title,
                "section title",
            )?;
            let row_name = required_scoped_delta_scalar(
                &prefix,
                "row_name",
                raw.row_name,
                "row-name template",
            )?;

            let parent_count = [
                raw.scope_section_key.is_some(),
                raw.scope_section_title.is_some(),
                raw.scope_row_name.is_some(),
            ]
            .into_iter()
            .filter(|present| *present)
            .count();
            if parent_count != 0 && parent_count != 3 {
                bail!(
                    "{prefix} parent reporting requires scope_section_key, scope_section_title, and scope_row_name together"
                );
            }
            for (field, value, label) in [
                (
                    "scope_section_key",
                    raw.scope_section_key.as_deref(),
                    "section key",
                ),
                (
                    "scope_section_title",
                    raw.scope_section_title.as_deref(),
                    "section title",
                ),
                (
                    "scope_row_name",
                    raw.scope_row_name.as_deref(),
                    "row-name template",
                ),
            ] {
                validate_optional_non_empty_scalar(
                    &format!("{prefix}.{field}"),
                    value,
                    label,
                )?;
            }

            Ok(UpdaterScopedDeltaConfig {
                scope_pattern,
                before_pattern,
                after_pattern,
                section_key,
                section_title,
                row_name,
                scope_section_key: raw.scope_section_key,
                scope_section_title: raw.scope_section_title,
                scope_row_name: raw.scope_row_name,
            })
        })
        .collect()
}

fn required_scoped_delta_pattern(
    prefix: &str,
    field: &str,
    value: Option<String>,
    required_captures: &[&str],
) -> Result<String> {
    let value = required_scoped_delta_scalar(prefix, field, value, "regex")?;
    let regex = Regex::new(&value).with_context(|| format!("invalid {prefix}.{field}"))?;
    for capture in required_captures {
        if !regex.capture_names().flatten().any(|name| name == *capture) {
            bail!("{prefix}.{field} must define a named '{capture}' capture");
        }
    }
    Ok(value)
}

fn required_scoped_delta_scalar(
    prefix: &str,
    field: &str,
    value: Option<String>,
    label: &str,
) -> Result<String> {
    let Some(value) = value else {
        bail!("{prefix}.{field} is required; add {field} = \"...\"");
    };
    validate_optional_non_empty_scalar(&format!("{prefix}.{field}"), Some(&value), label)?;
    Ok(value)
}

fn validate_report_pattern_status(id: &str, idx: usize, status: &str) -> Result<()> {
    match status.trim().to_ascii_lowercase().as_str() {
        "updated" | "refreshed" | "refresh" | "passed" | "pass" | "unchanged" | "skipped"
        | "failed" | "blocked" | "info" => {
            Ok(())
        }
        _ => bail!(
            "invalid updaters.tasks.{id}.report_patterns[{idx}].status '{}'; expected updated|refreshed|passed|pass|unchanged|skipped|failed|blocked|info",
            status
        ),
    }
}

fn parse_updater_pre_commands(
    id: &str,
    raw_commands: Vec<FileUpdaterPreCommandConfig>,
) -> Result<Vec<UpdaterPreCommandConfig>> {
    raw_commands
        .into_iter()
        .enumerate()
        .map(|(idx, raw)| {
            let Some(program) = raw.program else {
                bail!(
                    "updaters.tasks.{id}.pre_commands[{idx}].program is required; add program = \"pre-updater\""
                );
            };
            if program.trim().is_empty() {
                bail!(
                    "invalid updaters.tasks.{id}.pre_commands[{idx}].program ''; expected non-empty command name"
                );
            }
            validate_non_empty_list(
                &format!("updaters.tasks.{id}.pre_commands[{idx}].args"),
                raw.args.as_deref(),
            )?;
            Ok(UpdaterPreCommandConfig {
                program,
                args: raw.args.unwrap_or_default(),
            })
        })
        .collect()
}

fn validate_non_empty_list(field: &str, values: Option<&[String]>) -> Result<()> {
    validate_non_empty_labeled_list(field, values, "value")
}

fn validate_non_empty_labeled_list(
    field: &str,
    values: Option<&[String]>,
    label: &str,
) -> Result<()> {
    if let Some(values) = values {
        for value in values {
            if value.trim().is_empty() {
                bail!("invalid {field} entry ''; expected non-empty {label}");
            }
        }
    }
    Ok(())
}

fn validate_optional_non_empty_scalar(field: &str, value: Option<&str>, label: &str) -> Result<()> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        bail!("invalid {field} ''; expected non-empty {label}");
    }
    Ok(())
}

fn parse_completion_tool_configs(
    raw_tools: Option<Vec<FileCompletionToolConfig>>,
) -> Result<Vec<CompletionToolConfig>> {
    raw_tools
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(parse_completion_tool_config)
        .collect()
}

fn parse_completion_tool_config(
    (idx, tool): (usize, FileCompletionToolConfig),
) -> Result<CompletionToolConfig> {
    let entry = format!("completions.tools[{idx}]");
    let name = tool.name.unwrap_or_default().trim().to_string();
    if name.is_empty() {
        bail!(
            "{entry}.name is required; add for example:\n  [[completions.tools]]\n  name = \"privatebin\"\n  provider = \"path\""
        );
    }

    let provider = tool
        .provider
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if provider.is_empty() {
        bail!(
            "{entry}.provider is required; add for example:\n  [[completions.tools]]\n  name = \"privatebin\"\n  provider = \"path\""
        );
    }
    if !is_supported_completion_provider(&provider) {
        bail!(
            "invalid {entry}.provider '{}'; expected one of: path, npm, pipx, uv, go\nexample:\n  [[completions.tools]]\n  name = \"privatebin\"\n  provider = \"path\"",
            provider
        );
    }

    Ok(CompletionToolConfig {
        name,
        provider,
        enabled: tool.enabled.unwrap_or(true),
        managed_required: tool.managed_required.unwrap_or(false),
        priority: tool.priority,
        trust_dynamic: tool.trust_dynamic.unwrap_or(false),
    })
}

fn validate_custom_task_identity(id: &str, command: &str) -> Result<()> {
    if id.trim().is_empty() {
        bail!("invalid updaters.tasks task id '{id}'; expected non-empty task id");
    }
    validate_optional_non_empty_scalar(
        &format!("updaters.tasks.{id}.command"),
        Some(command),
        "command name",
    )?;
    Ok(())
}

fn validate_custom_task_shape(id: &str, raw: &FileUpdaterTaskConfig) -> Result<()> {
    validate_optional_non_empty_scalar(
        &format!("updaters.tasks.{id}.label"),
        raw.label.as_deref(),
        "label",
    )?;
    validate_optional_non_empty_scalar(
        &format!("updaters.tasks.{id}.category"),
        raw.category.as_deref(),
        "category",
    )?;
    validate_optional_non_empty_scalar(
        &format!("updaters.tasks.{id}.policy_key"),
        raw.policy_key.as_deref(),
        "task policy key",
    )?;
    validate_optional_non_empty_scalar(
        &format!("updaters.tasks.{id}.authority"),
        raw.authority.as_deref(),
        "authority claim",
    )?;
    if raw.result_protocol.is_some_and(|protocol| protocol != 1) {
        bail!("updaters.tasks.{id}.result_protocol requires supported protocol 1");
    }

    if let Some(os_names) = raw.os.as_deref() {
        if os_names.is_empty() {
            bail!("invalid updaters.tasks.{id}.os; expected at least one OS");
        }
        for os_name in os_names {
            let normalized = os_name.trim();
            let known = [HostOs::Linux, HostOs::Macos, HostOs::Windows]
                .iter()
                .any(|host_os| host_os.matches_name(normalized));
            if !known {
                bail!(
                    "invalid updaters.tasks.{id}.os entry '{}'; expected linux|macos|windows",
                    os_name
                );
            }
        }
    }

    Ok(())
}

fn validate_custom_task_lists(id: &str, raw: &FileUpdaterTaskConfig) -> Result<()> {
    for (field, values, label) in [
        ("detect", raw.detect.as_deref(), "command name"),
        ("detect_all", raw.detect_all.as_deref(), "command name"),
        (
            "detect_all_windows",
            raw.detect_all_windows.as_deref(),
            "command name",
        ),
        ("skip_if_any", raw.skip_if_any.as_deref(), "command name"),
        (
            "skip_if_any_windows",
            raw.skip_if_any_windows.as_deref(),
            "command name",
        ),
        ("depends_on", raw.depends_on.as_deref(), "task selector"),
        ("after", raw.after.as_deref(), "task selector"),
        (
            "requires_selected_any",
            raw.requires_selected_any.as_deref(),
            "task selector",
        ),
        (
            "depends_on_selected_exclude",
            raw.depends_on_selected_exclude.as_deref(),
            "task id",
        ),
        (
            "after_selected_exclude",
            raw.after_selected_exclude.as_deref(),
            "task id",
        ),
        (
            "success_details",
            raw.success_details.as_deref(),
            "detail text",
        ),
        (
            "resource_locks",
            raw.resource_locks.as_deref(),
            "resource lock",
        ),
    ] {
        validate_non_empty_labeled_list(&format!("updaters.tasks.{id}.{field}"), values, label)?;
    }
    Ok(())
}

fn validate_custom_detection_shape(
    id: &str,
    detect_mode: UpdaterDetectionMode,
    detect: Option<&[String]>,
) -> Result<()> {
    if matches!(detect_mode, UpdaterDetectionMode::AnyPresent)
        && detect.is_some_and(|v| v.is_empty())
    {
        bail!(
            "updaters.tasks.{id}.detect requires at least one command when detect_mode is any_present; omit detect to default to command or use detect_mode = \"command_available\""
        );
    }
    Ok(())
}

fn parse_custom_task(id: &str, raw: FileUpdaterTaskConfig) -> Result<UpdaterTaskConfig> {
    let Some(command) = raw.command.clone() else {
        bail!(
            "updaters.tasks.{id}.command is required; add for example:\n  [updaters.tasks.{id}]\n  command = \"your-updater\"\n  args = [\"--help\"]"
        );
    };
    validate_custom_task_identity(id, &command)?;
    validate_custom_task_shape(id, &raw)?;
    validate_custom_task_lists(id, &raw)?;
    let label = raw.label.unwrap_or_else(|| id.to_string());
    let detect_mode = match raw.detect_mode.as_deref() {
        Some(mode) => UpdaterDetectionMode::parse(mode).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid updaters.tasks.{id}.detect_mode '{}'; expected {}",
                mode,
                UpdaterDetectionMode::supported_values()
            )
        })?,
        None => UpdaterDetectionMode::AnyPresent,
    };
    let report_parser = match raw.report_parser.as_deref() {
        Some(parser) => Some(BuiltinReportParser::parse(parser).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid updaters.tasks.{id}.report_parser '{}'; expected one of: {}",
                parser,
                BuiltinReportParser::supported_values().join(", ")
            )
        })?),
        None => None,
    };
    validate_custom_detection_shape(id, detect_mode, raw.detect.as_deref())?;
    let command_candidates =
        parse_updater_command_candidates(id, raw.command_candidates.unwrap_or_default())?;
    let pre_commands = parse_updater_pre_commands(id, raw.pre_commands.unwrap_or_default())?;
    let report_commands =
        parse_updater_report_commands(id, raw.report_commands.unwrap_or_default())?;
    let report_patterns =
        parse_updater_report_patterns(id, raw.report_patterns.unwrap_or_default())?;
    let report_scoped_deltas =
        parse_updater_scoped_deltas(id, raw.report_scoped_deltas.unwrap_or_default())?;
    let shell = raw.shell.unwrap_or(false);
    if shell && !command_candidates.is_empty() {
        bail!(
            "updaters.tasks.{id}.command_candidates require shell=false; remove command_candidates or disable shell mode"
        );
    }
    Ok(UpdaterTaskConfig {
        id: id.to_string(),
        label,
        os: raw.os.unwrap_or_else(|| {
            vec![
                "linux".to_string(),
                "macos".to_string(),
                "windows".to_string(),
            ]
        }),
        detect_mode,
        detect_any: raw.detect.unwrap_or_else(|| vec![command.clone()]),
        detect_all: raw.detect_all.unwrap_or_default(),
        detect_all_windows: raw.detect_all_windows.unwrap_or_default(),
        skip_if_any: raw.skip_if_any.unwrap_or_default(),
        skip_if_any_windows: raw.skip_if_any_windows.unwrap_or_default(),
        depends_on: raw.depends_on.unwrap_or_default(),
        after: raw.after.unwrap_or_default(),
        requires_selected_any: raw.requires_selected_any.unwrap_or_default(),
        depends_on_selected: raw.depends_on_selected.unwrap_or(false),
        depends_on_selected_exclude: raw.depends_on_selected_exclude.unwrap_or_default(),
        after_selected: raw.after_selected.unwrap_or(false),
        after_selected_exclude: raw.after_selected_exclude.unwrap_or_default(),
        resource_locks: raw.resource_locks.unwrap_or_default(),
        authority: raw.authority,
        result_protocol: raw.result_protocol,
        command,
        args: raw.args.unwrap_or_default(),
        mode: raw.mode,
        command_candidates,
        pre_commands,
        report_commands,
        report_patterns,
        report_scoped_deltas,
        enabled: raw.enabled.unwrap_or(true),
        requires_elevation: raw.requires_elevation.unwrap_or(false),
        needs_sudo_session: raw.needs_sudo_session.unwrap_or(false),
        interactive: raw.interactive.unwrap_or(false),
        external_window: raw.external_window.unwrap_or(false),
        shell,
        policy_key: raw
            .policy_key
            .unwrap_or_else(|| "system_update".to_string()),
        category: raw.category.unwrap_or_else(|| "custom".to_string()),
        report_parser,
        plain_header: raw.plain_header,
        plain_start: raw.plain_start,
        success_details: raw.success_details.unwrap_or_default(),
        external_manager_skip: raw.external_manager_skip.unwrap_or(false),
    })
}

fn parse_custom_tasks(
    collected: CollectedUpdaterTaskConfigs,
) -> Result<BTreeMap<String, UpdaterTaskConfig>> {
    let mut custom_tasks = BTreeMap::new();
    for (id, raw) in collected.tasks {
        let source = collected
            .sources
            .get(&id)
            .map(|source| format!("validate updater task '{id}' from {source}"))
            .unwrap_or_else(|| format!("validate updater task '{id}'"));
        let task = parse_custom_task(&id, raw).map_err(|err| anyhow::anyhow!("{source}: {err}"))?;
        custom_tasks.insert(id, task);
    }
    let builtin_ids = builtin_catalog()?
        .into_iter()
        .map(|task| task.id)
        .collect::<BTreeSet<_>>();
    if let Some(id) = custom_tasks.keys().find(|id| builtin_ids.contains(*id)) {
        bail!("duplicate updater task id '{id}'; already defined in the embedded public catalog");
    }
    let mut authorities = BTreeMap::new();
    for task in custom_tasks.values() {
        let Some(authority) = task.authority.as_deref() else {
            continue;
        };
        if let Some(existing) = authorities.insert(authority, task.id.as_str()) {
            bail!(
                "updater authority '{authority}' is claimed by both '{existing}' and '{}'",
                task.id
            );
        }
    }
    validate_custom_task_references(&custom_tasks)?;
    Ok(custom_tasks)
}

fn parse_updater_catalog_file(path: &Path) -> Result<FileUpdaterCatalog> {
    let txt = std::fs::read_to_string(path)
        .with_context(|| format!("read updater catalog {}", path.display()))?;
    let catalog = toml::from_str::<FileUpdaterCatalog>(&txt)
        .with_context(|| format!("parse updater catalog {}", path.display()))?;
    for (field, actual, supported) in [
        ("schema_version", catalog.schema_version.unwrap_or(1), 1),
        ("engine_api", catalog.engine_api.unwrap_or(1), 1),
        ("adapter_api", catalog.adapter_api.unwrap_or(1), 1),
    ] {
        if actual != supported {
            bail!(
                "updater catalog {} {field}={actual} is unsupported; expected {supported}",
                path.display()
            );
        }
    }
    Ok(catalog)
}

fn resolve_updater_catalog_path(
    config_path: Option<&Path>,
    catalog_path: &Path,
) -> Result<PathBuf> {
    let raw = catalog_path.to_string_lossy();
    if raw.trim().is_empty() {
        bail!("invalid updaters.catalogs entry ''; expected non-empty path");
    }

    let expanded = expand_tilde_path(catalog_path);
    if expanded.is_absolute() {
        return Ok(expanded);
    }

    let Some(config_path) = config_path else {
        bail!(
            "relative updaters.catalogs entry '{}' requires a config file path",
            catalog_path.display()
        );
    };
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));
    Ok(base.join(expanded))
}

fn insert_updater_task_config(
    tasks: &mut BTreeMap<String, FileUpdaterTaskConfig>,
    sources: &mut BTreeMap<String, String>,
    id: String,
    raw: FileUpdaterTaskConfig,
    source: String,
) -> Result<()> {
    if let Some(existing) = sources.get(&id) {
        bail!("duplicate updater task id '{id}' in {source}; already defined in {existing}");
    }
    sources.insert(id.clone(), source);
    tasks.insert(id, raw);
    Ok(())
}

fn discovered_updater_catalogs(config_path: Option<&Path>) -> Result<Vec<(String, PathBuf)>> {
    let config_path = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_config_write_path);
    let root = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("catalog.d");
    let mut catalogs = Vec::new();
    for namespace in ["syscfg", "local"] {
        let directory = root.join(namespace);
        if !directory.is_dir() {
            continue;
        }
        let mut paths = std::fs::read_dir(&directory)
            .with_context(|| format!("read updater catalog directory {}", directory.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.is_file()
                    && path
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
            })
            .collect::<Vec<_>>();
        paths.sort();
        catalogs.extend(paths.into_iter().map(|path| (namespace.to_string(), path)));
    }
    Ok(catalogs)
}

fn validate_discovered_catalog_namespace(namespace: &str, id: &str, path: &Path) -> Result<()> {
    let prefix = format!("{namespace}/");
    if !id.starts_with(&prefix) || id.len() == prefix.len() {
        bail!(
            "updater catalog {} task id '{}' must use the '{namespace}/' namespace",
            path.display(),
            id
        );
    }
    Ok(())
}

fn collect_updater_task_configs(
    config_path: Option<&Path>,
    catalog_paths: Option<Vec<PathBuf>>,
    inline_tasks: Option<BTreeMap<String, FileUpdaterTaskConfig>>,
) -> Result<CollectedUpdaterTaskConfigs> {
    let mut tasks = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut explicit_paths = BTreeSet::new();

    for catalog_path in catalog_paths.unwrap_or_default() {
        let catalog_path = resolve_updater_catalog_path(config_path, &catalog_path)?;
        explicit_paths.insert(catalog_path.clone());
        let catalog = parse_updater_catalog_file(&catalog_path)?;
        let source = format!("updater catalog {}", catalog_path.display());
        for (id, raw) in catalog.tasks.unwrap_or_default() {
            insert_updater_task_config(&mut tasks, &mut sources, id, raw, source.clone())?;
        }
    }

    for (namespace, catalog_path) in discovered_updater_catalogs(config_path)? {
        if explicit_paths.contains(&catalog_path) {
            continue;
        }
        let catalog = parse_updater_catalog_file(&catalog_path)?;
        let source = format!("updater catalog {}", catalog_path.display());
        for (id, raw) in catalog.tasks.unwrap_or_default() {
            validate_discovered_catalog_namespace(&namespace, &id, &catalog_path)?;
            insert_updater_task_config(&mut tasks, &mut sources, id, raw, source.clone())?;
        }
    }

    let inline_source = config_path
        .map(|path| format!("config {}", path.display()))
        .unwrap_or_else(|| "inline config".to_string());
    for (id, raw) in inline_tasks.unwrap_or_default() {
        insert_updater_task_config(&mut tasks, &mut sources, id, raw, inline_source.clone())?;
    }

    Ok(CollectedUpdaterTaskConfigs { tasks, sources })
}

fn validate_custom_task_references(
    custom_tasks: &BTreeMap<String, UpdaterTaskConfig>,
) -> Result<()> {
    if custom_tasks.is_empty() {
        return Ok(());
    }

    let builtins = builtin_catalog()?;
    let mut known_ids = BTreeSet::new();
    let mut known_selectors = BTreeSet::new();

    for task in builtins {
        known_ids.insert(task.id.clone());
        known_selectors.insert(task.id);
        known_selectors.insert(task.category);
    }
    for task in custom_tasks.values() {
        known_ids.insert(task.id.clone());
        known_selectors.insert(task.id.clone());
        known_selectors.insert(task.category.clone());
    }

    for task in custom_tasks.values() {
        validate_custom_selector_references(
            &task.id,
            "depends_on",
            "task selector",
            &task.depends_on,
            &known_selectors,
        )?;
        validate_custom_selector_references(
            &task.id,
            "after",
            "task selector",
            &task.after,
            &known_selectors,
        )?;
        validate_custom_selector_references(
            &task.id,
            "requires_selected_any",
            "task selector",
            &task.requires_selected_any,
            &known_selectors,
        )?;
        validate_custom_selector_references(
            &task.id,
            "depends_on_selected_exclude",
            "task id",
            &task.depends_on_selected_exclude,
            &known_ids,
        )?;
        validate_custom_selector_references(
            &task.id,
            "after_selected_exclude",
            "task id",
            &task.after_selected_exclude,
            &known_ids,
        )?;
    }
    Ok(())
}

fn validate_custom_selector_references(
    id: &str,
    field: &str,
    label: &str,
    values: &[String],
    known: &BTreeSet<String>,
) -> Result<()> {
    for value in values {
        if !known.contains(value) {
            bail!("updaters.tasks.{id}.{field} references unknown {label} '{value}'");
        }
    }
    Ok(())
}

struct ParsedCoreConfig {
    ui_mode: Option<UiMode>,
    engine_mode: Option<EngineMode>,
    dashboard_quit_behavior: Option<DashboardQuitBehavior>,
    mouse_row_stride: Option<MouseRowStrideMode>,
    note_verbosity: Option<NoteVerbosity>,
    interactive_mode: Option<InteractiveExecutionMode>,
    privilege_mode: Option<PrivilegeMode>,
}

fn parse_optional_config_value<T>(
    field: &str,
    value: Option<&str>,
    expected: &str,
    parse: fn(&str) -> Option<T>,
) -> Result<Option<T>> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let Some(parsed) = parse(raw) else {
        bail!("invalid {field} '{raw}'; expected {expected}");
    };
    Ok(Some(parsed))
}

fn parse_core_config_values(parsed: &FileConfig) -> Result<ParsedCoreConfig> {
    let dashboard = parsed.ui.as_ref().and_then(|ui| ui.dashboard.as_ref());
    let interactive = parsed
        .runtime
        .as_ref()
        .and_then(|runtime| runtime.interactive.as_ref());
    let install = parsed.install.as_ref();
    let updaters = parsed.updaters.as_ref();

    if let Some(grace) = dashboard.and_then(|d| d.quit_cancel_grace_ms) {
        if grace < 500 {
            bail!("invalid ui.dashboard.quit_cancel_grace_ms '{grace}'; expected >= 500");
        }
    }
    if let Some(stall) = interactive.and_then(|i| i.stall_seconds) {
        if stall == 0 {
            bail!("invalid runtime.interactive.stall_seconds '{stall}'; expected >= 1");
        }
    }
    if let Some(max_line) = interactive.and_then(|i| i.max_line_bytes) {
        if max_line < 4096 {
            bail!("invalid runtime.interactive.max_line_bytes '{max_line}'; expected >= 4096");
        }
    }
    if let Some(max_capture) = interactive.and_then(|i| i.max_capture_bytes) {
        let min_line = interactive
            .and_then(|i| i.max_line_bytes)
            .unwrap_or(262_144);
        if max_capture < min_line {
            bail!(
                "invalid runtime.interactive.max_capture_bytes '{max_capture}'; expected >= max_line_bytes ({min_line})"
            );
        }
    }
    Ok(ParsedCoreConfig {
        ui_mode: parse_optional_config_value(
            "ui.mode",
            parsed.ui.as_ref().and_then(|ui| ui.mode.as_deref()),
            "auto|plain|dashboard",
            parse_ui_mode,
        )?,
        engine_mode: parse_optional_config_value(
            "engine.mode",
            parsed
                .engine
                .as_ref()
                .and_then(|engine| engine.mode.as_deref()),
            "sync|async",
            parse_engine_mode,
        )?,
        dashboard_quit_behavior: parse_optional_config_value(
            "ui.dashboard.quit_behavior",
            dashboard.and_then(|d| d.quit_behavior.as_deref()),
            "cancel_all|detach",
            DashboardQuitBehavior::parse,
        )?,
        mouse_row_stride: parse_optional_config_value(
            "ui.dashboard.mouse_row_stride",
            dashboard.and_then(|d| d.mouse_row_stride.as_deref()),
            "auto|1|2",
            MouseRowStrideMode::parse,
        )?,
        note_verbosity: parse_optional_config_value(
            "ui.dashboard.note_verbosity",
            dashboard.and_then(|d| d.note_verbosity.as_deref()),
            "failures|all|none",
            NoteVerbosity::parse,
        )?,
        interactive_mode: parse_optional_config_value(
            "runtime.interactive.mode",
            interactive.and_then(|i| i.mode.as_deref()),
            "auto_fallback|capture|direct_tty",
            InteractiveExecutionMode::parse,
        )?,
        privilege_mode: parse_optional_config_value(
            "updaters.privilege_mode",
            updaters.and_then(|up| up.privilege_mode.as_deref()),
            "skip|prompt_tty|fail",
            PrivilegeMode::parse,
        )?,
    })
}

pub fn load_runtime_config(config_path_cli: Option<PathBuf>) -> Result<RuntimeConfig> {
    let resolved_path = resolve_config_path(config_path_cli)?;
    let parsed = if let Some(path) = &resolved_path {
        parse_file_config(path)?
    } else {
        FileConfig::default()
    };
    let core_config = parse_core_config_values(&parsed)?;

    let mut task_map = BTreeMap::new();
    if let Some(tasks) = parsed.tasks {
        for (key, raw) in tasks {
            let timeout = raw.timeout_secs.unwrap_or(60);
            let retries = raw.retries.unwrap_or(0);
            let backoff = raw.retry_backoff_secs.unwrap_or(0);
            task_map.insert(key, TaskPolicy::new(timeout, retries, backoff));
        }
    }

    let install = parsed.install.as_ref();
    let interactive = parsed.runtime.as_ref().and_then(|r| r.interactive.as_ref());

    let updater_cfg = parsed.updaters.unwrap_or_default();
    let bootstrap_cfg = parsed.bootstrap.unwrap_or_default();
    let completion_cfg = parsed.completions.unwrap_or_default();
    let FileUpdaterConfig {
        run_all_detected,
        include,
        exclude,
        privilege_mode: _,
        catalogs,
        tasks,
    } = updater_cfg;
    let custom_tasks = parse_custom_tasks(collect_updater_task_configs(
        resolved_path.as_deref(),
        catalogs,
        tasks,
    )?)?;

    let privilege_mode = core_config
        .privilege_mode
        .unwrap_or(PrivilegeMode::PromptTty);
    let default_windows_foundations = default_windows_foundation_ids()?;

    let custom_completion_tools = parse_completion_tool_configs(completion_cfg.tools)?;
    let completion_shells = completion_cfg.shells.unwrap_or_default();
    if !completion_shells.is_empty() {
        crate::completions::resolve_completion_shells(&completion_shells, &[])
            .context("validate completions.shells")?;
    }

    Ok(RuntimeConfig {
        ui: UiConfig {
            mode: core_config.ui_mode.unwrap_or(UiMode::Dashboard),
            persist_until_exit: parsed
                .ui
                .as_ref()
                .and_then(|u| u.persist_until_exit)
                .unwrap_or(true),
            show_global_log: parsed
                .ui
                .as_ref()
                .and_then(|u| u.show_global_log)
                .unwrap_or(true),
            max_events_per_frame: parsed
                .ui
                .as_ref()
                .and_then(|u| u.max_events_per_frame)
                .unwrap_or(120),
            dashboard_quit_behavior: parsed
                .ui
                .as_ref()
                .and_then(|u| u.dashboard.as_ref())
                .and(core_config.dashboard_quit_behavior)
                .unwrap_or(DashboardQuitBehavior::CancelAll),
            quit_cancel_grace_ms: parsed
                .ui
                .as_ref()
                .and_then(|u| u.dashboard.as_ref())
                .and_then(|d| d.quit_cancel_grace_ms)
                .unwrap_or(3000),
            mouse_row_stride: parsed
                .ui
                .as_ref()
                .and_then(|u| u.dashboard.as_ref())
                .and(core_config.mouse_row_stride)
                .unwrap_or(MouseRowStrideMode::Auto),
            note_verbosity: parsed
                .ui
                .as_ref()
                .and_then(|u| u.dashboard.as_ref())
                .and(core_config.note_verbosity)
                .unwrap_or(NoteVerbosity::Failures),
        },
        engine: EngineConfig {
            mode: core_config.engine_mode.unwrap_or(EngineMode::Async),
            jobs: parsed
                .engine
                .as_ref()
                .and_then(|e| e.jobs.clone())
                .unwrap_or_else(|| "auto".to_string()),
            fail_fast: parsed
                .engine
                .as_ref()
                .and_then(|e| e.fail_fast)
                .unwrap_or(false),
        },
        install: InstallConfig {
            auto_update: install.and_then(|i| i.auto_update).unwrap_or(true),
        },
        interactive: InteractiveRuntimeConfig {
            mode: interactive
                .and(core_config.interactive_mode)
                .unwrap_or(InteractiveExecutionMode::AutoFallback),
            stall_seconds: interactive.and_then(|i| i.stall_seconds).unwrap_or(20),
            max_line_bytes: interactive
                .and_then(|i| i.max_line_bytes)
                .unwrap_or(262_144),
            max_capture_bytes: interactive
                .and_then(|i| i.max_capture_bytes)
                .unwrap_or(16_777_216),
            retry_once: interactive.and_then(|i| i.retry_once).unwrap_or(true),
        },
        logging: LoggingConfig {
            run_dir: parsed
                .logging
                .as_ref()
                .and_then(|l| l.run_dir.clone().map(|p| expand_tilde_path(&p)))
                .unwrap_or_else(default_run_root),
            max_in_memory_lines: parsed
                .logging
                .as_ref()
                .and_then(|l| l.max_in_memory_lines)
                .unwrap_or(20_000),
            filter_progress_noise: parsed
                .logging
                .as_ref()
                .and_then(|l| l.filter_progress_noise)
                .unwrap_or(false),
            timestamps: parsed
                .logging
                .as_ref()
                .and_then(|l| l.timestamps)
                .unwrap_or(true),
            task_colors: parsed
                .logging
                .as_ref()
                .and_then(|l| l.task_colors)
                .unwrap_or(true),
        },
        tasks: task_map,
        updaters: UpdaterConfig {
            run_all_detected: run_all_detected.unwrap_or(true),
            include: include
                .unwrap_or_default()
                .into_iter()
                .map(|v| v.to_ascii_lowercase())
                .collect(),
            exclude: exclude
                .unwrap_or_default()
                .into_iter()
                .map(|v| v.to_ascii_lowercase())
                .collect(),
            privilege_mode,
            custom_tasks,
            bootstrap: BootstrapConfig {
                enabled: bootstrap_cfg.enabled.unwrap_or(false),
                windows_foundations: bootstrap_cfg
                    .windows_foundations
                    .unwrap_or(default_windows_foundations),
            },
        },
        completions: CompletionConfig {
            tools: custom_completion_tools,
            shells: completion_shells,
        },
        source_path: resolved_path,
    })
}

fn default_windows_foundation_ids() -> Result<Vec<String>> {
    Ok(builtin_windows_foundations()?
        .into_iter()
        .map(|foundation| foundation.id)
        .collect())
}

pub fn init_config_file(path: Option<PathBuf>, force: bool) -> Result<PathBuf> {
    let out_path = path.unwrap_or_else(default_config_write_path);
    if out_path.exists() && !force {
        bail!(
            "config file already exists: {} (use --force to overwrite)",
            out_path.display()
        );
    }
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create config directory {}", parent.display()))?;
    }
    std::fs::write(&out_path, default_config_template())
        .with_context(|| format!("write config {}", out_path.display()))?;
    Ok(out_path)
}

pub fn validate_config(path: Option<PathBuf>, strict: bool) -> Result<ConfigValidationReport> {
    let resolved = if let Some(p) = path {
        if !p.exists() {
            bail!("config file not found: {}", p.display());
        }
        Some(p)
    } else {
        resolve_config_path(None)?
    };

    let Some(cfg_path) = resolved.clone() else {
        return Ok(ConfigValidationReport {
            path: None,
            warnings: vec!["no config file found; using runtime defaults".to_string()],
        });
    };

    let raw = std::fs::read_to_string(&cfg_path)
        .with_context(|| format!("read config {}", cfg_path.display()))?;

    let value: toml::Value =
        toml::from_str(&raw).with_context(|| format!("parse config {}", cfg_path.display()))?;
    let parsed = parse_file_config(&cfg_path)?;

    let mut warnings = Vec::new();
    if let Some(table) = value.as_table() {
        let allowed_top: BTreeSet<&str> = [
            "ui",
            "engine",
            "install",
            "runtime",
            "logging",
            "tasks",
            "updaters",
            "bootstrap",
            "completions",
        ]
        .into_iter()
        .collect();
        for key in table.keys() {
            if !allowed_top.contains(key.as_str()) {
                let msg = match key.as_str() {
                    "completion" => "unknown top-level key 'completion'; use [completions] for user-managed completion tools".to_string(),
                    _ => format!("unknown top-level key '{key}'; valid top-level sections are ui, engine, install, runtime, logging, tasks, updaters, bootstrap, completions"),
                };
                if strict {
                    bail!(msg);
                }
                warnings.push(msg);
            }
        }
    }

    parse_core_config_values(&parsed)?;

    if let Some(up) = parsed.updaters {
        let tasks = collect_updater_task_configs(Some(&cfg_path), up.catalogs, up.tasks)?;
        parse_custom_tasks(tasks)?;
    }

    if let Some(bootstrap) = parsed.bootstrap {
        if let Some(foundations) = bootstrap.windows_foundations {
            let supported: BTreeSet<String> =
                default_windows_foundation_ids()?.into_iter().collect();
            let supported_text = supported.iter().cloned().collect::<Vec<_>>().join("|");
            for foundation in foundations {
                let normalized = foundation.trim().to_ascii_lowercase();
                if !supported.contains(&normalized) {
                    bail!(
                        "invalid bootstrap.windows_foundations entry '{}'; expected {}",
                        foundation,
                        supported_text
                    );
                }
            }
        }
    }

    if let Some(completions) = parsed.completions {
        parse_completion_tool_configs(completions.tools)?;
        if let Some(shells) = completions.shells {
            if !shells.is_empty() {
                crate::completions::resolve_completion_shells(&shells, &[])
                    .context("validate completions.shells")?;
            }
        }
    }

    Ok(ConfigValidationReport {
        path: Some(cfg_path),
        warnings,
    })
}

pub fn default_config_template() -> &'static str {
    include_str!("../config.example.toml")
}

fn windows_roaming_config_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(appdata) = env::var("APPDATA") {
            if !appdata.trim().is_empty() {
                return Some(PathBuf::from(appdata));
            }
        }
        if let Ok(profile) = env::var("USERPROFILE") {
            if !profile.trim().is_empty() {
                return Some(PathBuf::from(profile).join("AppData").join("Roaming"));
            }
        }
    }
    None
}

pub(crate) fn windows_default_install_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        if let Ok(profile) = env::var("USERPROFILE") {
            if !profile.trim().is_empty() {
                return Some(PathBuf::from(profile).join(".local").join("bin"));
            }
        }
    }
    None
}

pub fn merge_user_completion_catalog(
    catalog: Registry,
    runtime_cfg: Option<&RuntimeConfig>,
) -> Registry {
    let Some(runtime_cfg) = runtime_cfg else {
        return catalog;
    };
    if runtime_cfg.completions.tools.is_empty() {
        return catalog;
    }

    let mut providers = catalog.providers;
    let mut provider_names: BTreeSet<String> = providers.iter().map(|p| p.name.clone()).collect();
    let mut tools = catalog.tools;

    for tool in &runtime_cfg.completions.tools {
        if provider_names.insert(tool.provider.clone()) {
            providers.push(RegistryProvider {
                name: tool.provider.clone(),
                enabled: Some(true),
            });
        }
        if let Some(existing) = tools.iter_mut().find(|existing| {
            existing.name == tool.name
                && existing.provider.as_deref().unwrap_or("npm") == tool.provider
        }) {
            existing.enabled = Some(tool.enabled);
            existing.managed_required = Some(tool.managed_required);
            existing.priority = tool.priority;
            existing.trust_dynamic = tool.trust_dynamic;
        } else {
            tools.push(RegistryTool {
                name: tool.name.clone(),
                provider: Some(tool.provider.clone()),
                enabled: Some(tool.enabled),
                managed_required: Some(tool.managed_required),
                priority: tool.priority,
                ambient: tool.provider == "path",
                trust_dynamic: tool.trust_dynamic,
                command: None,
                command_candidates: Vec::new(),
                bundled_completions: Vec::new(),
                completion_recipes: Vec::new(),
            });
        }
    }

    Registry {
        schema_version: catalog.schema_version,
        providers,
        tools,
    }
}

fn parse_file_config(path: &Path) -> Result<FileConfig> {
    let txt =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    toml::from_str::<FileConfig>(&txt).with_context(|| format!("parse config {}", path.display()))
}

fn is_supported_completion_provider(provider: &str) -> bool {
    matches!(
        provider.trim().to_ascii_lowercase().as_str(),
        "path" | "npm" | "pipx" | "uv" | "go"
    )
}

fn expand_tilde_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~" {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home);
        }
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            return Path::new(&home).join(rest);
        }
    }
    path.to_path_buf()
}

pub fn resolve_config_path(config_path_cli: Option<PathBuf>) -> Result<Option<PathBuf>> {
    if let Some(path) = config_path_cli {
        if !path.exists() {
            bail!("config file not found: {}", path.display());
        }
        return Ok(Some(path));
    }

    if let Ok(path) = env::var("UPDATE_ALL_CONFIG") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(Some(path));
        }
    }

    for candidate in default_config_candidates() {
        if candidate.exists() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn default_config_write_path() -> PathBuf {
    default_config_candidates()
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("update-all.config.toml"))
}

pub fn resolve_config_write_path(config_path_cli: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = config_path_cli {
        return Ok(path);
    }

    if let Ok(path) = env::var("UPDATE_ALL_CONFIG") {
        let path = PathBuf::from(path);
        if !path.to_string_lossy().trim().is_empty() {
            return Ok(path);
        }
    }

    if let Some(path) = resolve_config_path(None)? {
        return Ok(path);
    }
    Ok(default_config_write_path())
}

#[cfg(windows)]
fn default_config_candidates() -> Vec<PathBuf> {
    windows_roaming_config_root()
        .map(|root| vec![root.join("update-all").join("config.toml")])
        .unwrap_or_default()
}

#[cfg(not(windows))]
fn default_config_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(xdg) = env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            out.push(Path::new(&xdg).join("update-all/config.toml"));
        }
    }
    if let Ok(home) = env::var("HOME") {
        if !home.trim().is_empty() {
            out.push(Path::new(&home).join(".config/update-all/config.toml"));
        }
    }
    out
}

pub fn default_run_root() -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(root) = windows_roaming_config_root() {
            return root.join("update-all").join("runs");
        }
    }
    if let Ok(xdg) = env::var("XDG_STATE_HOME") {
        if !xdg.trim().is_empty() {
            return Path::new(&xdg).join("update-all/runs");
        }
    }
    if let Ok(home) = env::var("HOME") {
        if !home.trim().is_empty() {
            return Path::new(&home).join(".local/state/update-all/runs");
        }
    }
    PathBuf::from(".update-all-runs")
}

pub fn parse_ui_mode(s: &str) -> Option<UiMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "auto" => Some(UiMode::Auto),
        "plain" => Some(UiMode::Plain),
        "dashboard" => Some(UiMode::Dashboard),
        _ => None,
    }
}

pub fn parse_engine_mode(s: &str) -> Option<EngineMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "sync" => Some(EngineMode::Sync),
        "async" => Some(EngineMode::Async),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/config.rs"]
mod tests;
