use crate::util::process::{run_capture, which};
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOs {
    Linux,
    Macos,
    Windows,
    Unknown,
}

impl HostOs {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            _ => Self::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
            Self::Unknown => "unknown",
        }
    }

    pub fn matches_name(&self, name: &str) -> bool {
        let name = name.trim().to_ascii_lowercase();
        match self {
            Self::Linux => name == "linux",
            Self::Macos => name == "macos" || name == "darwin" || name == "osx",
            Self::Windows => name == "windows" || name == "win",
            Self::Unknown => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivilegeMode {
    Skip,
    PromptTty,
    Fail,
}

impl PrivilegeMode {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "skip" | "best_effort_skip" => Some(Self::Skip),
            "prompt_tty" | "prompt" => Some(Self::PromptTty),
            "fail" | "fail_run" => Some(Self::Fail),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
/// Alternate command invocation for a built-in updater catalog task.
pub struct BuiltinCommandCandidate {
    /// Executable name or path to run when the primary command is unavailable.
    pub program: String,
    /// Arguments used for the actual updater invocation.
    pub args: Vec<String>,
    /// Optional probe arguments used to verify that the candidate can run.
    pub probe_args: Vec<String>,
    /// Human-readable mode label included in command details.
    pub mode: Option<String>,
}

#[derive(Clone, Debug)]
/// Read-only command whose output supplements a built-in updater report.
pub struct BuiltinReportCommand {
    /// Executable name or path to run after the updater succeeds.
    pub program: String,
    /// Arguments used for the read-only report command.
    pub args: Vec<String>,
    /// When the read-only report command should run.
    pub when: BuiltinReportCommandWhen,
    /// Additional non-zero exit codes that still carry valid read-only report output.
    pub allow_exit_codes: Vec<i32>,
    /// Optional regex-driven state diff parser for before/after probes.
    pub state_pattern: Option<BuiltinStateReportPattern>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinReportCommandWhen {
    Before,
    After,
    BeforeAfter,
}

impl BuiltinReportCommandWhen {
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
pub struct BuiltinStateReportPattern {
    pub pattern: String,
    pub section_key: String,
    pub section_title: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub include_unchanged: bool,
}

#[derive(Clone, Debug)]
/// Data-backed Windows foundation bootstrap entry.
pub struct BuiltinWindowsFoundation {
    /// Stable selector used by bootstrap.windows_foundations.
    pub id: String,
    /// Command whose presence proves the foundation is installed.
    pub probe: String,
    /// Probe commands that must already be available before command execution.
    pub requires_probe: Vec<String>,
    /// Command used when the foundation is missing.
    pub missing_command: Option<BuiltinFoundationCommand>,
    /// Command used when the foundation is present and should be refreshed.
    pub present_command: Option<BuiltinFoundationCommand>,
    /// Note used when the foundation is present and no refresh command is configured.
    pub present_note: Option<String>,
}

#[derive(Clone, Debug)]
/// Data-backed command used by a Windows foundation bootstrap entry.
pub struct BuiltinFoundationCommand {
    /// Executable name or path.
    pub program: String,
    /// Command arguments.
    pub args: Vec<String>,
    /// Report-row after value when the command succeeds.
    pub after: String,
}

#[derive(Clone, Debug)]
/// Regex row extractor for a built-in updater catalog task.
pub struct BuiltinReportPattern {
    /// Regex pattern applied line-by-line, then against the whole output as a fallback.
    pub pattern: String,
    /// Stable report section key.
    pub section_key: String,
    /// Human-readable report section title.
    pub section_title: String,
    /// Row status label.
    pub status: String,
    /// Optional template for the row name.
    pub name: Option<String>,
    /// Optional template for the before value.
    pub before: Option<String>,
    /// Optional template for the after value.
    pub after: Option<String>,
    /// Optional template for the note value.
    pub note: Option<String>,
}

#[derive(Clone, Debug)]
/// Block-aware before/after extractor for nested updater dependency changes.
pub struct BuiltinScopedDelta {
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

#[derive(Clone, Debug)]
/// Command that runs before a built-in updater command.
pub struct BuiltinPreCommand {
    /// Executable name or path to run before the primary updater invocation.
    pub program: String,
    /// Arguments used for the pre-command invocation.
    pub args: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum BuiltinTaskKind {
    Managed {
        executor: BuiltinManagedExecutor,
    },
    Command {
        program: String,
        args: Vec<String>,
        mode: Option<String>,
        command_candidates: Vec<BuiltinCommandCandidate>,
        pre_commands: Vec<BuiltinPreCommand>,
        report_commands: Vec<BuiltinReportCommand>,
        report_patterns: Vec<BuiltinReportPattern>,
        report_scoped_deltas: Vec<BuiltinScopedDelta>,
        policy_key: String,
        requires_elevation: bool,
        needs_sudo_session: bool,
        interactive: bool,
        external_window: bool,
        shell: bool,
        plain_header: Option<String>,
        plain_start: Option<String>,
        success_details: Vec<String>,
        external_manager_skip: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinManagedExecutor {
    Npm,
    Completions,
    WindowsFoundations,
}

impl BuiltinManagedExecutor {
    fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "npm" => Some(Self::Npm),
            "completions" => Some(Self::Completions),
            "windows_foundations" => Some(Self::WindowsFoundations),
            _ => None,
        }
    }

    pub fn supported_values() -> &'static [&'static str] {
        &["npm", "completions", "windows_foundations"]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Completions => "completions",
            Self::WindowsFoundations => "windows_foundations",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinDetectionMode {
    AnyPresent,
    Always,
    CommandAvailable,
}

impl BuiltinDetectionMode {
    fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "any_present" => Some(Self::AnyPresent),
            "always" => Some(Self::Always),
            "command_available" => Some(Self::CommandAvailable),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuiltinReportParser {
    ArchUpdateServices,
    Scoop,
    VersionLines,
    Winget,
    Yay,
}

impl BuiltinReportParser {
    pub fn parse(input: &str) -> Option<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "arch_update_services" => Some(Self::ArchUpdateServices),
            "scoop" => Some(Self::Scoop),
            "version_lines" => Some(Self::VersionLines),
            "winget" => Some(Self::Winget),
            "yay" => Some(Self::Yay),
            _ => None,
        }
    }

    pub fn supported_values() -> &'static [&'static str] {
        &[
            "arch_update_services",
            "scoop",
            "version_lines",
            "winget",
            "yay",
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ArchUpdateServices => "arch_update_services",
            Self::Scoop => "scoop",
            Self::VersionLines => "version_lines",
            Self::Winget => "winget",
            Self::Yay => "yay",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BuiltinTask {
    pub id: String,
    pub label: String,
    pub os: Vec<String>,
    pub detect_mode: BuiltinDetectionMode,
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
    pub resource_locks: Vec<String>,
    pub include_with: Vec<String>,
    pub enabled_by_default: bool,
    pub category: String,
    pub order_rank: u16,
    pub report_parser: Option<BuiltinReportParser>,
    pub kind: BuiltinTaskKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinCatalog {
    tasks: Vec<BuiltinTaskEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinWindowsFoundationCatalog {
    foundations: Vec<BuiltinWindowsFoundationEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinTaskEntry {
    id: String,
    label: String,
    os: Vec<String>,
    detect_mode: Option<String>,
    detect_any: Vec<String>,
    detect_all: Option<Vec<String>>,
    detect_all_windows: Option<Vec<String>>,
    skip_if_any: Option<Vec<String>>,
    skip_if_any_windows: Option<Vec<String>>,
    depends_on: Vec<String>,
    after: Option<Vec<String>>,
    requires_selected_any: Option<Vec<String>>,
    depends_on_selected: Option<bool>,
    depends_on_selected_exclude: Option<Vec<String>>,
    resource_locks: Option<Vec<String>>,
    include_with: Option<Vec<String>>,
    enabled_by_default: bool,
    category: String,
    order_rank: Option<u16>,
    report_parser: Option<String>,
    kind: String,
    executor: Option<String>,
    program: Option<String>,
    args: Option<Vec<String>>,
    mode: Option<String>,
    command_candidates: Option<Vec<BuiltinCommandCandidateEntry>>,
    pre_commands: Option<Vec<BuiltinPreCommandEntry>>,
    report_commands: Option<Vec<BuiltinReportCommandEntry>>,
    report_patterns: Option<Vec<BuiltinReportPatternEntry>>,
    report_scoped_deltas: Option<Vec<BuiltinScopedDeltaEntry>>,
    policy_key: Option<String>,
    requires_elevation: Option<bool>,
    needs_sudo_session: Option<bool>,
    interactive: Option<bool>,
    external_window: Option<bool>,
    shell: Option<bool>,
    plain_header: Option<String>,
    plain_start: Option<String>,
    success_details: Option<Vec<String>>,
    external_manager_skip: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinCommandCandidateEntry {
    program: String,
    args: Option<Vec<String>>,
    probe_args: Option<Vec<String>>,
    mode: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinPreCommandEntry {
    program: String,
    args: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinReportCommandEntry {
    program: String,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinReportPatternEntry {
    pattern: Option<String>,
    section_key: Option<String>,
    section_title: Option<String>,
    status: Option<String>,
    name: Option<String>,
    before: Option<String>,
    after: Option<String>,
    note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinScopedDeltaEntry {
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinWindowsFoundationEntry {
    id: String,
    probe: String,
    requires_probe: Option<Vec<String>>,
    missing_command: Option<BuiltinFoundationCommandEntry>,
    present_command: Option<BuiltinFoundationCommandEntry>,
    present_note: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuiltinFoundationCommandEntry {
    program: String,
    args: Option<Vec<String>>,
    after: Option<String>,
}

static BUILTIN_CATALOG: OnceLock<std::result::Result<Vec<BuiltinTask>, String>> = OnceLock::new();
static BUILTIN_WINDOWS_FOUNDATIONS: OnceLock<
    std::result::Result<Vec<BuiltinWindowsFoundation>, String>,
> = OnceLock::new();

fn os_matches(task: &BuiltinTask, host_os: HostOs) -> bool {
    task.os.iter().any(|name| host_os.matches_name(name))
}

fn detect_present(bin: &str, host_os: HostOs) -> bool {
    if which(bin).is_some() {
        return true;
    }

    if matches!(host_os, HostOs::Windows) {
        return ["cmd", "bat", "exe"]
            .iter()
            .map(|ext| format!("{bin}.{ext}"))
            .any(|candidate| which(&candidate).is_some());
    }

    false
}

pub(crate) fn command_program_path(program: &str, host_os: HostOs) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.components().count() > 1 || path.is_absolute() {
        return path.is_file().then(|| path.to_path_buf());
    }
    if let Some(path) = which(program) {
        return Some(path);
    }

    if matches!(host_os, HostOs::Windows) {
        for ext in ["cmd", "bat", "exe"] {
            let candidate = format!("{program}.{ext}");
            if let Some(path) = which(&candidate) {
                return Some(path);
            }
        }
    }

    None
}

pub(crate) fn command_candidate_is_available(
    candidate: &BuiltinCommandCandidate,
    host_os: HostOs,
) -> bool {
    let Some(program) = command_program_path(&candidate.program, host_os) else {
        return false;
    };
    if candidate.probe_args.is_empty() {
        return true;
    }

    run_capture(
        program.to_string_lossy().as_ref(),
        candidate.probe_args.iter().map(String::as_str),
        Some(Duration::from_secs(5)),
    )
    .is_ok()
}

fn command_task_is_available(kind: &BuiltinTaskKind, host_os: HostOs) -> bool {
    let BuiltinTaskKind::Command {
        program,
        command_candidates,
        ..
    } = kind
    else {
        return false;
    };

    command_program_path(program, host_os).is_some()
        || command_candidates
            .iter()
            .any(|candidate| command_candidate_is_available(candidate, host_os))
}

fn detect_matches(task: &BuiltinTask, host_os: HostOs) -> bool {
    detect_matches_with_options(task, host_os, false)
}

fn detect_matches_with_options(
    task: &BuiltinTask,
    host_os: HostOs,
    ignore_skip_rules: bool,
) -> bool {
    if !ignore_skip_rules && task_skip_rule_matches(task, host_os) {
        return false;
    }
    if !task
        .detect_all
        .iter()
        .all(|bin| detect_present(bin, host_os))
    {
        return false;
    }
    if matches!(host_os, HostOs::Windows)
        && !task
            .detect_all_windows
            .iter()
            .all(|bin| detect_present(bin, host_os))
    {
        return false;
    }

    match task.detect_mode {
        BuiltinDetectionMode::Always => return true,
        BuiltinDetectionMode::CommandAvailable => {
            return command_task_is_available(&task.kind, host_os);
        }
        BuiltinDetectionMode::AnyPresent => {}
    }

    if !task
        .detect_any
        .iter()
        .any(|bin| detect_present(bin, host_os))
    {
        return false;
    }
    true
}

fn task_skip_rule_matches(task: &BuiltinTask, host_os: HostOs) -> bool {
    task.skip_if_any
        .iter()
        .chain(
            task.skip_if_any_windows
                .iter()
                .filter(|_| matches!(host_os, HostOs::Windows)),
        )
        .any(|bin| detect_present(bin, host_os))
}

pub fn detected_builtin_tasks(host_os: HostOs) -> Result<Vec<BuiltinTask>> {
    Ok(builtin_catalog()?
        .into_iter()
        .filter(|task| os_matches(task, host_os))
        .filter(|task| detect_matches(task, host_os))
        .collect())
}

pub(crate) fn detected_builtin_tasks_with_skip_overrides(
    host_os: HostOs,
    explicit_task_ids: &BTreeSet<String>,
) -> Result<Vec<BuiltinTask>> {
    Ok(builtin_catalog()?
        .into_iter()
        .filter(|task| os_matches(task, host_os))
        .filter(|task| {
            detect_matches_with_options(task, host_os, explicit_task_ids.contains(&task.id))
        })
        .collect())
}

pub fn builtin_catalog() -> Result<Vec<BuiltinTask>> {
    match BUILTIN_CATALOG.get_or_init(|| parse_builtin_catalog().map_err(|err| format!("{err:#}")))
    {
        Ok(tasks) => Ok(tasks.clone()),
        Err(err) => anyhow::bail!("{err}"),
    }
}

pub fn builtin_windows_foundations() -> Result<Vec<BuiltinWindowsFoundation>> {
    match BUILTIN_WINDOWS_FOUNDATIONS
        .get_or_init(|| parse_builtin_windows_foundations().map_err(|err| format!("{err:#}")))
    {
        Ok(foundations) => Ok(foundations.clone()),
        Err(err) => anyhow::bail!("{err}"),
    }
}

fn parse_builtin_catalog() -> Result<Vec<BuiltinTask>> {
    let catalog: BuiltinCatalog = toml::from_str(include_str!("builtin_tasks.toml"))
        .context("parse embedded built-in updater catalog")?;
    let mut tasks = Vec::with_capacity(catalog.tasks.len());
    for entry in catalog.tasks {
        tasks.push(entry.into_builtin_task()?);
    }
    let raw_ids = tasks
        .iter()
        .map(|task| task.id.clone())
        .collect::<BTreeSet<_>>();
    for task in &mut tasks {
        task.id = builtin_task_id(&task.id);
        qualify_builtin_references(&raw_ids, &mut task.depends_on);
        qualify_builtin_references(&raw_ids, &mut task.after);
        qualify_builtin_references(&raw_ids, &mut task.requires_selected_any);
        qualify_builtin_references(&raw_ids, &mut task.depends_on_selected_exclude);
        qualify_builtin_references(&raw_ids, &mut task.include_with);
    }
    validate_builtin_catalog(tasks)
}

fn builtin_task_id(id: &str) -> String {
    format!("builtin/{id}")
}

fn qualify_builtin_references(raw_ids: &BTreeSet<String>, references: &mut [String]) {
    for reference in references {
        if raw_ids.contains(reference) {
            *reference = builtin_task_id(reference);
        }
    }
}

fn parse_builtin_windows_foundations() -> Result<Vec<BuiltinWindowsFoundation>> {
    let catalog: BuiltinWindowsFoundationCatalog =
        toml::from_str(include_str!("windows_foundations.toml"))
            .context("parse embedded Windows foundation catalog")?;
    let mut foundations = Vec::with_capacity(catalog.foundations.len());
    for entry in catalog.foundations {
        foundations.push(entry.into_builtin_windows_foundation()?);
    }
    validate_builtin_windows_foundations(foundations)
}

impl BuiltinTaskEntry {
    fn into_builtin_task(self) -> Result<BuiltinTask> {
        validate_non_empty_catalog_values(
            &self.id,
            "resource locks",
            self.resource_locks.as_deref().unwrap_or_default(),
        )?;
        let detect_mode = match self.detect_mode.as_deref() {
            Some(raw) => BuiltinDetectionMode::parse(raw).with_context(|| {
                format!(
                    "built-in updater catalog task '{}' has unsupported detect_mode '{}'",
                    self.id, raw
                )
            })?,
            None => BuiltinDetectionMode::AnyPresent,
        };
        let kind = match self.kind.trim() {
            "managed" => {
                self.ensure_no_command_fields()?;
                let raw_executor = self.executor.as_deref().with_context(|| {
                    format!(
                        "built-in updater catalog task '{}' missing executor",
                        self.id
                    )
                })?;
                let executor = BuiltinManagedExecutor::parse(raw_executor).with_context(|| {
                    format!(
                        "built-in updater catalog task '{}' has unsupported executor '{}'; expected {}",
                        self.id,
                        raw_executor,
                        BuiltinManagedExecutor::supported_values().join("|")
                    )
                })?;
                BuiltinTaskKind::Managed { executor }
            }
            "command" => {
                self.ensure_no_executor()?;
                let task_id = self.id.clone();
                let command_candidates = self
                    .command_candidates
                    .unwrap_or_default()
                    .into_iter()
                    .map(|candidate| candidate.into_builtin_candidate(&task_id))
                    .collect::<Result<Vec<_>>>()?;
                let pre_commands = self
                    .pre_commands
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, command)| command.into_builtin_pre_command(&task_id, idx))
                    .collect::<Result<Vec<_>>>()?;
                let report_commands = self
                    .report_commands
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, command)| command.into_builtin_report_command(&task_id, idx))
                    .collect::<Result<Vec<_>>>()?;
                let report_patterns = self
                    .report_patterns
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, pattern)| pattern.into_builtin_report_pattern(&task_id, idx))
                    .collect::<Result<Vec<_>>>()?;
                let report_scoped_deltas = self
                    .report_scoped_deltas
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(idx, delta)| delta.into_builtin_scoped_delta(&task_id, idx))
                    .collect::<Result<Vec<_>>>()?;
                BuiltinTaskKind::Command {
                    program: self.program.with_context(|| {
                        format!(
                            "built-in updater catalog task '{}' missing program",
                            self.id
                        )
                    })?,
                    args: self.args.unwrap_or_default(),
                    mode: self.mode,
                    command_candidates,
                    pre_commands,
                    report_commands,
                    report_patterns,
                    report_scoped_deltas,
                    policy_key: self.policy_key.with_context(|| {
                        format!(
                            "built-in updater catalog task '{}' missing policy_key",
                            self.id
                        )
                    })?,
                    requires_elevation: self.requires_elevation.unwrap_or(false),
                    needs_sudo_session: self.needs_sudo_session.unwrap_or(false),
                    interactive: self.interactive.unwrap_or(false),
                    external_window: self.external_window.unwrap_or(false),
                    shell: self.shell.unwrap_or(false),
                    plain_header: self.plain_header,
                    plain_start: self.plain_start,
                    success_details: self.success_details.unwrap_or_default(),
                    external_manager_skip: self.external_manager_skip.unwrap_or(false),
                }
            }
            other => {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has unsupported kind '{}'; expected managed|command",
                    self.id,
                    other
                );
            }
        };
        let report_parser = match self.report_parser.as_deref() {
            Some(raw) => Some(BuiltinReportParser::parse(raw).with_context(|| {
                format!(
                    "built-in updater catalog task '{}' has unsupported report_parser '{}'",
                    self.id, raw
                )
            })?),
            None => None,
        };
        Ok(BuiltinTask {
            id: self.id,
            label: self.label,
            os: self.os,
            detect_mode,
            detect_any: self.detect_any,
            detect_all: self.detect_all.unwrap_or_default(),
            detect_all_windows: self.detect_all_windows.unwrap_or_default(),
            skip_if_any: self.skip_if_any.unwrap_or_default(),
            skip_if_any_windows: self.skip_if_any_windows.unwrap_or_default(),
            depends_on: self.depends_on,
            after: self.after.unwrap_or_default(),
            requires_selected_any: self.requires_selected_any.unwrap_or_default(),
            depends_on_selected: self.depends_on_selected.unwrap_or(false),
            depends_on_selected_exclude: self.depends_on_selected_exclude.unwrap_or_default(),
            resource_locks: self.resource_locks.unwrap_or_default(),
            include_with: self.include_with.unwrap_or_default(),
            enabled_by_default: self.enabled_by_default,
            category: self.category,
            order_rank: self.order_rank.unwrap_or(20),
            report_parser,
            kind,
        })
    }

    fn ensure_no_command_fields(&self) -> Result<()> {
        if self.program.is_some()
            || self.args.is_some()
            || self.mode.is_some()
            || self.command_candidates.is_some()
            || self.pre_commands.is_some()
            || self.report_commands.is_some()
            || self.report_patterns.is_some()
            || self.report_scoped_deltas.is_some()
            || self.policy_key.is_some()
            || self.requires_elevation.is_some()
            || self.needs_sudo_session.is_some()
            || self.interactive.is_some()
            || self.external_window.is_some()
            || self.shell.is_some()
            || self.plain_header.is_some()
            || self.plain_start.is_some()
            || self.success_details.is_some()
            || self.external_manager_skip.is_some()
            || self.report_parser.is_some()
        {
            anyhow::bail!(
                "built-in updater catalog task '{}' has command-only fields but kind '{}'",
                self.id,
                self.kind
            );
        }
        Ok(())
    }

    fn ensure_no_executor(&self) -> Result<()> {
        if self.executor.is_some() {
            anyhow::bail!(
                "built-in updater catalog task '{}' has executor but kind '{}'",
                self.id,
                self.kind
            );
        }
        Ok(())
    }
}

impl BuiltinCommandCandidateEntry {
    fn into_builtin_candidate(self, task_id: &str) -> Result<BuiltinCommandCandidate> {
        if self.program.trim().is_empty() {
            anyhow::bail!(
                "built-in updater catalog task '{}' has command candidate with empty program",
                task_id
            );
        }
        validate_non_empty_catalog_values(
            task_id,
            "command candidate args",
            self.args.as_deref().unwrap_or_default(),
        )?;
        validate_non_empty_catalog_values(
            task_id,
            "command candidate probe_args",
            self.probe_args.as_deref().unwrap_or_default(),
        )?;
        Ok(BuiltinCommandCandidate {
            program: self.program,
            args: self.args.unwrap_or_default(),
            probe_args: self.probe_args.unwrap_or_default(),
            mode: self.mode,
        })
    }
}

impl BuiltinReportCommandEntry {
    fn into_builtin_report_command(
        self,
        task_id: &str,
        idx: usize,
    ) -> Result<BuiltinReportCommand> {
        if self.program.trim().is_empty() {
            anyhow::bail!(
                "built-in updater catalog task '{}' has report command {} with empty program",
                task_id,
                idx
            );
        }
        validate_non_empty_catalog_values(
            task_id,
            "report command args",
            self.args.as_deref().unwrap_or_default(),
        )?;
        let when = parse_builtin_report_command_when(
            task_id,
            idx,
            self.when.as_deref(),
            self.state_pattern.is_some(),
        )?;
        let state_pattern = parse_builtin_state_report_pattern(task_id, idx, &self)?;
        let allow_exit_codes = parse_builtin_report_command_allow_exit_codes(
            task_id,
            idx,
            self.allow_exit_codes.unwrap_or_default(),
        )?;
        Ok(BuiltinReportCommand {
            program: self.program,
            args: self.args.unwrap_or_default(),
            when,
            allow_exit_codes,
            state_pattern,
        })
    }
}

fn parse_builtin_report_command_allow_exit_codes(
    task_id: &str,
    idx: usize,
    codes: Vec<i32>,
) -> Result<Vec<i32>> {
    for code in &codes {
        if *code < 0 || *code > 255 {
            anyhow::bail!(
                "built-in updater catalog task '{}' report command {} has invalid allow_exit_codes entry {}; expected 0..255",
                task_id,
                idx,
                code
            );
        }
    }
    Ok(codes)
}

fn parse_builtin_report_command_when(
    task_id: &str,
    idx: usize,
    raw: Option<&str>,
    has_state_pattern: bool,
) -> Result<BuiltinReportCommandWhen> {
    let when = match raw {
        Some(value) => BuiltinReportCommandWhen::parse(value).with_context(|| {
            format!(
                "built-in updater catalog task '{}' report command {} has unsupported when '{}'",
                task_id, idx, value
            )
        })?,
        None if has_state_pattern => BuiltinReportCommandWhen::BeforeAfter,
        None => BuiltinReportCommandWhen::After,
    };
    if has_state_pattern && when != BuiltinReportCommandWhen::BeforeAfter {
        anyhow::bail!(
            "built-in updater catalog task '{}' report command {} state_pattern requires when = \"before_after\"",
            task_id,
            idx
        );
    }
    Ok(when)
}

fn parse_builtin_state_report_pattern(
    task_id: &str,
    idx: usize,
    raw: &BuiltinReportCommandEntry,
) -> Result<Option<BuiltinStateReportPattern>> {
    let Some(pattern) = raw.state_pattern.clone() else {
        return Ok(None);
    };
    if pattern.trim().is_empty() {
        anyhow::bail!(
            "built-in updater catalog task '{}' report command {} has empty state_pattern",
            task_id,
            idx
        );
    }
    Regex::new(&pattern).with_context(|| {
        format!(
            "built-in updater catalog task '{}' has invalid state_pattern on report command {}",
            task_id, idx
        )
    })?;
    let section_key = raw
        .state_section_key
        .clone()
        .unwrap_or_else(|| "state_packages".to_string());
    validate_non_empty_catalog_scalar(task_id, "report command state_section_key", &section_key)?;
    let section_title = raw
        .state_section_title
        .clone()
        .unwrap_or_else(|| "State Package Results".to_string());
    validate_non_empty_catalog_scalar(
        task_id,
        "report command state_section_title",
        &section_title,
    )?;
    for (field, value) in [
        ("state_name", raw.state_name.as_deref()),
        ("state_version", raw.state_version.as_deref()),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            anyhow::bail!(
                "built-in updater catalog task '{}' report command {} has empty {}",
                task_id,
                idx,
                field
            );
        }
    }
    Ok(Some(BuiltinStateReportPattern {
        pattern,
        section_key,
        section_title,
        name: raw.state_name.clone(),
        version: raw.state_version.clone(),
        include_unchanged: raw.state_include_unchanged.unwrap_or(false),
    }))
}

impl BuiltinReportPatternEntry {
    fn into_builtin_report_pattern(
        self,
        task_id: &str,
        idx: usize,
    ) -> Result<BuiltinReportPattern> {
        let pattern = self.pattern.with_context(|| {
            format!(
                "built-in updater catalog task '{}' report pattern {} missing pattern",
                task_id, idx
            )
        })?;
        if pattern.trim().is_empty() {
            anyhow::bail!(
                "built-in updater catalog task '{}' has report pattern {} with empty pattern",
                task_id,
                idx
            );
        }
        Regex::new(&pattern).with_context(|| {
            format!(
                "built-in updater catalog task '{}' has invalid report pattern {}",
                task_id, idx
            )
        })?;

        let section_key = self
            .section_key
            .unwrap_or_else(|| "catalog_report".to_string());
        validate_non_empty_catalog_scalar(task_id, "report pattern section_key", &section_key)?;
        let section_title = self
            .section_title
            .unwrap_or_else(|| "Catalog Report Results".to_string());
        validate_non_empty_catalog_scalar(task_id, "report pattern section_title", &section_title)?;
        let status = self.status.unwrap_or_else(|| "updated".to_string());
        validate_report_pattern_status(task_id, idx, &status)?;

        for (field, value) in [
            ("name", self.name.as_deref()),
            ("before", self.before.as_deref()),
            ("after", self.after.as_deref()),
            ("note", self.note.as_deref()),
        ] {
            if let Some(value) = value {
                validate_non_empty_catalog_scalar(
                    task_id,
                    &format!("report pattern {field} template"),
                    value,
                )?;
            }
        }

        Ok(BuiltinReportPattern {
            pattern,
            section_key,
            section_title,
            status,
            name: self.name,
            before: self.before,
            after: self.after,
            note: self.note,
        })
    }
}

impl BuiltinScopedDeltaEntry {
    fn into_builtin_scoped_delta(self, task_id: &str, idx: usize) -> Result<BuiltinScopedDelta> {
        let prefix = format!("built-in updater catalog task '{task_id}' scoped delta {idx}");
        let scope_pattern =
            builtin_scoped_delta_pattern(&prefix, "scope_pattern", self.scope_pattern, &["scope"])?;
        let before_pattern = builtin_scoped_delta_pattern(
            &prefix,
            "before_pattern",
            self.before_pattern,
            &["name", "version"],
        )?;
        let after_pattern = builtin_scoped_delta_pattern(
            &prefix,
            "after_pattern",
            self.after_pattern,
            &["name", "version"],
        )?;
        let section_key =
            builtin_scoped_delta_scalar(task_id, &prefix, "section_key", self.section_key)?;
        let section_title =
            builtin_scoped_delta_scalar(task_id, &prefix, "section_title", self.section_title)?;
        let row_name = builtin_scoped_delta_scalar(task_id, &prefix, "row_name", self.row_name)?;

        let parent_count = [
            self.scope_section_key.is_some(),
            self.scope_section_title.is_some(),
            self.scope_row_name.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        if parent_count != 0 && parent_count != 3 {
            anyhow::bail!(
                "{prefix} parent reporting requires scope_section_key, scope_section_title, and scope_row_name together"
            );
        }
        for (field, value) in [
            ("scope_section_key", self.scope_section_key.as_deref()),
            ("scope_section_title", self.scope_section_title.as_deref()),
            ("scope_row_name", self.scope_row_name.as_deref()),
        ] {
            if let Some(value) = value {
                validate_non_empty_catalog_scalar(
                    task_id,
                    &format!("scoped delta {field}"),
                    value,
                )?;
            }
        }

        Ok(BuiltinScopedDelta {
            scope_pattern,
            before_pattern,
            after_pattern,
            section_key,
            section_title,
            row_name,
            scope_section_key: self.scope_section_key,
            scope_section_title: self.scope_section_title,
            scope_row_name: self.scope_row_name,
        })
    }
}

fn builtin_scoped_delta_pattern(
    prefix: &str,
    field: &str,
    value: Option<String>,
    required_captures: &[&str],
) -> Result<String> {
    let Some(value) = value else {
        anyhow::bail!("{prefix} missing {field}");
    };
    if value.trim().is_empty() {
        anyhow::bail!("{prefix} has empty {field}");
    }
    let regex = Regex::new(&value).with_context(|| format!("{prefix} has invalid {field}"))?;
    for capture in required_captures {
        if !regex.capture_names().flatten().any(|name| name == *capture) {
            anyhow::bail!("{prefix} {field} must define a named '{capture}' capture");
        }
    }
    Ok(value)
}

fn builtin_scoped_delta_scalar(
    task_id: &str,
    prefix: &str,
    field: &str,
    value: Option<String>,
) -> Result<String> {
    let Some(value) = value else {
        anyhow::bail!("{prefix} missing {field}");
    };
    validate_non_empty_catalog_scalar(task_id, &format!("scoped delta {field}"), &value)?;
    Ok(value)
}

impl BuiltinPreCommandEntry {
    fn into_builtin_pre_command(self, task_id: &str, idx: usize) -> Result<BuiltinPreCommand> {
        if self.program.trim().is_empty() {
            anyhow::bail!(
                "built-in updater catalog task '{}' has pre-command {} with empty program",
                task_id,
                idx
            );
        }
        validate_non_empty_catalog_values(
            task_id,
            "pre-command args",
            self.args.as_deref().unwrap_or_default(),
        )?;
        Ok(BuiltinPreCommand {
            program: self.program,
            args: self.args.unwrap_or_default(),
        })
    }
}

impl BuiltinWindowsFoundationEntry {
    fn into_builtin_windows_foundation(self) -> Result<BuiltinWindowsFoundation> {
        validate_non_empty_catalog_scalar(&self.id, "foundation id", &self.id)?;
        validate_non_empty_catalog_scalar(&self.id, "foundation probe", &self.probe)?;
        validate_non_empty_catalog_values(
            &self.id,
            "foundation requires_probe",
            self.requires_probe.as_deref().unwrap_or_default(),
        )?;
        let missing_command = self
            .missing_command
            .map(|command| command.into_builtin_foundation_command(&self.id, "missing_command"))
            .transpose()?;
        let present_command = self
            .present_command
            .map(|command| command.into_builtin_foundation_command(&self.id, "present_command"))
            .transpose()?;
        if let Some(note) = self.present_note.as_deref() {
            validate_non_empty_catalog_scalar(&self.id, "foundation present_note", note)?;
        }
        Ok(BuiltinWindowsFoundation {
            id: self.id,
            probe: self.probe,
            requires_probe: self.requires_probe.unwrap_or_default(),
            missing_command,
            present_command,
            present_note: self.present_note,
        })
    }
}

impl BuiltinFoundationCommandEntry {
    fn into_builtin_foundation_command(
        self,
        foundation_id: &str,
        field: &str,
    ) -> Result<BuiltinFoundationCommand> {
        validate_non_empty_catalog_scalar(
            foundation_id,
            &format!("{field} program"),
            &self.program,
        )?;
        validate_non_empty_catalog_values(
            foundation_id,
            &format!("{field} args"),
            self.args.as_deref().unwrap_or_default(),
        )?;
        let after = self.after.unwrap_or_else(|| "updated".to_string());
        validate_non_empty_catalog_scalar(foundation_id, &format!("{field} after"), &after)?;
        Ok(BuiltinFoundationCommand {
            program: self.program,
            args: self.args.unwrap_or_default(),
            after,
        })
    }
}

fn validate_builtin_catalog(tasks: Vec<BuiltinTask>) -> Result<Vec<BuiltinTask>> {
    let mut ids = BTreeSet::new();
    for task in &tasks {
        if task.id.trim().is_empty() {
            anyhow::bail!("built-in updater catalog contains an empty task id");
        }
        if !ids.insert(task.id.clone()) {
            anyhow::bail!(
                "built-in updater catalog contains duplicate task id '{}'",
                task.id
            );
        }
        if task.label.trim().is_empty() {
            anyhow::bail!(
                "built-in updater catalog task '{}' has an empty label",
                task.id
            );
        }
        if task.category.trim().is_empty() {
            anyhow::bail!(
                "built-in updater catalog task '{}' has an empty category",
                task.id
            );
        }
        if task.os.is_empty() {
            anyhow::bail!(
                "built-in updater catalog task '{}' must list at least one OS",
                task.id
            );
        }
        for os_name in &task.os {
            let normalized = os_name.trim();
            let known = [HostOs::Linux, HostOs::Macos, HostOs::Windows]
                .iter()
                .any(|host_os| host_os.matches_name(normalized));
            if !known {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has unsupported OS '{}'",
                    task.id,
                    os_name
                );
            }
        }
        if matches!(task.detect_mode, BuiltinDetectionMode::AnyPresent)
            && task.detect_any.is_empty()
        {
            anyhow::bail!(
                "built-in updater catalog task '{}' uses any_present detection without detect_any entries",
                task.id
            );
        }
        for bin in &task.detect_any {
            if bin.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has an empty detector",
                    task.id
                );
            }
        }
        for bin in task
            .detect_all
            .iter()
            .chain(task.detect_all_windows.iter())
            .chain(task.skip_if_any.iter())
            .chain(task.skip_if_any_windows.iter())
        {
            if bin.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has an empty detector",
                    task.id
                );
            }
        }
        for selector in task
            .requires_selected_any
            .iter()
            .chain(task.depends_on_selected_exclude.iter())
        {
            if selector.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has an empty task selector",
                    task.id
                );
            }
        }
        for dep in &task.depends_on {
            if dep.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has an empty dependency",
                    task.id
                );
            }
        }
        for predecessor in &task.after {
            if predecessor.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has an empty ordering predecessor",
                    task.id
                );
            }
        }
        for selector in &task.include_with {
            if selector.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog task '{}' has an empty include_with selector",
                    task.id
                );
            }
        }
        if let BuiltinTaskKind::Command {
            program,
            policy_key,
            command_candidates,
            pre_commands,
            success_details,
            ..
        } = &task.kind
        {
            if program.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog command task '{}' has an empty program",
                    task.id
                );
            }
            if policy_key.trim().is_empty() {
                anyhow::bail!(
                    "built-in updater catalog command task '{}' has an empty policy_key",
                    task.id
                );
            }
            for candidate in command_candidates {
                if candidate.program.trim().is_empty() {
                    anyhow::bail!(
                        "built-in updater catalog command task '{}' has an empty candidate program",
                        task.id
                    );
                }
            }
            for command in pre_commands {
                if command.program.trim().is_empty() {
                    anyhow::bail!(
                        "built-in updater catalog command task '{}' has an empty pre-command program",
                        task.id
                    );
                }
            }
            for detail in success_details {
                if detail.trim().is_empty() {
                    anyhow::bail!(
                        "built-in updater catalog command task '{}' has an empty success detail",
                        task.id
                    );
                }
            }
        }
    }
    let categories: BTreeSet<&str> = tasks.iter().map(|task| task.category.as_str()).collect();
    for task in &tasks {
        for dep in &task.depends_on {
            if !ids.contains(dep) {
                anyhow::bail!(
                    "built-in updater catalog task '{}' depends on unknown task '{}'",
                    task.id,
                    dep
                );
            }
        }
        for predecessor in &task.after {
            if !ids.contains(predecessor) {
                anyhow::bail!(
                    "built-in updater catalog task '{}' runs after unknown task '{}'",
                    task.id,
                    predecessor
                );
            }
        }
        for selector in &task.requires_selected_any {
            if !ids.contains(selector) && !categories.contains(selector.as_str()) {
                anyhow::bail!(
                    "built-in updater catalog task '{}' requires unknown selected task selector '{}'",
                    task.id,
                    selector
                );
            }
        }
        for id in &task.depends_on_selected_exclude {
            if !ids.contains(id) {
                anyhow::bail!(
                    "built-in updater catalog task '{}' excludes unknown selected task '{}'",
                    task.id,
                    id
                );
            }
        }
    }
    Ok(tasks)
}

fn validate_builtin_windows_foundations(
    foundations: Vec<BuiltinWindowsFoundation>,
) -> Result<Vec<BuiltinWindowsFoundation>> {
    let mut ids = BTreeSet::new();
    let mut probes = BTreeSet::new();
    for foundation in &foundations {
        if foundation.id.trim().is_empty() {
            anyhow::bail!("built-in Windows foundation catalog contains an empty foundation id");
        }
        if !ids.insert(foundation.id.clone()) {
            anyhow::bail!(
                "built-in Windows foundation catalog contains duplicate foundation id '{}'",
                foundation.id
            );
        }
        if foundation.probe.trim().is_empty() {
            anyhow::bail!(
                "built-in Windows foundation '{}' has an empty probe",
                foundation.id
            );
        }
        probes.insert(foundation.probe.clone());
    }
    for foundation in &foundations {
        for required in &foundation.requires_probe {
            if !probes.contains(required) {
                anyhow::bail!(
                    "built-in Windows foundation '{}' requires unknown probe '{}'",
                    foundation.id,
                    required
                );
            }
        }
    }
    Ok(foundations)
}

fn validate_non_empty_catalog_values(task_id: &str, field: &str, values: &[String]) -> Result<()> {
    for value in values {
        validate_non_empty_catalog_scalar(task_id, field, value)?;
    }
    Ok(())
}

fn validate_non_empty_catalog_scalar(task_id: &str, field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        anyhow::bail!(
            "built-in updater catalog task '{}' has empty {} entry",
            task_id,
            field
        );
    }
    Ok(())
}

fn validate_report_pattern_status(task_id: &str, idx: usize, status: &str) -> Result<()> {
    match status.trim().to_ascii_lowercase().as_str() {
        "updated" | "refreshed" | "refresh" | "passed" | "pass" | "unchanged" | "skipped"
        | "failed" | "blocked" | "info" => {
            Ok(())
        }
        _ => anyhow::bail!(
            "built-in updater catalog task '{}' report pattern {} has invalid status '{}'; expected updated|refreshed|passed|pass|unchanged|skipped|failed|blocked|info",
            task_id,
            idx,
            status
        ),
    }
}

#[cfg(test)]
#[path = "../tests/updaters_mod.rs"]
mod tests;
