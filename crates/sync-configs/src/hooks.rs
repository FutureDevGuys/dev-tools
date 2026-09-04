//! Execution boundary for manifest-authorized per-entry hooks.
//!
//! Hooks are deliberately an explicit trusted shell-string interface. The
//! manifest, rather than this module, owns the command text. This module fixes
//! the shell executable and argv grammar, validates every selected hook before
//! authentication, and keeps command/output bytes out of its structured status.
//!
//! Hook execution is bounded through `dev-tools-command`: production hooks get
//! five minutes and independent 16 MiB stdout/stderr capture ceilings. On Unix,
//! output limits are enforced while the hook runs and timeout or overflow
//! terminalizes its owned process group. A process that deliberately creates a
//! new session leaves that domain, but inherited output handles cannot keep the
//! runner blocked. On non-Unix platforms the shared runner currently owns only
//! the direct child, so detached hook descendants remain unsupported.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use dev_tools_command::{
    is_executable_file, run_bounded_command_with_cancellation, BoundedCommand, BoundedCommandError,
    BoundedCommandErrorKind, BoundedCommandOutput, BoundedCommandStream,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::manifest::{Entry, Privilege, ScriptFailurePolicy};
use crate::privilege::{PrivilegeError, PrivilegeSession};

const DEFAULT_HOOK_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_HOOK_OUTPUT_LIMIT: usize = 16 << 20;

#[derive(Clone, Copy, Debug)]
struct HookExecutionLimits {
    timeout: Duration,
    output_limit: usize,
}

impl Default for HookExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_HOOK_TIMEOUT,
            output_limit: DEFAULT_HOOK_OUTPUT_LIMIT,
        }
    }
}

struct PreparedHookCommand {
    executable: PathBuf,
    arguments: Vec<OsString>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookRunMode {
    Apply,
    DryRun,
    Validate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HookPhase {
    #[serde(rename = "pre_script")]
    Pre,
    #[serde(rename = "post_script")]
    Post,
}

impl HookPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pre => "pre_script",
            Self::Post => "post_script",
        }
    }
}

impl fmt::Display for HookPhase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookState {
    Planned,
    Succeeded,
    FailedAbort,
    FailedSkip,
    FailedContinue,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookStatus {
    pub phase: HookPhase,
    pub state: HookState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookProgressState {
    Running,
    Planned,
}

/// A fixed-token progress record. Entry identity remains available from the
/// surrounding [`PreHookRecord`] or [`PostHookRecord`] and can be hashed by the
/// diagnostic recorder; command text and hook output are intentionally absent.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookProgress {
    pub phase: HookPhase,
    pub state: HookProgressState,
}

pub struct HookExecution {
    status: HookStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl HookExecution {
    pub fn status(&self) -> &HookStatus {
        &self.status
    }

    /// Captured bytes are returned only to the immediate caller. This module
    /// never writes them to a transcript, structured log, or filesystem.
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Captured bytes are returned only to the immediate caller. This module
    /// never writes them to a transcript, structured log, or filesystem.
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub fn into_output(self) -> (Vec<u8>, Vec<u8>) {
        (self.stdout, self.stderr)
    }
}

impl fmt::Debug for HookExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookExecution")
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookDecision {
    Proceed,
    Skip,
    Abort,
}

pub struct PreHookRecord<'a> {
    pub entry: &'a Entry,
    pub decision: HookDecision,
    pub progress: Option<HookProgress>,
    pub execution: Option<HookExecution>,
}

impl fmt::Debug for PreHookRecord<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreHookRecord")
            .field("decision", &self.decision)
            .field("progress", &self.progress)
            .field("execution", &self.execution)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostHookDecision {
    Complete,
    Abort,
}

pub struct PostHookRecord<'a> {
    pub entry: &'a Entry,
    pub decision: PostHookDecision,
    pub progress: HookProgress,
    pub execution: HookExecution,
}

impl fmt::Debug for PostHookRecord<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostHookRecord")
            .field("decision", &self.decision)
            .field("progress", &self.progress)
            .field("execution", &self.execution)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryConvergence {
    Changed,
    UpToDate,
    Failed,
    MissingSource,
    Skipped,
}

impl EntryConvergence {
    const fn permits_post_hook(self) -> bool {
        matches!(self, Self::Changed | Self::UpToDate)
    }
}

/// Safe, prevalidated platform-shell authority and its fixed argument prefix.
#[derive(Clone)]
pub struct HookShell {
    executable: PathBuf,
    arguments_before_script: Vec<OsString>,
}

impl HookShell {
    pub fn posix(executable: PathBuf) -> Result<Self, HookError> {
        Self::new(executable, vec![OsString::from("-c")])
    }

    pub fn windows_cmd(executable: PathBuf) -> Result<Self, HookError> {
        Self::new(
            executable,
            vec![
                OsString::from("/D"),
                OsString::from("/S"),
                OsString::from("/C"),
            ],
        )
    }

    pub fn current() -> Result<Self, HookError> {
        #[cfg(unix)]
        {
            Self::posix(PathBuf::from("/bin/sh"))
        }
        #[cfg(windows)]
        {
            let system_root = std::env::var_os("SystemRoot").ok_or(HookError::UnsafeShell)?;
            Self::windows_cmd(PathBuf::from(system_root).join("System32/cmd.exe"))
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(HookError::UnsupportedPlatform)
        }
    }

    fn new(executable: PathBuf, arguments_before_script: Vec<OsString>) -> Result<Self, HookError> {
        let executable = validated_executable(&executable)?;
        Ok(Self {
            executable,
            arguments_before_script,
        })
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl fmt::Debug for HookShell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookShell")
            .field("executable", &self.executable)
            .field("fixed_argument_count", &self.arguments_before_script.len())
            .finish()
    }
}

pub struct HookSpec<'a> {
    entry: &'a Entry,
    phase: HookPhase,
    command: &'a str,
    privilege: Privilege,
    on_failure: ScriptFailurePolicy,
}

impl<'a> HookSpec<'a> {
    fn pre(entry: &'a Entry) -> Option<Self> {
        entry.pre_script.as_deref().map(|command| Self {
            entry,
            phase: HookPhase::Pre,
            command,
            privilege: entry.pre_script_privilege,
            on_failure: entry.pre_script_on_fail,
        })
    }

    fn post(entry: &'a Entry) -> Option<Self> {
        entry.post_script.as_deref().map(|command| Self {
            entry,
            phase: HookPhase::Post,
            command,
            privilege: entry.post_script_privilege,
            on_failure: entry.post_script_on_fail,
        })
    }

    pub fn entry(&self) -> &'a Entry {
        self.entry
    }

    pub const fn phase(&self) -> HookPhase {
        self.phase
    }

    pub const fn privilege(&self) -> Privilege {
        self.privilege
    }

    pub const fn on_failure(&self) -> ScriptFailurePolicy {
        self.on_failure
    }

    pub const fn progress(&self, state: HookProgressState) -> HookProgress {
        HookProgress {
            phase: self.phase,
            state,
        }
    }
}

impl fmt::Debug for HookSpec<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookSpec")
            .field("phase", &self.phase)
            .field("privilege", &self.privilege)
            .field("on_failure", &self.on_failure)
            .field("command", &"<redacted>")
            .finish()
    }
}

struct EntryHooks<'a> {
    entry: &'a Entry,
    pre: Option<HookSpec<'a>>,
    post: Option<HookSpec<'a>>,
}

pub struct HookPlan<'a> {
    entries: Vec<EntryHooks<'a>>,
    config_dir: PathBuf,
    shell: HookShell,
    environment: BTreeMap<OsString, OsString>,
    limits: HookExecutionLimits,
    mode: HookRunMode,
    requires_pre_privilege: bool,
    requires_post_privilege: bool,
}

impl fmt::Debug for HookPlan<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HookPlan")
            .field("entry_count", &self.entries.len())
            .field("config_dir", &self.config_dir)
            .field("shell", &self.shell)
            .field("environment_variable_count", &self.environment.len())
            .field("limits", &self.limits)
            .field("mode", &self.mode)
            .field("requires_pre_privilege", &self.requires_pre_privilege)
            .field("requires_post_privilege", &self.requires_post_privilege)
            .finish()
    }
}

impl<'a> HookPlan<'a> {
    /// Prepare every selected entry before authentication or hook execution.
    /// Callers pass the already profile-selected, base/override-merged entries.
    pub fn prepare<I>(
        entries: I,
        config_dir: &Path,
        shell: HookShell,
        mode: HookRunMode,
    ) -> Result<Self, HookError>
    where
        I: IntoIterator<Item = &'a Entry>,
    {
        validate_working_directory(config_dir)?;
        let mut prepared = Vec::new();
        let mut requires_pre_privilege = false;
        let mut requires_post_privilege = false;
        for entry in entries {
            let pre = HookSpec::pre(entry);
            let post = HookSpec::post(entry);
            for hook in pre.iter() {
                validate_command(hook)?;
                if hook.privilege == Privilege::Sudo {
                    validate_privileged_hook_platform()?;
                    requires_pre_privilege = true;
                }
            }
            for hook in post.iter() {
                validate_command(hook)?;
                if hook.privilege == Privilege::Sudo {
                    validate_privileged_hook_platform()?;
                    requires_post_privilege = true;
                }
            }
            prepared.push(EntryHooks { entry, pre, post });
        }
        if mode != HookRunMode::Apply {
            requires_pre_privilege = false;
            requires_post_privilege = false;
        }
        Ok(Self {
            entries: prepared,
            config_dir: config_dir.to_path_buf(),
            shell,
            environment: std::env::vars_os().collect(),
            limits: HookExecutionLimits::default(),
            mode,
            requires_pre_privilege,
            requires_post_privilege,
        })
    }

    /// Replace production resource bounds for fast deterministic integration
    /// tests. Release builds contain no caller-selectable limits surface.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_execution_limits_for_test(
        mut self,
        timeout: Duration,
        output_limit: usize,
    ) -> Self {
        self.limits = HookExecutionLimits {
            timeout,
            output_limit,
        };
        self
    }

    pub const fn mode(&self) -> HookRunMode {
        self.mode
    }

    pub const fn requires_privilege(&self) -> bool {
        self.requires_pre_privilege || self.requires_post_privilege
    }

    pub const fn requires_pre_privilege(&self) -> bool {
        self.requires_pre_privilege
    }

    pub const fn requires_post_privilege(&self) -> bool {
        self.requires_post_privilege
    }

    pub(crate) fn declares_privilege(&self) -> bool {
        self.entries.iter().any(|entry| {
            entry
                .pre
                .as_ref()
                .is_some_and(|hook| hook.privilege == Privilege::Sudo)
                || entry
                    .post
                    .as_ref()
                    .is_some_and(|hook| hook.privilege == Privilege::Sudo)
        })
    }

    pub fn requires_eligible_post_privilege<F>(&self, mut convergence: F) -> bool
    where
        F: FnMut(&Entry) -> EntryConvergence,
    {
        self.mode == HookRunMode::Apply
            && self.entries.iter().any(|entry| {
                entry
                    .post
                    .as_ref()
                    .is_some_and(|hook| hook.privilege == Privilege::Sudo)
                    && matches!(
                        convergence(entry.entry),
                        EntryConvergence::Changed | EntryConvergence::UpToDate
                    )
            })
    }

    /// Validate the fixed elevated shell authority without acquiring a sudo
    /// timestamp. Engines call this during global preflight so a post-only
    /// privileged hook cannot reveal an unsafe shell after target mutation.
    pub(crate) fn validate_privileged_authority(&self) -> Result<(), HookError> {
        if self.declares_privilege() {
            crate::privilege::validate_trusted_executable(&self.shell.executable)
                .map_err(|_| HookError::UnsafeShell)?;
        }
        Ok(())
    }

    /// Authenticate at most once through the caller-owned shared session.
    /// Dry-run, validation, and hook-free plans are strict no-ops.
    pub fn authenticate(&self, session: &mut PrivilegeSession) -> Result<(), HookError> {
        if self.requires_privilege() {
            session.elevated_executable(&self.shell.executable)?;
            session.ensure_authenticated()?;
        }
        Ok(())
    }

    /// Run selected pre-hooks in manifest order. A failed `abort` hook marks
    /// that entry erroneous and ineligible, but—matching the established CLI
    /// contract—does not prevent later independent pre-hooks from running.
    pub fn run_pre_hooks(
        &self,
        session: Option<&PrivilegeSession>,
    ) -> Result<Vec<PreHookRecord<'a>>, HookError> {
        let mut records = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let Some(hook) = entry.pre.as_ref() else {
                records.push(PreHookRecord {
                    entry: entry.entry,
                    decision: HookDecision::Proceed,
                    progress: None,
                    execution: None,
                });
                continue;
            };
            let progress = hook.progress(match self.mode {
                HookRunMode::DryRun => HookProgressState::Planned,
                HookRunMode::Apply | HookRunMode::Validate => HookProgressState::Running,
            });
            match self.mode {
                HookRunMode::Validate => records.push(PreHookRecord {
                    entry: entry.entry,
                    decision: HookDecision::Proceed,
                    progress: None,
                    execution: None,
                }),
                HookRunMode::DryRun => records.push(PreHookRecord {
                    entry: entry.entry,
                    decision: HookDecision::Proceed,
                    progress: Some(progress),
                    execution: Some(planned_execution(hook.phase)),
                }),
                HookRunMode::Apply => {
                    let execution = self.execute(hook, session)?;
                    records.push(PreHookRecord {
                        entry: entry.entry,
                        decision: pre_decision(execution.status.state),
                        progress: Some(progress),
                        execution: Some(execution),
                    });
                }
            }
        }
        Ok(records)
    }

    /// Run post-hooks in original manifest order only for entries whose actual
    /// convergence succeeded. Dry-run records a value-free plan without
    /// executing anything; validation records nothing.
    pub fn run_post_hooks<F>(
        &self,
        session: Option<&PrivilegeSession>,
        mut convergence: F,
    ) -> Result<Vec<PostHookRecord<'a>>, HookError>
    where
        F: FnMut(&Entry) -> EntryConvergence,
    {
        let mut records = Vec::new();
        if self.mode == HookRunMode::Validate {
            return Ok(records);
        }
        for entry in &self.entries {
            let Some(hook) = entry.post.as_ref() else {
                continue;
            };
            if self.mode == HookRunMode::Apply && !convergence(entry.entry).permits_post_hook() {
                continue;
            }
            let progress = hook.progress(if self.mode == HookRunMode::DryRun {
                HookProgressState::Planned
            } else {
                HookProgressState::Running
            });
            let execution = if self.mode == HookRunMode::DryRun {
                planned_execution(hook.phase)
            } else {
                self.execute(hook, session)?
            };
            let decision = if execution.status.state == HookState::FailedAbort {
                PostHookDecision::Abort
            } else {
                PostHookDecision::Complete
            };
            records.push(PostHookRecord {
                entry: entry.entry,
                decision,
                progress,
                execution,
            });
        }
        Ok(records)
    }

    fn execute(
        &self,
        hook: &HookSpec<'_>,
        session: Option<&PrivilegeSession>,
    ) -> Result<HookExecution, HookError> {
        // Linux can briefly return ETXTBSY for a newly replaced executable
        // while an older mapping is being released. Rebuild the exact command
        // and retry only that transient kernel condition; every other spawn
        // failure remains immediate and value-conscious.
        let mut attempt = 0_u32;
        loop {
            let command = match hook.privilege {
                Privilege::User => self.user_command(hook.command),
                Privilege::Sudo => self.privileged_command(hook.command, session)?,
            };
            let output = run_bounded_command_with_cancellation(
                &BoundedCommand {
                    executable: &command.executable,
                    arguments: &command.arguments,
                    environment: &self.environment,
                    cwd: Some(&self.config_dir),
                    timeout: self.limits.timeout,
                    output_limit: self.limits.output_limit,
                },
                crate::interrupt::cancellation_flag(),
            );
            match output {
                Ok(output) => return Ok(completed_execution(hook, output)),
                Err(source) if attempt < 4 && executable_temporarily_busy(&source) => {
                    std::thread::sleep(Duration::from_millis(2_u64 << attempt));
                    attempt += 1;
                }
                Err(source) => return Err(classify_bounded_error(hook.phase, source)),
            }
        }
    }

    fn user_command(&self, script: &str) -> PreparedHookCommand {
        let mut arguments = self.shell.arguments_before_script.clone();
        arguments.push(OsString::from(script));
        PreparedHookCommand {
            executable: self.shell.executable.clone(),
            arguments,
        }
    }

    fn privileged_command(
        &self,
        script: &str,
        session: Option<&PrivilegeSession>,
    ) -> Result<PreparedHookCommand, HookError> {
        let session = session.ok_or(HookError::MissingPrivilegeSession)?;
        if !session.is_authenticated() {
            return Err(HookError::MissingPrivilegeSession);
        }
        let shell = session.elevated_executable(&self.shell.executable)?;
        let mut arguments = vec![OsString::from("-n"), OsString::from("--")];
        arguments.push(shell.into_os_string());
        arguments.extend(self.shell.arguments_before_script.iter().cloned());
        arguments.push(OsString::from(script));
        Ok(PreparedHookCommand {
            executable: session.sudo_path().to_path_buf(),
            arguments,
        })
    }
}

#[cfg(unix)]
fn executable_temporarily_busy(error: &BoundedCommandError) -> bool {
    error.kind() == BoundedCommandErrorKind::Start
        && error
            .io_error()
            .is_some_and(|source| source.raw_os_error() == Some(libc::ETXTBSY))
}

#[cfg(not(unix))]
fn executable_temporarily_busy(_error: &BoundedCommandError) -> bool {
    false
}

fn classify_bounded_error(phase: HookPhase, source: BoundedCommandError) -> HookError {
    match source.kind() {
        BoundedCommandErrorKind::Cancelled => HookError::Interrupted,
        BoundedCommandErrorKind::TimedOut => HookError::TimedOut { phase },
        BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout) => {
            HookError::OutputLimit {
                phase,
                stream: HookOutputStream::Stdout,
            }
        }
        BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stderr) => {
            HookError::OutputLimit {
                phase,
                stream: HookOutputStream::Stderr,
            }
        }
        BoundedCommandErrorKind::Start | BoundedCommandErrorKind::InvalidExecutable => {
            HookError::Start { phase }
        }
        _ => HookError::Runner { phase },
    }
}

fn planned_execution(phase: HookPhase) -> HookExecution {
    HookExecution {
        status: HookStatus {
            phase,
            state: HookState::Planned,
            exit_code: None,
        },
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

fn completed_execution(hook: &HookSpec<'_>, output: BoundedCommandOutput) -> HookExecution {
    let state = if output.status.success() {
        HookState::Succeeded
    } else {
        match hook.on_failure {
            ScriptFailurePolicy::Abort => HookState::FailedAbort,
            ScriptFailurePolicy::Skip => HookState::FailedSkip,
            ScriptFailurePolicy::Continue => HookState::FailedContinue,
        }
    };
    HookExecution {
        status: HookStatus {
            phase: hook.phase,
            state,
            exit_code: output.status.code(),
        },
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookOutputStream {
    Stdout,
    Stderr,
}

impl fmt::Display for HookOutputStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

fn pre_decision(state: HookState) -> HookDecision {
    match state {
        HookState::FailedAbort => HookDecision::Abort,
        HookState::FailedSkip => HookDecision::Skip,
        HookState::Planned | HookState::Succeeded | HookState::FailedContinue => {
            HookDecision::Proceed
        }
    }
}

fn validate_command(hook: &HookSpec<'_>) -> Result<(), HookError> {
    if hook.command.is_empty() || hook.command.as_bytes().contains(&0) {
        return Err(HookError::InvalidCommand { phase: hook.phase });
    }
    Ok(())
}

fn validate_working_directory(path: &Path) -> Result<(), HookError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(HookError::InvalidWorkingDirectory);
    }
    let metadata = fs::metadata(path).map_err(|_| HookError::InvalidWorkingDirectory)?;
    if !metadata.is_dir() {
        return Err(HookError::InvalidWorkingDirectory);
    }
    Ok(())
}

fn validated_executable(path: &Path) -> Result<PathBuf, HookError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(HookError::UnsafeShell);
    }
    let canonical = fs::canonicalize(path).map_err(|_| HookError::UnsafeShell)?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|_| HookError::UnsafeShell)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err(HookError::UnsafeShell);
    }
    if !is_executable_file(path) {
        return Err(HookError::UnsafeShell);
    }
    // Preserve the explicitly selected executable spelling. In particular,
    // invoking `/bin/sh` by that name can select POSIX behavior that would be
    // lost if a symlink were replaced with its canonical Bash target.
    Ok(path.to_path_buf())
}

#[cfg(unix)]
fn validate_privileged_hook_platform() -> Result<(), HookError> {
    Ok(())
}

#[cfg(not(unix))]
fn validate_privileged_hook_platform() -> Result<(), HookError> {
    Err(HookError::PrivilegedHooksUnsupported)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes()
        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
        != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Debug, Error)]
pub enum HookError {
    #[error("hook execution interrupted")]
    Interrupted,
    #[error("trusted hook shell has unsafe authority")]
    UnsafeShell,
    #[error("hook working directory is invalid")]
    InvalidWorkingDirectory,
    #[error("selected {phase} has an invalid hook command")]
    InvalidCommand { phase: HookPhase },
    #[error("selected privileged hooks are unsupported on this platform")]
    PrivilegedHooksUnsupported,
    #[error("privileged hook requires one authenticated shared sudo session")]
    MissingPrivilegeSession,
    #[error("{phase} hook failed to start")]
    Start { phase: HookPhase },
    #[error("{phase} hook exceeded the configured execution limit")]
    TimedOut { phase: HookPhase },
    #[error("{phase} hook {stream} exceeded the configured capture limit")]
    OutputLimit {
        phase: HookPhase,
        stream: HookOutputStream,
    },
    #[error("{phase} hook could not complete bounded execution")]
    Runner { phase: HookPhase },
    #[error(transparent)]
    Privilege(#[from] PrivilegeError),
    #[error("trusted hooks are unsupported on this platform")]
    UnsupportedPlatform,
}
