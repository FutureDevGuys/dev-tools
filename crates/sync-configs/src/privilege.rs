use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;
#[cfg(unix)]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(debug_assertions, feature = "test-support"))]
use std::sync::Arc;
use std::time::Duration;

use dev_tools_command::{
    is_executable_file, run_bounded_command, run_bounded_command_with_cancellation, BoundedCommand,
    BoundedCommandError, BoundedCommandErrorKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_PRIVILEGED_COMMAND_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_PRIVILEGED_COMMAND_OUTPUT_LIMIT: usize = 16 << 20;
#[cfg(unix)]
const AUTHORIZATION_PROBE_LIMITS: PrivilegedExecutionLimits = PrivilegedExecutionLimits {
    timeout: Duration::from_secs(30),
    output_limit: 64 << 10,
};
#[cfg(unix)]
const AUTHORIZATION_PROBE_CANDIDATES: [&str; 2] = ["/usr/bin/true", "/bin/true"];

#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[error("privileged operation interrupted")]
    Interrupted,
    #[error("sudo executable has unsafe authority")]
    UnsafeSudo,
    #[error("unable to authenticate one shared sudo session ({stage}: {failure})")]
    Authentication {
        stage: AuthenticationStage,
        failure: AuthenticationFailure,
    },
    #[error("privileged command executable has unsafe authority")]
    UnsafeCommand,
    #[error("privileged command requires an authenticated sudo session")]
    NotAuthenticated,
    #[error(
        "sudo requires interactive authentication, but no foreground terminal is available to \
         request it, so no credential was collected; run sync-configs directly in a terminal, \
         or authenticate first in a user-visible terminal and verify with `sudo -n -v`"
    )]
    PromptUnavailable,
    #[error("privileged command failed to start")]
    Start,
    #[error("privileged command exceeded its execution timeout")]
    TimedOut,
    #[error("privileged command exceeded its output capture limit")]
    OutputLimit,
    #[error("privileged command could not complete bounded execution")]
    Runner,
    #[error("privileged command exited unsuccessfully")]
    Failed,
    #[error("sudo privilege is not available on this platform")]
    Unsupported,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationStage {
    CachedCheck,
    Prompt,
}

impl std::fmt::Display for AuthenticationStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CachedCheck => "cached check",
            Self::Prompt => "prompt",
        })
    }
}

/// Value-free process evidence: no executable path, arguments, environment,
/// captured output or original I/O error text is retained.
#[derive(Debug, Error)]
pub enum AuthenticationFailure {
    #[error("process error {kind:?}, OS code {os_code:?}")]
    Process {
        kind: std::io::ErrorKind,
        os_code: Option<i32>,
    },
    #[error("exit code {code:?}, signal {signal:?}")]
    Exit {
        code: Option<i32>,
        signal: Option<i32>,
    },
}

#[cfg(unix)]
fn authentication_process_error(
    stage: AuthenticationStage,
    error: std::io::Error,
) -> PrivilegeError {
    PrivilegeError::Authentication {
        stage,
        failure: AuthenticationFailure::Process {
            kind: error.kind(),
            os_code: error.raw_os_error(),
        },
    }
}

#[derive(Debug)]
pub struct PrivilegeSession {
    sudo: PathBuf,
    authenticated: bool,
    authority: ExecutableAuthority,
    environment: BTreeMap<OsString, OsString>,
    limits: PrivilegedExecutionLimits,
    #[cfg(any(debug_assertions, feature = "test-support"))]
    cancellation_for_test: Option<Arc<AtomicBool>>,
    #[cfg(all(unix, any(debug_assertions, feature = "test-support")))]
    foreground_terminal_for_test: Option<bool>,
}

#[derive(Clone, Copy, Debug)]
struct PrivilegedExecutionLimits {
    timeout: Duration,
    output_limit: usize,
}

impl Default for PrivilegedExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_PRIVILEGED_COMMAND_TIMEOUT,
            output_limit: DEFAULT_PRIVILEGED_COMMAND_OUTPUT_LIMIT,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutableAuthority {
    TrustedSystem,
    #[cfg(any(debug_assertions, feature = "test-support"))]
    InjectedSudoForTest,
    #[cfg(any(debug_assertions, feature = "test-support"))]
    InjectedAllForTest,
}

impl PrivilegeSession {
    pub fn new(sudo: PathBuf) -> Result<Self, PrivilegeError> {
        let sudo = resolve_trusted_sudo(&sudo).map_err(|_| PrivilegeError::UnsafeSudo)?;
        Ok(Self {
            sudo,
            authenticated: false,
            authority: ExecutableAuthority::TrustedSystem,
            environment: env::vars_os().collect(),
            limits: PrivilegedExecutionLimits::default(),
            #[cfg(any(debug_assertions, feature = "test-support"))]
            cancellation_for_test: None,
            #[cfg(all(unix, any(debug_assertions, feature = "test-support")))]
            foreground_terminal_for_test: None,
        })
    }

    /// Inject a non-system sudo stand-in while retaining strict authority for
    /// every executable launched through it.
    ///
    /// The production CLI has no input or branch that selects this constructor;
    /// normal construction always enforces system authority for sudo and every
    /// executable launched through it.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new_injected_sudo_for_test(sudo: PathBuf) -> Result<Self, PrivilegeError> {
        validate_executable(&sudo).map_err(|_| PrivilegeError::UnsafeSudo)?;
        Ok(Self {
            sudo,
            authenticated: false,
            authority: ExecutableAuthority::InjectedSudoForTest,
            environment: env::vars_os().collect(),
            limits: PrivilegedExecutionLimits::default(),
            cancellation_for_test: None,
            #[cfg(unix)]
            foreground_terminal_for_test: None,
        })
    }

    /// Inject both sudo and elevated executable authority for end-to-end tests
    /// whose stand-ins live under a private temporary directory.
    ///
    /// The production CLI has no input or branch that selects this constructor.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new_fully_injected_for_test(sudo: PathBuf) -> Result<Self, PrivilegeError> {
        validate_executable(&sudo).map_err(|_| PrivilegeError::UnsafeSudo)?;
        Ok(Self {
            sudo,
            authenticated: false,
            authority: ExecutableAuthority::InjectedAllForTest,
            environment: env::vars_os().collect(),
            limits: PrivilegedExecutionLimits::default(),
            cancellation_for_test: None,
            #[cfg(unix)]
            foreground_terminal_for_test: None,
        })
    }

    /// Inject a non-system sudo stand-in that starts already authenticated for
    /// tests that are validating post-auth execution semantics rather than the
    /// prompt/reuse flow itself.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new_authenticated_injected_sudo_for_test(sudo: PathBuf) -> Result<Self, PrivilegeError> {
        validate_executable(&sudo).map_err(|_| PrivilegeError::UnsafeSudo)?;
        Ok(Self {
            sudo,
            authenticated: true,
            authority: ExecutableAuthority::InjectedSudoForTest,
            environment: env::vars_os().collect(),
            limits: PrivilegedExecutionLimits::default(),
            cancellation_for_test: None,
            #[cfg(unix)]
            foreground_terminal_for_test: None,
        })
    }

    /// Inject both command authorities with an already-authenticated session
    /// for tests whose contract starts at bounded helper execution. This keeps
    /// resource-limit and cancellation tests independent from the separate
    /// interactive-authentication subprocess fixture.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn new_authenticated_fully_injected_for_test(
        sudo: PathBuf,
    ) -> Result<Self, PrivilegeError> {
        validate_executable(&sudo).map_err(|_| PrivilegeError::UnsafeSudo)?;
        Ok(Self {
            sudo,
            authenticated: true,
            authority: ExecutableAuthority::InjectedAllForTest,
            environment: env::vars_os().collect(),
            limits: PrivilegedExecutionLimits::default(),
            cancellation_for_test: None,
            #[cfg(unix)]
            foreground_terminal_for_test: None,
        })
    }

    /// Replace the captured process environment for deterministic integration
    /// tests. Release builds contain no caller-selectable environment surface.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_environment_for_test(mut self, environment: BTreeMap<OsString, OsString>) -> Self {
        self.environment = environment;
        self
    }

    /// Replace production resource bounds for deterministic integration tests.
    /// Release builds contain no caller-selectable limits surface.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_execution_limits_for_test(
        mut self,
        timeout: Duration,
        output_limit: usize,
    ) -> Self {
        self.limits = PrivilegedExecutionLimits {
            timeout,
            output_limit,
        };
        self
    }

    /// Replace process-global Ctrl-C state for bounded helper execution with a
    /// caller-owned flag for tests. Authentication retains its terminal-facing
    /// process interruption contract.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn with_cancellation_for_test(mut self, cancelled: Arc<AtomicBool>) -> Self {
        self.cancellation_for_test = Some(cancelled);
        self
    }

    /// Replace foreground-terminal detection for tests whose contract is the
    /// prompt decision rather than the test runner's own terminal.
    #[cfg(all(unix, any(debug_assertions, feature = "test-support")))]
    #[doc(hidden)]
    pub fn with_foreground_terminal_for_test(mut self, owns_foreground: bool) -> Self {
        self.foreground_terminal_for_test = Some(owns_foreground);
        self
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Authorize one shared sudo session, reusing existing authorization first.
    ///
    /// A cached timestamp (`sudo -n -v`) authorizes the session. Otherwise a
    /// harmless command in the exact `sudo -n --` form of later privileged work
    /// detects policy that admits commands without a timestamp, such as a
    /// NOPASSWD rule or a policy plugin grant. Only then does an interactive
    /// `sudo -v` run, inheriting the caller's terminal, and only when this
    /// process group owns that terminal's foreground: a background group would
    /// be stopped by the prompt's terminal read. This function never reads or
    /// proxies credential input itself.
    pub fn ensure_authenticated(&mut self) -> Result<(), PrivilegeError> {
        #[cfg(not(unix))]
        {
            Err(PrivilegeError::Unsupported)
        }
        #[cfg(unix)]
        {
            interruption_point()?;
            if self.authenticated {
                return Ok(());
            }
            self.authorize()?;
            self.authenticated = true;
            Ok(())
        }
    }

    #[cfg(unix)]
    fn authorize(&self) -> Result<(), PrivilegeError> {
        use std::os::unix::process::ExitStatusExt;

        let cached = Command::new(&self.sudo)
            .args(["-n", "-v"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| {
                authentication_process_error(AuthenticationStage::CachedCheck, error)
            })?;
        interruption_point()?;
        if cached.success() {
            return Ok(());
        }
        let policy_admits_commands = self.noninteractive_command_authorized()?;
        interruption_point()?;
        if policy_admits_commands {
            return Ok(());
        }
        if !self.owns_foreground_terminal() {
            return Err(PrivilegeError::PromptUnavailable);
        }
        let prompted = Command::new(&self.sudo)
            .arg("-v")
            .status()
            .map_err(|error| authentication_process_error(AuthenticationStage::Prompt, error))?;
        interruption_point()?;
        if prompted.success() {
            Ok(())
        } else {
            Err(PrivilegeError::Authentication {
                stage: AuthenticationStage::Prompt,
                failure: AuthenticationFailure::Exit {
                    code: prompted.code(),
                    signal: prompted.signal(),
                },
            })
        }
    }

    /// `sudo -v` validates only the timestamp, so policy that authorizes
    /// commands without one is visible only by running a command.
    #[cfg(unix)]
    fn noninteractive_command_authorized(&self) -> Result<bool, PrivilegeError> {
        let Some(probe) = AUTHORIZATION_PROBE_CANDIDATES
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| validate_trusted_executable(candidate).is_ok())
        else {
            return Ok(false);
        };
        match self.run_noninteractive(probe, &[], AUTHORIZATION_PROBE_LIMITS, true) {
            Ok(output) => Ok(output.status.success()),
            Err(PrivilegeError::Interrupted) => Err(PrivilegeError::Interrupted),
            Err(_) => Ok(false),
        }
    }

    #[cfg(unix)]
    fn owns_foreground_terminal(&self) -> bool {
        #[cfg(any(debug_assertions, feature = "test-support"))]
        if let Some(owns_foreground) = self.foreground_terminal_for_test {
            return owns_foreground;
        }
        use std::io::IsTerminal;
        use std::os::unix::fs::OpenOptionsExt;

        if !std::io::stdin().is_terminal() {
            return false;
        }
        let Ok(terminal) = fs::File::options()
            .read(true)
            .custom_flags(libc::O_NOCTTY)
            .open("/dev/tty")
        else {
            return false;
        };
        rustix::termios::tcgetpgrp(&terminal).is_ok_and(|group| group == rustix::process::getpgrp())
    }

    pub fn run(&self, command: &[OsString]) -> Result<Output, PrivilegeError> {
        self.run_inner(command, true)
    }

    /// Cleanup is allowed to settle after cancellation so privileged staging
    /// never abandons an adjacent temporary candidate.
    pub(crate) fn run_cleanup(&self, command: &[OsString]) -> Result<Output, PrivilegeError> {
        self.run_inner(command, false)
    }

    /// Exercise the non-cancellable cleanup path from integration tests without
    /// exposing it to release callers.
    #[cfg(any(debug_assertions, feature = "test-support"))]
    #[doc(hidden)]
    pub fn run_cleanup_for_test(&self, command: &[OsString]) -> Result<Output, PrivilegeError> {
        self.run_cleanup(command)
    }

    fn run_inner(
        &self,
        command: &[OsString],
        observe_cancellation: bool,
    ) -> Result<Output, PrivilegeError> {
        if observe_cancellation && self.cancellation_flag().load(Ordering::Acquire) {
            return Err(PrivilegeError::Interrupted);
        }
        let (executable, arguments) = command.split_first().ok_or(PrivilegeError::UnsafeCommand)?;
        let executable = self.elevated_executable(Path::new(executable))?;
        if !self.authenticated {
            return Err(PrivilegeError::NotAuthenticated);
        }
        let output =
            self.run_noninteractive(executable, arguments, self.limits, observe_cancellation)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(PrivilegeError::Failed)
        }
    }

    fn run_noninteractive(
        &self,
        executable: PathBuf,
        arguments: &[OsString],
        limits: PrivilegedExecutionLimits,
        observe_cancellation: bool,
    ) -> Result<Output, PrivilegeError> {
        let mut sudo_arguments = Vec::with_capacity(arguments.len() + 3);
        sudo_arguments.push(OsString::from("-n"));
        sudo_arguments.push(OsString::from("--"));
        sudo_arguments.push(executable.into_os_string());
        sudo_arguments.extend_from_slice(arguments);
        let request = BoundedCommand {
            executable: &self.sudo,
            arguments: &sudo_arguments,
            environment: &self.environment,
            cwd: None,
            timeout: limits.timeout,
            output_limit: limits.output_limit,
        };
        let output = if observe_cancellation {
            run_bounded_command_with_cancellation(&request, self.cancellation_flag())
        } else {
            run_bounded_command(&request)
        }
        .map_err(classify_bounded_error)?;
        Ok(Output {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    pub fn sudo_path(&self) -> &Path {
        &self.sudo
    }

    fn cancellation_flag(&self) -> &AtomicBool {
        #[cfg(any(debug_assertions, feature = "test-support"))]
        if let Some(cancelled) = self.cancellation_for_test.as_deref() {
            return cancelled;
        }
        crate::interrupt::cancellation_flag()
    }

    pub(crate) fn elevated_executable(&self, path: &Path) -> Result<PathBuf, PrivilegeError> {
        match self.authority {
            ExecutableAuthority::TrustedSystem => {
                validate_trusted_executable(path).map_err(|_| PrivilegeError::UnsafeCommand)?;
                Ok(path.to_path_buf())
            }
            #[cfg(any(debug_assertions, feature = "test-support"))]
            ExecutableAuthority::InjectedSudoForTest => {
                validate_trusted_executable(path).map_err(|_| PrivilegeError::UnsafeCommand)?;
                Ok(path.to_path_buf())
            }
            #[cfg(any(debug_assertions, feature = "test-support"))]
            ExecutableAuthority::InjectedAllForTest => {
                validate_executable(path).map_err(|_| PrivilegeError::UnsafeCommand)?;
                Ok(path.to_path_buf())
            }
        }
    }
}

#[cfg(unix)]
fn interruption_point() -> Result<(), PrivilegeError> {
    crate::interrupt::check().map_err(|_| PrivilegeError::Interrupted)
}

fn classify_bounded_error(error: BoundedCommandError) -> PrivilegeError {
    match error.kind() {
        BoundedCommandErrorKind::Cancelled => PrivilegeError::Interrupted,
        BoundedCommandErrorKind::TimedOut => PrivilegeError::TimedOut,
        BoundedCommandErrorKind::OutputLimit(_) => PrivilegeError::OutputLimit,
        BoundedCommandErrorKind::Start | BoundedCommandErrorKind::InvalidExecutable => {
            PrivilegeError::Start
        }
        _ => PrivilegeError::Runner,
    }
}

fn validate_executable(path: &Path) -> Result<(), ()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(());
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || !is_executable_file(path) {
        return Err(());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(());
        }
    }
    Ok(())
}

/// Resolve a fixed executable spelling to the exact immutable entry point and
/// prove that unprivileged users cannot replace it or any ancestor directory.
pub(crate) fn resolve_trusted_executable(path: &Path) -> Result<PathBuf, ()> {
    validate_trusted_executable(path)?;
    fs::canonicalize(path).map_err(|_| ())
}

pub(crate) fn resolve_trusted_sudo(path: &Path) -> Result<PathBuf, ()> {
    let canonical = resolve_trusted_executable(path)?;
    match canonical.file_name().and_then(|name| name.to_str()) {
        Some("sudo" | "sudo-rs") => Ok(canonical),
        _ => Err(()),
    }
}

/// Discover sudo through the caller's native PATH while retaining the fixed
/// system locations as a recovery fallback. Every candidate still passes the
/// complete trusted-executable and root-owned ancestor validation before it is
/// returned; user-writable or relative PATH entries cannot become authority.
pub(crate) fn discover_trusted_sudo(path: Option<&OsStr>) -> Option<PathBuf> {
    sudo_candidates(path)
        .into_iter()
        .find_map(|candidate| resolve_trusted_sudo(&candidate).ok())
}

fn sudo_candidates(path: Option<&OsStr>) -> Vec<PathBuf> {
    let mut candidates = path
        .into_iter()
        .flat_map(env::split_paths)
        .filter(|directory| directory.is_absolute())
        .map(|directory| directory.join("sudo"))
        .collect::<Vec<_>>();
    for fallback in ["/usr/bin/sudo", "/bin/sudo", "/usr/local/bin/sudo"] {
        let fallback = PathBuf::from(fallback);
        if !candidates.contains(&fallback) {
            candidates.push(fallback);
        }
    }
    candidates
}

/// Validate an executable and every path element that selects it while
/// preserving its caller-visible spelling. This matters for programs such as
/// `/bin/sh`, whose behavior is selected in part by the invoked path/argv0.
pub(crate) fn validate_trusted_executable(path: &Path) -> Result<(), ()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(());
    }
    let canonical = fs::canonicalize(path).map_err(|_| ())?;
    validate_executable(&canonical)?;
    validate_trusted_authority(&canonical)?;
    validate_trusted_spelling(path)
}

#[cfg(unix)]
fn validate_trusted_authority(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;

    let executable = fs::symlink_metadata(path).map_err(|_| ())?;
    if executable.uid() != 0 || executable.mode() & 0o022 != 0 {
        return Err(());
    }

    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let metadata = fs::symlink_metadata(directory).map_err(|_| ())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(());
        }
        ancestor = directory.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn validate_trusted_spelling(path: &Path) -> Result<(), ()> {
    use std::os::unix::fs::MetadataExt;

    for (index, component) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(component).map_err(|_| ())?;
        if metadata.uid() != 0 {
            return Err(());
        }
        if metadata.file_type().is_symlink() {
            // Unix symlink mode bits are not an authority boundary (and are
            // commonly reported as 0777). Replacement is controlled by the
            // already-validated parent, while the canonical target and its
            // complete ancestor chain are validated separately above.
            continue;
        }
        let expected_type = if index == 0 {
            metadata.is_file()
        } else {
            metadata.is_dir()
        };
        if !expected_type || metadata.mode() & 0o022 != 0 {
            return Err(());
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::sudo_candidates;
    use std::env;
    use std::path::PathBuf;

    #[test]
    fn sudo_discovery_includes_absolute_path_entries_before_fixed_fallbacks() {
        let path = env::join_paths([
            PathBuf::from("relative-bin"),
            PathBuf::from("/opt/vendor/sbin"),
            PathBuf::from("/usr/bin"),
        ])
        .expect("representable PATH");

        let candidates = sudo_candidates(Some(&path));

        assert_eq!(candidates[0], PathBuf::from("/opt/vendor/sbin/sudo"));
        assert_eq!(candidates[1], PathBuf::from("/usr/bin/sudo"));
        assert!(!candidates.contains(&PathBuf::from("relative-bin/sudo")));
        assert!(candidates.contains(&PathBuf::from("/bin/sudo")));
        assert!(candidates.contains(&PathBuf::from("/usr/local/bin/sudo")));
    }
}

#[cfg(not(unix))]
fn validate_trusted_authority(_path: &Path) -> Result<(), ()> {
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_spelling(path: &Path) -> Result<(), ()> {
    validate_executable(path)
}
