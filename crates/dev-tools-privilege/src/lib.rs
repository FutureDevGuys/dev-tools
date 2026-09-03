//! Product-neutral one-shot privileged helper authorization.
//!
//! This crate does not cache elevation, accept passwords, run shell command
//! strings, or expose a reusable privileged RPC surface. A caller supplies one
//! absolute executable plus native arguments, and the selected platform backend
//! owns that authorizer child until it is terminal.

use std::ffi::OsString;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io;
use std::path::Path;
#[cfg(unix)]
use std::path::{Component, PathBuf};
#[cfg(unix)]
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

use anyhow::Result;
#[cfg(unix)]
use anyhow::{bail, Context};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserInteraction {
    Allowed,
    Forbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioPolicy {
    Inherit,
    Null,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessTermination {
    pub code: Option<i32>,
    pub signal: Option<i32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnavailableReason {
    AuthorizationProgram,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeOutcome {
    Exited(ProcessTermination),
    /// The backend positively proved that authorization was denied before the
    /// helper started. Backends must return `Exited` when denial and a helper
    /// exit code cannot be distinguished.
    Denied,
    /// The authorization surface positively attributed termination to a user
    /// cancellation. Raw process signals alone are not sufficient evidence.
    Cancelled,
    /// The selected backend positively proved that its complete privileged
    /// boundary exceeded a supported deadline.
    TimedOut,
    Unavailable(UnavailableReason),
}

#[derive(Debug)]
pub struct ExactHelperRequest<'a> {
    pub helper: &'a Path,
    pub arguments: &'a [OsString],
    /// Optional backend-owned transaction deadline. The sudo backend requires
    /// `None` because it cannot safely terminate and prove its full helper
    /// subtree without additional sudoers policy or a stronger OS boundary.
    pub deadline: Option<Duration>,
    pub interaction: UserInteraction,
    pub stdio: StdioPolicy,
}

pub trait PrivilegeAuthorizer {
    /// Authorize and run exactly one helper transaction.
    fn authorize_and_run_exact_helper(
        &self,
        request: &ExactHelperRequest<'_>,
    ) -> Result<PrivilegeOutcome>;
}

#[derive(Debug, Clone)]
#[cfg(unix)]
pub struct SudoAuthorizer {
    program: PathBuf,
}

#[cfg(unix)]
impl SudoAuthorizer {
    /// Bind this backend to one exact `sudo` executable selected by the caller's
    /// platform policy. The path is never resolved through `PATH`.
    pub fn new(program: impl Into<PathBuf>) -> Result<Self> {
        let program = program.into();
        validate_exact_executable(&program, "authorization program")?;
        Ok(Self { program })
    }
}

#[cfg(unix)]
impl PrivilegeAuthorizer for SudoAuthorizer {
    fn authorize_and_run_exact_helper(
        &self,
        request: &ExactHelperRequest<'_>,
    ) -> Result<PrivilegeOutcome> {
        validate_request(request)?;
        match fs::symlink_metadata(&self.program) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(PrivilegeOutcome::Unavailable(
                    UnavailableReason::AuthorizationProgram,
                ));
            }
            Err(error) => return Err(error).context("inspect authorization program"),
            Ok(_) => validate_exact_executable(&self.program, "authorization program")?,
        }

        // `sudo` cannot distinguish its own ordinary denial status from an
        // arbitrary helper's same exit code. Preserve all ordinary statuses as
        // `Exited`; a receipt-aware caller can interpret its helper protocol.
        let mut command = Command::new(&self.program);
        command.env_clear().current_dir("/");
        if request.interaction == UserInteraction::Forbidden {
            command.arg("-n");
        }
        command
            .arg("--")
            .arg(request.helper)
            .args(request.arguments);
        match request.stdio {
            StdioPolicy::Inherit => {
                command
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
            }
            StdioPolicy::Null => {
                command
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
            }
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
                ) =>
            {
                return Ok(PrivilegeOutcome::Unavailable(
                    UnavailableReason::AuthorizationProgram,
                ));
            }
            Err(error) => return Err(error).context("start exact privilege authorizer"),
        };
        // Modern sudo may create a pty, monitor, new session, and separate
        // command child even in noninteractive mode. Wait for sudo to become
        // terminal; killing only the direct process or its original process
        // group cannot prove that the privileged helper stopped.
        let status = child.wait().context("wait for exact privileged helper")?;
        Ok(classify_status(status))
    }
}

#[cfg(unix)]
fn validate_request(request: &ExactHelperRequest<'_>) -> Result<()> {
    validate_exact_executable(request.helper, "privileged helper")?;
    if request.deadline.is_some() {
        bail!("sudo cannot safely enforce a complete privileged helper deadline");
    }
    if request.interaction == UserInteraction::Allowed && request.stdio != StdioPolicy::Inherit {
        bail!("interactive privilege authorization requires inherited standard streams");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_exact_executable(path: &Path, description: &str) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                Component::RootDir | Component::Prefix(_) | Component::Normal(_)
            )
        })
    {
        bail!("{description} path must be absolute and normalized");
    }
    let components = path.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {description} at {}", current.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("{description} path must not contain symlinks");
        }
        if index + 1 < components.len() && !metadata.file_type().is_dir() {
            bail!("{description} ancestor must be a directory");
        }
        if index + 1 == components.len() && !metadata.file_type().is_file() {
            bail!("{description} must be a regular file");
        }
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} at {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("{description} is not executable");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn classify_status(status: ExitStatus) -> PrivilegeOutcome {
    use std::os::unix::process::ExitStatusExt;
    PrivilegeOutcome::Exited(ProcessTermination {
        code: status.code(),
        signal: status.signal(),
    })
}
