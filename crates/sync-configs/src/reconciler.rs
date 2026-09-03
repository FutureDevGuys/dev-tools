use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use dev_tools_command::{is_executable_file, run_bounded_command, BoundedCommand};
use dev_tools_reconcile_protocol::ReconcileResult;
use sha2::{Digest, Sha256};
use thiserror::Error;

const PROTOCOL: &str = "dev-tools-reconcile-v1";
const MAX_OUTPUT: usize = 16 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcilerPrivilege {
    User,
    Sudo,
}

#[derive(Clone, Debug)]
pub struct ReconcilerSpec {
    pub name: String,
    pub executable: PathBuf,
    pub source: PathBuf,
    pub privilege: ReconcilerPrivilege,
    pub protocol: String,
}

#[derive(Clone, Debug)]
pub struct ReconcilerRunner {
    pub environment: BTreeMap<OsString, OsString>,
    pub sudo_path: Option<PathBuf>,
    pub timeout: Duration,
    pub output_limit: usize,
}

#[derive(Debug, Error)]
pub enum ReconcilerError {
    #[error("external reconciler executable has unsafe authority")]
    UnsafeExecutable,
    #[error("external reconciler source has unsafe authority")]
    UnsafeSource,
    #[error("external reconciler requires one shared sudo session")]
    MissingSudo,
    #[error("external reconciler {operation} invocation failed")]
    Invocation { operation: &'static str },
    #[error("external reconciler returned an invalid result")]
    InvalidResult,
    #[error("external reconciler produced an unsafe plan")]
    UnsafePlan,
    #[error("external reconciler did not verify its postcondition")]
    Postcondition,
    #[error("external reconciler resource limits are invalid")]
    InvalidLimits,
    #[error("external reconciler protocol is unsupported")]
    UnsupportedProtocol,
}

impl ReconcilerRunner {
    /// Validate every static authority and resource bound without invoking the
    /// provider. Callers use this during the global preflight before any sudo
    /// authentication or desired-state mutation.
    pub fn validate(&self, spec: &ReconcilerSpec) -> Result<(), ReconcilerError> {
        self.validate_limits()?;
        Self::validate_protocol(&spec.protocol)?;
        validate_executable(&spec.executable)?;
        validate_source(&spec.source, self.output_limit)
    }

    pub fn run(
        &self,
        spec: &ReconcilerSpec,
        dry_run: bool,
    ) -> Result<ReconcileResult, ReconcilerError> {
        self.validate(spec)?;

        let temporary = tempfile::Builder::new()
            .prefix("sync-configs-reconcile-")
            .tempdir()
            .map_err(|_| ReconcilerError::UnsafePlan)?;
        set_private_directory(temporary.path()).map_err(|_| ReconcilerError::UnsafePlan)?;
        let plan = temporary.path().join("plan.json");

        let planned = self.invoke(
            spec,
            "plan",
            vec![
                "reconcile".into(),
                "plan".into(),
                "--source".into(),
                spec.source.as_os_str().to_owned(),
                "--output".into(),
                plan.as_os_str().to_owned(),
                "--format".into(),
                "json".into(),
            ],
        )?;
        if planned.deferred || !planned.input_required.is_empty() || dry_run {
            return Ok(planned);
        }

        let plan_bytes = read_private_plan(&plan, self.output_limit)?;
        let plan_digest = format!("{:x}", Sha256::digest(&plan_bytes));
        let applied = self.invoke(
            spec,
            "apply",
            vec![
                "reconcile".into(),
                "apply".into(),
                "--plan".into(),
                plan.as_os_str().to_owned(),
                "--sha256".into(),
                plan_digest.into(),
                "--format".into(),
                "json".into(),
            ],
        )?;
        if applied.deferred || !applied.input_required.is_empty() {
            return Ok(applied);
        }

        let mut verified = self.invoke(
            spec,
            "verify",
            vec![
                "reconcile".into(),
                "verify".into(),
                "--source".into(),
                spec.source.as_os_str().to_owned(),
                "--format".into(),
                "json".into(),
            ],
        )?;
        if !verified.verified
            || verified.changed
            || verified.deferred
            || !verified.input_required.is_empty()
        {
            return Err(ReconcilerError::Postcondition);
        }
        verified.changed = applied.changed;
        Ok(verified)
    }

    pub fn validate_protocol(protocol: &str) -> Result<(), ReconcilerError> {
        if protocol == PROTOCOL {
            Ok(())
        } else {
            Err(ReconcilerError::UnsupportedProtocol)
        }
    }

    fn validate_limits(&self) -> Result<(), ReconcilerError> {
        if self.timeout.is_zero() || self.output_limit == 0 || self.output_limit > MAX_OUTPUT {
            Err(ReconcilerError::InvalidLimits)
        } else {
            Ok(())
        }
    }

    fn invoke(
        &self,
        spec: &ReconcilerSpec,
        operation: &'static str,
        arguments: Vec<OsString>,
    ) -> Result<ReconcileResult, ReconcilerError> {
        let (executable, arguments) = match spec.privilege {
            ReconcilerPrivilege::User => (spec.executable.as_path(), arguments),
            ReconcilerPrivilege::Sudo => {
                let sudo = self
                    .sudo_path
                    .as_deref()
                    .ok_or(ReconcilerError::MissingSudo)?;
                let mut elevated = Vec::with_capacity(arguments.len() + 3);
                elevated.push("-n".into());
                elevated.push("--".into());
                elevated.push(spec.executable.as_os_str().to_owned());
                elevated.extend(arguments);
                (sudo, elevated)
            }
        };
        let output = run_bounded_command(&BoundedCommand {
            executable,
            arguments: &arguments,
            environment: &self.environment,
            cwd: None,
            timeout: self.timeout,
            output_limit: self.output_limit,
        })
        .map_err(|_| ReconcilerError::Invocation { operation })?;
        if !output.status.success() {
            return Err(ReconcilerError::Invocation { operation });
        }
        let result: ReconcileResult =
            serde_json::from_slice(&output.stdout).map_err(|_| ReconcilerError::InvalidResult)?;
        result
            .validate()
            .map_err(|_| ReconcilerError::InvalidResult)?;
        Ok(result)
    }
}

fn validate_executable(path: &Path) -> Result<(), ReconcilerError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ReconcilerError::UnsafeExecutable);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ReconcilerError::UnsafeExecutable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(ReconcilerError::UnsafeExecutable);
    }
    if !is_executable_file(path) {
        return Err(ReconcilerError::UnsafeExecutable);
    }
    Ok(())
}

fn validate_source(path: &Path, limit: usize) -> Result<(), ReconcilerError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(ReconcilerError::UnsafeSource);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| ReconcilerError::UnsafeSource)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || is_reparse_point(&metadata)
        || metadata.len() > limit as u64
    {
        return Err(ReconcilerError::UnsafeSource);
    }
    Ok(())
}

fn read_private_plan(path: &Path, limit: usize) -> Result<Vec<u8>, ReconcilerError> {
    let before_path = fs::symlink_metadata(path).map_err(|_| ReconcilerError::UnsafePlan)?;
    if before_path.file_type().is_symlink()
        || !before_path.is_file()
        || is_reparse_point(&before_path)
    {
        return Err(ReconcilerError::UnsafePlan);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| ReconcilerError::UnsafePlan)?;
    let before = file.metadata().map_err(|_| ReconcilerError::UnsafePlan)?;
    validate_plan_metadata(&before, limit)?;
    if !same_file_identity(&before_path, &before) {
        return Err(ReconcilerError::UnsafePlan);
    }

    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReconcilerError::UnsafePlan)?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err(ReconcilerError::UnsafePlan);
    }
    let after = file.metadata().map_err(|_| ReconcilerError::UnsafePlan)?;
    if bytes.len() as u64 != before.len() || !stable_file_metadata(&before, &after) {
        return Err(ReconcilerError::UnsafePlan);
    }
    Ok(bytes)
}

fn validate_plan_metadata(metadata: &fs::Metadata, limit: usize) -> Result<(), ReconcilerError> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        return Err(ReconcilerError::UnsafePlan);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ReconcilerError::UnsafePlan);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn stable_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn stable_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
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
