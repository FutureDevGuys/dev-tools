//! Product-neutral executable discovery and operating-system PATH composition.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use wait_timeout::ChildExt;

pub struct BoundedCommand<'a> {
    pub executable: &'a Path,
    pub arguments: &'a [OsString],
    pub environment: &'a BTreeMap<OsString, OsString>,
    pub cwd: Option<&'a Path>,
    pub timeout: Duration,
    pub output_limit: usize,
}

#[derive(Debug)]
pub struct BoundedCommandOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run an exact executable with a cleared, explicitly supplied environment.
///
/// Output is captured through unnamed temporary files so a child cannot block
/// on a full pipe before the bounded wait completes.
pub fn run_bounded_command(request: &BoundedCommand<'_>) -> Result<BoundedCommandOutput> {
    if !request.executable.is_absolute() || !is_executable_file(request.executable) {
        bail!("bounded command executable is not an absolute executable file");
    }
    if request.timeout.is_zero() || request.output_limit == 0 || request.output_limit > 16 << 20 {
        bail!("bounded command resource limits are invalid");
    }
    if request.cwd.is_some_and(|cwd| !cwd.is_absolute()) {
        bail!("bounded command working directory must be absolute");
    }

    let mut stdout = tempfile::tempfile().context("create bounded command stdout")?;
    let mut stderr = tempfile::tempfile().context("create bounded command stderr")?;
    let mut command = std::process::Command::new(request.executable);
    command
        .args(request.arguments)
        .env_clear()
        .envs(request.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::from(
            stdout.try_clone().context("clone bounded command stdout")?,
        ))
        .stderr(Stdio::from(
            stderr.try_clone().context("clone bounded command stderr")?,
        ));
    if let Some(cwd) = request.cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().context("start bounded command")?;
    let status = match child
        .wait_timeout(request.timeout)
        .context("wait for bounded command")?
    {
        Some(status) => status,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            bail!("bounded command timed out");
        }
    };
    let stdout = read_bounded_output(&mut stdout, request.output_limit, "stdout")?;
    let stderr = read_bounded_output(&mut stderr, request.output_limit, "stderr")?;
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_bounded_output(
    file: &mut std::fs::File,
    limit: usize,
    description: &str,
) -> Result<Vec<u8>> {
    if file.metadata()?.len() > limit as u64 {
        bail!("bounded command {description} exceeds the output limit");
    }
    file.rewind()?;
    let mut output = Vec::with_capacity(file.metadata()?.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut output)
        .with_context(|| format!("read bounded command {description}"))?;
    if output.len() > limit {
        bail!("bounded command {description} exceeds the output limit");
    }
    Ok(output)
}

/// Return executable candidates in the same order as the supplied PATH entries.
pub fn executable_candidates(path_entries: &[PathBuf], command: &str) -> Vec<PathBuf> {
    path_entries
        .iter()
        .flat_map(|directory| command_candidates(directory, command))
        .filter(|candidate| is_executable_file(candidate))
        .collect()
}

/// Return the first executable candidate in the supplied PATH entries.
pub fn first_executable(path_entries: &[PathBuf], command: &str) -> Option<PathBuf> {
    executable_candidates(path_entries, command)
        .into_iter()
        .next()
}

/// Compare two command paths by filename and canonical parent directory.
pub fn same_path_location(left: &Path, right: &Path) -> bool {
    left.file_name() == right.file_name()
        && left.parent().and_then(|path| fs::canonicalize(path).ok())
            == right.parent().and_then(|path| fs::canonicalize(path).ok())
}

/// Prepend an absolute directory to an optional PATH using native encoding.
pub fn prepend_path(directory: &Path, existing: Option<&OsStr>) -> Result<OsString> {
    if !directory.is_absolute() {
        bail!("command directory must be absolute");
    }
    let entries = std::iter::once(directory.to_path_buf()).chain(
        existing
            .into_iter()
            .flat_map(env::split_paths)
            .collect::<Vec<_>>(),
    );
    env::join_paths(entries).context("command directory cannot be represented in PATH")
}

#[cfg(not(windows))]
pub fn command_candidates(directory: &Path, command: &str) -> Vec<PathBuf> {
    vec![directory.join(command)]
}

#[cfg(windows)]
pub fn command_candidates(directory: &Path, command: &str) -> Vec<PathBuf> {
    let extensions = env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned());
    extensions
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(|extension| directory.join(format!("{command}{extension}")))
        .collect()
}

#[cfg(unix)]
pub fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
pub fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}
