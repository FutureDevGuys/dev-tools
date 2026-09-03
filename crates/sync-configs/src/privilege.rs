use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use dev_tools_command::is_executable_file;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrivilegeError {
    #[error("sudo executable has unsafe authority")]
    UnsafeSudo,
    #[error("unable to authenticate one shared sudo session")]
    Authentication,
    #[error("privileged command executable has unsafe authority")]
    UnsafeCommand,
    #[error("privileged command requires an authenticated sudo session")]
    NotAuthenticated,
    #[error("privileged command failed to start")]
    Start,
    #[error("privileged command exited unsuccessfully")]
    Failed,
    #[error("sudo privilege is not available on this platform")]
    Unsupported,
}

#[derive(Debug)]
pub struct PrivilegeSession {
    sudo: PathBuf,
    authenticated: bool,
}

impl PrivilegeSession {
    pub fn new(sudo: PathBuf) -> Result<Self, PrivilegeError> {
        validate_executable(&sudo).map_err(|_| PrivilegeError::UnsafeSudo)?;
        Ok(Self {
            sudo,
            authenticated: false,
        })
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Acquire one native sudo timestamp, reusing an existing timestamp when present.
    ///
    /// The interactive `sudo -v` inherits the caller's terminal. This function never
    /// reads or proxies credential input itself.
    pub fn ensure_authenticated(&mut self) -> Result<(), PrivilegeError> {
        #[cfg(not(unix))]
        {
            return Err(PrivilegeError::Unsupported);
        }
        #[cfg(unix)]
        {
            if self.authenticated {
                return Ok(());
            }
            let cached = Command::new(&self.sudo)
                .args(["-n", "-v"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map_err(|_| PrivilegeError::Authentication)?;
            if !cached.success() {
                let prompted = Command::new(&self.sudo)
                    .arg("-v")
                    .status()
                    .map_err(|_| PrivilegeError::Authentication)?;
                if !prompted.success() {
                    return Err(PrivilegeError::Authentication);
                }
            }
            self.authenticated = true;
            Ok(())
        }
    }

    pub fn run(&self, command: &[OsString]) -> Result<Output, PrivilegeError> {
        if !self.authenticated {
            return Err(PrivilegeError::NotAuthenticated);
        }
        let executable = command
            .first()
            .map(PathBuf::from)
            .ok_or(PrivilegeError::UnsafeCommand)?;
        validate_executable(&executable).map_err(|_| PrivilegeError::UnsafeCommand)?;
        let output = Command::new(&self.sudo)
            .args(["-n", "--"])
            .args(command)
            .stdin(Stdio::null())
            .output()
            .map_err(|_| PrivilegeError::Start)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(PrivilegeError::Failed)
        }
    }

    pub fn sudo_path(&self) -> &Path {
        &self.sudo
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
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
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
