//! Out-of-band, value-free execution observation, not an authorization receipt.
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Serialize)]
pub(super) struct ExecutionResult {
    pub schema: &'static str,
    pub product: &'static str,
    pub operation: &'static str,
    pub outcome: &'static str,
    /// None means the execution boundary was entered but progress is uncertain.
    pub started: Option<bool>,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<&'static str>,
}

impl ExecutionResult {
    pub fn launch(outcome: &'static str, started: Option<bool>, exit_code: i32) -> Self {
        Self {
            schema: "dev-auth-execution-result-v1",
            product: "dev-auth",
            operation: "workload_launch",
            outcome,
            started,
            exit_code,
            error_kind: None,
        }
    }

    pub fn error(mut self, kind: &'static str) -> Self {
        self.error_kind = Some(kind);
        self
    }
}

pub(super) struct ResultDestination(File);

impl ResultDestination {
    #[cfg(unix)]
    pub fn reserve(path: &Path) -> anyhow::Result<Self> {
        use anyhow::{bail, Context};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        use std::path::Component;

        if !path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            bail!("result destination must be an absolute normal path");
        }
        let parent = path.parent().context("result destination has no parent")?;
        for ancestor in parent.ancestors() {
            let metadata = std::fs::symlink_metadata(ancestor)?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                bail!("result destination ancestor is not a directory");
            }
        }
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(parent)?;
        let metadata = directory.metadata()?;
        if metadata.uid() != nix::unistd::Uid::effective().as_raw()
            || metadata.mode() & 0o777 != 0o700
        {
            bail!("result destination parent must be private to the caller");
        }
        let name = path
            .file_name()
            .context("result destination has no filename")?;
        let descriptor = rustix::fs::openat(
            &directory,
            name,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_bits_truncate(0o600),
        )?;
        rustix::fs::fchmod(&descriptor, rustix::fs::Mode::from_bits_truncate(0o600))?;
        Ok(Self(File::from(descriptor)))
    }

    #[cfg(not(unix))]
    pub fn reserve(_path: &Path) -> anyhow::Result<Self> {
        anyhow::bail!("native protected result destinations are not qualified on this platform")
    }

    pub fn finish(mut self, result: &ExecutionResult) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(result)?;
        bytes.push(b'\n');
        self.0.write_all(&bytes)?;
        self.0.sync_all()?;
        Ok(())
    }
}
