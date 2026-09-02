mod app;
mod build_info;
mod cli;
mod completions;
mod config;
mod logging;
mod release;
mod runs;
mod sections;
mod tasks;
mod ui;
mod updaters;
mod util;

use anyhow::Result;

pub use util::process::Cancelled;

#[derive(Debug)]
pub struct InvalidPlan(pub String);

impl std::fmt::Display for InvalidPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid updater configuration or plan: {}",
            self.0
        )
    }
}

impl std::error::Error for InvalidPlan {}

#[derive(Debug)]
pub struct IntegrityFailure(pub String);

impl std::fmt::Display for IntegrityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "updater integrity failure: {}", self.0)
    }
}

impl std::error::Error for IntegrityFailure {}

#[derive(Debug)]
pub struct Deferred;

impl std::fmt::Display for Deferred {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("one or more tasks were deferred")
    }
}

impl std::error::Error for Deferred {}

#[cfg(test)]
pub(crate) mod test_support {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub(crate) fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    pub(crate) fn write_executable(path: &Path, content: &str) -> std::io::Result<()> {
        let tmp = executable_temp_path(path);
        fs::write(&tmp, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = fs::metadata(&tmp)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&tmp, perms)?;
        }
        fs::rename(tmp, path)
    }

    fn executable_temp_path(path: &Path) -> PathBuf {
        let file_name = path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("executable"))
            .to_string_lossy();
        path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()))
    }
}

#[macro_export]
macro_rules! ua_outln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        let _ = writeln!(&mut out, $($arg)*);
    }};
}

#[macro_export]
macro_rules! ua_errln {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let mut out = std::io::stderr().lock();
        let _ = writeln!(&mut out, $($arg)*);
    }};
}

#[macro_export]
macro_rules! ua_out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        let _ = write!(&mut out, $($arg)*);
    }};
}

pub fn main_entry() -> Result<()> {
    app::main_entry()
}

/// Internal, versioned completion-query entry point used by managed shell adapters.
///
/// This is hidden from the user-facing command surface. Returning `None` leaves the
/// normal CLI path untouched.
#[doc(hidden)]
pub fn maybe_run_completion_query() -> Option<i32> {
    completions::completion_query::run_from_env()
}
