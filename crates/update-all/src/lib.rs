mod app;
mod build_info;
mod cli;
mod completions;
mod config;
mod logging;
mod release;
mod restart;
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

/// A common operation already emitted its value-free result document.
#[derive(Debug)]
pub struct CommonOperationExit(pub i32);

impl std::fmt::Display for CommonOperationExit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("common operation failed")
    }
}

impl std::error::Error for CommonOperationExit {}

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
        formatter.write_str("one or more tasks were blocked or deferred")
    }
}

impl std::error::Error for Deferred {}

#[cfg(test)]
pub(crate) mod test_support;

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
