use crate::cli::RunCli;
use anyhow::Result;
use clap::Parser;

pub fn main_entry() -> Result<()> {
    // Best-effort Ctrl-C handler: request cancellation; main loop will observe and exit 3.
    let _ = ctrlc::set_handler(|| {
        crate::util::cancel::request_cancel();
    });

    RunCli::parse().run()
}
