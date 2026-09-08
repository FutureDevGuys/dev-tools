//! One invocation owns sequential provider calls and their cancellation.
use anyhow::{anyhow, Result};
use dev_tools_command::{run_prepared_bounded_command_with_cancellation, BoundedCommandOutput};
use std::{
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        OnceLock,
    },
    time::Duration,
};

static CANCELLED: AtomicBool = AtomicBool::new(false);
static HANDLER: OnceLock<Result<(), ()>> = OnceLock::new();
const OUTPUT_LIMIT: usize = 16 * 1024 * 1024;

pub(super) fn install_cancellation() -> Result<()> {
    HANDLER
        .get_or_init(|| {
            ctrlc::set_handler(|| CANCELLED.store(true, Ordering::Release)).map_err(|_| ())
        })
        .as_ref()
        .map_err(|_| anyhow!("could not install cancellation handler"))?;
    Ok(())
}

pub(super) fn cancelled() -> bool {
    CANCELLED.load(Ordering::Acquire)
}

pub(super) fn check_cancellation() -> Result<()> {
    if cancelled() {
        Err(anyhow!("operation cancelled"))
    } else {
        Ok(())
    }
}

pub(super) fn execute(
    mut command: Command,
    timeout: Duration,
    public_listing: bool,
) -> Result<BoundedCommandOutput> {
    // Freeze the caller-selected environment and directory. Providers need the
    // caller's auth/network configuration; the legacy state-root exclusion stays.
    let environment = std::env::vars_os()
        .filter(|(name, _)| name != "XDG_STATE_HOME")
        .collect::<Vec<_>>();
    command.env_clear().envs(environment).current_dir(
        std::env::current_dir().map_err(|_| anyhow!("provider working directory unavailable"))?,
    );
    #[cfg(target_os = "linux")]
    let result = if public_listing {
        dev_tools_command::run_prepared_bounded_command_with_public_file_stdout_and_cancellation(
            command,
            timeout,
            OUTPUT_LIMIT,
            &CANCELLED,
        )
    } else {
        run_prepared_bounded_command_with_cancellation(
            &mut command,
            timeout,
            OUTPUT_LIMIT,
            &CANCELLED,
        )
    };
    #[cfg(not(target_os = "linux"))]
    let result = {
        let _ = public_listing;
        run_prepared_bounded_command_with_cancellation(
            &mut command,
            timeout,
            OUTPUT_LIMIT,
            &CANCELLED,
        )
    };
    result.map_err(|error| {
        let cleanup = error
            .cleanup_failures()
            .iter()
            .map(|failure| format!("{:?}", failure.operation()))
            .collect::<Vec<_>>();
        if cleanup.is_empty() {
            anyhow!("{error}")
        } else {
            anyhow!("{error}; cleanup failed: {}", cleanup.join(", "))
        }
    })
}
