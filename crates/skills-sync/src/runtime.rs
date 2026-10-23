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
        if error.io_error().is_none() && cleanup.is_empty() {
            return anyhow::Error::new(error);
        }
        let mut detail = error.to_string();
        if let Some(source) = error.io_error() {
            if let Some(errno) = source.raw_os_error() {
                detail.push_str(&format!(" ({:?}, os error {errno})", source.kind()));
            } else {
                detail.push_str(&format!(" ({:?})", source.kind()));
            }
        }
        if !cleanup.is_empty() {
            detail.push_str(&format!("; cleanup failed: {}", cleanup.join(", ")));
        }
        anyhow::Error::new(error).context(detail)
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use dev_tools_command::{BoundedCommandError, BoundedCommandErrorKind};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn provider_spawn_failure_preserves_safe_errno_and_typed_source() {
        let temp = tempfile::tempdir().unwrap();
        let program = temp.path().join("invalid-provider");
        std::fs::write(&program, b"not an executable format\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o600)).unwrap();
        for public_listing in [false, true] {
            let mut command = Command::new(&program);
            command.arg("secret-fixture-argument");
            let error = execute(command, Duration::from_secs(2), public_listing).unwrap_err();
            let source = error
                .downcast_ref::<BoundedCommandError>()
                .expect("typed command cause");
            assert_eq!(source.kind(), BoundedCommandErrorKind::Start);
            let errno = source
                .io_error()
                .and_then(std::io::Error::raw_os_error)
                .unwrap();
            assert!(error.to_string().contains(&format!("os error {errno}")));
            assert!(!format!("{error:#}").contains("secret-fixture-argument"));
            assert!(!format!("{error:#}").contains("not an executable format"));
        }
    }

    #[test]
    fn provider_timeout_preserves_category_without_captured_output() {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args([
            "--ignored",
            "--exact",
            "runtime::tests::provider_wait_fixture",
            "--nocapture",
        ]);
        let error = execute(command, Duration::from_millis(100), false).unwrap_err();
        let source = error
            .downcast_ref::<BoundedCommandError>()
            .expect("typed timeout cause");
        assert_eq!(source.kind(), BoundedCommandErrorKind::TimedOut);
        assert!(!format!("{error:#}").contains("secret-fixture-output"));
    }

    #[test]
    #[ignore = "owned subprocess fixture for timeout diagnostic containment"]
    fn provider_wait_fixture() {
        println!("secret-fixture-output");
        std::thread::sleep(Duration::from_secs(2));
    }
}
