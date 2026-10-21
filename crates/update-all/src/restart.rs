//! Opt-in, non-forced post-run restart requests. Never a task or retryable update.
use crate::{logging::RunLogSink, updaters::HostOs};
use anyhow::{bail, Context, Result};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "macos")]
mod macos;

pub(crate) struct RestartRequest;

impl RestartRequest {
    pub(crate) fn prepare() -> Result<Self> {
        #[cfg(not(feature = "restart-test-backend"))]
        native_preflight()?;
        #[cfg(feature = "restart-test-backend")]
        if std::env::var_os("UPDATE_ALL_TEST_RESTART_MARKER").is_none() {
            bail!("restart-test-backend builds cannot restart: a test marker is required");
        }
        Ok(Self)
    }

    pub(crate) fn request(self, log: &RunLogSink) -> Result<()> {
        if crate::util::cancel::is_cancel_requested() {
            return Err(crate::Cancelled.into());
        }
        if !log.restart_eligible()? {
            bail!("Restart not requested: a clean run with at least one completed task and no canceled tasks or issues is required; restart manually if appropriate");
        }
        // Evidence is committed before the one irreversible request. A pending
        // record after power loss/termination is deliberately not replay authority.
        write_receipt(log, "request_pending", None)?;
        log.sync_before_restart()
            .context("restart withheld: failed to sync run evidence")?;
        crate::ua_errln!("Update run completed. Requesting a non-forced OS restart; applications or OS policy may block it.");
        io::stdout().flush()?;
        io::stderr().flush()?;
        if crate::util::cancel::is_cancel_requested() {
            write_receipt(log, "canceled_before_request", None)?;
            return Err(crate::Cancelled.into());
        }
        let result = request_backend(log.run_dir());
        match result {
            Ok(()) => {
                write_receipt(log, "request_accepted", None)
                    .context("restart may already be pending; receipt write failed; do not retry automatically")?;
                log.sync_before_restart()
                    .context("restart may already be pending; receipt sync failed; do not retry automatically")?;
                crate::ua_outln!("Restart request accepted by the OS (not proof of a completed restart). Complete any system restart confirmation dialog.");
                Ok(())
            }
            Err(error) => {
                // Never retry an ambiguous result, attempt elevation, force-close
                // applications, or relabel already-completed update task evidence.
                let reason = format!("{error:#}");
                write_receipt(log, "request_failed_or_uncertain", Some(&reason))
                    .context("restart outcome is uncertain and receipt write failed; do not retry automatically")?;
                log.sync_before_restart()
                    .context("restart outcome is uncertain and receipt sync failed; do not retry automatically")?;
                Err(error.context("Updates completed, but restart was not confirmed. Check the OS and restart manually if needed; the request was not retried"))
            }
        }
    }
}

fn write_receipt(log: &RunLogSink, status: &str, reason: Option<&str>) -> Result<()> {
    log.write_json_file(
        "restart.json",
        &serde_json::json!({
            "schema_version": 1,
            "run_id": log.run_id(),
            "status": status,
            "reason": reason.map(|text| text.chars().take(1024).collect::<String>()),
            "automatic_retry_allowed": false,
        }),
    )
}

fn restart_args(os: HostOs) -> Result<&'static [&'static str]> {
    match os {
        HostOs::Linux => Ok(&["--no-ask-password", "--check-inhibitors=yes", "reboot"]),
        // Microsoft: a positive timeout IMPLIES /f, including the default 30s.
        HostOs::Windows => Ok(&["/r", "/t", "0"]),
        _ => bail!("no command-based safe restart adapter for {}", os.as_str()),
    }
}

#[cfg(not(feature = "restart-test-backend"))]
fn native_preflight() -> Result<()> {
    match HostOs::current() {
        HostOs::Linux => {
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .context("cannot establish Linux restart runtime")?;
            if release.to_ascii_lowercase().contains("microsoft")
                || std::env::var_os("WSL_INTEROP").is_some()
                || Path::new("/.dockerenv").exists()
                || Path::new("/run/.containerenv").exists()
                || std::env::var_os("container").is_some()
                || !Path::new("/run/systemd/system").is_dir()
            {
                bail!("--restart-after requires a native systemd Linux host, not WSL, a container, or an unsupported init system; restart manually");
            }
            if !Path::new("/usr/bin/systemctl").is_file() {
                bail!("--restart-after requires /usr/bin/systemctl; no fallback restart command will be used");
            }
            Ok(())
        }
        HostOs::Macos | HostOs::Windows => Ok(()),
        HostOs::Unknown => bail!("--restart-after is unsupported on this operating system"),
    }
}

#[cfg(not(feature = "restart-test-backend"))]
fn request_backend(_run_dir: &Path) -> Result<()> {
    // Recheck runtime after updates; never make the preflight an authority lease.
    native_preflight()?;
    #[cfg(target_os = "macos")]
    return macos::request();
    #[cfg(not(target_os = "macos"))]
    {
        let program = restart_program()?;
        if crate::util::cancel::is_cancel_requested() {
            return Err(crate::Cancelled.into());
        }
        crate::util::process::run_capture(
            program
                .to_str()
                .context("invalid native restart executable path")?,
            restart_args(HostOs::current())?,
            Some(Duration::from_secs(30)),
        )?;
        Ok(())
    }
}

#[cfg(all(not(feature = "restart-test-backend"), not(target_os = "macos")))]
#[allow(unsafe_code)] // GetSystemDirectoryW is the narrow, documented native lookup.
fn restart_program() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        }
        let mut buffer = vec![0u16; 32768];
        // SAFETY: writable buffer spans the passed size; no pointer survives call.
        let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if len == 0 || len >= buffer.len() {
            bail!("cannot resolve the native Windows system directory");
        }
        return Ok(
            PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len])).join("shutdown.exe")
        );
    }
    #[cfg(not(windows))]
    Ok(PathBuf::from("/usr/bin/systemctl"))
}

// Compile-time substitution is fail-closed: even missing env can never fall
// through to a native backend. No runtime arbitrary executable injection exists.
#[cfg(feature = "restart-test-backend")]
fn request_backend(run_dir: &Path) -> Result<()> {
    if std::env::var_os("UPDATE_ALL_TEST_RESTART_FAIL").is_some() {
        bail!("simulated restart backend denial");
    }
    let marker = std::env::var_os("UPDATE_ALL_TEST_RESTART_MARKER")
        .context("test restart marker is required; native restart is disabled")?;
    let read = |name: &str| -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&std::fs::read(run_dir.join(name))?)?)
    };
    let events = std::fs::read_to_string(run_dir.join("events.jsonl"))?;
    let run_completed_count = events
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["event"] == "run_completed" || event["kind"] == "run_completed")
        .count();
    let payload = serde_json::json!({
        "run_dir": run_dir,
        "run": read("run.json")?,
        "metadata": read("run-meta.json")?,
        "run_completed_count": run_completed_count,
        "terminal_raw_mode": crossterm::terminal::is_raw_mode_enabled()?,
    });
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(marker)?;
    writeln!(file, "{}", serde_json::to_string(&payload)?)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_adapters_never_force_or_prompt_for_elevation() {
        assert_eq!(
            restart_args(HostOs::Linux).unwrap(),
            ["--no-ask-password", "--check-inhibitors=yes", "reboot"]
        );
        assert_eq!(restart_args(HostOs::Windows).unwrap(), ["/r", "/t", "0"]);
        assert!(restart_args(HostOs::Unknown).is_err());
        assert!(restart_args(HostOs::Macos).is_err());
    }
}
