use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wait_timeout::ChildExt;

use crate::util::cancel;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub fn which(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    #[cfg(windows)]
    let pathexts: Vec<String> = env::var("PATHEXT")
        .ok()
        .map(|v| {
            v.split(';')
                .filter_map(|e| {
                    let e = e.trim();
                    if e.is_empty() {
                        None
                    } else {
                        Some(e.to_ascii_lowercase())
                    }
                })
                .collect()
        })
        .unwrap_or_else(|| vec![".exe".to_string(), ".cmd".to_string(), ".bat".to_string()]);

    for p in env::split_paths(&path) {
        let full = p.join(name);
        #[cfg(windows)]
        {
            let lower_name = name.to_ascii_lowercase();
            let has_ext = pathexts.iter().any(|ext| lower_name.ends_with(ext));
            if has_ext {
                if full.is_file() {
                    return Some(absolutize_path_candidate(full));
                }
            } else {
                for ext in &pathexts {
                    let with_ext = p.join(format!("{name}{ext}"));
                    if with_ext.is_file() {
                        return Some(absolutize_path_candidate(with_ext));
                    }
                }
                // Fallback for tools intentionally installed without extensions.
                if full.is_file() {
                    return Some(absolutize_path_candidate(full));
                }
            }
        }
        #[cfg(not(windows))]
        {
            if full.is_file() {
                return Some(absolutize_path_candidate(full));
            }
        }
    }
    None
}

fn absolutize_path_candidate(candidate: PathBuf) -> PathBuf {
    if candidate.is_absolute() {
        return candidate;
    }
    if let Ok(cwd) = env::current_dir() {
        return cwd.join(candidate);
    }
    candidate
}

pub fn resolve_executable(program: &str) -> PathBuf {
    let path = Path::new(program);
    if path.components().count() > 1 || path.is_absolute() {
        return resolve_explicit_program(path).unwrap_or_else(|| path.to_path_buf());
    }
    which(program).unwrap_or_else(|| PathBuf::from(program))
}

#[cfg(windows)]
fn resolve_explicit_program(path: &Path) -> Option<PathBuf> {
    if path.is_file() {
        return Some(absolutize_path_candidate(path.to_path_buf()));
    }
    let has_extension = path.extension().is_some();
    if has_extension {
        return None;
    }
    for ext in windows_path_extensions() {
        let candidate = path.with_extension(ext.trim_start_matches('.'));
        if candidate.is_file() {
            return Some(absolutize_path_candidate(candidate));
        }
    }
    None
}

#[cfg(not(windows))]
fn resolve_explicit_program(path: &Path) -> Option<PathBuf> {
    path.is_file()
        .then(|| absolutize_path_candidate(path.to_path_buf()))
}

#[cfg(windows)]
fn windows_path_extensions() -> Vec<String> {
    env::var("PATHEXT")
        .ok()
        .map(|v| {
            v.split(';')
                .filter_map(|e| {
                    let e = e.trim();
                    if e.is_empty() {
                        None
                    } else {
                        Some(e.to_ascii_lowercase())
                    }
                })
                .collect()
        })
        .unwrap_or_else(|| {
            vec![
                ".com".to_string(),
                ".exe".to_string(),
                ".bat".to_string(),
                ".cmd".to_string(),
            ]
        })
}

pub fn command_for_executable(program: &Path) -> Command {
    #[cfg(windows)]
    {
        if is_windows_batch_script(program) {
            let mut cmd = Command::new("cmd");
            cmd.arg("/C").arg(program);
            return cmd;
        }
    }
    Command::new(program)
}

#[cfg(windows)]
fn is_windows_batch_script(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|ext| matches!(ext.to_ascii_lowercase().as_str(), "cmd" | "bat"))
        .unwrap_or(false)
}

#[derive(Debug)]
pub struct Cancelled;

impl std::fmt::Display for Cancelled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cancelled")
    }
}

impl std::error::Error for Cancelled {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureGuard {
    pub stall_timeout: Duration,
    pub max_line_bytes: usize,
    pub max_capture_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureGuardReason {
    Stall,
    LineTooLong,
    CaptureLimitExceeded,
}

#[derive(Debug)]
pub struct CaptureGuardError {
    pub reason: CaptureGuardReason,
}

impl std::fmt::Display for CaptureGuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            CaptureGuardReason::Stall => write!(f, "interactive capture stalled"),
            CaptureGuardReason::LineTooLong => write!(f, "interactive capture line too long"),
            CaptureGuardReason::CaptureLimitExceeded => {
                write!(f, "interactive capture exceeded memory limit")
            }
        }
    }
}

impl std::error::Error for CaptureGuardError {}

#[derive(Debug)]
pub struct ProcessExitError {
    pub program: String,
    pub code: String,
    pub output: Option<String>,
}

impl std::fmt::Display for ProcessExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(output) = &self.output {
            let msg = summarize_error_output(output.trim(), 500);
            write!(
                f,
                "{} exited non-zero (code={}); output: {}",
                self.program, self.code, msg
            )
        } else {
            write!(f, "{} exited non-zero (code={})", self.program, self.code)
        }
    }
}

impl std::error::Error for ProcessExitError {}

pub fn capture_guard_reason(err: &anyhow::Error) -> Option<CaptureGuardReason> {
    err.downcast_ref::<CaptureGuardError>().map(|e| e.reason)
}

pub fn process_exit_output(err: &anyhow::Error) -> Option<&str> {
    err.downcast_ref::<ProcessExitError>()
        .and_then(|e| e.output.as_deref())
}

pub fn run_capture<I, S>(program: &str, args: I, timeout: Option<Duration>) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        false,
        false,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
    )
}

pub fn run_capture_allow_exit_codes<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    allowed_exit_codes: &[i32],
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        allowed_exit_codes,
        false,
        false,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
    )
}

pub fn run_capture_streaming<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    stdin_inherit: bool,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        stdin_inherit,
        stdin_inherit,
        Some(line_cb),
        None,
        None,
        None,
        true,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Reason: command execution contract is explicit and shared.
pub fn run_capture_streaming_controlled<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    stdin_inherit: bool,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        stdin_inherit,
        stdin_inherit,
        Some(line_cb),
        Some(cancel_check),
        Some(on_spawn),
        Some(on_exit),
        true,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Reason: mirrors controlled streaming while allowing report probes to accept data exit codes.
pub fn run_capture_streaming_controlled_allow_exit_codes<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    allowed_exit_codes: &[i32],
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        allowed_exit_codes,
        false,
        false,
        Some(line_cb),
        Some(cancel_check),
        Some(on_spawn),
        Some(on_exit),
        true,
        None,
        None,
    )
}

pub fn run_capture_streaming_controlled_foreground<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // Foreground interactive commands must stay in the caller's process group so
    // terminal input (e.g., password prompts) behaves like normal shell execution.
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        true,
        true,
        Some(line_cb),
        Some(cancel_check),
        Some(on_spawn),
        Some(on_exit),
        false,
        None,
        None,
    )
}

pub fn run_capture_streaming_controlled_stdin_tty_capture<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // Capture-mode interactive commands should run in their own process group so
    // cancel/timeout can reliably terminate helper subprocesses (e.g., sudo loops).
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        true,
        false,
        Some(line_cb),
        Some(cancel_check),
        Some(on_spawn),
        Some(on_exit),
        true,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Reason: guarded variant mirrors controlled API to keep callsites simple.
pub fn run_capture_streaming_controlled_stdin_tty_capture_guarded<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
    guard: CaptureGuard,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    // Capture-mode interactive commands should run in their own process group so
    // cancel/timeout can reliably terminate helper subprocesses (e.g., sudo loops).
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        true,
        false,
        Some(line_cb),
        Some(cancel_check),
        Some(on_spawn),
        Some(on_exit),
        true,
        Some(guard),
        None,
    )
}

pub fn run_capture_streaming_foreground<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        true,
        true,
        Some(line_cb),
        None,
        None,
        None,
        false,
        None,
        None,
    )
}

pub fn run_capture_streaming_allow_exit_codes<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    allowed_exit_codes: &[i32],
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        allowed_exit_codes,
        false,
        false,
        Some(line_cb),
        None,
        None,
        None,
        true,
        None,
        None,
    )
}

pub fn run_capture_streaming_stdin_tty_capture<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        true,
        false,
        Some(line_cb),
        None,
        None,
        None,
        true,
        None,
        None,
    )
}

pub fn run_capture_streaming_stdin_tty_capture_guarded<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    guard: CaptureGuard,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        true,
        false,
        Some(line_cb),
        None,
        None,
        None,
        true,
        Some(guard),
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Reason: controlled capture variant with stdin writer mirrors existing APIs.
pub fn run_capture_streaming_controlled_stdin_pipe_capture_guarded<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
    guard: CaptureGuard,
    stdin_rx: mpsc::Receiver<String>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        false,
        false,
        Some(line_cb),
        Some(cancel_check),
        Some(on_spawn),
        Some(on_exit),
        true,
        Some(guard),
        Some(stdin_rx),
    )
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)] // Reason: unix PTY capture variant mirrors controlled API to keep callsites simple.
pub fn run_capture_streaming_controlled_stdin_pty_capture_guarded<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
    guard: CaptureGuard,
    stdin_rx: mpsc::Receiver<String>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_capture_with_pty_options(
        program,
        args,
        timeout,
        line_cb,
        cancel_check,
        on_spawn,
        on_exit,
        guard,
        stdin_rx,
        true,
    )
}

#[cfg(not(unix))]
#[allow(clippy::too_many_arguments)] // Reason: signature parity with unix PTY implementation keeps callsites cfg-free.
pub fn run_capture_streaming_controlled_stdin_pty_capture_guarded<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
    guard: CaptureGuard,
    stdin_rx: mpsc::Receiver<String>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let _ = stdin_rx;
    run_capture_with_options(
        program,
        args,
        timeout,
        &[],
        false,
        false,
        Some(line_cb),
        Some(cancel_check),
        Some(on_spawn),
        Some(on_exit),
        true,
        Some(guard),
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Reason: consolidates all spawn/capture controls in one internal entrypoint.
fn run_capture_with_options<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    allowed_exit_codes: &[i32],
    stdin_inherit: bool,
    stdout_stderr_inherit: bool,
    line_cb: Option<std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>>,
    cancel_check: Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
    on_spawn: Option<std::sync::Arc<dyn Fn(u32) + Send + Sync>>,
    on_exit: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
    managed_process_group: bool,
    capture_guard: Option<CaptureGuard>,
    stdin_rx: Option<mpsc::Receiver<String>>,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let resolved_program = resolve_executable(program);
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect::<Vec<OsString>>();
    let mut cmd = command_for_executable(&resolved_program);
    cmd.args(&args);
    if stdin_rx.is_some() {
        cmd.stdin(Stdio::piped());
    } else if stdin_inherit {
        cmd.stdin(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::null());
    }
    if stdout_stderr_inherit {
        // Fully inherit output streams for commands that need direct terminal rendering.
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
    } else {
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
    }

    #[cfg(unix)]
    if managed_process_group {
        // Create a dedicated process group so cancellation can terminate descendants too.
        cmd.process_group(0);
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", resolved_program.display()))?;
    let stdin_writer_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stdin_writer = if let Some(rx) = stdin_rx {
        let stop = stdin_writer_stop.clone();
        child.stdin.take().map(|mut stdin| {
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let mut line = match rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(line) => line,
                        Err(RecvTimeoutError::Timeout) => continue,
                        Err(RecvTimeoutError::Disconnected) => break,
                    };
                    if !line.ends_with('\n') {
                        line.push('\n');
                    }
                    if stdin.write_all(line.as_bytes()).is_err() {
                        break;
                    }
                    let _ = stdin.flush();
                }
            })
        })
    } else {
        None
    };
    if let Some(cb) = &on_spawn {
        cb(child.id());
    }
    let _exit_guard = OnExitGuard(on_exit);
    let guard_state = capture_guard.map(CaptureGuardState::new).map(Arc::new);

    // Drain child pipes concurrently to avoid deadlocks when output fills OS pipe buffers.
    let stdout_reader = if let Some(reader) = child.stdout.take() {
        Some(read_pipe_thread(
            StreamKind::Stdout,
            reader,
            line_cb.clone(),
            guard_state.clone(),
        ))
    } else {
        None
    };
    let stderr_reader = if let Some(reader) = child.stderr.take() {
        Some(read_pipe_thread(
            StreamKind::Stderr,
            reader,
            line_cb.clone(),
            guard_state.clone(),
        ))
    } else {
        None
    };

    let status =
        match wait_with_cancel_timeout(&mut child, timeout, cancel_check, guard_state.clone()) {
            Ok(s) => s,
            Err(WaitOutcome::Cancelled) => {
                terminate_child(&mut child, managed_process_group);
                let _ = child.wait();
                return Err(anyhow!(Cancelled));
            }
            Err(WaitOutcome::TimedOut) => {
                terminate_child(&mut child, managed_process_group);
                let _ = child.wait();
                bail!("timeout running {program}");
            }
            Err(WaitOutcome::GuardTriggered(reason)) => {
                terminate_child(&mut child, managed_process_group);
                let _ = child.wait();
                return Err(anyhow!(CaptureGuardError { reason }));
            }
            Err(WaitOutcome::Other(e)) => return Err(e),
        };

    if let Some(reason) = guard_state.as_ref().and_then(|state| state.reason()) {
        return Err(anyhow!(CaptureGuardError { reason }));
    }

    let out_bytes = stdout_reader.map(join_pipe_reader).unwrap_or_default();
    let err_bytes = stderr_reader.map(join_pipe_reader).unwrap_or_default();
    stdin_writer_stop.store(true, Ordering::SeqCst);
    if let Some(handle) = stdin_writer {
        let _ = handle.join();
    }
    let mut out = String::from_utf8_lossy(&out_bytes).to_string();
    if !err_bytes.is_empty() {
        out.push_str(&String::from_utf8_lossy(&err_bytes));
    }

    if status.success()
        || status
            .code()
            .is_some_and(|code| allowed_exit_codes.contains(&code))
    {
        Ok(out)
    } else {
        let code = status
            .code()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "terminated-by-signal".to_string());
        let trimmed = out.trim();
        if trimmed.is_empty() {
            Err(anyhow!(ProcessExitError {
                program: program.to_string(),
                code,
                output: None,
            }))
        } else {
            Err(anyhow!(ProcessExitError {
                program: program.to_string(),
                code,
                output: Some(trimmed.to_string()),
            }))
        }
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)] // Reason: PTY-backed execution needs the same control hooks as the pipe-backed path.
#[allow(unsafe_code)] // Reason: PTY setup requires pre-exec session/controlling-terminal syscalls before spawn.
fn run_capture_with_pty_options<I, S>(
    program: &str,
    args: I,
    timeout: Option<Duration>,
    line_cb: std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>,
    cancel_check: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
    on_spawn: std::sync::Arc<dyn Fn(u32) + Send + Sync>,
    on_exit: std::sync::Arc<dyn Fn() + Send + Sync>,
    guard: CaptureGuard,
    stdin_rx: mpsc::Receiver<String>,
    managed_process_group: bool,
) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let resolved_program = resolve_executable(program);
    let args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_os_string())
        .collect::<Vec<OsString>>();
    let (master, slave) = open_pty_pair()?;
    set_cloexec(master.as_raw_fd(), true)?;

    let slave_fd = slave.as_raw_fd();
    let slave_stdout = slave.try_clone().context("clone pty slave stdout")?;
    let slave_stderr = slave.try_clone().context("clone pty slave stderr")?;

    let mut cmd = command_for_executable(&resolved_program);
    cmd.args(&args);
    cmd.stdin(Stdio::from(slave));
    cmd.stdout(Stdio::from(slave_stdout));
    cmd.stderr(Stdio::from(slave_stderr));

    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd
        .spawn()
        .with_context(|| format!("spawn {}", resolved_program.display()))?;
    on_spawn(child.id());
    let _exit_guard = OnExitGuard(Some(on_exit));

    let guard_state = Arc::new(CaptureGuardState::new(guard));
    let reader_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = read_pty_thread(
        master.try_clone().context("clone pty master reader")?,
        Some(line_cb),
        Some(guard_state.clone()),
        reader_stop.clone(),
    );

    let stdin_writer_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stdin_writer = {
        let stop = stdin_writer_stop.clone();
        let guard_state = guard_state.clone();
        let mut writer = master;
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let mut line = match stdin_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(line) => line,
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => break,
                };
                if !line.ends_with('\n') {
                    line.push('\n');
                }
                guard_state.mark_activity();
                if writer.write_all(line.as_bytes()).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
        })
    };

    let status = match wait_with_cancel_timeout(
        &mut child,
        timeout,
        Some(cancel_check),
        Some(guard_state.clone()),
    ) {
        Ok(s) => s,
        Err(WaitOutcome::Cancelled) => {
            terminate_child(&mut child, managed_process_group);
            let _ = child.wait();
            stdin_writer_stop.store(true, Ordering::SeqCst);
            let _ = stdin_writer.join();
            reader_stop.store(true, Ordering::SeqCst);
            return Err(anyhow!(Cancelled));
        }
        Err(WaitOutcome::TimedOut) => {
            terminate_child(&mut child, managed_process_group);
            let _ = child.wait();
            stdin_writer_stop.store(true, Ordering::SeqCst);
            let _ = stdin_writer.join();
            reader_stop.store(true, Ordering::SeqCst);
            bail!("timeout running {program}");
        }
        Err(WaitOutcome::GuardTriggered(reason)) => {
            terminate_child(&mut child, managed_process_group);
            let _ = child.wait();
            stdin_writer_stop.store(true, Ordering::SeqCst);
            let _ = stdin_writer.join();
            reader_stop.store(true, Ordering::SeqCst);
            return Err(anyhow!(CaptureGuardError { reason }));
        }
        Err(WaitOutcome::Other(e)) => {
            stdin_writer_stop.store(true, Ordering::SeqCst);
            let _ = stdin_writer.join();
            reader_stop.store(true, Ordering::SeqCst);
            return Err(e);
        }
    };

    stdin_writer_stop.store(true, Ordering::SeqCst);
    let _ = stdin_writer.join();
    reader_stop.store(true, Ordering::SeqCst);

    if let Some(reason) = guard_state.reason() {
        return Err(anyhow!(CaptureGuardError { reason }));
    }

    let out_bytes = join_pipe_reader(reader);
    let out = String::from_utf8_lossy(&out_bytes).to_string();

    if status.success() {
        Ok(out)
    } else {
        let code = status
            .code()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "terminated-by-signal".to_string());
        let trimmed = out.trim();
        if trimmed.is_empty() {
            Err(anyhow!(ProcessExitError {
                program: program.to_string(),
                code,
                output: None,
            }))
        } else {
            Err(anyhow!(ProcessExitError {
                program: program.to_string(),
                code,
                output: Some(trimmed.to_string()),
            }))
        }
    }
}

fn summarize_error_output(input: &str, max_chars: usize) -> String {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max_chars {
        return collapsed;
    }
    let mut out = String::new();
    for ch in collapsed.chars().take(max_chars) {
        out.push(ch);
    }
    out.push_str(" ...");
    out
}

const GUARD_REASON_NONE: u8 = 0;
const GUARD_REASON_STALL: u8 = 1;
const GUARD_REASON_LINE_TOO_LONG: u8 = 2;
const GUARD_REASON_CAPTURE_LIMIT: u8 = 3;

struct CaptureGuardState {
    guard: CaptureGuard,
    last_activity_unix_ms: AtomicU64,
    total_capture_bytes: AtomicUsize,
    reason: AtomicU8,
}

impl CaptureGuardState {
    fn new(guard: CaptureGuard) -> Self {
        Self {
            guard,
            last_activity_unix_ms: AtomicU64::new(now_unix_ms()),
            total_capture_bytes: AtomicUsize::new(0),
            reason: AtomicU8::new(GUARD_REASON_NONE),
        }
    }

    fn mark_activity(&self) {
        self.last_activity_unix_ms
            .store(now_unix_ms(), Ordering::Relaxed);
    }

    fn note_capture_bytes(&self, bytes: usize) -> bool {
        if self.guard.max_capture_bytes == 0 {
            return true;
        }
        let total = self
            .total_capture_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        if total > self.guard.max_capture_bytes {
            self.mark_reason(CaptureGuardReason::CaptureLimitExceeded);
            return false;
        }
        true
    }

    fn note_line_len(&self, line_len: usize) -> bool {
        if self.guard.max_line_bytes == 0 {
            return true;
        }
        if line_len > self.guard.max_line_bytes {
            self.mark_reason(CaptureGuardReason::LineTooLong);
            return false;
        }
        true
    }

    fn mark_stall_if_needed(&self) {
        if self.guard.stall_timeout.is_zero() {
            return;
        }
        // Keep monitoring for inactivity even after initial output so auto-fallback can
        // hand off to direct TTY when an interactive command later blocks on input.
        let last = self.last_activity_unix_ms.load(Ordering::Relaxed);
        let elapsed_ms = now_unix_ms().saturating_sub(last);
        if elapsed_ms >= self.guard.stall_timeout.as_millis() as u64 {
            self.mark_reason(CaptureGuardReason::Stall);
        }
    }

    fn mark_reason(&self, reason: CaptureGuardReason) {
        let code = match reason {
            CaptureGuardReason::Stall => GUARD_REASON_STALL,
            CaptureGuardReason::LineTooLong => GUARD_REASON_LINE_TOO_LONG,
            CaptureGuardReason::CaptureLimitExceeded => GUARD_REASON_CAPTURE_LIMIT,
        };
        let _ = self.reason.compare_exchange(
            GUARD_REASON_NONE,
            code,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    fn reason(&self) -> Option<CaptureGuardReason> {
        match self.reason.load(Ordering::SeqCst) {
            GUARD_REASON_NONE => None,
            GUARD_REASON_STALL => Some(CaptureGuardReason::Stall),
            GUARD_REASON_LINE_TOO_LONG => Some(CaptureGuardReason::LineTooLong),
            GUARD_REASON_CAPTURE_LIMIT => Some(CaptureGuardReason::CaptureLimitExceeded),
            _ => None,
        }
    }
}

fn read_pipe_thread<R: Read + Send + 'static>(
    kind: StreamKind,
    mut reader: R,
    line_cb: Option<std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>>,
    guard_state: Option<Arc<CaptureGuardState>>,
) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut acc = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut line_buf: Vec<u8> = Vec::new();
        let mut partial_prompt_emitted = false;

        let emit_line =
            |line_buf: &mut Vec<u8>,
             kind: StreamKind,
             line_cb: &Option<std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>>,
             guard_state: &Option<Arc<CaptureGuardState>>| {
                if line_buf.is_empty() {
                    return;
                }
                if let Some(state) = guard_state {
                    if !state.note_line_len(line_buf.len()) {
                        line_buf.clear();
                        return;
                    }
                }
                if let Some(cb) = line_cb {
                    let text = String::from_utf8_lossy(line_buf).to_string();
                    if !text.is_empty() {
                        cb(kind, text);
                    }
                }
                line_buf.clear();
            };

        loop {
            let read: usize = reader.read(&mut chunk).unwrap_or_default();
            if read == 0 {
                break;
            }

            if let Some(state) = &guard_state {
                state.mark_activity();
                if state.note_capture_bytes(read) {
                    acc.extend_from_slice(&chunk[..read]);
                }
            } else {
                acc.extend_from_slice(&chunk[..read]);
            }

            for b in &chunk[..read] {
                match *b {
                    b'\n' | b'\r' => {
                        emit_line(&mut line_buf, kind, &line_cb, &guard_state);
                        partial_prompt_emitted = false;
                    }
                    _ => {
                        line_buf.push(*b);
                        if let Some(state) = &guard_state {
                            if !state.note_line_len(line_buf.len()) {
                                line_buf.clear();
                                partial_prompt_emitted = false;
                            }
                        }
                    }
                }
            }

            if !partial_prompt_emitted
                && looks_like_partial_interactive_prompt(&line_buf)
                && guard_state
                    .as_ref()
                    .and_then(|state| state.reason())
                    .is_none()
            {
                emit_line(&mut line_buf, kind, &line_cb, &guard_state);
                partial_prompt_emitted = true;
            }

            if guard_state
                .as_ref()
                .and_then(|state| state.reason())
                .is_some()
            {
                line_buf.clear();
                partial_prompt_emitted = false;
            }
        }

        if !line_buf.is_empty()
            && guard_state
                .as_ref()
                .and_then(|state| state.reason())
                .is_none()
        {
            if let Some(state) = &guard_state {
                if state.note_line_len(line_buf.len()) {
                    if let Some(cb) = &line_cb {
                        let text = String::from_utf8_lossy(&line_buf).to_string();
                        if !text.is_empty() {
                            cb(kind, text);
                        }
                    }
                }
            } else if let Some(cb) = &line_cb {
                let text = String::from_utf8_lossy(&line_buf).to_string();
                if !text.is_empty() {
                    cb(kind, text);
                }
            }
        }
        acc
    })
}

#[cfg(unix)]
fn read_pty_thread(
    mut reader: File,
    line_cb: Option<std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>>,
    guard_state: Option<Arc<CaptureGuardState>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let _ = set_nonblocking(reader.as_raw_fd(), true);
        let mut acc = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut line_buf: Vec<u8> = Vec::new();
        let mut partial_prompt_emitted = false;

        let emit_line =
            |line_buf: &mut Vec<u8>,
             line_cb: &Option<std::sync::Arc<dyn Fn(StreamKind, String) + Send + Sync>>,
             guard_state: &Option<Arc<CaptureGuardState>>| {
                if line_buf.is_empty() {
                    return;
                }
                if let Some(state) = guard_state {
                    if !state.note_line_len(line_buf.len()) {
                        line_buf.clear();
                        return;
                    }
                }
                if let Some(cb) = line_cb {
                    let text = String::from_utf8_lossy(line_buf).to_string();
                    if !text.is_empty() {
                        cb(StreamKind::Stdout, text);
                    }
                }
                line_buf.clear();
            };

        loop {
            let read = match reader.read(&mut chunk) {
                Ok(read) => read,
                Err(err) if err.raw_os_error() == Some(libc::EIO) => 0,
                Err(err)
                    if err.kind() == io::ErrorKind::WouldBlock
                        || err.raw_os_error() == Some(libc::EAGAIN) =>
                {
                    if stop.load(Ordering::SeqCst) {
                        0
                    } else {
                        std::thread::sleep(Duration::from_millis(25));
                        continue;
                    }
                }
                Err(_) => 0,
            };
            if read == 0 {
                break;
            }

            if let Some(state) = &guard_state {
                state.mark_activity();
                if state.note_capture_bytes(read) {
                    acc.extend_from_slice(&chunk[..read]);
                }
            } else {
                acc.extend_from_slice(&chunk[..read]);
            }

            for b in &chunk[..read] {
                match *b {
                    b'\n' | b'\r' => {
                        emit_line(&mut line_buf, &line_cb, &guard_state);
                        partial_prompt_emitted = false;
                    }
                    _ => {
                        line_buf.push(*b);
                        if let Some(state) = &guard_state {
                            if !state.note_line_len(line_buf.len()) {
                                line_buf.clear();
                                partial_prompt_emitted = false;
                            }
                        }
                    }
                }
            }

            if !partial_prompt_emitted
                && looks_like_partial_interactive_prompt(&line_buf)
                && guard_state
                    .as_ref()
                    .and_then(|state| state.reason())
                    .is_none()
            {
                emit_line(&mut line_buf, &line_cb, &guard_state);
                partial_prompt_emitted = true;
            }

            if guard_state
                .as_ref()
                .and_then(|state| state.reason())
                .is_some()
            {
                line_buf.clear();
                partial_prompt_emitted = false;
            }
        }

        if !line_buf.is_empty()
            && guard_state
                .as_ref()
                .and_then(|state| state.reason())
                .is_none()
        {
            if let Some(state) = &guard_state {
                if state.note_line_len(line_buf.len()) {
                    if let Some(cb) = &line_cb {
                        let text = String::from_utf8_lossy(&line_buf).to_string();
                        if !text.is_empty() {
                            cb(StreamKind::Stdout, text);
                        }
                    }
                }
            } else if let Some(cb) = &line_cb {
                let text = String::from_utf8_lossy(&line_buf).to_string();
                if !text.is_empty() {
                    cb(StreamKind::Stdout, text);
                }
            }
        }
        acc
    })
}

#[cfg(unix)]
#[allow(unsafe_code)] // Reason: openpty returns owned raw fds that must be wrapped into File handles here.
fn open_pty_pair() -> Result<(File, File)> {
    let mut master = -1;
    let mut slave = -1;
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc == -1 {
        return Err(anyhow!(io::Error::last_os_error())).context("open pty");
    }

    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok((master, slave))
}

#[cfg(unix)]
#[allow(unsafe_code)] // Reason: fcntl flag updates require direct libc calls on the provided fd.
fn set_cloexec(fd: i32, cloexec: bool) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(anyhow!(io::Error::last_os_error())).context("fcntl(F_GETFD)");
    }
    let next_flags = if cloexec {
        flags | libc::FD_CLOEXEC
    } else {
        flags & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next_flags) } == -1 {
        return Err(anyhow!(io::Error::last_os_error())).context("fcntl(F_SETFD)");
    }
    Ok(())
}

#[cfg(unix)]
#[allow(unsafe_code)] // Reason: fcntl flag updates require direct libc calls on the provided fd.
fn set_nonblocking(fd: i32, nonblocking: bool) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(anyhow!(io::Error::last_os_error())).context("fcntl(F_GETFL)");
    }
    let next_flags = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFL, next_flags) } == -1 {
        return Err(anyhow!(io::Error::last_os_error())).context("fcntl(F_SETFL)");
    }
    Ok(())
}

fn looks_like_partial_interactive_prompt(line_buf: &[u8]) -> bool {
    if line_buf.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(line_buf);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("select the service(s) to restart")
        || lower.contains("password for ")
        || lower.contains("proceed with installation")
        || lower.contains("excluding packages may cause partial upgrades")
        || lower.contains("packages to exclude")
        || lower.contains("packages to cleanbuild")
        || lower.contains("diffs to show")
        || lower.contains("pkgbuilds to edit")
    {
        return true;
    }

    lower.contains("[y/n]")
        || lower.contains("[n]one [a]ll [ab]ort")
        || trimmed.ends_with(':')
        || trimmed.ends_with('?')
}

fn join_pipe_reader(handle: JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

enum WaitOutcome {
    Cancelled,
    TimedOut,
    GuardTriggered(CaptureGuardReason),
    Other(anyhow::Error),
}

fn wait_with_cancel_timeout(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
    cancel_check: Option<std::sync::Arc<dyn Fn() -> bool + Send + Sync>>,
    guard_state: Option<Arc<CaptureGuardState>>,
) -> std::result::Result<std::process::ExitStatus, WaitOutcome> {
    let slice = Duration::from_millis(200);
    let mut elapsed = Duration::from_millis(0);
    loop {
        if cancel::is_cancel_requested() || cancel_check.as_ref().is_some_and(|cb| cb()) {
            return Err(WaitOutcome::Cancelled);
        }
        if let Some(state) = &guard_state {
            state.mark_stall_if_needed();
            if let Some(reason) = state.reason() {
                return Err(WaitOutcome::GuardTriggered(reason));
            }
        }
        match child.wait_timeout(slice) {
            Ok(Some(s)) => return Ok(s),
            Ok(None) => {
                elapsed += slice;
                if let Some(t) = timeout {
                    if elapsed >= t {
                        return Err(WaitOutcome::TimedOut);
                    }
                }
            }
            Err(e) => return Err(WaitOutcome::Other(anyhow!(e))),
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct OnExitGuard(Option<std::sync::Arc<dyn Fn() + Send + Sync>>);

impl Drop for OnExitGuard {
    fn drop(&mut self) {
        if let Some(cb) = &self.0 {
            cb();
        }
    }
}

fn terminate_child(child: &mut std::process::Child, managed_process_group: bool) {
    #[cfg(unix)]
    {
        if managed_process_group {
            terminate_process_group(child.id());
        } else {
            let _ = child.kill();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = managed_process_group;
        let _ = child.kill();
    }
}

pub(crate) fn terminate_process_group(pid: u32) {
    #[cfg(unix)]
    {
        signal_process_group(pid, libc::SIGTERM);
        // Avoid blocking the caller for a full second per task cancellation.
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            signal_process_group(pid, libc::SIGKILL);
        });
    }
    #[cfg(not(unix))]
    {
        // Process-group termination is unix-specific.
        let _ = pid;
    }
}

pub(crate) fn terminate_process(pid: u32) {
    #[cfg(unix)]
    {
        signal_process(pid, libc::SIGTERM);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            signal_process(pid, libc::SIGKILL);
        });
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
    }
}

#[cfg(unix)]
#[allow(unsafe_code)] // Reason: process-group signaling requires libc::kill with a negative process-group id.
fn signal_process_group(pid: u32, signal: libc::c_int) {
    let pgid = -(pid as libc::pid_t);
    unsafe {
        let _ = libc::kill(pgid, signal);
    }
}

#[cfg(unix)]
#[allow(unsafe_code)] // Reason: signaling an existing child by pid requires libc::kill.
fn signal_process(pid: u32, signal: libc::c_int) {
    unsafe {
        let _ = libc::kill(pid as libc::pid_t, signal);
    }
}

#[cfg(all(test, unix))]
#[path = "../tests/util_process.rs"]
mod tests;
