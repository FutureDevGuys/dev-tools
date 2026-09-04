//! Product-neutral executable discovery, PATH composition, and bounded execution.

use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
#[cfg(any(
    not(unix),
    target_os = "cygwin",
    target_os = "horizon",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "wasi"
))]
use std::io::Seek;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result as AnyhowResult};
use wait_timeout::ChildExt;
use zeroize::Zeroize;
#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
use zeroize::Zeroizing;

const MAX_OUTPUT_LIMIT: usize = 16 << 20;
const MONITOR_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
const TERMINATION_GRACE: Duration = Duration::from_millis(100);
const FORCE_TERMINATION_GRACE: Duration = Duration::from_secs(1);
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);

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

struct CaptureBuffer {
    bytes: Vec<u8>,
}

impl CaptureBuffer {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "cygwin",
            target_os = "horizon",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "wasi"
        ))
    ))]
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for CaptureBuffer {
    fn drop(&mut self) {
        #[cfg(all(
            test,
            unix,
            not(any(
                target_os = "cygwin",
                target_os = "horizon",
                target_os = "openbsd",
                target_os = "redox",
                target_os = "wasi"
            ))
        ))]
        let byte_count = self.bytes.len();
        self.bytes.as_mut_slice().zeroize();
        #[cfg(all(
            test,
            unix,
            not(any(
                target_os = "cygwin",
                target_os = "horizon",
                target_os = "openbsd",
                target_os = "redox",
                target_os = "wasi"
            ))
        ))]
        record_capture_zeroization(byte_count, self.bytes.iter().all(|byte| *byte == 0));
        self.bytes.clear();
    }
}

#[cfg(all(
    test,
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
#[derive(Clone, Copy, Default)]
struct CaptureZeroizationAudit {
    buffers: usize,
    bytes: usize,
    all_zero: bool,
}

#[cfg(all(
    test,
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
thread_local! {
    static CAPTURE_ZEROIZATION_AUDIT: std::cell::Cell<Option<CaptureZeroizationAudit>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(all(
    test,
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn record_capture_zeroization(byte_count: usize, all_zero: bool) {
    if byte_count == 0 {
        return;
    }
    CAPTURE_ZEROIZATION_AUDIT.with(|audit| {
        if let Some(mut current) = audit.get() {
            current.buffers += 1;
            current.bytes += byte_count;
            current.all_zero &= all_zero;
            audit.set(Some(current));
        }
    });
}

#[cfg(all(
    test,
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn observe_capture_zeroization<T>(operation: impl FnOnce() -> T) -> (T, CaptureZeroizationAudit) {
    CAPTURE_ZEROIZATION_AUDIT.with(|audit| {
        assert!(audit
            .replace(Some(CaptureZeroizationAudit {
                all_zero: true,
                ..CaptureZeroizationAudit::default()
            }))
            .is_none());
    });
    let result = operation();
    let audit = CAPTURE_ZEROIZATION_AUDIT.with(|audit| audit.take().unwrap_or_default());
    (result, audit)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedCommandStream {
    Stdout,
    Stderr,
}

impl fmt::Display for BoundedCommandStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedCommandErrorKind {
    InvalidExecutable,
    InvalidResourceLimits,
    InvalidWorkingDirectory,
    Start,
    Wait,
    Cancelled,
    TimedOut,
    OutputLimit(BoundedCommandStream),
    Capture(BoundedCommandStream),
    Cleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedCommandCleanupOperation {
    TerminateDomain,
    KillChild,
    WaitChild,
    Drain(BoundedCommandStream),
    Join(BoundedCommandStream),
}

#[derive(Debug)]
pub struct BoundedCommandCleanupFailure {
    operation: BoundedCommandCleanupOperation,
    source: Option<io::Error>,
}

impl BoundedCommandCleanupFailure {
    fn io(operation: BoundedCommandCleanupOperation, source: io::Error) -> Self {
        Self {
            operation,
            source: Some(source),
        }
    }

    fn marker(operation: BoundedCommandCleanupOperation) -> Self {
        Self {
            operation,
            source: None,
        }
    }

    pub fn operation(&self) -> BoundedCommandCleanupOperation {
        self.operation
    }

    pub fn io_error(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }
}

#[derive(Debug)]
pub struct BoundedCommandError {
    kind: BoundedCommandErrorKind,
    source: Option<io::Error>,
    cleanup_failures: Vec<BoundedCommandCleanupFailure>,
}

impl BoundedCommandError {
    fn new(kind: BoundedCommandErrorKind) -> Self {
        Self {
            kind,
            source: None,
            cleanup_failures: Vec::new(),
        }
    }

    fn with_source(kind: BoundedCommandErrorKind, source: io::Error) -> Self {
        Self {
            kind,
            source: Some(source),
            cleanup_failures: Vec::new(),
        }
    }

    fn with_cleanup_failures(
        mut self,
        cleanup_failures: Vec<BoundedCommandCleanupFailure>,
    ) -> Self {
        self.cleanup_failures = cleanup_failures;
        self
    }

    pub fn kind(&self) -> BoundedCommandErrorKind {
        self.kind
    }

    pub fn io_error(&self) -> Option<&io::Error> {
        self.source.as_ref()
    }

    pub fn cleanup_failures(&self) -> &[BoundedCommandCleanupFailure] {
        &self.cleanup_failures
    }
}

impl fmt::Display for BoundedCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            BoundedCommandErrorKind::InvalidExecutable => {
                formatter.write_str("bounded command executable is not an absolute executable file")
            }
            BoundedCommandErrorKind::InvalidResourceLimits => {
                formatter.write_str("bounded command resource limits are invalid")
            }
            BoundedCommandErrorKind::InvalidWorkingDirectory => {
                formatter.write_str("bounded command working directory must be absolute")
            }
            BoundedCommandErrorKind::Start => formatter.write_str("start bounded command"),
            BoundedCommandErrorKind::Wait => formatter.write_str("wait for bounded command"),
            BoundedCommandErrorKind::Cancelled => {
                formatter.write_str("bounded command was cancelled")
            }
            BoundedCommandErrorKind::TimedOut => formatter.write_str("bounded command timed out"),
            BoundedCommandErrorKind::OutputLimit(stream) => {
                write!(
                    formatter,
                    "bounded command {stream} exceeds the output limit"
                )
            }
            BoundedCommandErrorKind::Capture(stream) => {
                write!(formatter, "capture bounded command {stream}")
            }
            BoundedCommandErrorKind::Cleanup => formatter.write_str("clean up bounded command"),
        }
    }
}

impl Error for BoundedCommandError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

/// Run an exact executable with a cleared, explicitly supplied environment.
///
/// On supported Unix targets, the exact child starts a new process group and
/// both output pipes are drained nonblockingly into independent bounded
/// buffers. Timeout or overflow closes those read handles and terminalizes the
/// owned process group without waiting on pipe EOF. Children must not detach
/// from that group; a process which deliberately does so is outside the
/// admitted process domain, but inherited output handles cannot hold this call
/// open. Safe process-group ownership requires a platform `waitid` interface
/// with non-reaping observation; Unix targets without it use the direct-child
/// behavior described below.
///
/// On other platforms, the standard library only provides direct-child
/// termination. Those builds use polled temporary files and callers must not
/// launch detached descendants until this crate has an equivalent job
/// boundary; output can transiently exceed the requested limit between polling
/// passes.
pub fn run_bounded_command(
    request: &BoundedCommand<'_>,
) -> std::result::Result<BoundedCommandOutput, BoundedCommandError> {
    run_bounded_command_with_cancellation(request, &NEVER_CANCELLED)
}

/// Run a bounded command while observing a caller-owned cancellation flag.
///
/// Cancellation is cooperative at the controller boundary: the child never
/// receives the flag. Once observed, the runner terminalizes and reaps the
/// same owned process domain used for timeout and output-limit failures before
/// returning [`BoundedCommandErrorKind::Cancelled`].
pub fn run_bounded_command_with_cancellation(
    request: &BoundedCommand<'_>,
    cancelled: &AtomicBool,
) -> std::result::Result<BoundedCommandOutput, BoundedCommandError> {
    validate_bounded_command(request)?;
    let mut command = Command::new(request.executable);
    command
        .args(request.arguments)
        .env_clear()
        .envs(request.environment);
    if let Some(cwd) = request.cwd {
        command.current_dir(cwd);
    }
    run_prepared_bounded_command_with_cancellation(
        &mut command,
        request.timeout,
        request.output_limit,
        cancelled,
    )
}

/// Run a caller-prepared command with bounded output and no cancellation.
///
/// The caller's program, argument vector, environment, working directory, and
/// platform-specific child setup remain attached to the same [`Command`]. This
/// function is an execution controller, not an executable-identity validator;
/// the caller remains responsible for admitting the prepared program and its
/// child setup. The runner replaces standard input, output, and error: input is
/// closed and both output streams are captured independently up to
/// `output_limit` bytes. On supported Unix targets it also assigns the child to
/// a new process group; caller-provided child setup must not detach from or
/// reassign that domain. Environment values remain owned by the [`Command`]
/// after this call, so their later clearing or destruction remains the caller's
/// responsibility.
pub fn run_prepared_bounded_command(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
) -> std::result::Result<BoundedCommandOutput, BoundedCommandError> {
    run_prepared_bounded_command_with_cancellation(command, timeout, output_limit, &NEVER_CANCELLED)
}

/// Run a caller-prepared command while observing a cancellation flag.
///
/// Unlike [`run_bounded_command_with_cancellation`], this entry point does not
/// rebuild the [`Command`] or copy its environment. This is required when a
/// caller has bound execution to an already-open executable identity using a
/// platform-specific child transition. The runner validates resource limits
/// and observes pre-cancellation before modifying standard I/O or spawning.
pub fn run_prepared_bounded_command_with_cancellation(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
    cancelled: &AtomicBool,
) -> std::result::Result<BoundedCommandOutput, BoundedCommandError> {
    validate_resource_limits(timeout, output_limit)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(BoundedCommandError::new(BoundedCommandErrorKind::Cancelled));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(all(
        unix,
        not(any(
            target_os = "cygwin",
            target_os = "horizon",
            target_os = "openbsd",
            target_os = "redox",
            target_os = "wasi"
        ))
    ))]
    {
        run_prepared_bounded_command_unix(command, timeout, output_limit, cancelled)
    }
    #[cfg(any(
        not(unix),
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))]
    {
        run_prepared_bounded_command_direct_child(command, timeout, output_limit, cancelled)
    }
}

fn validate_resource_limits(
    timeout: Duration,
    output_limit: usize,
) -> std::result::Result<(), BoundedCommandError> {
    if timeout.is_zero() || output_limit == 0 || output_limit > MAX_OUTPUT_LIMIT {
        return Err(BoundedCommandError::new(
            BoundedCommandErrorKind::InvalidResourceLimits,
        ));
    }
    Ok(())
}

fn validate_bounded_command(
    request: &BoundedCommand<'_>,
) -> std::result::Result<(), BoundedCommandError> {
    if !request.executable.is_absolute() || !is_executable_file(request.executable) {
        return Err(BoundedCommandError::new(
            BoundedCommandErrorKind::InvalidExecutable,
        ));
    }
    validate_resource_limits(request.timeout, request.output_limit)?;
    if request.cwd.is_some_and(|cwd| !cwd.is_absolute()) {
        return Err(BoundedCommandError::new(
            BoundedCommandErrorKind::InvalidWorkingDirectory,
        ));
    }
    Ok(())
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn run_prepared_bounded_command_unix(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
    cancelled: &AtomicBool,
) -> std::result::Result<BoundedCommandOutput, BoundedCommandError> {
    configure_process_domain(command);
    let mut child = command.spawn().map_err(|source| {
        BoundedCommandError::with_source(BoundedCommandErrorKind::Start, source)
    })?;
    let domain = ProcessDomain::for_child(&child);
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let cleanup = terminate_process_domain(&mut child, domain);
            return Err(BoundedCommandError::new(BoundedCommandErrorKind::Capture(
                BoundedCommandStream::Stdout,
            ))
            .with_cleanup_failures(cleanup));
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            drop(stdout);
            let cleanup = terminate_process_domain(&mut child, domain);
            return Err(BoundedCommandError::new(BoundedCommandErrorKind::Capture(
                BoundedCommandStream::Stderr,
            ))
            .with_cleanup_failures(cleanup));
        }
    };
    if let Err(source) = set_nonblocking(&stdout) {
        drop(stdout);
        drop(stderr);
        let cleanup = terminate_process_domain(&mut child, domain);
        return Err(BoundedCommandError::with_source(
            BoundedCommandErrorKind::Capture(BoundedCommandStream::Stdout),
            source,
        )
        .with_cleanup_failures(cleanup));
    }
    if let Err(source) = set_nonblocking(&stderr) {
        drop(stdout);
        drop(stderr);
        let cleanup = terminate_process_domain(&mut child, domain);
        return Err(BoundedCommandError::with_source(
            BoundedCommandErrorKind::Capture(BoundedCommandStream::Stderr),
            source,
        )
        .with_cleanup_failures(cleanup));
    }

    let mut stdout = stdout;
    let mut stderr = stderr;
    let mut stdout_buffer = CaptureBuffer::with_capacity(output_limit.min(8 * 1024));
    let mut stderr_buffer = CaptureBuffer::with_capacity(output_limit.min(8 * 1024));
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    let mut leader_exited = false;
    let started = Instant::now();
    let primary = loop {
        if cancelled.load(Ordering::Acquire) {
            break Some(BoundedCommandError::new(BoundedCommandErrorKind::Cancelled));
        }
        if !stdout_closed {
            match drain_available(
                &mut stdout,
                &mut stdout_buffer,
                output_limit,
                BoundedCommandStream::Stdout,
            ) {
                Ok(DrainProgress::Pending) => {}
                Ok(DrainProgress::Closed) => stdout_closed = true,
                Err(error) => break Some(error),
            }
        }
        if !stderr_closed {
            match drain_available(
                &mut stderr,
                &mut stderr_buffer,
                output_limit,
                BoundedCommandStream::Stderr,
            ) {
                Ok(DrainProgress::Pending) => {}
                Ok(DrainProgress::Closed) => stderr_closed = true,
                Err(error) => break Some(error),
            }
        }
        if !leader_exited {
            match process_exit_observed(domain) {
                Ok(observed) => leader_exited = observed,
                Err(source) => {
                    break Some(BoundedCommandError::with_source(
                        BoundedCommandErrorKind::Wait,
                        source,
                    ));
                }
            }
        }
        if leader_exited && stdout_closed && stderr_closed {
            break None;
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break Some(BoundedCommandError::new(BoundedCommandErrorKind::TimedOut));
        }
        thread::sleep(remaining.min(MONITOR_INTERVAL));
    };

    if let Some(primary) = primary {
        drop(stdout);
        drop(stderr);
        let cleanup = terminate_process_domain(&mut child, domain);
        return Err(primary.with_cleanup_failures(cleanup));
    }

    drop(stdout);
    drop(stderr);
    let (status, cleanup) = terminate_lingering_domain(&mut child, domain);
    if !cleanup.is_empty() {
        return Err(BoundedCommandError::new(BoundedCommandErrorKind::Cleanup)
            .with_cleanup_failures(cleanup));
    }
    let status = status.ok_or_else(|| BoundedCommandError::new(BoundedCommandErrorKind::Wait))?;
    Ok(BoundedCommandOutput {
        status,
        stdout: stdout_buffer.into_vec(),
        stderr: stderr_buffer.into_vec(),
    })
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
enum DrainProgress {
    Pending,
    Closed,
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn set_nonblocking(pipe: &impl std::os::fd::AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(pipe)
        .map_err(|source| io::Error::from_raw_os_error(source.raw_os_error()))?;
    rustix::fs::fcntl_setfl(pipe, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|source| io::Error::from_raw_os_error(source.raw_os_error()))
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn drain_available(
    reader: &mut impl Read,
    output: &mut CaptureBuffer,
    limit: usize,
    stream: BoundedCommandStream,
) -> std::result::Result<DrainProgress, BoundedCommandError> {
    let mut buffer = Zeroizing::new([0_u8; 8 * 1024]);
    loop {
        let remaining = limit.saturating_sub(output.len());
        let read_limit = remaining.saturating_add(1).min(buffer.len());
        match reader.read(&mut buffer[..read_limit]) {
            Ok(0) => return Ok(DrainProgress::Closed),
            Ok(count) if count > remaining => {
                output.extend_from_slice(&buffer[..remaining]);
                return Err(BoundedCommandError::new(
                    BoundedCommandErrorKind::OutputLimit(stream),
                ));
            }
            Ok(count) => output.extend_from_slice(&buffer[..count]),
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                return Ok(DrainProgress::Pending);
            }
            Err(source) => {
                return Err(BoundedCommandError::with_source(
                    BoundedCommandErrorKind::Capture(stream),
                    source,
                ));
            }
        }
    }
}

#[cfg(any(
    not(unix),
    target_os = "cygwin",
    target_os = "horizon",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "wasi"
))]
fn run_prepared_bounded_command_direct_child(
    command: &mut Command,
    timeout: Duration,
    output_limit: usize,
    cancelled: &AtomicBool,
) -> std::result::Result<BoundedCommandOutput, BoundedCommandError> {
    let mut stdout = tempfile::tempfile().map_err(|source| {
        BoundedCommandError::with_source(
            BoundedCommandErrorKind::Capture(BoundedCommandStream::Stdout),
            source,
        )
    })?;
    let mut stderr = tempfile::tempfile().map_err(|source| {
        BoundedCommandError::with_source(
            BoundedCommandErrorKind::Capture(BoundedCommandStream::Stderr),
            source,
        )
    })?;
    command
        .stdout(Stdio::from(stdout.try_clone().map_err(|source| {
            BoundedCommandError::with_source(
                BoundedCommandErrorKind::Capture(BoundedCommandStream::Stdout),
                source,
            )
        })?))
        .stderr(Stdio::from(stderr.try_clone().map_err(|source| {
            BoundedCommandError::with_source(
                BoundedCommandErrorKind::Capture(BoundedCommandStream::Stderr),
                source,
            )
        })?));
    let mut child = command.spawn().map_err(|source| {
        BoundedCommandError::with_source(BoundedCommandErrorKind::Start, source)
    })?;
    let mut status = None;
    let started = Instant::now();
    let primary = loop {
        if cancelled.load(Ordering::Acquire) {
            break Some(BoundedCommandError::new(BoundedCommandErrorKind::Cancelled));
        }
        match file_exceeds_limit(&stdout, output_limit, BoundedCommandStream::Stdout) {
            Ok(true) => {
                break Some(BoundedCommandError::new(
                    BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout),
                ));
            }
            Ok(false) => {}
            Err(error) => break Some(error),
        }
        match file_exceeds_limit(&stderr, output_limit, BoundedCommandStream::Stderr) {
            Ok(true) => {
                break Some(BoundedCommandError::new(
                    BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stderr),
                ));
            }
            Ok(false) => {}
            Err(error) => break Some(error),
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(observed) => status = observed,
                Err(source) => {
                    break Some(BoundedCommandError::with_source(
                        BoundedCommandErrorKind::Wait,
                        source,
                    ));
                }
            }
        }
        if status.is_some() {
            break None;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break Some(BoundedCommandError::new(BoundedCommandErrorKind::TimedOut));
        }
        thread::sleep(remaining.min(MONITOR_INTERVAL));
    };

    if let Some(primary) = primary {
        let cleanup = terminate_direct_child(&mut child, &mut status);
        return Err(primary.with_cleanup_failures(cleanup));
    }
    let stdout = read_bounded_file(&mut stdout, output_limit, BoundedCommandStream::Stdout)?;
    let stderr = read_bounded_file(&mut stderr, output_limit, BoundedCommandStream::Stderr)?;
    let status = status.ok_or_else(|| BoundedCommandError::new(BoundedCommandErrorKind::Wait))?;
    Ok(BoundedCommandOutput {
        status,
        stdout: stdout.into_vec(),
        stderr: stderr.into_vec(),
    })
}

#[cfg(any(
    not(unix),
    target_os = "cygwin",
    target_os = "horizon",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "wasi"
))]
fn file_exceeds_limit(
    file: &std::fs::File,
    limit: usize,
    stream: BoundedCommandStream,
) -> std::result::Result<bool, BoundedCommandError> {
    file.metadata()
        .map(|metadata| metadata.len() > limit as u64)
        .map_err(|source| {
            BoundedCommandError::with_source(BoundedCommandErrorKind::Capture(stream), source)
        })
}

#[cfg(any(
    not(unix),
    target_os = "cygwin",
    target_os = "horizon",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "wasi"
))]
fn read_bounded_file(
    file: &mut std::fs::File,
    limit: usize,
    stream: BoundedCommandStream,
) -> std::result::Result<CaptureBuffer, BoundedCommandError> {
    file.rewind().map_err(|source| {
        BoundedCommandError::with_source(BoundedCommandErrorKind::Capture(stream), source)
    })?;
    let mut output = CaptureBuffer::with_capacity(limit.min(8 * 1024));
    file.take(limit as u64 + 1)
        .read_to_end(&mut output.bytes)
        .map_err(|source| {
            BoundedCommandError::with_source(BoundedCommandErrorKind::Capture(stream), source)
        })?;
    if output.len() > limit {
        return Err(BoundedCommandError::new(
            BoundedCommandErrorKind::OutputLimit(stream),
        ));
    }
    Ok(output)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
#[derive(Clone, Copy)]
struct ProcessDomain {
    group: Option<rustix::process::Pid>,
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
impl ProcessDomain {
    fn for_child(child: &Child) -> Self {
        Self {
            group: i32::try_from(child.id())
                .ok()
                .and_then(rustix::process::Pid::from_raw),
        }
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn configure_process_domain(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn process_exit_observed(domain: ProcessDomain) -> io::Result<bool> {
    let leader = domain.group.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "process-group leader PID is unavailable",
        )
    })?;
    let options = rustix::process::WaitIdOptions::EXITED
        | rustix::process::WaitIdOptions::NOHANG
        | rustix::process::WaitIdOptions::NOWAIT;
    rustix::process::waitid(rustix::process::WaitId::Pid(leader), options)
        .map(|status| status.is_some())
        .map_err(|source| io::Error::from_raw_os_error(source.raw_os_error()))
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn wait_for_process_exit(domain: ProcessDomain, deadline: Instant) -> io::Result<bool> {
    loop {
        if process_exit_observed(domain)? {
            return Ok(true);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        thread::sleep(remaining.min(MONITOR_INTERVAL));
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn terminate_process_domain(
    child: &mut Child,
    domain: ProcessDomain,
) -> Vec<BoundedCommandCleanupFailure> {
    let mut failures = Vec::new();

    // A successful non-reaping observation proves that the leader PID still
    // names our child. Keep it waitable until every real group signal has been
    // issued so the numeric PID/PGID cannot be recycled underneath cleanup.
    if let Err(source) = process_exit_observed(domain) {
        failures.push(BoundedCommandCleanupFailure::io(
            BoundedCommandCleanupOperation::WaitChild,
            source,
        ));
        return failures;
    }
    signal_process_group(domain, rustix::process::Signal::TERM, &mut failures);

    let identity_reserved = match wait_for_process_exit(domain, Instant::now() + TERMINATION_GRACE)
    {
        Ok(_) => true,
        Err(source) => {
            failures.push(BoundedCommandCleanupFailure::io(
                BoundedCommandCleanupOperation::WaitChild,
                source,
            ));
            false
        }
    };
    if identity_reserved {
        signal_process_group(domain, rustix::process::Signal::KILL, &mut failures);
        kill_child_before_reap(child, &mut failures);
    }

    let force_deadline = Instant::now() + FORCE_TERMINATION_GRACE;
    match child.wait_timeout(force_deadline.saturating_duration_since(Instant::now())) {
        Ok(Some(_)) => {}
        Ok(None) => failures.push(BoundedCommandCleanupFailure::marker(
            BoundedCommandCleanupOperation::WaitChild,
        )),
        Err(source) => failures.push(BoundedCommandCleanupFailure::io(
            BoundedCommandCleanupOperation::WaitChild,
            source,
        )),
    }
    record_process_group_exit(domain, force_deadline, &mut failures);
    failures
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn kill_child_before_reap(child: &mut Child, failures: &mut Vec<BoundedCommandCleanupFailure>) {
    if let Err(source) = child.kill() {
        if source.kind() != io::ErrorKind::InvalidInput {
            failures.push(BoundedCommandCleanupFailure::io(
                BoundedCommandCleanupOperation::KillChild,
                source,
            ));
        }
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn signal_process_group(
    domain: ProcessDomain,
    signal: rustix::process::Signal,
    failures: &mut Vec<BoundedCommandCleanupFailure>,
) {
    let Some(group) = domain.group else {
        failures.push(BoundedCommandCleanupFailure::marker(
            BoundedCommandCleanupOperation::TerminateDomain,
        ));
        return;
    };
    if let Err(source) = rustix::process::kill_process_group(group, signal) {
        if source != rustix::io::Errno::SRCH {
            failures.push(BoundedCommandCleanupFailure::io(
                BoundedCommandCleanupOperation::TerminateDomain,
                io::Error::from_raw_os_error(source.raw_os_error()),
            ));
        }
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn terminate_lingering_domain(
    child: &mut Child,
    domain: ProcessDomain,
) -> (Option<ExitStatus>, Vec<BoundedCommandCleanupFailure>) {
    let mut failures = Vec::new();

    match process_exit_observed(domain) {
        Ok(true) => {}
        Ok(false) => {
            failures.push(BoundedCommandCleanupFailure::marker(
                BoundedCommandCleanupOperation::WaitChild,
            ));
            return (None, failures);
        }
        Err(source) => {
            failures.push(BoundedCommandCleanupFailure::io(
                BoundedCommandCleanupOperation::WaitChild,
                source,
            ));
            return (None, failures);
        }
    }

    // The leader is already exited, so waiting for group extinction while it
    // remains unreaped would wait on the leader's zombie. Issue both cleanup
    // signals while that zombie reserves the PGID, then reap exactly once.
    signal_process_group(domain, rustix::process::Signal::TERM, &mut failures);
    signal_process_group(domain, rustix::process::Signal::KILL, &mut failures);
    kill_child_before_reap(child, &mut failures);

    let force_deadline = Instant::now() + FORCE_TERMINATION_GRACE;
    let status = match child.wait_timeout(force_deadline.saturating_duration_since(Instant::now()))
    {
        Ok(Some(status)) => Some(status),
        Ok(None) => {
            failures.push(BoundedCommandCleanupFailure::marker(
                BoundedCommandCleanupOperation::WaitChild,
            ));
            None
        }
        Err(source) => {
            failures.push(BoundedCommandCleanupFailure::io(
                BoundedCommandCleanupOperation::WaitChild,
                source,
            ));
            None
        }
    };
    record_process_group_exit(domain, force_deadline, &mut failures);
    (status, failures)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn record_process_group_exit(
    domain: ProcessDomain,
    deadline: Instant,
    failures: &mut Vec<BoundedCommandCleanupFailure>,
) {
    // The leader may have been reaped, so this PGID could now be reused. The
    // probe uses signal 0 and cannot affect a reused group; reuse can only make
    // cleanup conservatively wait and report failure instead of claiming that
    // the owned descendants reached their terminal boundary.
    match wait_for_process_group_exit(domain, deadline) {
        Ok(true) => {}
        Ok(false) => failures.push(BoundedCommandCleanupFailure::marker(
            BoundedCommandCleanupOperation::TerminateDomain,
        )),
        Err(failure) => failures.push(failure),
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn wait_for_process_group_exit(
    domain: ProcessDomain,
    deadline: Instant,
) -> std::result::Result<bool, BoundedCommandCleanupFailure> {
    let Some(group) = domain.group else {
        return Err(BoundedCommandCleanupFailure::marker(
            BoundedCommandCleanupOperation::TerminateDomain,
        ));
    };
    loop {
        match process_group_exists(group) {
            Ok(false) => return Ok(true),
            Ok(true) => {}
            Err(source) => {
                return Err(BoundedCommandCleanupFailure::io(
                    BoundedCommandCleanupOperation::TerminateDomain,
                    source,
                ));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        thread::sleep(remaining.min(MONITOR_INTERVAL));
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
fn process_group_exists(group: rustix::process::Pid) -> io::Result<bool> {
    match rustix::process::test_kill_process_group(group) {
        Ok(()) => Ok(true),
        Err(source) if source == rustix::io::Errno::SRCH => Ok(false),
        Err(source) => Err(io::Error::from_raw_os_error(source.raw_os_error())),
    }
}

#[cfg(any(
    not(unix),
    target_os = "cygwin",
    target_os = "horizon",
    target_os = "openbsd",
    target_os = "redox",
    target_os = "wasi"
))]
fn terminate_direct_child(
    child: &mut Child,
    status: &mut Option<ExitStatus>,
) -> Vec<BoundedCommandCleanupFailure> {
    let mut failures = Vec::new();
    if status.is_none() {
        if let Err(source) = child.kill() {
            if source.kind() != io::ErrorKind::InvalidInput {
                failures.push(BoundedCommandCleanupFailure::io(
                    BoundedCommandCleanupOperation::KillChild,
                    source,
                ));
            }
        }
        match child.wait_timeout(FORCE_TERMINATION_GRACE) {
            Ok(Some(observed)) => *status = Some(observed),
            Ok(None) => failures.push(BoundedCommandCleanupFailure::marker(
                BoundedCommandCleanupOperation::WaitChild,
            )),
            Err(source) => failures.push(BoundedCommandCleanupFailure::io(
                BoundedCommandCleanupOperation::WaitChild,
                source,
            )),
        }
    }
    failures
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
pub fn prepend_path(directory: &Path, existing: Option<&OsStr>) -> AnyhowResult<OsString> {
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
    [".COM", ".EXE", ".BAT", ".CMD"]
        .into_iter()
        .map(|extension| directory.join(format!("{command}{extension}")))
        .collect()
}

#[cfg(unix)]
pub fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
pub fn is_executable_file(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return false;
    }

    let Some(extension) = path.extension().and_then(OsStr::to_str) else {
        return false;
    };
    let extension = format!(".{extension}");
    [".COM", ".EXE", ".BAT", ".CMD"]
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&extension))
}

#[cfg(not(any(unix, windows)))]
pub fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(all(
    test,
    unix,
    not(any(
        target_os = "cygwin",
        target_os = "horizon",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "wasi"
    ))
))]
mod tests {
    use super::*;

    #[test]
    fn discarded_capture_buffers_are_zeroized_on_failure() {
        let timeout_arguments = [
            OsString::from("-c"),
            OsString::from("printf secret; printf private >&2; sleep 1"),
        ];
        let (timeout_result, timeout_audit) = observe_capture_zeroization(|| {
            run_bounded_command(&BoundedCommand {
                executable: Path::new("/bin/sh"),
                arguments: &timeout_arguments,
                environment: &BTreeMap::new(),
                cwd: None,
                timeout: Duration::from_millis(50),
                output_limit: 32,
            })
        });
        assert_eq!(
            timeout_result.unwrap_err().kind(),
            BoundedCommandErrorKind::TimedOut
        );
        assert_eq!(timeout_audit.buffers, 2);
        assert!(timeout_audit.bytes >= b"secretprivate".len());
        assert!(timeout_audit.all_zero);

        let limit_arguments = [OsString::from("-c"), OsString::from("printf 123456789")];
        let (limit_result, limit_audit) = observe_capture_zeroization(|| {
            run_bounded_command(&BoundedCommand {
                executable: Path::new("/bin/sh"),
                arguments: &limit_arguments,
                environment: &BTreeMap::new(),
                cwd: None,
                timeout: Duration::from_secs(1),
                output_limit: 8,
            })
        });
        assert_eq!(
            limit_result.unwrap_err().kind(),
            BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout)
        );
        assert!(limit_audit.buffers > 0);
        assert_eq!(limit_audit.bytes, 8);
        assert!(limit_audit.all_zero);
    }

    #[test]
    fn observing_child_exit_does_not_reap_the_process_group_leader() {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "exit 23"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_domain(&mut command);
        let mut child = command.spawn().unwrap();
        let domain = ProcessDomain::for_child(&child);
        let deadline = Instant::now() + Duration::from_secs(2);

        loop {
            if process_exit_observed(domain).unwrap() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit before the test deadline"
            );
            thread::sleep(MONITOR_INTERVAL);
        }

        assert!(
            process_exit_observed(domain).unwrap(),
            "the first observation reaped the process-group leader"
        );
        assert_eq!(child.wait().unwrap().code(), Some(23));
    }
}
