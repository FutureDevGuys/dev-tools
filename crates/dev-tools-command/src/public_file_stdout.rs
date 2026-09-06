//! Linux public-output capture. Lifecycle remains owned by the Unix supervisor.

use super::*;
use std::os::unix::{fs::FileExt, process::CommandExt};

/// A consumed prepared command, retaining a held executable's borrow when used.
///
/// Construct with `Command::into()` or `HeldCommand::into()`. Consumption prevents
/// the child-only file-size setup from persisting into a subsequent execution.
pub struct OwnedPreparedCommand<'a>(PreparedCommand<'a>);

enum PreparedCommand<'a> {
    Plain(Command),
    Held(HeldCommand<'a>),
}

impl From<Command> for OwnedPreparedCommand<'_> {
    fn from(command: Command) -> Self {
        Self(PreparedCommand::Plain(command))
    }
}

impl<'a> From<HeldCommand<'a>> for OwnedPreparedCommand<'a> {
    fn from(command: HeldCommand<'a>) -> Self {
        Self(PreparedCommand::Held(command))
    }
}

/// Run an admitted public-output observer with anonymous regular-file stdout.
///
/// Linux only. Unlike the default pipe API, this consumes the prepared command.
/// It preserves native argv, environment, cwd and child setup; stdin is closed,
/// stderr remains a bounded pipe, and the existing process-group supervisor owns
/// timeout and cleanup. All stdout work must finish by command-leader completion.
///
/// The child inherits a hard and soft `RLIMIT_FSIZE` of at most `output_limit + 1`
/// bytes (or its lower inherited limit). This restricts extension of **all regular
/// files**, including incidental cache writes, not only stdout. Select this
/// mode only when that restriction is compatible with the admitted operation.
/// It is not a sandbox for privileged or deliberately escaping programs, nor a
/// bound on total process memory or filesystem allocation. Caller setup must not
/// escape the owned process group or defeat the limit. No shell is introduced.
///
/// The extra byte detects overflow independently of monitor timing. After owned
/// process cleanup, stdout is sealed against writes and size changes, then read
/// without sharing the child's file offset. Capture or sealing failure returns
/// a value-free error and no partial output. Storage is anonymous, does not use
/// `TMPDIR`, and is for public bytes only; secure erasure is not promised.
pub fn run_prepared_bounded_command_with_public_file_stdout<'a>(
    command: impl Into<OwnedPreparedCommand<'a>>,
    timeout: Duration,
    output_limit: usize,
) -> Result<BoundedCommandOutput, BoundedCommandError> {
    run_prepared_bounded_command_with_public_file_stdout_and_cancellation(
        command,
        timeout,
        output_limit,
        &NEVER_CANCELLED,
    )
}

/// Cancellable form of [`run_prepared_bounded_command_with_public_file_stdout`].
///
/// Invalid limits take precedence over cancellation. Pre-cancellation prevents
/// capture allocation and spawn. The command is consumed on every outcome.
pub fn run_prepared_bounded_command_with_public_file_stdout_and_cancellation<'a>(
    command: impl Into<OwnedPreparedCommand<'a>>,
    timeout: Duration,
    output_limit: usize,
    cancelled: &AtomicBool,
) -> Result<BoundedCommandOutput, BoundedCommandError> {
    validate_resource_limits(timeout, output_limit)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(BoundedCommandError::new(BoundedCommandErrorKind::Cancelled));
    }
    let mut owned = command.into();
    let command = match &mut owned.0 {
        PreparedCommand::Plain(command) => command,
        PreparedCommand::Held(command) => &mut command.command,
    };
    let file = configure(command, output_limit).map_err(capture_error)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(BoundedCommandError::new(BoundedCommandErrorKind::Cancelled));
    }
    run_prepared_bounded_command_unix(command, timeout, output_limit, cancelled, Some(file))
}

fn capture_error(source: io::Error) -> BoundedCommandError {
    BoundedCommandError::with_source(
        BoundedCommandErrorKind::Capture(BoundedCommandStream::Stdout),
        source,
    )
}

// Only used on consumed commands. The public entrypoint validates output_limit
// before this helper so conversion and the sentinel addition cannot overflow.
fn configure(command: &mut Command, output_limit: usize) -> io::Result<fs::File> {
    let file = fs::File::from(rustix::fs::memfd_create(
        "dev-tools-public-stdout",
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )?);
    rustix::fs::fchmod(&file, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::piped());
    let maximum = (output_limit + 1) as libc::rlim_t;
    // SAFETY: the callback uses only initialized stack scalars, async-signal-safe
    // getrlimit/setrlimit and errno conversion; it neither allocates nor locks.
    // It executes only in the child, and does not capture any borrowed handles.
    unsafe {
        command.pre_exec(move || {
            let mut inherited = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: the writable pointer is aligned, initialized and live for
            // this synchronous libc call; resource and ABI types come from libc.
            if libc::getrlimit(libc::RLIMIT_FSIZE, &mut inherited) != 0 {
                return Err(io::Error::last_os_error());
            }
            let bound = maximum.min(inherited.rlim_cur).min(inherited.rlim_max);
            let limit = libc::rlimit {
                rlim_cur: bound,
                rlim_max: bound,
            };
            // SAFETY: the readable pointer remains valid throughout this call.
            // Both limits are only lowered; the parent's limits are untouched.
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(file)
}

pub(super) fn check_size(file: &fs::File, limit: usize) -> Result<(), BoundedCommandError> {
    if file.metadata().map_err(capture_error)?.len() > limit as u64 {
        return Err(BoundedCommandError::new(
            BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout),
        ));
    }
    Ok(())
}

pub(super) fn finish(file: fs::File, limit: usize) -> Result<CaptureBuffer, BoundedCommandError> {
    rustix::fs::fcntl_add_seals(
        &file,
        rustix::fs::SealFlags::WRITE
            | rustix::fs::SealFlags::GROW
            | rustix::fs::SealFlags::SHRINK
            | rustix::fs::SealFlags::SEAL,
    )
    .map_err(|error| capture_error(error.into()))?;
    check_size(&file, limit)?;
    let mut output = CaptureBuffer::with_capacity(limit.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = match file.read_at(&mut buffer, output.len() as u64) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(capture_error(error)),
        };
        if count == 0 {
            return Ok(output);
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_caps_public_file_without_a_running_supervisor() {
        let mut command = Command::new("/usr/bin/head");
        command.env_clear().args(["-c", "1048576", "/dev/zero"]);
        let file = configure(&mut command, 1024).unwrap();
        // Deliberately do not run the monitor: this must be a kernel bound,
        // not an observation that only happens to catch a fast writer in time.
        let mut child = command.spawn().unwrap();
        let completed = child.wait_timeout(Duration::from_secs(3)).unwrap();
        if completed.is_none() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
        assert!(completed.is_some(), "finite writer did not terminate");
        assert_eq!(file.metadata().unwrap().len(), 1025);
        assert_eq!(
            check_size(&file, 1024).unwrap_err().kind(),
            BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout)
        );
    }

    #[test]
    fn final_capture_seals_bytes_and_ignores_the_shared_offset() {
        let mut command = Command::new("/bin/true");
        let mut file = configure(&mut command, 1024).unwrap();
        file.write_all(b"immutable").unwrap();
        let mut other = file.try_clone().unwrap();
        other.seek(io::SeekFrom::Start(700)).unwrap();
        assert_eq!(finish(file, 1024).unwrap().into_vec(), b"immutable");
        assert!(other.write_at(b"changed", 0).is_err());
        assert!(other.set_len(0).is_err());
        assert!(other.set_len(1024).is_err());
    }
}
