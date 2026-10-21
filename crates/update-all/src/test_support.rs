#![cfg(test)]

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use wait_timeout::ChildExt;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
const WRITER_MARKER: &str = "UPDATE_ALL_TEST_EXECUTABLE_WRITER";
const WRITER_PAYLOAD: &str = "UPDATE_ALL_TEST_EXECUTABLE_PAYLOAD";
const WRITER_STAGE: &str = "UPDATE_ALL_TEST_EXECUTABLE_STAGE";
const WRITER_TEST: &str = "test_support::executable_writer_child";

pub(crate) fn env_guard() -> MutexGuard<'static, ()> {
    ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|err| err.into_inner())
}

/// Publish a fixture without opening its executable inode writable in this process.
/// A concurrent fork can retain even a CLOEXEC writer until exec, causing ETXTBSY.
/// The isolated writer never spawns while its writer is live; publication happens
/// only after that child has exited and been reaped, not merely after file close.
pub(crate) fn write_executable(path: &Path, content: &str) -> io::Result<()> {
    write_executable_with_child(path, content, WRITER_TEST, Duration::from_secs(10))
}

fn write_executable_with_child(
    path: &Path,
    content: &str,
    child_test: &str,
    timeout: Duration,
) -> io::Result<()> {
    let target = std::path::absolute(path)?;
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "fixture has no parent"))?;
    let temporary = tempfile::Builder::new()
        .prefix(".executable-writer-")
        .tempdir_in(parent)?;
    let payload = temporary.path().join("payload");
    let stage = temporary.path().join("stage");
    // This spool is never executed. Inheriting its descriptor cannot pin stage.
    fs::write(&payload, content)?;
    // Stage must remain absent until the child creates it. Its presence after a
    // successful child exit rejects accidentally matching zero libtest tests.
    let child = writer_command(child_test, &payload, &stage)?.spawn()?;
    let mut owner = WriterChild::new(child);
    let status = owner.wait_for_completion(timeout)?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "executable writer child failed: {status}"
        )));
    }
    fs::rename(stage, target)
}

fn writer_command(child_test: &str, payload: &Path, stage: &Path) -> io::Result<Command> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", child_test, "--test-threads=1", "--nocapture"])
        .env_clear()
        .env(WRITER_MARKER, "1")
        .env(WRITER_PAYLOAD, payload)
        .env(WRITER_STAGE, stage)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", system_root);
    }
    Ok(command)
}

struct WriterChild {
    child: Child,
    reaped: bool,
}

impl WriterChild {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn wait_for_completion(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        match self.child.wait_timeout(timeout) {
            Ok(Some(status)) => {
                self.child.wait()?;
                self.reaped = true;
                Ok(status)
            }
            Ok(None) => {
                let status = self.terminate_and_reap()?;
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("executable writer timed out; child reaped with {status}"),
                ))
            }
            Err(wait_error) => {
                self.terminate_and_reap().map_err(|cleanup_error| {
                    io::Error::other(format!(
                        "executable writer wait failed: {wait_error}; cleanup failed: {cleanup_error}"
                    ))
                })?;
                Err(wait_error)
            }
        }
    }

    fn terminate_and_reap(&mut self) -> io::Result<ExitStatus> {
        let kill_result = self.child.kill();
        let status = self.child.wait().map_err(|wait_error| {
            io::Error::other(format!(
                "executable writer reap failed: {wait_error}; kill result: {kill_result:?}"
            ))
        })?;
        self.reaped = true;
        if let Err(kill_error) = kill_result {
            // A child may have exited between the deadline and kill. The wait
            // above must still observe its terminal status before ignoring this.
            if kill_error.kind() != io::ErrorKind::InvalidInput {
                return Err(kill_error);
            }
        }
        Ok(status)
    }
}

impl Drop for WriterChild {
    fn drop(&mut self) {
        if !self.reaped {
            if let Err(error) = self.terminate_and_reap() {
                let _ = writeln!(io::stderr(), "executable writer cleanup failed: {error}");
            }
        }
    }
}

fn writer_request() -> io::Result<Option<(std::path::PathBuf, std::path::PathBuf)>> {
    match std::env::var_os(WRITER_MARKER) {
        None => return Ok(None),
        Some(marker) if marker == "1" => {}
        Some(_) => return Err(io::Error::other("invalid executable writer marker")),
    }
    let required_path = |key| {
        std::env::var_os(key)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .ok_or_else(|| io::Error::other(format!("missing executable writer path: {key}")))
    };
    Ok(Some((
        required_path(WRITER_PAYLOAD)?,
        required_path(WRITER_STAGE)?,
    )))
}

#[test]
fn executable_writer_child() -> io::Result<()> {
    let Some((payload, stage)) = writer_request()? else {
        return Ok(());
    };
    let bytes = fs::read(payload)?;
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)?;
    writer.write_all(&bytes)?;
    drop(writer);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(stage, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

#[test]
fn executable_writer_failure_child() -> io::Result<()> {
    if let Some((_, stage)) = writer_request()? {
        // Even an existing stage cannot authorize publication after child failure.
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(stage)?
            .write_all(b"must not publish")?;
        return Err(io::Error::other("deliberate executable writer failure"));
    }
    Ok(())
}

#[test]
fn executable_writer_blocked_child() -> io::Result<()> {
    if writer_request()?.is_some() {
        loop {
            std::thread::park();
        }
    }
    Ok(())
}

fn directory_names(path: &Path) -> Vec<std::ffi::OsString> {
    let mut names: Vec<_> = fs::read_dir(path)
        .expect("fixture directory")
        .map(|entry| entry.expect("fixture entry").file_name())
        .collect();
    names.sort();
    names
}

#[test]
fn executable_writer_preserves_bytes_mode_and_replaces_atomically() {
    let temporary = tempfile::tempdir().expect("fixture directory");
    let target = temporary.path().join("fixture");
    fs::write(&target, "previous bytes").expect("old fixture");
    let content = "\0exact bytes\r\nwith Unicode \u{2603}\n";
    write_executable(&target, content).expect("isolated executable writer");
    assert_eq!(
        fs::read(&target).expect("fixture bytes"),
        content.as_bytes()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    assert_eq!(directory_names(temporary.path()), ["fixture"]);
}

#[cfg(unix)]
#[test]
fn executable_writer_accepts_non_utf8_paths() {
    use std::os::unix::ffi::OsStringExt;
    let temporary = tempfile::tempdir().expect("fixture directory");
    let directory = temporary
        .path()
        .join(std::ffi::OsString::from_vec(b"dir-\xff".to_vec()));
    fs::create_dir(&directory).expect("native directory");
    let name = std::ffi::OsString::from_vec(b"fixture-\xfe".to_vec());
    let target = directory.join(&name);
    write_executable(&target, "native path bytes").expect("native executable path");
    assert_eq!(fs::read(target).unwrap(), b"native path bytes");
    assert_eq!(directory_names(&directory), [name]);
}

#[test]
fn executable_writer_supports_parallel_distinct_targets() {
    let temporary = tempfile::tempdir().expect("fixture directory");
    let barrier = std::sync::Barrier::new(4);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|index| {
                let barrier = &barrier;
                let path = temporary.path().join(format!("fixture-{index}"));
                scope.spawn(move || {
                    barrier.wait();
                    let content = format!("fixture bytes {index}\n");
                    write_executable(&path, &content).expect("parallel fixture writer");
                    assert_eq!(fs::read(path).unwrap(), content.as_bytes());
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("parallel writer completed");
        }
    });
    assert_eq!(directory_names(temporary.path()).len(), 4);
}

#[test]
fn executable_writer_missing_stage_or_child_failure_preserves_destination() {
    let temporary = tempfile::tempdir().expect("fixture directory");
    let target = temporary.path().join("fixture");
    fs::write(&target, "old fixture").unwrap();
    for (child_test, timeout, expected_kind) in [
        (
            "test_support::no_such_writer_test",
            Duration::from_secs(5),
            io::ErrorKind::NotFound,
        ),
        (
            "test_support::executable_writer_failure_child",
            Duration::from_secs(5),
            io::ErrorKind::Other,
        ),
        (
            "test_support::executable_writer_blocked_child",
            Duration::from_millis(100),
            io::ErrorKind::TimedOut,
        ),
    ] {
        let error = write_executable_with_child(&target, "new fixture", child_test, timeout)
            .expect_err("invalid writer must not publish");
        assert_eq!(error.kind(), expected_kind, "writer error: {error}");
        assert_eq!(fs::read(&target).unwrap(), b"old fixture");
        assert_eq!(directory_names(temporary.path()), ["fixture"]);
    }
}

#[test]
fn executable_writer_publication_failure_cleans_stage_and_preserves_siblings() {
    let temporary = tempfile::tempdir().expect("fixture directory");
    let target = temporary.path().join("fixture");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), "unchanged").unwrap();
    fs::write(temporary.path().join("sibling"), "also unchanged").unwrap();
    assert!(write_executable(&target, "new fixture").is_err());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"unchanged");
    assert_eq!(
        fs::read(temporary.path().join("sibling")).unwrap(),
        b"also unchanged"
    );
    assert_eq!(directory_names(temporary.path()), ["fixture", "sibling"]);
}

#[test]
fn executable_writer_deadline_kills_and_reaps_child() {
    let temporary = tempfile::tempdir().expect("fixture directory");
    let payload = temporary.path().join("payload");
    let stage = temporary.path().join("stage");
    fs::write(&payload, "fixture").unwrap();
    let child = writer_command(
        "test_support::executable_writer_blocked_child",
        &payload,
        &stage,
    )
    .unwrap()
    .spawn()
    .unwrap();
    let mut owner = WriterChild::new(child);
    let error = owner
        .wait_for_completion(Duration::from_millis(100))
        .expect_err("blocked child must time out");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(owner.reaped, "deadline must reap before returning");
    assert!(
        owner.child.try_wait().unwrap().is_some(),
        "terminal child status"
    );
    assert!(!stage.exists());
}

#[test]
fn executable_writer_rejects_marked_malformed_request() {
    let temporary = tempfile::tempdir().expect("fixture directory");
    let stage = temporary.path().join("stage");
    let mut command =
        writer_command(WRITER_TEST, &temporary.path().join("payload"), &stage).unwrap();
    command.env_remove(WRITER_PAYLOAD);
    let child = command.spawn().unwrap();
    let mut owner = WriterChild::new(child);
    assert!(!owner
        .wait_for_completion(Duration::from_secs(5))
        .unwrap()
        .success());
    assert!(owner.reaped);
    assert!(!stage.exists());
}
