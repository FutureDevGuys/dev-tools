use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use dev_tools_command::{
    prepend_path, run_bounded_command, same_path_location, BoundedCommand, BoundedCommandErrorKind,
};

#[cfg(windows)]
#[test]
fn windows_executable_validation_requires_a_native_command_regular_file() {
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("tool.ExE");
    let text = root.path().join("tool.txt");
    fs::write(&executable, b"fixture").unwrap();
    fs::write(&text, b"fixture").unwrap();

    assert!(dev_tools_command::is_executable_file(&executable));
    assert!(!dev_tools_command::is_executable_file(&text));
}

#[cfg(unix)]
use dev_tools_command::{
    executable_candidates, first_executable, run_prepared_bounded_command, BoundedCommandStream,
};
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
use dev_tools_command::{
    run_bounded_command_with_cancellation, run_prepared_bounded_command_with_cancellation,
};
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
use std::sync::atomic::{AtomicBool, Ordering};
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
use std::sync::{mpsc, Arc};
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
use std::thread;

#[cfg(unix)]
fn executable(path: &Path) {
    fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(unix)]
#[test]
fn bounded_command_capture_is_environment_explicit_size_bounded_and_timed() {
    let output = run_bounded_command(&BoundedCommand {
        executable: Path::new("/usr/bin/printf"),
        arguments: &["%s".into(), "hello".into()],
        environment: &Default::default(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 32,
    })
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"hello");
    assert!(output.stderr.is_empty());

    let oversized = run_bounded_command(&BoundedCommand {
        executable: Path::new("/usr/bin/printf"),
        arguments: &["%033d".into(), "1".into()],
        environment: &Default::default(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 32,
    });
    assert_eq!(
        oversized.unwrap_err().kind(),
        BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout)
    );

    let timed_out = run_bounded_command(&BoundedCommand {
        executable: Path::new("/usr/bin/sleep"),
        arguments: &["2".into()],
        environment: &Default::default(),
        cwd: None,
        timeout: Duration::from_millis(10),
        output_limit: 32,
    });
    assert_eq!(
        timed_out.unwrap_err().kind(),
        BoundedCommandErrorKind::TimedOut
    );
}

#[cfg(unix)]
#[test]
fn bounded_command_preserves_exact_environment_and_null_stdin() {
    let environment = BTreeMap::from([(OsString::from("ONLY_VAR"), OsString::from("present"))]);
    let output = run_bounded_command(&BoundedCommand {
        executable: Path::new("/usr/bin/env"),
        arguments: &[],
        environment: &environment,
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 64,
    })
    .unwrap();
    assert_eq!(output.stdout, b"ONLY_VAR=present\n");

    let arguments = [
        OsString::from("-c"),
        OsString::from("if IFS= read -r value; then printf unexpected; else printf eof; fi"),
    ];
    let output = run_bounded_command(&BoundedCommand {
        executable: Path::new("/bin/sh"),
        arguments: &arguments,
        environment: &BTreeMap::new(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 16,
    })
    .unwrap();
    assert_eq!(output.stdout, b"eof");
}

#[cfg(target_os = "linux")]
#[test]
fn prepared_command_preserves_held_executable_identity_and_configuration() {
    use std::os::fd::{AsRawFd, BorrowedFd};
    use std::os::unix::process::CommandExt;

    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("held-script");
    fs::write(
        &source,
        b"#!/bin/sh\nprintf '%s\\n%s\\n' \"$1\" \"$ONLY_VAR\"\npwd\n",
    )
    .unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let held = rustix::fs::open(
        &source,
        rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let raw_descriptor = held.as_raw_fd();
    let execution_path = PathBuf::from(format!("/proc/self/fd/{raw_descriptor}"));

    fs::remove_file(&source).unwrap();
    fs::write(&source, b"#!/bin/sh\nprintf replacement\n").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();

    let mut command = std::process::Command::new(&execution_path);
    command
        .arg("argument")
        .env_clear()
        .env("ONLY_VAR", "present")
        .current_dir(root.path());
    // SAFETY: `held` stays alive until the synchronous runner returns, so this
    // exact descriptor remains valid through the child-only callback. Clearing
    // only FD_CLOEXEC is async-signal-safe and lets the script interpreter
    // reopen the already-admitted executable through `/proc/self/fd`.
    unsafe {
        command.pre_exec(move || {
            let descriptor = BorrowedFd::borrow_raw(raw_descriptor);
            rustix::io::fcntl_setfd(descriptor, rustix::io::FdFlags::empty())
                .map_err(std::io::Error::from)
        });
    }

    let output = run_prepared_bounded_command(&mut command, Duration::from_secs(1), 4096)
        .expect("run the caller-prepared held executable");
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("argument\npresent\n{}\n", root.path().display()).into_bytes()
    );
    assert!(output.stderr.is_empty());
    assert!(
        rustix::io::fcntl_getfd(&held)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC),
        "the child-only transition changed the parent descriptor"
    );
}

#[cfg(unix)]
#[test]
fn prepared_command_preserves_a_child_setup_failure_as_a_typed_start_error() {
    use std::os::unix::process::CommandExt;

    let mut command = std::process::Command::new("/bin/true");
    // SAFETY: this test callback performs no mutation and returns one fixed OS
    // error immediately, exercising the caller-owned child setup boundary.
    unsafe {
        command.pre_exec(|| Err(std::io::Error::from_raw_os_error(1)));
    }

    let error = run_prepared_bounded_command(&mut command, Duration::from_secs(1), 32)
        .expect_err("the prepared child setup must prevent spawn");
    assert_eq!(error.kind(), BoundedCommandErrorKind::Start);
    assert_eq!(
        error.io_error().and_then(std::io::Error::raw_os_error),
        Some(1)
    );
    assert!(error.cleanup_failures().is_empty());
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
#[test]
fn prepared_command_rejects_invalid_limits_and_precancellation_before_spawn() {
    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("spawned");
    let script = root.path().join("command");
    fs::write(&script, format!("#!/bin/sh\n: > '{}'\n", marker.display())).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();

    let mut invalid_limits = std::process::Command::new(&script);
    let error = run_prepared_bounded_command(&mut invalid_limits, Duration::ZERO, 1).unwrap_err();
    assert_eq!(error.kind(), BoundedCommandErrorKind::InvalidResourceLimits);
    assert!(!marker.exists());

    let cancelled = AtomicBool::new(true);
    let mut cancelled_command = std::process::Command::new(&script);
    let error = run_prepared_bounded_command_with_cancellation(
        &mut cancelled_command,
        Duration::from_secs(1),
        1,
        &cancelled,
    )
    .unwrap_err();
    assert_eq!(error.kind(), BoundedCommandErrorKind::Cancelled);
    assert!(!marker.exists());
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
#[test]
fn cancellation_terminalizes_the_owned_process_group_before_returning() {
    let root = tempfile::tempdir().unwrap();
    let ready = root.path().join("ready");
    let release = root.path().join("release");
    let survived = root.path().join("survived");
    let descendant_pid = root.path().join("descendant-pid");
    let script = format!(
        "( trap '' HUP TERM; touch '{}'; while [ ! -e '{}' ]; do /bin/sleep 0.01; done; touch '{}' ) & \
         descendant=$!; printf '%s' \"$descendant\" > '{}'; \
         while [ ! -e '{}' ]; do /bin/sleep 0.01; done; wait",
        ready.display(),
        release.display(),
        survived.display(),
        descendant_pid.display(),
        ready.display(),
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let runner_cancelled = Arc::clone(&cancelled);
    let (sender, receiver) = mpsc::sync_channel(1);
    let runner = thread::spawn(move || {
        let arguments = [OsString::from("-c"), OsString::from(script)];
        let result = run_bounded_command_with_cancellation(
            &BoundedCommand {
                executable: Path::new("/bin/sh"),
                arguments: &arguments,
                environment: &BTreeMap::new(),
                cwd: None,
                timeout: Duration::from_secs(30),
                output_limit: 32,
            },
            &runner_cancelled,
        )
        .map(|_| ())
        .map_err(|error| error.kind());
        let _ = sender.send(result);
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !ready.exists() && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready.exists(),
        "child did not complete its readiness handshake"
    );
    cancelled.store(true, Ordering::Release);
    let result = receiver
        .recv_timeout(Duration::from_secs(3))
        .expect("cancelled runner did not return within its cleanup bound");
    runner.join().unwrap();

    fs::write(&release, b"release").unwrap();
    for _ in 0..50 {
        if survived.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let escaped = survived.exists();
    if escaped {
        let raw_pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if let Some(pid) = rustix::process::Pid::from_raw(raw_pid) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
    assert_eq!(result.unwrap_err(), BoundedCommandErrorKind::Cancelled);
    assert!(
        !escaped,
        "a descendant continued running after cancellation"
    );
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
#[test]
fn output_limit_is_enforced_while_child_and_descendant_are_still_running() {
    let root = tempfile::tempdir().unwrap();
    let ready = root.path().join("ready");
    let release = root.path().join("release");
    let survived = root.path().join("survived");
    let descendant_pid = root.path().join("descendant-pid");
    let script = format!(
        "( touch '{}'; while [ ! -e '{}' ]; do /bin/sleep 0.01; done; touch '{}' ) & \
         descendant=$!; printf '%s' \"$descendant\" > '{}'; \
         while [ ! -e '{}' ]; do /bin/sleep 0.01; done; printf xx; wait",
        ready.display(),
        release.display(),
        survived.display(),
        descendant_pid.display(),
        ready.display(),
    );
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let error = run_bounded_command(&BoundedCommand {
        executable: Path::new("/bin/sh"),
        arguments: &arguments,
        environment: &BTreeMap::new(),
        cwd: None,
        timeout: Duration::from_millis(400),
        output_limit: 1,
    })
    .unwrap_err();

    let error_kind = error.kind();

    // Releasing the descendant after the runner returns distinguishes a
    // terminalized process group from the old direct-child-only cleanup.
    fs::write(&release, b"release").unwrap();
    for _ in 0..50 {
        if survived.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let escaped = survived.exists();
    if escaped {
        let raw_pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if let Some(pid) = rustix::process::Pid::from_raw(raw_pid) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
    assert_eq!(
        error_kind,
        BoundedCommandErrorKind::OutputLimit(BoundedCommandStream::Stdout)
    );
    assert!(!escaped, "a descendant continued running after return");
}

#[test]
fn validation_failures_are_typed() {
    let error = run_bounded_command(&BoundedCommand {
        executable: Path::new("relative/tool"),
        arguments: &[],
        environment: &BTreeMap::new(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 1,
    })
    .unwrap_err();
    assert_eq!(error.kind(), BoundedCommandErrorKind::InvalidExecutable);
}

#[cfg(unix)]
#[test]
fn spawn_failures_preserve_the_typed_io_source() {
    let root = tempfile::tempdir().unwrap();
    let invalid = root.path().join("invalid-executable");
    fs::write(&invalid, b"not an executable image").unwrap();
    fs::set_permissions(&invalid, fs::Permissions::from_mode(0o755)).unwrap();

    let error = run_bounded_command(&BoundedCommand {
        executable: &invalid,
        arguments: &[],
        environment: &BTreeMap::new(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 1,
    })
    .unwrap_err();
    assert_eq!(error.kind(), BoundedCommandErrorKind::Start);
    assert!(error
        .io_error()
        .and_then(std::io::Error::raw_os_error)
        .is_some());
    assert!(error.cleanup_failures().is_empty());
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
#[test]
fn successful_leader_exit_still_terminalizes_its_process_group() {
    let root = tempfile::tempdir().unwrap();
    let ready = root.path().join("ready");
    let release = root.path().join("release");
    let survived = root.path().join("survived");
    let descendant_pid = root.path().join("descendant-pid");
    let script = format!(
        "( trap '' HUP TERM; touch '{}'; while [ ! -e '{}' ]; do /bin/sleep 0.01; done; touch '{}' ) \
         </dev/null >/dev/null 2>&1 & descendant=$!; printf '%s' \"$descendant\" > '{}'; \
         while [ ! -e '{}' ]; do /bin/sleep 0.01; done; exit 0",
        ready.display(),
        release.display(),
        survived.display(),
        descendant_pid.display(),
        ready.display(),
    );
    let arguments = [OsString::from("-c"), OsString::from(script)];
    let result = run_bounded_command(&BoundedCommand {
        executable: Path::new("/bin/sh"),
        arguments: &arguments,
        environment: &BTreeMap::new(),
        cwd: None,
        timeout: Duration::from_secs(1),
        output_limit: 32,
    });

    fs::write(&release, b"release").unwrap();
    for _ in 0..50 {
        if survived.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    let escaped = survived.exists();
    if escaped {
        let raw_pid = fs::read_to_string(descendant_pid)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if let Some(pid) = rustix::process::Pid::from_raw(raw_pid) {
            let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
        }
    }
    assert!(result.unwrap().status.success());
    assert!(!escaped, "a descendant continued running after return");
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_return_is_bounded_when_detached_descendant_holds_output_pipes() {
    let root = tempfile::tempdir().unwrap();
    let ready = root.path().join("ready");
    let escaped_pid = root.path().join("escaped-pid");
    let script = format!(
        "/usr/bin/setsid /bin/sh -c 'printf %s \"$$\" > \"$1\"; touch \"$2\"; \
         trap \"\" HUP TERM; while :; do /bin/sleep 1; done' sh '{}' '{}' & \
         while [ ! -e '{}' ]; do /bin/sleep 0.01; done; /bin/sleep 30",
        escaped_pid.display(),
        ready.display(),
        ready.display(),
    );
    let (sender, receiver) = mpsc::sync_channel(1);
    let runner = thread::spawn(move || {
        let arguments = [OsString::from("-c"), OsString::from(script)];
        let result = run_bounded_command(&BoundedCommand {
            executable: Path::new("/bin/sh"),
            arguments: &arguments,
            environment: &BTreeMap::new(),
            cwd: None,
            timeout: Duration::from_millis(200),
            output_limit: 32,
        })
        .map(|_| ())
        .map_err(|error| error.kind());
        let _ = sender.send(result);
    });

    let handshake_deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !ready.exists() && std::time::Instant::now() < handshake_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let ready_seen = ready.exists();
    let first_result = receiver.recv_timeout(Duration::from_secs(2));
    let returned_within_bound = first_result.is_ok();

    let raw_pid = fs::read_to_string(&escaped_pid)
        .ok()
        .and_then(|value| value.trim().parse().ok());
    if let Some(pid) = raw_pid.and_then(rustix::process::Pid::from_raw) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
    }

    let result = match first_result {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("runner remained blocked after escaped descendant cleanup"),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("runner result channel disconnected")
        }
    };
    runner.join().unwrap();

    assert!(
        ready_seen,
        "escaped descendant did not complete its handshake"
    );
    assert!(
        returned_within_bound,
        "runner exceeded its bounded return after the public timeout"
    );
    assert_eq!(result.unwrap_err(), BoundedCommandErrorKind::TimedOut);
}

#[cfg(unix)]
#[test]
fn executable_search_preserves_path_order_and_requires_execute_permission() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    fs::write(first.path().join("tool"), b"not executable").unwrap();
    executable(&second.path().join("tool"));
    let path = vec![first.path().to_path_buf(), second.path().to_path_buf()];

    assert_eq!(
        executable_candidates(&path, "tool"),
        vec![second.path().join("tool")]
    );
    assert_eq!(
        first_executable(&path, "tool"),
        Some(second.path().join("tool"))
    );
}

#[test]
fn same_location_accepts_equivalent_parent_paths_but_not_other_names() {
    let root = tempfile::tempdir().unwrap();
    let nested = root.path().join("nested");
    fs::create_dir(&nested).unwrap();
    assert!(same_path_location(
        &nested.join("../nested/tool"),
        &nested.join("tool")
    ));
    assert!(!same_path_location(
        &nested.join("tool"),
        &nested.join("other")
    ));
}

#[test]
fn path_prepend_is_platform_encoded_and_rejects_non_absolute_directory() {
    let inherited = std::env::join_paths([Path::new("/usr/bin"), Path::new("/bin")]).unwrap();
    let value = prepend_path(
        Path::new("/opt/dev-auth/session-bin"),
        Some(OsStr::new(&inherited)),
    )
    .unwrap();
    assert_eq!(
        std::env::split_paths(&value).collect::<Vec<PathBuf>>(),
        vec![
            PathBuf::from("/opt/dev-auth/session-bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin")
        ]
    );
    assert!(prepend_path(Path::new("relative/bin"), None).is_err());
}
