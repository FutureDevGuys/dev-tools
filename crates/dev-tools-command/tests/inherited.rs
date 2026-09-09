#![cfg(target_os = "linux")]
use dev_tools_command::run_prepared_inherited_command;
use std::fs::File;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

#[test]
fn inherited_execution_preserves_native_arguments_streams_and_status() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input");
    let output = directory.path().join("output");
    let error = directory.path().join("error");
    std::fs::write(&input, [0, 255, 10]).unwrap();
    let result = run_prepared_inherited_command(
        Command::new("/bin/sh")
            .args([
                "-c",
                "cat; printf '%s' \"$1\"; printf error >&2; exit 23",
                "fixture",
            ])
            .arg(std::ffi::OsString::from_vec(vec![254, b' ']))
            .stdin(Stdio::from(File::open(&input).unwrap()))
            .stdout(Stdio::from(File::create(&output).unwrap()))
            .stderr(Stdio::from(File::create(&error).unwrap())),
        || true,
    )
    .unwrap();
    assert_eq!(result.status.code(), Some(23));
    assert!(!result.cancelled);
    assert_eq!(std::fs::read(output).unwrap(), [0, 255, 10, 254, b' ']);
    assert_eq!(std::fs::read(error).unwrap(), b"error");
}

#[test]
fn inherited_execution_preserves_signal_termination_and_prestart_cancellation() {
    let result = run_prepared_inherited_command(
        Command::new("/bin/sh").args(["-c", "kill -TERM $$"]),
        || true,
    )
    .unwrap();
    assert_eq!(result.status.signal(), Some(15));
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    assert!(
        run_prepared_inherited_command(Command::new("/usr/bin/touch").arg(&marker), || false)
            .is_err()
    );
    assert!(!marker.exists());
}

#[test]
fn cancellation_waits_for_owned_child_terminal_status() {
    let mut calls = 0;
    let result = run_prepared_inherited_command(Command::new("/bin/sleep").arg("30"), || {
        calls += 1;
        calls < 3
    })
    .unwrap();
    assert!(result.cancelled);
    assert!(result.status.signal().is_some());
}

#[test]
fn inherited_tty_fixture() {
    if std::env::var_os("DEV_TOOLS_TEST_INHERITED_TTY").is_none() {
        return;
    }
    let result = run_prepared_inherited_command(
        Command::new("/bin/sh").args([
            "-c",
            "test -t 0 || exit 70; read answer; printf 'tty:%s\\n' \"$answer\"; kill -TERM $$",
        ]),
        || true,
    )
    .unwrap();
    assert_eq!(result.status.signal(), Some(15));
    println!("native-status:15");
}

#[test]
fn native_foreground_handoff_keeps_terminal_input_and_signal_status() {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: output descriptors are live integers; optional name, termios and
    // window-size pointers are null. Successful descriptors transfer to File.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
    // SAFETY: both descriptors were freshly returned by openpty and have exactly
    // one File owner. They are distinct ends of the retained private terminal.
    let (mut master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC).unwrap();
    rustix::io::fcntl_setfd(&slave, rustix::io::FdFlags::CLOEXEC).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "inherited_tty_fixture", "--nocapture"])
        .env("DEV_TOOLS_TEST_INHERITED_TTY", "1")
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()));
    // SAFETY: this child-only callback performs async-signal-safe session/terminal
    // syscalls using the already-prepared stdin descriptor; no Rust state escapes.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(slave);
    master.write_all(b"native-input\n").unwrap();
    // SAFETY: the master descriptor is retained, and fcntl flags are native
    // integer values. Nonblocking observation keeps the outer test bounded.
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
        0
    );
    let start = Instant::now();
    let mut output = Vec::new();
    loop {
        let mut bytes = [0u8; 4096];
        while let Ok(length) = master.read(&mut bytes) {
            if length == 0 {
                break;
            }
            output.extend_from_slice(&bytes[..length]);
            assert!(output.len() <= 64 * 1024);
        }
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "{}", String::from_utf8_lossy(&output));
            break;
        }
        if start.elapsed() > Duration::from_secs(10) {
            drop(master);
            let _ = child.kill();
            let _ = child.wait();
            panic!("native terminal fixture did not settle");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("tty:native-input"), "{output}");
    assert!(output.contains("native-status:15"), "{output}");
}
