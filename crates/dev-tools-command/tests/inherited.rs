//! Isolated single-threaded signal acceptance; no libtest worker exists here.
#[cfg(target_os = "linux")]
mod linux {
    use dev_tools_command::{run_prepared_inherited_command, HeldExecutable};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn child(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["child", mode]);
        command
    }

    fn mask() -> Vec<bool> {
        // SAFETY: the output object is initialized; null set queries this thread.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut set),
                0
            );
            [
                libc::SIGINT,
                libc::SIGTERM,
                libc::SIGQUIT,
                libc::SIGHUP,
                libc::SIGCHLD,
                libc::SIGTTOU,
            ]
            .map(|signal| libc::sigismember(&set, signal) == 1)
            .to_vec()
        }
    }

    fn fixture_root() -> std::path::PathBuf {
        std::env::var_os("INHERITED_FIXTURE_ROOT").unwrap().into()
    }
    fn disposition() -> (usize, i32) {
        let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current) },
            0
        );
        (
            current.sa_sigaction,
            current.sa_flags
                & (libc::SA_NOCLDWAIT
                    | libc::SA_NOCLDSTOP
                    | libc::SA_RESTART
                    | libc::SA_NODEFER
                    | libc::SA_SIGINFO),
        )
    }
    fn case(name: &str) {
        let before = mask();
        let disposition_before = disposition();
        match name {
            "exit" => {
                let output = run_prepared_inherited_command(child("exit"), || true).unwrap();
                assert_eq!(output.status.code(), Some(23));
                assert!(!output.cancelled);
            }
            "pipes" => {
                let mut command = child("sleep");
                command.stdout(std::process::Stdio::piped());
                let error = run_prepared_inherited_command(command, || true)
                    .err()
                    .unwrap();
                assert!(error
                    .to_string()
                    .contains("does not service caller-selected pipes"));
            }
            "io-context" => {
                let root = fixture_root();
                std::fs::write(root.join("input"), b"public fixture").unwrap();
                let mut command = child("context");
                command
                    .arg("space ✓")
                    .env("PUBLIC_TEST_VALUE", "one")
                    .current_dir(&root)
                    .stdin(std::fs::File::open(root.join("input")).unwrap())
                    .stdout(std::fs::File::create(root.join("output")).unwrap())
                    .stderr(std::process::Stdio::null());
                assert!(run_prepared_inherited_command(command, || true)
                    .unwrap()
                    .status
                    .success());
                assert_eq!(
                    std::fs::read(root.join("output")).unwrap(),
                    b"public fixture"
                );
            }
            "entry-mask" => {
                let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
                let mut previous: libc::sigset_t = unsafe { std::mem::zeroed() };
                unsafe {
                    libc::sigemptyset(&mut set);
                    libc::sigaddset(&mut set, libc::SIGUSR1);
                }
                assert_eq!(
                    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut previous) },
                    0
                );
                assert!(run_prepared_inherited_command(child("mask"), || true)
                    .unwrap()
                    .status
                    .success());
                let mut actual: libc::sigset_t = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe {
                        libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut actual)
                    },
                    0
                );
                assert_eq!(unsafe { libc::sigismember(&actual, libc::SIGUSR1) }, 1);
                assert_eq!(
                    unsafe {
                        libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut())
                    },
                    0
                );
            }
            "held-validation" => {
                use dev_tools_command::HeldComponentKind;
                use std::os::fd::AsFd;
                let path = std::env::current_exe().unwrap().canonicalize().unwrap();
                let mut roles = Vec::new();
                let held = HeldExecutable::open_with_validation(&path, |fd, role| {
                    let stat = rustix::fs::fstat(fd)?;
                    assert!(stat.st_ino > 0);
                    roles.push(role);
                    Ok(())
                })
                .unwrap();
                assert_eq!(roles.last(), Some(&HeldComponentKind::Executable));
                assert_eq!(
                    roles
                        .iter()
                        .filter(|role| **role == HeldComponentKind::Executable)
                        .count(),
                    1
                );
                assert!(roles.len() > 1);
                assert!(rustix::fs::fstat(held.as_fd()).is_ok());
                assert!(
                    HeldExecutable::open_with_validation(&path, |_, _| anyhow::bail!(
                        "fixture policy denial"
                    ))
                    .is_err()
                );
                let link = fixture_root().join("linked-executable");
                std::os::unix::fs::symlink(path, &link).unwrap();
                assert!(HeldExecutable::open_with_validation(&link, |_, _| Ok(())).is_err());
            }
            "held" => {
                let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
                let held = HeldExecutable::open(&executable).unwrap();
                let mut command = held
                    .command(std::ffi::OsStr::new("inherited-fixture"))
                    .unwrap();
                command.args(["child", "exit"]);
                let output = run_prepared_inherited_command(command, || true).unwrap();
                assert_eq!(output.status.code(), Some(23));
            }
            "terminal" | "jobcontrol" => {
                // SAFETY: query only this fixture's inherited terminal descriptor.
                let original = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
                assert!(original > 0);
                let output = run_prepared_inherited_command(
                    child(if name == "terminal" {
                        "terminal"
                    } else {
                        "stop"
                    }),
                    {
                        let mut calls = 0;
                        move || {
                            calls += 1;
                            if calls >= 2 {
                                std::fs::write(fixture_root().join("admitted"), b"1").unwrap();
                            }
                            true
                        }
                    },
                )
                .unwrap();
                assert_eq!(output.status.code(), Some(23));
                assert_eq!(unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) }, original);
            }
            "descendants" | "unreaped" => {
                let result = run_prepared_inherited_command(child("descendants"), || true);
                if name == "descendants" {
                    assert_eq!(result.unwrap().status.code(), Some(23));
                } else {
                    let error = result
                        .err()
                        .expect("unreaped descendants must fail cleanup");
                    let error = error
                        .downcast_ref::<dev_tools_command::BoundedCommandError>()
                        .unwrap();
                    assert!(error.cleanup_failures().iter().any(|f| f.operation()
                        == dev_tools_command::BoundedCommandCleanupOperation::TerminateDomain));
                }
            }
            "ignore-child" | "no-child-wait" => {
                // SAFETY: this isolated worker installs/restores only its own disposition.
                let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
                let mut changed: libc::sigaction = unsafe { std::mem::zeroed() };
                changed.sa_sigaction = if name == "ignore-child" {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                };
                changed.sa_flags = if name == "no-child-wait" {
                    libc::SA_NOCLDWAIT
                } else {
                    0
                };
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, &changed, &mut previous) },
                    0
                );
                let error = run_prepared_inherited_command(
                    Command::new("/absent-inherited-fixture"),
                    || true,
                )
                .err()
                .unwrap();
                assert!(error.to_string().contains("automatic child reaping"));
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, &previous, std::ptr::null_mut()) },
                    0
                );
            }
            "precancel" => {
                assert!(run_prepared_inherited_command(child("exit"), || false).is_err());
                assert!(!fixture_root().join("spawned").exists());
            }
            "spawnfailure" => {
                assert!(run_prepared_inherited_command(
                    Command::new("/absent-inherited-fixture"),
                    || true
                )
                .is_err());
            }
            "resistant-cancel" => {
                let start = Instant::now();
                let output = run_prepared_inherited_command(child("resistant"), || {
                    !fixture_root().join("resistant-ready").exists()
                        && start.elapsed() < Duration::from_secs(2)
                })
                .unwrap();
                assert!(fixture_root().join("resistant-ready").exists());
                assert!(output.cancelled);
                assert_eq!(output.status.signal(), Some(libc::SIGKILL));
                assert!(start.elapsed() < Duration::from_secs(3));
            }
            "cancel" => {
                let start = Instant::now();
                let output = run_prepared_inherited_command(child("sleep"), || {
                    start.elapsed() < Duration::from_millis(100)
                })
                .unwrap();
                assert!(output.cancelled);
                assert!(start.elapsed() < Duration::from_secs(3));
            }
            "panic" => {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_prepared_inherited_command(child("sleep"), || {
                        assert!(
                            !fixture_root().join("spawned").exists(),
                            "intentional callback panic fixture"
                        );
                        true
                    })
                }));
                assert!(result.is_err());
                let pid: i32 = std::fs::read_to_string(fixture_root().join("spawned"))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH)
                );
            }
            value if value.starts_with("signal-") => {
                let signal: i32 = value[7..].parse().unwrap();
                let start = Instant::now();
                let mut sent = false;
                let output = run_prepared_inherited_command(child("sleep"), || {
                    if !sent && start.elapsed() > Duration::from_millis(100) {
                        // SAFETY: target is this fixture's own process and a fixed signal.
                        assert_eq!(unsafe { libc::kill(libc::getpid(), signal) }, 0);
                        sent = true;
                    }
                    start.elapsed() < Duration::from_secs(3)
                })
                .unwrap();
                assert!(sent);
                assert_eq!(output.status.signal(), Some(signal));
                assert!(!output.cancelled);
            }
            _ => panic!("unknown fixture"),
        }
        assert_eq!(mask(), before, "calling thread mask must be restored");
        assert_eq!(
            disposition(),
            disposition_before,
            "global SIGCHLD disposition must remain unchanged"
        );
    }

    pub fn run() {
        let args: Vec<_> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("child") {
            // Atomic helper receipt; it proves actual child execution for admission tests.
            let root = fixture_root();
            if !root.join("spawned").exists() {
                let prepared = root.join(format!("spawned-{}", std::process::id()));
                std::fs::write(&prepared, std::process::id().to_string()).unwrap();
                std::fs::rename(prepared, root.join("spawned")).unwrap();
            }
            if args.get(2).map(String::as_str) == Some("exit") {
                std::process::exit(23);
            }
            match args.get(2).map(String::as_str) {
                Some("resistant") => {
                    unsafe {
                        libc::signal(libc::SIGTERM, libc::SIG_IGN);
                    }
                    std::fs::write(root.join("resistant-ready"), b"1").unwrap();
                    std::thread::sleep(Duration::from_secs(10));
                }
                Some("context") => {
                    use std::io::{Read, Write};
                    assert_eq!(std::env::current_dir().unwrap(), root);
                    assert_eq!(std::env::var("PUBLIC_TEST_VALUE").unwrap(), "one");
                    assert_eq!(args[3], "space ✓");
                    let mut bytes = Vec::new();
                    std::io::stdin().take(32).read_to_end(&mut bytes).unwrap();
                    assert_eq!(bytes, b"public fixture");
                    std::io::stdout().write_all(&bytes).unwrap();
                }
                Some("mask") => {
                    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
                    assert_eq!(
                        unsafe {
                            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut set)
                        },
                        0
                    );
                    assert_eq!(unsafe { libc::sigismember(&set, libc::SIGUSR1) }, 1);
                }
                Some("stop") => {
                    let start = Instant::now();
                    while !fixture_root().join("admitted").exists() {
                        assert!(start.elapsed() < Duration::from_secs(2));
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    unsafe {
                        libc::raise(libc::SIGSTOP);
                    }
                    std::process::exit(23);
                }
                Some("terminal") => {
                    let start = Instant::now();
                    while unsafe { libc::tcgetpgrp(0) != libc::getpgrp() } {
                        assert!(start.elapsed() < Duration::from_secs(2));
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    std::process::exit(23);
                }
                Some("descendants") => {
                    let _descendant = child("sleep").spawn().unwrap();
                    std::process::exit(23);
                }
                _ => std::thread::sleep(Duration::from_secs(10)),
            }
            return;
        }
        if args.get(1).map(String::as_str) == Some("case") {
            case(&args[2]);
            return;
        }
        // SAFETY: this isolated fixture driver adopts only its own descendants.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let _cleanup = DriverCleanup;
        for name in [
            "exit",
            "held",
            "precancel",
            "spawnfailure",
            "cancel",
            "panic",
            "signal-2",
            "signal-15",
            "signal-3",
            "signal-1",
            "terminal",
            "jobcontrol",
            "descendants",
            "unreaped",
            "ignore-child",
            "no-child-wait",
            "pipes",
            "io-context",
            "entry-mask",
            "resistant-cancel",
            "held-validation",
        ] {
            let root = tempfile::tempdir().unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["case", name])
                .env("INHERITED_FIXTURE_ROOT", root.path());
            let mut terminal = None;
            if matches!(name, "terminal" | "jobcontrol") {
                use std::os::fd::{AsRawFd, FromRawFd};
                let (mut master, mut slave) = (-1, -1);
                // SAFETY: fresh descriptor outputs; default termios/window size.
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
                let master = unsafe { std::fs::File::from_raw_fd(master) };
                let slave = unsafe { std::fs::File::from_raw_fd(slave) };
                let fd = slave.as_raw_fd();
                command
                    .stdin(slave.try_clone().unwrap())
                    .stdout(slave.try_clone().unwrap())
                    .stderr(slave.try_clone().unwrap());
                // SAFETY: child-only session/terminal syscalls; descriptor remains held through spawn.
                unsafe {
                    command.pre_exec(move || {
                        if libc::setsid() < 0 || libc::ioctl(fd, libc::TIOCSCTTY, 0) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                terminal = Some((master, slave));
            } else {
                command.process_group(0);
            }
            let mut process = command.spawn().unwrap();
            let start = Instant::now();
            let mut resumed = false;
            loop {
                // Reap adopted descendants, but preserve the case worker's status.
                if name != "unreaped" {
                    reap_adopted(process.id() as i32);
                }
                if let Some(status) = process.try_wait().unwrap() {
                    assert!(status.success(), "{name}: {status}");
                    break;
                }
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe {
                        libc::waitid(
                            libc::P_PID,
                            process.id(),
                            &mut info,
                            libc::WSTOPPED | libc::WNOHANG,
                        )
                    },
                    0
                );
                if unsafe { info.si_pid() } != 0 {
                    assert_eq!(name, "jobcontrol");
                    assert_eq!(unsafe { libc::kill(process.id() as i32, libc::SIGCONT) }, 0);
                    resumed = true;
                }
                if start.elapsed() > Duration::from_secs(8) {
                    cleanup_children();
                    panic!("{name}: fixture watchdog expired");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            if name == "jobcontrol" {
                assert!(resumed);
            }
            reap_adopted(-1);
            drop(terminal);
            println!("passed {name}");
        }
    }

    struct DriverCleanup;
    impl Drop for DriverCleanup {
        fn drop(&mut self) {
            cleanup_children();
        }
    }

    fn cleanup_children() {
        let start = Instant::now();
        let pid = std::process::id();
        let path = format!("/proc/{pid}/task/{pid}/children");
        while start.elapsed() < Duration::from_secs(2) {
            let children = std::fs::read_to_string(&path).unwrap_or_default();
            if children.trim().is_empty() {
                return;
            }
            for child in children
                .split_whitespace()
                .filter_map(|s| s.parse::<i32>().ok())
            {
                // The single-threaded driver owns all reaping. Keep each direct
                // child's identity waitable while signalling only that child.
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                if unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child as u32,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                } == 0
                {
                    unsafe {
                        libc::kill(child, libc::SIGKILL);
                    }
                    if unsafe { info.si_pid() } != 0 {
                        unsafe {
                            libc::waitpid(child, std::ptr::null_mut(), 0);
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn reap_adopted(leader: i32) {
        loop {
            // SAFETY: non-reaping observation of this fixture driver's children.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return;
            }
            let pid = unsafe { info.si_pid() };
            if pid <= 0 || pid == leader {
                return;
            }
            assert_eq!(unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) }, pid);
        }
    }
}
fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}
