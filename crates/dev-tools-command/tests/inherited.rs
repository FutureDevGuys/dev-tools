//! Isolated single-threaded signal acceptance; no libtest worker exists here.
#[cfg(target_os = "linux")]
mod linux {
    use dev_tools_command::{
        run_prepared_inherited_command, run_prepared_inherited_command_after_spawn, HeldExecutable,
    };
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
                libc::SIGTSTP,
                libc::SIGCONT,
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
    fn graph_node<'a>(
        command: impl Into<dev_tools_command::OwnedPreparedCommand<'a>>,
        after: Vec<usize>,
        pipe_from: Option<usize>,
    ) -> dev_tools_command::CommandGraphNode<'a> {
        dev_tools_command::CommandGraphNode {
            command: command.into(),
            dependencies: dev_tools_command::GraphDependencies { after, pipe_from },
        }
    }

    fn graph_run(
        nodes: Vec<dev_tools_command::CommandGraphNode<'_>>,
        policy: dev_tools_command::GraphExitPolicy,
        keep_running: impl FnMut() -> bool,
    ) -> anyhow::Result<dev_tools_command::CommandGraphOutput> {
        dev_tools_command::run_prepared_terminal_command_graph(
            nodes,
            policy,
            dev_tools_command::TerminalGraphSignalMask::RestoreEntry,
            keep_running,
        )
    }

    fn assert_gone(path: &std::path::Path) {
        let pid: i32 = std::fs::read_to_string(path).unwrap().parse().unwrap();
        // The fixture has a completed owned-child reap. Signal zero only observes;
        // it cannot affect a reused process identity.
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    fn terminal_attributes() -> libc::termios {
        let mut attributes = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(0, &mut attributes) }, 0);
        attributes
    }

    fn foreground_custody_case(name: &str) {
        use dev_tools_command::ForegroundTerminal;
        if name == "foreground-no-tty" {
            assert!(ForegroundTerminal::open().unwrap().is_none());
            return;
        }
        if name == "foreground-background-refuse" {
            assert!(ForegroundTerminal::open().is_err());
            return;
        }
        if name == "foreground-background" {
            assert!(Command::new(std::env::current_exe().unwrap())
                .args(["case", "foreground-background-refuse"])
                .process_group(0)
                .status()
                .unwrap()
                .success());
            return;
        }
        let original = unsafe { libc::tcgetpgrp(0) };
        let attributes = terminal_attributes();
        let mut terminal = ForegroundTerminal::open().unwrap().unwrap();
        assert!(mask()[5], "handoff thread blocks SIGTTOU");
        let mut command = child("foreground-probe");
        terminal.prepare_child(&mut command);
        if name == "foreground-spawn-failure" {
            let mut missing = Command::new(fixture_root().join("absent-foreground-command"));
            terminal.prepare_child(&mut missing);
            assert!(missing.spawn().is_err());
            terminal.restore().unwrap();
        } else {
            let mut child = command.spawn().unwrap();
            terminal.give_to(&child).unwrap();
            assert_eq!(
                unsafe { libc::kill(-(child.id() as i32), libc::SIGCONT) },
                0
            );
            assert_eq!(child.wait().unwrap().code(), Some(23));
            if name == "foreground-explicit" {
                terminal.restore().unwrap();
            } else if name == "foreground-panic" {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _terminal = terminal;
                    panic!("intentional foreground custody panic");
                }));
                assert!(result.is_err());
            } else {
                drop(terminal);
            }
        }
        assert_eq!(unsafe { libc::tcgetpgrp(0) }, original);
        assert_eq!(terminal_attributes().c_lflag, attributes.c_lflag);
    }

    fn terminal_graph_case(name: &str) {
        use dev_tools_command::{
            CommandGraphNode, GraphDependencies, GraphExitPolicy, TerminalGraphSignalMask,
        };
        let original = if name != "terminal-graph-no-tty" {
            unsafe { libc::tcgetpgrp(0) }
        } else {
            -1
        };
        match name {
            "terminal-graph-pipe" => {
                let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
                let held = HeldExecutable::open(&executable).unwrap();
                for policy in [
                    GraphExitPolicy::Last,
                    GraphExitPolicy::All,
                    GraphExitPolicy::Pipefail,
                ] {
                    for file in [
                        "graph-producer-done",
                        "graph-consumer-done",
                        "graph-dependent-done",
                    ] {
                        let _ = std::fs::remove_file(fixture_root().join(file));
                    }
                    let mut producer = held
                        .command(std::ffi::OsStr::new("terminal-graph-fixture"))
                        .unwrap();
                    producer.args(["child", "graph-producer"]);
                    let output = graph_run(
                        vec![
                            CommandGraphNode {
                                command: producer.into(),
                                dependencies: GraphDependencies::default(),
                            },
                            graph_node(child("graph-consumer"), vec![], Some(0)),
                            graph_node(child("graph-dependent"), vec![0], None),
                        ],
                        policy,
                        || true,
                    )
                    .unwrap();
                    assert_eq!(
                        output
                            .statuses
                            .iter()
                            .map(|status| status.code())
                            .collect::<Vec<_>>(),
                        vec![Some(7), Some(23), Some(0)]
                    );
                    assert_eq!(
                        output.status.code(),
                        Some(match policy {
                            GraphExitPolicy::Last => 0,
                            GraphExitPolicy::All => 7,
                            GraphExitPolicy::Pipefail => 23,
                        })
                    );
                    let producer_group =
                        std::fs::read_to_string(fixture_root().join("graph-producer-group"))
                            .unwrap();
                    let consumer_group =
                        std::fs::read_to_string(fixture_root().join("graph-consumer-group"))
                            .unwrap();
                    assert_eq!(
                        producer_group, consumer_group,
                        "one foreground group per pipe component"
                    );
                    assert_eq!(
                        std::fs::read(fixture_root().join("graph-binary")).unwrap(),
                        b"\0\xffnative\0pipe"
                    );
                    assert!(fixture_root().join("graph-dependent-done").exists());
                }
            }
            "terminal-graph-jobcontrol" | "terminal-graph-stop-expiry" => {
                let result = graph_run(
                    vec![
                        graph_node(child("graph-stop-producer"), vec![], None),
                        graph_node(child("graph-stop-consumer"), vec![], Some(0)),
                    ],
                    GraphExitPolicy::All,
                    || !fixture_root().join("expired").exists(),
                );
                if name == "terminal-graph-jobcontrol" {
                    assert!(result.unwrap().status.success());
                    assert!(fixture_root().join("graph-resumed").exists());
                } else {
                    assert!(result.is_err());
                    assert!(
                        !fixture_root().join("graph-resumed").exists(),
                        "expired stopped payload must never continue"
                    );
                }
                assert_gone(&fixture_root().join("graph-stop-producer-pid"));
                // The consumer may have been stopped before its first instruction;
                // when present, its receipt also binds native child cleanup.
                let consumer = fixture_root().join("graph-stop-consumer-pid");
                if consumer.exists() {
                    assert_gone(&consumer);
                }
            }
            "terminal-graph-interrupt" => {
                let output = graph_run(
                    vec![graph_node(child("graph-interrupt"), vec![], None)],
                    GraphExitPolicy::Last,
                    || true,
                )
                .unwrap();
                assert_eq!(output.status.signal(), Some(libc::SIGINT));
                assert_gone(&fixture_root().join("graph-interrupt-pid"));
            }
            "terminal-graph-partial" => {
                let mut absent = Command::new(fixture_root().join("absent-terminal-node"));
                // Read the producer's byte before attempting the absent exec.
                // This kernel pipe handshake proves actual producer admission;
                // the fixture driver supplies the independent bounded watchdog.
                unsafe {
                    absent.pre_exec(|| {
                        let mut byte = 0u8;
                        loop {
                            let read = libc::read(0, (&mut byte as *mut u8).cast(), 1);
                            if read == 1 {
                                return Ok(());
                            }
                            if read < 0
                                && std::io::Error::last_os_error().kind()
                                    == std::io::ErrorKind::Interrupted
                            {
                                continue;
                            }
                            return Err(std::io::Error::other("fixture producer handshake absent"));
                        }
                    });
                }
                assert!(graph_run(
                    vec![
                        graph_node(child("graph-partial-producer"), vec![], None),
                        graph_node(absent, vec![], Some(0))
                    ],
                    GraphExitPolicy::All,
                    || true
                )
                .is_err());
                assert_gone(&fixture_root().join("graph-partial-producer-pid"));
            }
            "terminal-graph-cancel" => {
                assert!(graph_run(
                    vec![graph_node(child("graph-cancel"), vec![], None)],
                    GraphExitPolicy::Last,
                    || !fixture_root().join("graph-cancel-ready").exists()
                )
                .is_err());
                assert_gone(&fixture_root().join("graph-cancel-pid"));
            }
            "terminal-graph-mask" => {
                let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
                let mut payload: libc::sigset_t = unsafe { std::mem::zeroed() };
                unsafe {
                    libc::sigemptyset(&mut blocked);
                    libc::sigaddset(&mut blocked, libc::SIGTERM);
                }
                assert_eq!(
                    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut payload) },
                    0
                );
                let mut command = child("graph-mask");
                // The caller's already-prepared payload mask must survive the
                // graph worker's intentionally blocked transport/helper mask.
                unsafe {
                    command.pre_exec(move || {
                        if libc::sigprocmask(libc::SIG_SETMASK, &payload, std::ptr::null_mut()) == 0
                        {
                            Ok(())
                        } else {
                            Err(std::io::Error::last_os_error())
                        }
                    });
                }
                let result = dev_tools_command::run_prepared_terminal_command_graph(
                    vec![graph_node(command, vec![], None)],
                    GraphExitPolicy::Last,
                    TerminalGraphSignalMask::PreservePrepared,
                    || true,
                );
                assert_eq!(
                    unsafe {
                        libc::pthread_sigmask(libc::SIG_SETMASK, &payload, std::ptr::null_mut())
                    },
                    0
                );
                assert_eq!(result.unwrap().status.code(), Some(23));
            }
            "terminal-graph-no-tty" => {
                assert!(graph_run(
                    vec![graph_node(child("exit"), vec![], None)],
                    GraphExitPolicy::Last,
                    || true
                )
                .is_err());
                assert!(!fixture_root().join("spawned").exists());
            }
            "terminal-graph-background" => {
                let status = Command::new(std::env::current_exe().unwrap())
                    .args(["case", "terminal-graph-background-refuse"])
                    .process_group(0)
                    .status()
                    .unwrap();
                assert!(status.success());
                assert!(!fixture_root().join("spawned").exists());
            }
            "terminal-graph-background-refuse" => {
                assert!(original > 0);
                assert_ne!(original, unsafe { libc::getpgrp() });
                assert!(graph_run(
                    vec![graph_node(child("exit"), vec![], None)],
                    GraphExitPolicy::Last,
                    || true
                )
                .is_err());
                assert!(!fixture_root().join("spawned").exists());
            }
            _ => panic!("unknown terminal graph case"),
        }
        if original > 0 {
            assert_eq!(
                unsafe { libc::tcgetpgrp(0) },
                original,
                "terminal foreground restored"
            );
        }
    }

    fn terminal_graph_child(mode: &str) -> bool {
        use std::io::{Read, Write};
        let root = fixture_root();
        if !mode.starts_with("graph-") {
            return false;
        }
        std::fs::write(
            root.join(format!("{mode}-pid")),
            std::process::id().to_string(),
        )
        .unwrap();
        let terminal_ready = || {
            // A real native read cannot complete in a background terminal group;
            // SIGTTIN/foreground continuation, not elapsed time, proves admission.
            std::io::stdin().read_exact(&mut [0u8]).unwrap();
            assert_eq!(unsafe { libc::tcgetpgrp(0) }, unsafe { libc::getpgrp() });
        };
        let group_receipt = |name: &str| {
            std::fs::write(root.join(name), unsafe { libc::getpgrp() }.to_string()).unwrap();
        };
        match mode {
            "graph-producer" => {
                terminal_ready();
                group_receipt("graph-producer-group");
                std::io::stdout().write_all(b"\0\xffnative\0pipe").unwrap();
                std::io::stdout().flush().unwrap();
                std::fs::write(root.join("graph-producer-done"), b"1").unwrap();
                std::process::exit(7);
            }
            "graph-consumer" => {
                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes).unwrap();
                let tty = std::fs::File::open("/dev/tty").unwrap();
                use std::os::fd::AsRawFd;
                assert_eq!(unsafe { libc::tcgetpgrp(tty.as_raw_fd()) }, unsafe {
                    libc::getpgrp()
                });
                group_receipt("graph-consumer-group");
                std::fs::write(root.join("graph-binary"), bytes).unwrap();
                std::fs::write(root.join("graph-consumer-done"), b"1").unwrap();
                std::process::exit(23);
            }
            "graph-dependent" => {
                assert!(root.join("graph-producer-done").exists());
                assert!(root.join("graph-consumer-done").exists());
                std::fs::write(root.join("graph-dependent-done"), b"1").unwrap();
            }
            "graph-stop-producer" => {
                terminal_ready();
                std::io::stdout().write_all(b"1").unwrap();
                std::io::stdout().flush().unwrap();
                assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
                assert_eq!(unsafe { libc::tcgetpgrp(0) }, unsafe { libc::getpgrp() });
                std::fs::write(root.join("graph-resumed"), b"1").unwrap();
            }
            "graph-stop-consumer" => {
                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"1");
            }
            "graph-interrupt" => {
                terminal_ready();
                std::fs::write(root.join("graph-terminal-ready"), b"1").unwrap();
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }
            "graph-partial-producer" => {
                std::io::stdout().write_all(b"1").unwrap();
                std::io::stdout().flush().unwrap();
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }
            "graph-cancel" => {
                std::fs::write(root.join("graph-cancel-ready"), b"1").unwrap();
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }
            "graph-mask" => {
                let mut current: libc::sigset_t = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe {
                        libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut current)
                    },
                    0
                );
                assert_eq!(unsafe { libc::sigismember(&current, libc::SIGTERM) }, 0);
                std::process::exit(23);
            }
            _ => panic!("unknown terminal graph child"),
        }
        true
    }

    fn case(name: &str) {
        let before = mask();
        let disposition_before = disposition();
        match name {
            "startup-observer-failure" => {
                let started = Instant::now();
                let calls = std::cell::Cell::new(0);
                let result = run_prepared_inherited_command_after_spawn(
                    child("sleep"),
                    |_| {
                        calls.set(calls.get() + 1);
                        Err(anyhow::anyhow!("fixture startup observation rejected"))
                    },
                    || true,
                );
                assert_eq!(calls.get(), 1);
                assert!(result
                    .err()
                    .expect("startup observation rejection must fail")
                    .to_string()
                    .contains("fixture startup observation rejected"));
                assert!(started.elapsed() < Duration::from_secs(5));
            }
            "failed-spawn-no-observer" => {
                let calls = std::cell::Cell::new(0);
                let result = run_prepared_inherited_command_after_spawn(
                    Command::new(fixture_root().join("absent-native-command")),
                    |_| {
                        calls.set(calls.get() + 1);
                        Ok(())
                    },
                    || true,
                );
                assert!(result.is_err());
                assert_eq!(calls.get(), 0);
            }
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
                let graph_error = graph_run(
                    vec![graph_node(
                        Command::new("/absent-inherited-fixture"),
                        vec![],
                        None,
                    )],
                    dev_tools_command::GraphExitPolicy::Last,
                    || true,
                )
                .err()
                .expect("terminal graph must reject automatic reaping before tty/spawn");
                assert!(graph_error.to_string().contains("automatic child reaping"));
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, &previous, std::ptr::null_mut()) },
                    0
                );
            }
            "precancel" => {
                assert!(run_prepared_inherited_command(child("exit"), || false).is_err());
                assert!(graph_run(
                    vec![graph_node(child("exit"), vec![], None)],
                    dev_tools_command::GraphExitPolicy::Last,
                    || false
                )
                .is_err());
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
                let needs_ready_receipt = signal == libc::SIGQUIT;
                let helper = if needs_ready_receipt {
                    "signal-without-core"
                } else {
                    "sleep"
                };
                let output = run_prepared_inherited_command(child(helper), || {
                    if !sent
                        && start.elapsed() > Duration::from_millis(100)
                        && (!needs_ready_receipt || fixture_root().join("spawned").exists())
                    {
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
            value if value.starts_with("terminal-graph-") => terminal_graph_case(value),
            value if value.starts_with("foreground-") => foreground_custody_case(value),
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
            if args.get(2).map(String::as_str) == Some("foreground-probe") {
                use std::io::Read;
                assert!(
                    !mask()[5],
                    "payload must not inherit the guard's SIGTTOU block"
                );
                let mut tty = std::fs::File::open("/dev/tty").unwrap();
                tty.read_exact(&mut [0u8]).unwrap();
                assert_eq!(unsafe { libc::tcgetpgrp(0) }, unsafe { libc::getpgrp() });
                let mut attributes = terminal_attributes();
                attributes.c_lflag ^= libc::ECHO;
                assert_eq!(unsafe { libc::tcsetattr(0, libc::TCSANOW, &attributes) }, 0);
                std::process::exit(23);
            }
            if args.get(2).map(String::as_str) == Some("signal-without-core") {
                // Only this synthetic helper opts out of host core collection.
                // Its ready receipt follows the kernel-confirmed setting, so the
                // SIGQUIT case still tests real signal termination without racing
                // an unrelated core collector against its unchanged deadline.
                use rustix::process::{dumpable_behavior, set_dumpable_behavior, DumpableBehavior};
                set_dumpable_behavior(DumpableBehavior::NotDumpable).unwrap();
                assert_eq!(dumpable_behavior().unwrap(), DumpableBehavior::NotDumpable);
            }
            // Atomic helper receipt; it proves actual child execution for admission tests.
            let root = fixture_root();
            if !root.join("spawned").exists() {
                let prepared = root.join(format!("spawned-{}", std::process::id()));
                std::fs::write(&prepared, std::process::id().to_string()).unwrap();
                std::fs::rename(prepared, root.join("spawned")).unwrap();
            }
            if terminal_graph_child(args.get(2).map(String::as_str).unwrap_or("")) {
                return;
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
        const FIXTURES: &[&str] = &[
            "foreground-explicit",
            "foreground-drop",
            "foreground-panic",
            "foreground-spawn-failure",
            "foreground-background",
            "foreground-no-tty",
            "startup-observer-failure",
            "failed-spawn-no-observer",
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
            "terminal-graph-pipe",
            "terminal-graph-jobcontrol",
            "terminal-graph-stop-expiry",
            "terminal-graph-interrupt",
            "terminal-graph-partial",
            "terminal-graph-cancel",
            "terminal-graph-mask",
            "terminal-graph-no-tty",
            "terminal-graph-background",
        ];
        // Select the outer driver, retaining its native PTY/session setup,
        // ownership, stop observation and finite watchdog. Internal case/child
        // dispatch above remains private to that driver and unchanged.
        let selected = match args.as_slice() {
            [_] => FIXTURES.to_vec(),
            [_, selector, name] if selector == "--fixture" && FIXTURES.contains(&name.as_str()) => {
                vec![name.as_str()]
            }
            _ => {
                eprintln!("expected --fixture and one declared inherited fixture name");
                std::process::exit(2);
            }
        };
        // SAFETY: this isolated fixture driver adopts only its own descendants.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        let _cleanup = DriverCleanup;
        for name in selected {
            // Fresh private tempfile authority is the existing driver contract.
            // A caller-supplied fixture-root is never adopted by this driver;
            // root may select its parent through the existing TMPDIR facility.
            let root = tempfile::tempdir().unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["case", name])
                .env("INHERITED_FIXTURE_ROOT", root.path());
            let mut terminal = None;
            if matches!(name, "terminal" | "jobcontrol")
                || (name.starts_with("terminal-graph-") && name != "terminal-graph-no-tty")
                || (name.starts_with("foreground-") && name != "foreground-no-tty")
            {
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
            } else if matches!(name, "terminal-graph-no-tty" | "foreground-no-tty") {
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() < 0 {
                            Err(std::io::Error::last_os_error())
                        } else {
                            Ok(())
                        }
                    });
                }
                command.stdin(std::process::Stdio::null());
            } else {
                command.process_group(0);
            }
            let mut process = command.spawn().unwrap();
            if matches!(
                name,
                "foreground-explicit"
                    | "foreground-drop"
                    | "foreground-panic"
                    | "terminal-graph-pipe"
                    | "terminal-graph-jobcontrol"
                    | "terminal-graph-stop-expiry"
                    | "terminal-graph-interrupt"
            ) {
                use std::io::Write;
                terminal
                    .as_mut()
                    .unwrap()
                    .0
                    .write_all(b"x\nx\nx\n")
                    .unwrap();
            }
            let start = Instant::now();
            let mut resumed = false;
            let mut interrupt_sent = false;
            loop {
                if name == "terminal-graph-interrupt"
                    && !interrupt_sent
                    && root.path().join("graph-terminal-ready").exists()
                {
                    use std::io::Write;
                    terminal.as_mut().unwrap().0.write_all(&[3]).unwrap();
                    interrupt_sent = true;
                }
                // Reap adopted descendants, but preserve the case worker's status.
                if name != "unreaped" {
                    reap_adopted(process.id() as i32);
                }
                if let Some(status) = process.try_wait().unwrap() {
                    assert!(status.success(), "{name}: {status}");
                    break;
                }
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // SAFETY: initialized output for this driver's exclusively
                // owned, unreaped direct case child; the stop query cannot reap
                // an exit between try_wait and this observation.
                let observed = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        process.id(),
                        &mut info,
                        libc::WSTOPPED | libc::WNOHANG,
                    )
                };
                if observed != 0 {
                    let error = std::io::Error::last_os_error();
                    assert_eq!(
                        error.raw_os_error(),
                        Some(libc::ECHILD),
                        "observe owned fixture stop: {error}"
                    );
                    let mut exited: libc::siginfo_t = unsafe { std::mem::zeroed() };
                    // SAFETY: same retained child; WNOWAIT preserves the exact
                    // exit/PID so the next try_wait owns its normal status/reap.
                    assert_eq!(
                        unsafe {
                            libc::waitid(
                                libc::P_PID,
                                process.id(),
                                &mut exited,
                                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                            )
                        },
                        0,
                        "fixture exit wait custody must remain owned"
                    );
                    assert_eq!(unsafe { exited.si_pid() }, process.id() as i32);
                    assert!(matches!(
                        exited.si_code,
                        libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                    ));
                    continue;
                }
                if unsafe { info.si_pid() } != 0 {
                    assert!(matches!(
                        name,
                        "jobcontrol" | "terminal-graph-jobcontrol" | "terminal-graph-stop-expiry"
                    ));
                    if name.starts_with("terminal-graph-") {
                        use std::os::fd::AsRawFd;
                        // The driver is outside the case's controlling session.
                        // Linux permits foreground observation through our owned
                        // PTY master; querying its slave here fails with ENOTTY.
                        // SAFETY: the driver retains this live PTY master until
                        // the exclusively owned, unreaped case child settles.
                        let foreground =
                            unsafe { libc::tcgetpgrp(terminal.as_ref().unwrap().0.as_raw_fd()) };
                        assert!(
                            foreground >= 0,
                            "query owned PTY master foreground: {}",
                            std::io::Error::last_os_error()
                        );
                        assert_eq!(
                            foreground,
                            process.id() as i32,
                            "foreground returned before owner stop"
                        );
                    }
                    if name == "terminal-graph-stop-expiry" {
                        std::fs::write(root.path().join("expired"), b"1").unwrap();
                    }
                    assert_eq!(unsafe { libc::kill(process.id() as i32, libc::SIGCONT) }, 0);
                    resumed = true;
                }
                if start.elapsed() > Duration::from_secs(8) {
                    cleanup_children();
                    panic!("{name}: fixture watchdog expired");
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            if matches!(
                name,
                "jobcontrol" | "terminal-graph-jobcontrol" | "terminal-graph-stop-expiry"
            ) {
                assert!(resumed);
            }
            if name == "terminal-graph-interrupt" {
                assert!(interrupt_sent);
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
