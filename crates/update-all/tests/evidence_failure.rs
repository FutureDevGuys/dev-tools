//! Actual CLI/PTY evidence-loss acceptance, without restart flags or host updates.
#![cfg(all(target_os = "linux", feature = "tui"))]
#![allow(unsafe_code)]
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use wait_timeout::ChildExt;

fn json(path: impl AsRef<Path>) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn general_enospc_stops_admission_settles_processes_and_restores_terminal() {
    let native = TempDir::new().unwrap();
    let shim = native.path().join("enospc.so");
    assert!(Command::new("cc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&shim)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/enospc.c"
        ))
        .arg("-ldl")
        .status()
        .unwrap()
        .success());
    for engine in ["sync", "async"] {
        for dashboard in [false, true] {
            for target in [
                "concurrent",
                "startup",
                "events.jsonl",
                "run.log",
                "task-local%2Fa.raw.log",
                "task-local%2Fa.json",
                "run.json",
            ] {
                let concurrent = target == "concurrent";
                if concurrent && (engine != "async" || !dashboard) {
                    continue;
                }
                let jobs = if concurrent { 2 } else { 1 };
                let home = TempDir::new().unwrap();
                let config = home.path().join("config/update-all");
                fs::create_dir_all(config.join("catalog.d/local")).unwrap();
                fs::write(config.join("config.toml"), format!(
                    "[install]\nauto_update=false\n[engine]\nmode={engine:?}\njobs=\"{jobs}\"\n[tasks.tool_update]\nretries=0\ntimeout_secs=10\n"
                )).unwrap();
                let script = "echo $$ > \"$HOME/owned-pid\"; touch \"$HOME/armed\"; echo first-evidence-line; sleep 0.2; i=0; while [ $i -lt 100 ]; do echo harmless-evidence-line; i=$((i+1)); done; touch \"$HOME/effect-completed\"";
                let script = if concurrent {
                    format!("while [ ! -e \"$HOME/sibling-ready\" ]; do sleep 0.01; done; {script}")
                } else {
                    script.to_string()
                };
                let second_script = if concurrent {
                    "echo $$ > \"$HOME/sibling-pid\"; touch \"$HOME/sibling-ready\"; sleep 5"
                } else {
                    "touch \"$HOME/later-started\""
                };
                fs::write(
                    config.join("catalog.d/local/evidence.toml"),
                    format!(
                        r#"
[tasks."local/a"]
label="First harmless task"
category="maintenance"
os=["linux"]
detect_mode="command_available"
command="/bin/sh"
args=["-c", {}]
policy_key="tool_update"
[tasks."local/b"]
label="Later harmless task"
category="maintenance"
os=["linux"]
detect_mode="command_available"
command="/bin/sh"
args=["-c", {}]
policy_key="tool_update"
"#,
                        serde_json::to_string(&script).unwrap(),
                        serde_json::to_string(second_script).unwrap()
                    ),
                )
                .unwrap();
                if concurrent {
                    use std::io::Write;
                    let mut catalog = fs::OpenOptions::new()
                        .append(true)
                        .open(config.join("catalog.d/local/evidence.toml"))
                        .unwrap();
                    writeln!(
                        catalog,
                        r#"
[tasks."local/c"]
label="Unstarted harmless task"
category="maintenance"
os=["linux"]
detect_mode="command_available"
command="/bin/sh"
args=["-c", "touch \"$HOME/later-started\""]
policy_key="tool_update"
"#
                    )
                    .unwrap();
                }
                let mut command = Command::new(env!("CARGO_BIN_EXE_update-all"));
                command
                    .env_clear()
                    .env("HOME", home.path())
                    .env("XDG_CONFIG_HOME", home.path().join("config"))
                    .env("XDG_STATE_HOME", home.path().join("state"))
                    .env("PATH", "/usr/bin:/bin")
                    .env("TERM", "xterm-256color")
                    .env("LD_PRELOAD", &shim)
                    .env(
                        "EVIDENCE_FAILURE_TARGET",
                        if target == "startup" {
                            "events.jsonl"
                        } else if concurrent {
                            "run.log"
                        } else {
                            target
                        },
                    )
                    .args([
                        if dashboard { "--dashboard" } else { "--plain" },
                        "--completions",
                        "off",
                        "--only",
                        if concurrent {
                            "local/a,local/b,local/c"
                        } else {
                            "local/a,local/b"
                        },
                    ]);
                if target != "startup" {
                    command.env("EVIDENCE_FAILURE_ARMED", home.path().join("armed"));
                }
                let mut master_fd = -1;
                let mut slave_fd = -1;
                let size = libc::winsize {
                    ws_row: 24,
                    ws_col: 80,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                // SAFETY: native openpty initializes distinct owned descriptors.
                assert_eq!(
                    unsafe {
                        libc::openpty(
                            &mut master_fd,
                            &mut slave_fd,
                            std::ptr::null_mut(),
                            std::ptr::null(),
                            &size,
                        )
                    },
                    0
                );
                // SAFETY: successful descriptors are transferred to File once.
                let master = unsafe { fs::File::from_raw_fd(master_fd) };
                let slave = unsafe { fs::File::from_raw_fd(slave_fd) };
                let mut before = std::mem::MaybeUninit::<libc::termios>::uninit();
                // SAFETY: valid descriptor and writable termios storage.
                assert_eq!(
                    unsafe { libc::tcgetattr(slave.as_raw_fd(), before.as_mut_ptr()) },
                    0
                );
                let before = unsafe { before.assume_init() };
                let mut reader = master.try_clone().unwrap();
                let capture = std::thread::spawn(move || {
                    let mut all = Vec::new();
                    let mut buf = [0; 8192];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => all.extend_from_slice(&buf[..n]),
                            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                            Err(e) => panic!("PTY read: {e}"),
                        }
                    }
                    all
                });
                command
                    .stdin(slave.try_clone().unwrap())
                    .stdout(slave.try_clone().unwrap())
                    .stderr(slave.try_clone().unwrap());
                // SAFETY: only async-signal-safe calls are made before exec.
                unsafe {
                    command.pre_exec(|| {
                        if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                let mut child = command.spawn().unwrap();
                drop(command);
                let status = child
                    .wait_timeout(Duration::from_secs(20))
                    .unwrap()
                    .unwrap_or_else(|| {
                        child.kill().unwrap();
                        child.wait().unwrap();
                        panic!("hung: {engine}/{dashboard}/{target}")
                    });
                let mut after = std::mem::MaybeUninit::<libc::termios>::uninit();
                // SAFETY: live slave descriptor and writable termios storage.
                assert_eq!(
                    unsafe { libc::tcgetattr(slave.as_raw_fd(), after.as_mut_ptr()) },
                    0
                );
                let after = unsafe { after.assume_init() };
                assert_eq!(
                    (
                        before.c_iflag,
                        before.c_oflag,
                        before.c_lflag,
                        before.c_cflag
                    ),
                    (after.c_iflag, after.c_oflag, after.c_lflag, after.c_cflag),
                    "terminal flags: {engine}/{dashboard}/{target}"
                );
                drop(slave);
                drop(master);
                let output = String::from_utf8_lossy(&capture.join().unwrap()).into_owned();
                assert!(
                    !status.success(),
                    "unexpected success: {engine}/{dashboard}/{target}: {output}"
                );
                assert!(
                    output.contains("os error 28"),
                    "missing ENOSPC: {engine}/{dashboard}/{target}: {output}"
                );
                assert!(
                    output.matches("os error 28").count() <= 3,
                    "unbounded diagnostic: {output}"
                );
                if dashboard && output.contains("\x1b[?1049h") {
                    let restored = output
                        .rfind("\x1b[?1049l")
                        .expect("alternate screen restored");
                    assert!(
                        output.find("os error 28").unwrap() > restored,
                        "raw diagnostic corrupted dashboard: {output}"
                    );
                }
                if target == "startup" {
                    assert!(!home.path().join("armed").exists());
                    assert!(!home.path().join("later-started").exists());
                    continue;
                }
                if target != "run.json" {
                    assert!(
                        !home.path().join("later-started").exists(),
                        "admission continued: {target}"
                    );
                }
                let pid: i32 = fs::read_to_string(home.path().join("owned-pid"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                // SAFETY: signal 0 observes whether our fixture process still exists.
                assert_eq!(
                    unsafe { libc::kill(pid, 0) },
                    -1,
                    "owned subprocess not settled"
                );
                if concurrent {
                    let sibling: i32 = fs::read_to_string(home.path().join("sibling-pid"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    // SAFETY: signal 0 observes our second owned fixture process.
                    assert_eq!(
                        unsafe { libc::kill(sibling, 0) },
                        -1,
                        "concurrent subprocess not settled"
                    );
                }
                let root = home.path().join("state/update-all/runs");
                let run = fs::read_dir(&root)
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .find(|p| p.join("run-meta.json").exists())
                    .unwrap();
                assert_eq!(json(run.join("run-meta.json"))["status"], "failed");
                assert!(!root.join(".update-all-task-run.lock").exists());
                if target != "run.json" {
                    let result = json(run.join("run.json"));
                    assert_eq!(result["status"], "failed");
                    assert_eq!(result["exit_code"], 1);
                    assert!(result["unstarted_tasks"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|v| v == if concurrent { "local/c" } else { "local/b" }));
                    if target == "task-local%2Fa.json" {
                        assert!(home.path().join("effect-completed").exists());
                        assert!(
                            result["tasks"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|t| t["task_id"] == "local/a" && t["status"] == "completed"),
                            "observed effects lost: {result}"
                        );
                    }
                }
            }
        }
    }
}
