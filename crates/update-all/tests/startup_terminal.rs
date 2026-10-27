#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn executable(path: &std::path::Path, source: &str) {
    fs::write(path, source).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

struct SessionChild {
    process: Child,
    session: u32,
}

impl Drop for SessionChild {
    fn drop(&mut self) {
        for entry in fs::read_dir("/proc").unwrap().flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some((_, fields)) = stat.rsplit_once(") ") else {
                continue;
            };
            if fields
                .split_whitespace()
                .nth(3)
                .and_then(|v| v.parse::<u32>().ok())
                == Some(self.session)
            {
                // SAFETY: the fixture launched the retained child as this private session leader.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
        }
        let _ = self.process.wait();
    }
}

fn completed_artifact(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let runs = fs::read_dir(root.join("state/update-all/runs")).ok()?;
    runs.flatten()
        .map(|entry| entry.path().join("run.json"))
        .find(|path| {
            fs::read(path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
                .is_some_and(|artifact| artifact["tasks_completed_unix_ms"].as_u64().is_some())
        })
}

fn journey(ui: &str, engine: &str, outcome: &str) {
    let direct = outcome == "direct";
    let blocked_output = outcome == "blocked-output";
    let nested = outcome == "nested";
    let root = TempDir::new().unwrap();
    let bin = root.path().join("bin");
    let config = root.path().join("config/update-all");
    let catalog = config.join("catalog.d/local");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(&catalog).unwrap();
    executable(
        &bin.join("sudo"),
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$FIXTURE_ROOT/sudo.log"
read -r pid comm state parent group session tty rest < /proc/$$/stat
identity="$parent $session $tty"
if [ "$*" = '-v' ] || { [ "$FIXTURE_OUTCOME" = blocked-output ] && [ "$*" = '-n -v' ] && [ ! -f "$FIXTURE_ROOT/ticket" ]; }; then
    printf '%s\n' "$identity" > "$FIXTURE_ROOT/ticket"
    exit 0
fi
if [ "${FIXTURE_NESTED:-0}" = 1 ]; then
    read -r expected_parent expected_session expected_tty < "$FIXTURE_ROOT/ticket"
    [ "$session $tty" = "$expected_session $expected_tty" ] && [ "$parent" != "$expected_parent" ] || exit 94
    printf '%s\n' "$identity" > "$FIXTURE_ROOT/nested-identity"
else
    IFS= read -r expected < "$FIXTURE_ROOT/ticket"
    [ "$identity" = "$expected" ] || exit 90
fi
if [ "$*" = '-n -v' ]; then exit 0; fi
[ "$1" = '-n' ] && [ "$2" = '--' ] || exit 91
shift 2
exec "$@"
"#,
    );
    executable(
        &bin.join("manager"),
        r#"#!/bin/sh
set -eu
FIXTURE_NESTED=1 "$FIXTURE_ROOT/bin/sudo" -n -- "$FIXTURE_ROOT/bin/probe" "$@"
code=$?
exit "$code"
"#,
    );
    executable(
        &bin.join("probe"),
        &r#"#!/bin/sh
set -eu
printf 'effect\n' >> "$FIXTURE_ROOT/launches"
printf '<%s>\n' "$@" >> "$FIXTURE_ROOT/effects"
if [ "$FIXTURE_OUTCOME" = direct ]; then
    [ -t 1 ] && [ -t 2 ] || exit 93
    printf 'Native stdout and stderr are terminals\n'
fi
printf 'Native question? '
IFS= read -r answer < /dev/tty
[ "$answer" = yes ] || exit 92
printf '\n'
printf 'captured stderr\n' >&2
case "$FIXTURE_OUTCOME" in
    failure) printf 'sudo: a password is required\n' >&2; exit 7 ;;
    cancel) printf 'Ready for cancellation\n'; while :; do sleep 1; done ;;
    timeout)
        sleep 60 &
        printf '%s\n' "$!" > "$FIXTURE_ROOT/descendant"
        printf 'Ready for cancellation\n'
        wait "$!" ;;
    blocked-output)
        sleep 60 &
        printf '%s\n' "$!" > "$FIXTURE_ROOT/descendant"
        payload='FLOOD_PAYLOAD'
        while :; do printf '%s\n' "$payload"; sleep 0.01; done ;;
    stop) kill -STOP $$ ;;
esac
printf 'UPDATE_ALL_RESULT {"outcome":"updated","detail":"native terminal verified"}\n'
"#
        .replace("FLOOD_PAYLOAD", &"m".repeat(1024)),
    );
    fs::write(
        config.join("config.toml"),
        format!(
            r#"
[ui]
persist_until_exit=false
[updaters]
run_all_detected=false
{}
[tasks.tool_update]
timeout_secs={}
retries=2
retry_backoff_secs=0
{}
"#,
            if blocked_output {
                "privilege_mode=\"required\""
            } else {
                ""
            },
            if matches!(outcome, "timeout" | "blocked-output") {
                1
            } else {
                5
            },
            if direct {
                "[runtime.interactive]\nmode=\"direct_tty\""
            } else {
                ""
            }
        ),
    )
    .unwrap();
    let mut tasks = String::new();
    let count = if outcome == "success" { 2 } else { 1 };
    for index in 0..count {
        tasks.push_str(&format!(
            r#"
[tasks."local/probe-{index}"]
label="Native terminal {index}"
os=["linux"]
detect_mode="command_available"
command="{}"
args=["literal space", "$(literal)"]
requires_elevation={}
needs_sudo_session={}
interactive=true
{}
policy_key="tool_update"
"#,
            if nested { "manager" } else { "probe" },
            !nested,
            nested,
            if direct { "" } else { "result_protocol=1" }
        ));
    }
    fs::write(catalog.join("terminal.toml"), tasks).unwrap();

    let (mut master, slave) = unsafe {
        let (mut master, mut slave) = (-1, -1);
        let size = libc::winsize {
            ws_row: 30,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty initializes both fresh descriptors and borrows size.
        assert_eq!(
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &size
            ),
            0
        );
        (File::from_raw_fd(master), File::from_raw_fd(slave))
    };
    let slave_fd = slave.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_update-all"));
    command
        .env_clear()
        .env("HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("TERM", "xterm-256color")
        .env("FIXTURE_ROOT", root.path())
        .env("FIXTURE_OUTCOME", outcome)
        .args([
            "--ui",
            ui,
            "--engine-mode",
            engine,
            "--jobs",
            "2",
            "--only",
            if count == 2 {
                "local/probe-0,local/probe-1"
            } else {
                "local/probe-0"
            },
        ])
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(if blocked_output {
            Stdio::piped()
        } else {
            Stdio::from(slave.try_clone().unwrap())
        })
        .stderr(Stdio::from(slave));
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 || libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let process = command.spawn().unwrap();
    let mut child = SessionChild {
        session: process.id(),
        process,
    };
    drop(command);
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        assert_eq!(
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
    let started = Instant::now();
    let mut output = String::new();
    let mut stdout_drain = None;
    let mut artifact_before_stdout_drain = false;
    let (mut questions, mut cursor_queries, mut cancelled) = (0, 0, false);
    let status = loop {
        let mut chunk = [0; 8192];
        if let Ok(length) = master.read(&mut chunk) {
            output.push_str(&String::from_utf8_lossy(&chunk[..length]));
        }
        let queries = output.matches("\x1b[6n").count();
        while cursor_queries < queries {
            master.write_all(b"\x1b[1;1R").unwrap();
            cursor_queries += 1;
        }
        let prompts = output.matches("Native question? ").count();
        while questions < prompts && questions < count {
            master.write_all(b"yes\n").unwrap();
            questions += 1;
        }
        if outcome == "cancel" && output.contains("Ready for cancellation") && !cancelled {
            master.write_all(&[3]).unwrap();
            cancelled = true;
        }
        if blocked_output && stdout_drain.is_none() && completed_artifact(root.path()).is_some() {
            artifact_before_stdout_drain = true;
            let mut stdout = child.process.stdout.take().unwrap();
            stdout_drain = Some(thread::spawn(move || {
                let mut bytes = Vec::new();
                stdout.read_to_end(&mut bytes).unwrap();
                bytes
            }));
        }
        if let Some(status) = child.process.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(15) {
            panic!("{ui}/{engine}/{outcome} did not settle: {output}");
        }
        thread::sleep(Duration::from_millis(5));
    };
    let expected_exit = match outcome {
        "success" | "direct" | "nested" => 0,
        "cancel" => 3,
        _ => 1,
    };
    assert_eq!(
        status.code(),
        Some(expected_exit),
        "{ui}/{engine}/{outcome}: {output}"
    );
    if let Some(reader) = stdout_drain {
        let _ = reader.join().unwrap();
    }
    if blocked_output {
        assert!(
            artifact_before_stdout_drain,
            "task completion waited for caller stdout"
        );
    }
    let runs = root.path().join("state/update-all/runs");
    let run = fs::read_dir(runs).unwrap().next().unwrap().unwrap().path();
    let artifact: serde_json::Value =
        serde_json::from_slice(&fs::read(run.join("run.json")).unwrap()).unwrap();
    for task in artifact["tasks"].as_array().unwrap() {
        let expected = match outcome {
            "success" | "direct" | "nested" => "completed",
            "cancel" => "canceled",
            _ => "failed",
        };
        assert_eq!(task["status"], expected, "{artifact}");
        if matches!(outcome, "success" | "nested") {
            assert_eq!(task["detail"], "native terminal verified");
        }
        if matches!(outcome, "timeout" | "blocked-output") {
            assert!(
                task["detail"].as_str().unwrap().contains("timeout running"),
                "{artifact}"
            );
        }
    }
    let effects = fs::read_to_string(root.path().join("effects")).unwrap();
    let launches = fs::read_to_string(root.path().join("launches")).unwrap();
    assert_eq!(
        launches.lines().count(),
        count,
        "protected command replayed: {launches}"
    );
    assert_eq!(effects, "<literal space>\n<$(literal)>\n".repeat(count));
    let sudo = fs::read_to_string(root.path().join("sudo.log")).unwrap();
    assert_eq!(
        sudo.lines().filter(|line| *line == "-v").count(),
        if blocked_output { 0 } else { 1 },
        "{sudo}"
    );
    let log = fs::read_to_string(run.join("run.log")).unwrap();
    if direct {
        assert!(
            output.contains("Native stdout and stderr are terminals"),
            "{output}"
        );
    } else {
        assert!(log.contains("captured stderr"), "{log}");
    }
    if outcome == "success" {
        assert!(log.contains("UPDATE_ALL_RESULT"), "{log}");
    }
    if nested {
        let startup = fs::read_to_string(root.path().join("ticket")).unwrap();
        let nested = fs::read_to_string(root.path().join("nested-identity")).unwrap();
        let startup = startup.split_whitespace().collect::<Vec<_>>();
        let nested = nested.split_whitespace().collect::<Vec<_>>();
        assert_ne!(startup[0], nested[0]);
        assert_eq!(&startup[1..], &nested[1..]);
    }
    if matches!(outcome, "timeout" | "blocked-output") {
        let pid = fs::read_to_string(root.path().join("descendant")).unwrap();
        let stat = fs::read_to_string(format!("/proc/{}/stat", pid.trim()));
        assert!(
            stat.is_err() || stat.unwrap().rsplit_once(") ").unwrap().1.starts_with('Z'),
            "owned descendant {} survived {outcome}",
            pid.trim()
        );
    }
}

#[test]
fn custom_privileged_tasks_reuse_startup_terminal_and_preserve_captured_results() {
    for ui in ["plain", "dashboard"] {
        for engine in ["sync", "async"] {
            journey(ui, engine, "success");
        }
    }
}

#[test]
fn native_terminal_failure_and_cancellation_never_replay_protected_effects() {
    for outcome in ["failure", "cancel", "stop", "timeout"] {
        journey("dashboard", "async", outcome);
    }
}

#[test]
fn explicit_direct_tty_privileged_tasks_keep_native_output_terminals() {
    journey("dashboard", "async", "direct");
}

#[test]
fn redirected_caller_stdout_does_not_block_native_task_timeout_or_artifact() {
    journey("plain", "async", "blocked-output");
}

#[test]
fn custom_nested_sudo_reuses_startup_terminal_without_direct_parent_identity() {
    journey("dashboard", "async", "nested");
}
