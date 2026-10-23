//! Real native pager and PTY acceptance for dashboard log inspection.
#![cfg(all(target_os = "linux", feature = "tui"))]
#![allow(unsafe_code)] // Native PTY ownership and terminal-state observation require FFI.

use serde_json::Value;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tempfile::TempDir;

const PAGER_PROMPT: &str = "UPDATE_ALL_PAGER_READY";
const LOG_MARKER: &str = "PAGER_LOG_MARKER";

#[derive(Clone, Copy)]
enum Viewer {
    Less,
    Tail,
}

impl Viewer {
    fn command(self) -> &'static str {
        match self {
            Self::Less => "less",
            Self::Tail => "tail",
        }
    }
}

#[derive(Clone, Copy)]
enum RunOutcome {
    Completed,
    Canceled,
}

struct LogViewRun {
    home: TempDir,
    viewer: Viewer,
    child: Child,
    master: File,
    slave: File,
    original_modes: libc::termios,
    output: Vec<u8>,
    answered_cursor_queries: usize,
    dimensions: (u16, u16),
    keys: Vec<String>,
    terminal_ownership: Vec<String>,
}

impl LogViewRun {
    fn start(active: bool, columns: u16, rows: u16) -> Self {
        Self::start_with_viewer(active, columns, rows, Viewer::Less)
    }

    fn start_with_viewer(active: bool, columns: u16, rows: u16, viewer: Viewer) -> Self {
        let program = format!("/usr/bin/{}", viewer.command());
        assert!(
            Command::new(&program)
                .arg("--version")
                .output()
                .is_ok_and(|output| output.status.success()),
            "real native pager is required at {program} for this acceptance test"
        );
        let home = TempDir::new().unwrap();
        let path = match viewer {
            Viewer::Less => PathBuf::from("/usr/bin:/bin"),
            Viewer::Tail => {
                let bin = home.path().join("bin");
                fs::create_dir(&bin).unwrap();
                std::os::unix::fs::symlink(&program, bin.join("tail")).unwrap();
                bin
            }
        };
        let config = home.path().join("config/update-all");
        fs::create_dir_all(config.join("catalog.d/local")).unwrap();
        fs::write(
            config.join("config.toml"),
            "[install]\nauto_update=false\n[engine]\nmode=\"async\"\njobs=\"1\"\n[tasks.tool_update]\nretries=0\ntimeout_secs=30\n",
        )
        .unwrap();
        let script = if active {
            "printf 'PAGER_LOG_MARKER\\n'; emitted=false; while [ ! -e \"$HOME/release\" ]; do if [ \"$emitted\" = false ] && [ -e \"$HOME/emit\" ]; then printf 'FOLLOW_LOG_MARKER\\n'; emitted=true; fi; /bin/sleep 0.05; done; printf 'TASK_FINISHED_MARKER\\n'"
        } else {
            "printf 'PAGER_LOG_MARKER\\nTASK_FINISHED_MARKER\\n'"
        };
        let script_path = home.path().join("fixture.sh");
        fs::write(
            &script_path,
            format!(
                "i=0; while [ \"$i\" -lt 60 ]; do printf 'earlier log line %s\\n' \"$i\"; i=$((i+1)); done; {script}"
            ),
        )
        .unwrap();
        fs::write(
            config.join("catalog.d/local/log-view.toml"),
            format!(
                "[tasks.\"local/log-view\"]\nlabel=\"Log view fixture\"\ncategory=\"maintenance\"\nos=[\"linux\"]\ndetect_mode=\"command_available\"\ncommand=\"/bin/sh\"\nargs=[{}]\npolicy_key=\"tool_update\"\n",
                serde_json::to_string(&script_path).unwrap()
            ),
        )
        .unwrap();
        let size = libc::winsize {
            ws_row: rows,
            ws_col: columns,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd = -1;
        let mut slave_fd = -1;
        // SAFETY: all output pointers and the window-size pointer remain valid during openpty.
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
        // SAFETY: successful openpty returned two distinct owned descriptors.
        let master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        let original_modes = terminal_modes(&slave);
        let executable = std::env::var_os("UPDATE_ALL_LOG_VIEW_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")));
        let mut command = Command::new(executable);
        command
            .env_clear()
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path().join("config"))
            .env("XDG_STATE_HOME", home.path().join("state"))
            .env("XDG_CACHE_HOME", home.path().join("cache"))
            .env("XDG_DATA_HOME", home.path().join("data"))
            .env("PATH", path)
            .env("TERM", "xterm-256color")
            .env("LESS", format!("-P{PAGER_PROMPT}"))
            .current_dir(home.path())
            .args([
                "--dashboard",
                "--completions",
                "off",
                "--only",
                "local/log-view",
            ])
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap());
        // SAFETY: the child only performs async-signal-safe calls before exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let mut run = Self {
            home,
            viewer,
            child,
            master,
            slave,
            original_modes,
            output: Vec::new(),
            answered_cursor_queries: 0,
            dimensions: (columns, rows),
            keys: Vec::new(),
            terminal_ownership: Vec::new(),
        };
        run.wait_for(
            "dashboard and fixture output",
            Duration::from_secs(10),
            |run| run.screen_since(0).contains("Dashboard") && run.journal().contains(LOG_MARKER),
        );
        if !active {
            run.wait_for("task completion", Duration::from_secs(10), |run| {
                run.event_count("tasks_completed") == 1
                    && run.screen_since(0).contains(" completed ")
            });
        }
        run
    }

    fn run_dir(&self) -> Option<PathBuf> {
        fs::read_dir(self.home.path().join("state/update-all/runs"))
            .ok()?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("events.jsonl").is_file())
    }

    fn journal(&self) -> String {
        self.run_dir()
            .and_then(|path| fs::read_to_string(path.join("events.jsonl")).ok())
            .unwrap_or_default()
    }

    fn event_count(&self, kind: &str) -> usize {
        self.journal()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["kind"] == kind)
            .count()
    }

    fn screen_since(&self, offset: usize) -> String {
        String::from_utf8_lossy(&self.output[offset..]).into_owned()
    }

    fn read_output(&mut self) {
        let mut descriptor = libc::pollfd {
            fd: self.master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll receives one live descriptor and writable pollfd storage.
        if unsafe { libc::poll(&mut descriptor, 1, 10) } <= 0 {
            return;
        }
        let mut buffer = [0; 8192];
        match self.master.read(&mut buffer) {
            Ok(count) => self.output.extend_from_slice(&buffer[..count]),
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => panic!("read log viewer PTY: {error}"),
        }
        assert!(
            self.output.len() < 2 * 1024 * 1024,
            "fixture output exceeded 2 MiB"
        );
        let cursor_queries = self
            .output
            .windows(4)
            .filter(|bytes| *bytes == b"\x1b[6n")
            .count();
        for _ in self.answered_cursor_queries..cursor_queries {
            self.master.write_all(b"\x1b[1;1R").unwrap();
        }
        self.answered_cursor_queries = cursor_queries;
    }

    fn wait_for(
        &mut self,
        description: &str,
        timeout: Duration,
        condition: impl Fn(&Self) -> bool,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            self.read_output();
            if condition(self) {
                return;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "UpdateAll exited before {description}: {}\nJournal: {}",
                self.screen_since(0),
                self.journal()
            );
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {description}: {}\nJournal: {}",
                self.screen_since(0),
                self.journal()
            );
        }
    }

    fn send(&mut self, keys: &[u8]) {
        self.keys.extend(keys.iter().map(|key| match key {
            3 => "Ctrl+C".to_string(),
            9 => "Tab".to_string(),
            27 => "Esc".to_string(),
            key => char::from(*key).to_string(),
        }));
        self.master.write_all(keys).unwrap();
    }

    fn open_log(&mut self, global: bool) {
        if global {
            self.send(b"\t\t");
        }
        let offset = self.output.len();
        let log_marker = if global {
            "Log view fixture"
        } else {
            LOG_MARKER
        };
        self.send(b"m");
        self.wait_for(
            "real native pager to display the log",
            Duration::from_secs(5),
            |run| {
                let screen = run.screen_since(offset);
                screen.contains(log_marker)
                    && match run.viewer {
                        Viewer::Less => {
                            screen.contains(PAGER_PROMPT) || screen.contains("Waiting for data")
                        }
                        Viewer::Tail => true,
                    }
            },
        );
    }

    fn dismiss_pager(&mut self, key: &[u8], description: &str) {
        let resumed = self.event_count("frontend_resumed");
        let offset = self.output.len();
        self.send(key);
        self.wait_for_resume(resumed, offset, description);
    }

    fn wait_for_resume(&mut self, resumed: usize, offset: usize, description: &str) {
        self.wait_for(description, Duration::from_secs(3), |run| {
            run.event_count("frontend_resumed") > resumed
                && run.screen_since(offset).contains("Dashboard")
        });
        assert_eq!(self.foreground_group(), self.updater_group());
        self.terminal_ownership.push(format!(
            "dashboard: updater={}, foreground={}",
            self.updater_group(),
            self.foreground_group()
        ));
    }

    fn foreground_group(&self) -> i32 {
        // SAFETY: the retained PTY master refers to this fixture's terminal.
        let group = unsafe { libc::tcgetpgrp(self.master.as_raw_fd()) };
        assert!(
            group > 0,
            "fixture terminal has no foreground process group"
        );
        group
    }

    fn updater_group(&self) -> i32 {
        nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(
            i32::try_from(self.child.id()).unwrap(),
        )))
        .unwrap()
        .as_raw()
    }

    fn pager_group(&self) -> Option<i32> {
        for process in fs::read_dir("/proc").ok()?.filter_map(Result::ok) {
            let Some(pid) = process
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(process.path().join("stat")) else {
                continue;
            };
            let Some((name, fields)) = stat.rsplit_once(") ") else {
                continue;
            };
            let Some(parent) = fields
                .split_whitespace()
                .nth(1)
                .and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            if parent == self.child.id()
                && name
                    .split_once('(')
                    .is_some_and(|(_, name)| name == self.viewer.command())
            {
                return nix::unistd::getpgid(Some(nix::unistd::Pid::from_raw(pid)))
                    .ok()
                    .map(|group| group.as_raw());
            }
        }
        None
    }

    fn require_pager_ownership(&mut self) {
        let description = format!(
            "{} foreground ownership (updater={}, pager={:?}, foreground={})",
            self.viewer.command(),
            self.updater_group(),
            self.pager_group(),
            self.foreground_group()
        );
        self.wait_for(&description, Duration::from_secs(3), |run| {
            run.pager_group().is_some_and(|pager| {
                pager != run.updater_group() && pager == run.foreground_group()
            })
        });
        self.terminal_ownership.push(format!(
            "{}: updater={}, pager={}, foreground={}",
            self.viewer.command(),
            self.updater_group(),
            self.pager_group().unwrap(),
            self.foreground_group()
        ));
    }

    fn finish(&mut self, evidence_name: &str) {
        fs::write(self.home.path().join("release"), "release").unwrap();
        self.wait_for("task completion", Duration::from_secs(10), |run| {
            run.event_count("tasks_completed") == 1 && run.screen_since(0).contains(" completed ")
        });
        self.close_dashboard(evidence_name, RunOutcome::Completed);
    }

    fn finish_canceled(&mut self, evidence_name: &str) {
        self.wait_for("canceled task completion", Duration::from_secs(10), |run| {
            run.journal()
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .any(|event| {
                    event["kind"] == "tasks_completed" && event["payload"]["canceled"] == true
                })
        });
        let offset = self.output.len();
        self.send(b"?");
        self.wait_for("completion help frame", Duration::from_secs(3), |run| {
            run.screen_since(offset).contains("Reference")
        });
        let offset = self.output.len();
        self.send(b"\x1b");
        self.wait_for("completed dashboard frame", Duration::from_secs(3), |run| {
            run.screen_since(offset).contains("Global")
        });
        self.close_dashboard(evidence_name, RunOutcome::Canceled);
    }

    fn cancel_updater_and_finish(&mut self, evidence_name: &str) {
        let pager_group = self.pager_group().unwrap();
        let resumed = self.event_count("frontend_resumed");
        let offset = self.output.len();
        self.keys.push("SIGINT(updater)".to_string());
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
            nix::sys::signal::Signal::SIGINT,
        )
        .unwrap();
        self.wait_for_resume(
            resumed,
            offset,
            "direct SIGINT to restore dashboard ownership",
        );
        assert_eq!(
            nix::sys::signal::killpg(nix::unistd::Pid::from_raw(pager_group), None),
            Err(nix::errno::Errno::ESRCH)
        );
        self.finish_canceled(evidence_name);
    }

    fn close_dashboard(&mut self, evidence_name: &str, expected: RunOutcome) {
        let (expected_exit, expected_status) = match expected {
            RunOutcome::Completed => (0, "completed"),
            RunOutcome::Canceled => (3, "canceled"),
        };
        self.send(b"q");
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            self.read_output();
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "dashboard did not exit after q");
        };
        assert_eq!(
            status.code(),
            Some(expected_exit),
            "viewer dismissal changed the run outcome: {status}"
        );
        let result: Value =
            serde_json::from_slice(&fs::read(self.run_dir().unwrap().join("run.json")).unwrap())
                .unwrap();
        assert_eq!(result["exit_code"], expected_exit, "{result}");
        assert_eq!(result["status"], expected_status, "{result}");
        let tasks = result["tasks"].as_array().unwrap();
        assert_eq!(tasks.len(), 1, "{result}");
        assert_eq!(tasks[0]["status"], expected_status, "{result}");
        assert!(!self.journal().contains("log viewer failed"));
        if matches!(expected, RunOutcome::Completed) {
            assert!(!self.journal().contains("cancel-all requested"));
        }
        let after = terminal_modes(&self.slave);
        assert_eq!(self.original_modes.c_iflag, after.c_iflag);
        assert_eq!(self.original_modes.c_oflag, after.c_oflag);
        assert_eq!(self.original_modes.c_lflag, after.c_lflag);
        assert_eq!(self.original_modes.c_cflag, after.c_cflag);
        assert_eq!(self.original_modes.c_cc, after.c_cc);
        if let Some(directory) = std::env::var_os("UPDATE_ALL_LOG_VIEW_EVIDENCE_DIR") {
            let directory = PathBuf::from(directory);
            fs::create_dir_all(&directory).unwrap();
            let (columns, rows) = self.dimensions;
            let transcript = self.screen_since(0).replace(
                self.home.path().to_string_lossy().as_ref(),
                "<fixture-home>",
            );
            fs::write(
                directory.join(format!("{evidence_name}-{columns}x{rows}.pty.txt")),
                format!(
                    "Dimensions: {columns}x{rows}\nKeys: {}\nOutcome: {expected_status}; terminal modes restored\nOwnership: {}\n\n{transcript}",
                    self.keys.join(" "), self.terminal_ownership.join("; ")
                ),
            )
            .unwrap();
        }
    }
}

impl Drop for LogViewRun {
    fn drop(&mut self) {
        let _ = fs::write(self.home.path().join("release"), "release");
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(self.child.id()).unwrap()),
                nix::sys::signal::Signal::SIGINT,
            );
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !matches!(self.child.try_wait(), Ok(Some(_))) && Instant::now() < deadline {
            let _ = self.master.write_all(b"\x03");
            std::thread::sleep(Duration::from_millis(50));
            let _ = self.master.write_all(b"q");
            std::thread::sleep(Duration::from_millis(50));
        }
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            if let Some(group) = self.pager_group() {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(group),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            if let Ok(pid) = i32::try_from(self.child.id()) {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid),
                    nix::sys::signal::Signal::SIGKILL,
                );
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn terminal_modes(terminal: &File) -> libc::termios {
    let mut modes = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: the descriptor is live and the output buffer can hold one termios value.
    assert_eq!(
        unsafe { libc::tcgetattr(terminal.as_raw_fd(), modes.as_mut_ptr()) },
        0
    );
    // SAFETY: successful tcgetattr initialized the whole value.
    unsafe { modes.assume_init() }
}

#[test]
fn real_less_q_returns_from_completed_task_and_run_logs() {
    for (columns, rows) in [(80, 24), (120, 40)] {
        let mut run = LogViewRun::start(false, columns, rows);
        run.open_log(false);
        run.dismiss_pager(b"q", "q to return from the completed task log");
        run.open_log(true);
        run.dismiss_pager(b"q", "q to return from the completed run log");
        run.finish("completed-task-and-run");
    }
}

#[test]
fn real_less_q_returns_while_task_keeps_running() {
    let mut run = LogViewRun::start(true, 80, 24);
    run.open_log(false);
    run.dismiss_pager(b"q", "q to return from the active task log");
    assert_eq!(run.event_count("tasks_completed"), 0);
    run.open_log(false);
    run.require_pager_ownership();
    run.dismiss_pager(b"\x03", "Ctrl-C to return from normal browsing");
    assert_eq!(run.event_count("tasks_completed"), 0);
    run.finish("active-browse");
}

#[test]
fn real_less_explicit_follow_ctrl_c_returns_without_canceling_task() {
    let mut run = LogViewRun::start(true, 80, 24);
    run.open_log(false);
    run.require_pager_ownership();
    let offset = run.output.len();
    run.send(b"F");
    run.wait_for("explicit follow mode", Duration::from_secs(5), |run| {
        run.screen_since(offset).contains("Waiting for data")
    });
    let offset = run.output.len();
    fs::write(run.home.path().join("emit"), "emit").unwrap();
    run.wait_for("new output in follow mode", Duration::from_secs(5), |run| {
        run.screen_since(offset).contains("FOLLOW_LOG_MARKER")
    });
    run.dismiss_pager(b"\x03", "Ctrl-C to return from explicit follow mode");
    assert_eq!(run.event_count("tasks_completed"), 0);
    run.finish("active-follow");
}

#[test]
fn real_less_owns_foreground_until_dashboard_resumes() {
    let mut run = LogViewRun::start(true, 80, 24);
    run.open_log(false);
    run.require_pager_ownership();
    run.dismiss_pager(b"q", "q to restore dashboard foreground ownership");
    run.finish("foreground-custody");
}

#[test]
fn direct_sigint_cancels_updater_and_reaps_foreground_pager() {
    let mut run = LogViewRun::start(true, 80, 24);
    run.open_log(false);
    run.require_pager_ownership();
    run.cancel_updater_and_finish("direct-sigint");
}

#[test]
fn real_tail_ctrl_c_returns_without_canceling_task_or_warning() {
    let mut run = LogViewRun::start_with_viewer(true, 80, 24, Viewer::Tail);
    run.open_log(false);
    run.require_pager_ownership();
    run.dismiss_pager(b"\x03", "Ctrl-C to return from native tail fallback");
    assert_eq!(run.event_count("tasks_completed"), 0);
    run.finish("tail-follow");
}

#[test]
fn direct_sigint_cancels_updater_and_reaps_tail_fallback() {
    let mut run = LogViewRun::start_with_viewer(true, 80, 24, Viewer::Tail);
    run.open_log(false);
    run.require_pager_ownership();
    run.cancel_updater_and_finish("tail-direct-sigint");
}
