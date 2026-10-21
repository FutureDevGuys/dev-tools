//! Real executable configuration selection, with isolated roots and Rust-only effects.
#![cfg(unix)]

use serde_json::{json, Value};
use std::{
    ffi::{OsStr, OsString},
    fs,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::TempDir;
use wait_timeout::ChildExt;

fn provider() -> &'static Path {
    static FIXTURE: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
    &FIXTURE
        .get_or_init(|| {
            let dir = match std::env::var_os("UPDATE_ALL_CONFIG_TEST_KEEP_DIR") {
                Some(root) => tempfile::Builder::new()
                    .prefix("provider-")
                    .tempdir_in(root)
                    .unwrap(),
                None => TempDir::new().unwrap(),
            };
            let executable = dir.path().join("fixture-marker");
            assert!(Command::new("rustc")
                .args(["--edition=2021", "-C", "debuginfo=0"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/config_selection.rs"
                ))
                .arg("-o")
                .arg(&executable)
                .status()
                .unwrap()
                .success());
            (dir, executable)
        })
        .1
}

fn executable() -> PathBuf {
    std::env::var_os("UPDATE_ALL_CONFIG_TEST_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")))
}

struct Fixture {
    _temp: Option<TempDir>,
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let temp = match std::env::var_os("UPDATE_ALL_CONFIG_TEST_KEEP_DIR") {
            Some(root) => tempfile::Builder::new()
                .prefix(&format!("{label}-"))
                .tempdir_in(root)
                .unwrap(),
            None => TempDir::new().unwrap(),
        };
        let root = temp.path().to_path_buf();
        let temp = if std::env::var_os("UPDATE_ALL_CONFIG_TEST_KEEP_DIR").is_some() {
            temp.keep();
            None
        } else {
            Some(temp)
        };
        for name in [
            "home", "config", "cache", "state", "data", "runtime", "tmp", "cwd", "bin",
        ] {
            fs::create_dir(root.join(name)).unwrap();
        }
        fs::hard_link(provider(), root.join("bin/fixture-marker")).unwrap_or_else(|_| {
            fs::copy(provider(), root.join("bin/fixture-marker")).unwrap();
        });
        Self { _temp: temp, root }
    }

    fn config(&self, relative: &str, marker: &str, plain: bool) -> PathBuf {
        let path = self.root.join(relative);
        self.write_config(&path, marker, plain);
        path
    }

    fn write_config(&self, path: &Path, marker: &str, plain: bool) {
        let parent = path.parent().unwrap();
        fs::create_dir_all(parent.join("catalog.d/local")).unwrap();
        // Safety comes from the isolated PATH and catalog, not inert auto_update.
        let ui = if plain { "[ui]\nmode=\"plain\"\n" } else { "" };
        fs::write(path, format!(
            "{ui}[updaters]\nexclude=[\"builtin/completions\"]\n[tasks.tool_update]\ntimeout_secs=2\nretries=0\n"
        )).unwrap();
        fs::write(parent.join("catalog.d/local/marker.toml"), format!(
            "[tasks.\"local/{marker}\"]\nlabel=\"Configuration {marker}\"\nos=[\"linux\",\"macos\"]\ndetect_mode=\"command_available\"\ncategory=\"maintenance\"\ncommand=\"fixture-marker\"\nargs=[{marker:?}]\npolicy_key=\"tool_update\"\n"
        )).unwrap();
    }

    fn command(&self, env_config: Option<&OsStr>) -> Command {
        let mut command = Command::new(executable());
        command.env_clear();
        for (key, directory) in [
            ("HOME", "home"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_RUNTIME_DIR", "runtime"),
            ("TMPDIR", "tmp"),
            ("TMP", "tmp"),
            ("TEMP", "tmp"),
            ("PATH", "bin"),
        ] {
            command.env(key, self.root.join(directory));
        }
        command
            .env("LANG", "C.UTF-8")
            .env("CONFIG_SELECTION_FIXTURE_ROOT", &self.root)
            .current_dir(self.root.join("cwd"))
            .stdin(Stdio::null())
            .process_group(0);
        if let Some(path) = env_config {
            command.env("UPDATE_ALL_CONFIG", path);
        }
        command
    }

    fn run(&self, env_config: Option<&OsStr>, cli_config: Option<&Path>) -> Output {
        let mut command = self.command(env_config);
        if let Some(path) = cli_config {
            command.arg("--config").arg(path);
        }
        self.capture(command)
    }

    fn capture(&self, mut command: Command) -> Output {
        let arguments: Vec<_> = command.get_args().map(|value| value.as_bytes()).collect();
        let environment: Vec<_> = command.get_envs().map(|(key, value)| {
            json!({"key": key.to_string_lossy(), "value_bytes": value.map(OsStr::as_bytes)})
        }).collect();
        fs::write(
            self.root.join("invocation.json"),
            serde_json::to_vec_pretty(&json!({
                "program": command.get_program().to_string_lossy(),
                "arguments_bytes": arguments,
                "environment": environment,
                "environment_cleared": true,
                "cwd": command.get_current_dir(),
                "stdin": "null",
                "timeout_seconds": 10,
            }))
            .unwrap(),
        )
        .unwrap();
        let stdout = self.root.join("stdout.txt");
        let stderr = self.root.join("stderr.txt");
        command.stdout(fs::File::create(&stdout).unwrap());
        command.stderr(fs::File::create(&stderr).unwrap());
        let mut child = command.spawn().unwrap();
        let status = child.wait_timeout(Duration::from_secs(10)).unwrap();
        let timed_out = status.is_none();
        let status = match status {
            Some(status) => status,
            None => {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(child.id() as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                child.wait().unwrap()
            }
        };
        fs::write(
            self.root.join("result.json"),
            serde_json::to_vec_pretty(&json!({
                "exit_code": status.code(), "timed_out": timed_out, "child_reaped": true,
                "fallback_marker": self.root.join("fallback.marker").exists(),
                "selected_marker": self.root.join("selected.marker").exists(),
                "cli_marker": self.root.join("cli.marker").exists(),
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            !timed_out,
            "configuration selection hung: {}",
            self.root.display()
        );
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        }
    }

    fn assert_rejected(&self, output: &Output, message: &str) {
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}\n{}\n{}",
            self.root.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for marker in ["fallback", "selected", "cli"] {
            assert!(!self.root.join(format!("{marker}.marker")).exists());
        }
        assert!(
            !self.root.join("state/update-all/runs").exists(),
            "startup rejection invented a run"
        );
        assert_eq!(
            fs::read_dir(self.root.join("cache")).unwrap().count(),
            0,
            "startup rejection must precede UI preference persistence"
        );
    }

    fn assert_completed(&self, output: &Output, marker: &str, ui: &str) {
        assert!(
            output.status.success(),
            "{}\n{}\n{}",
            self.root.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for name in ["fallback", "selected", "cli"] {
            assert_eq!(
                self.root.join(format!("{name}.marker")).exists(),
                name == marker
            );
        }
        let runs: Vec<_> = fs::read_dir(self.root.join("state/update-all/runs"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.join("run.json").is_file())
            .collect();
        assert_eq!(runs.len(), 1);
        let run: Value =
            serde_json::from_slice(&fs::read(runs[0].join("run.json")).unwrap()).unwrap();
        let meta: Value =
            serde_json::from_slice(&fs::read(runs[0].join("run-meta.json")).unwrap()).unwrap();
        assert_eq!(run["exit_code"], 0);
        assert_eq!(run["issue_count"], 0);
        assert_eq!(run["status"], "completed");
        assert_eq!(meta["status"], "completed");
        assert_eq!(run["ui_mode"], ui);
        assert_eq!(run["selected_tasks"], json!([format!("local/{marker}")]));
        assert_eq!(run["tasks"].as_array().unwrap().len(), 1);
        assert_eq!(run["tasks"][0]["status"], "completed");
        let events: Vec<Value> = fs::read_to_string(runs[0].join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for kind in ["tasks_completed", "run_completed"] {
            let completion: Vec<_> = events
                .iter()
                .filter(|event| event["kind"] == kind)
                .collect();
            assert_eq!(completion.len(), 1);
            assert_eq!(completion[0]["payload"]["success"], true);
            assert_eq!(completion[0]["payload"]["had_failures"], false);
        }
        assert_eq!(
            events
                .iter()
                .filter(|event| event["kind"] == "frontend_detached")
                .count(),
            usize::from(ui == "dashboard")
        );
        assert_eq!(events.last().unwrap()["kind"], "run_completed");
        assert_eq!(events.last().unwrap()["payload"]["exit_code"], 0);
    }
}

#[test]
fn zero_argument_missing_explicit_environment_config_never_runs_discovered_fallback() {
    let fixture = Fixture::new("missing-explicit");
    fixture.config("config/update-all/config.toml", "fallback", true);
    let missing = fixture.root.join("intended-but-missing.toml");
    let output = fixture.run(Some(missing.as_os_str()), None);
    fixture.assert_rejected(&output, "config file not found");
    assert!(String::from_utf8_lossy(&output.stderr).contains(missing.to_str().unwrap()));
}

#[test]
fn zero_argument_valid_environment_config_precedes_discovered_defaults() {
    let fixture = Fixture::new("valid-explicit");
    fixture.config("config/update-all/config.toml", "fallback", true);
    let selected = fixture.config("selected/config.toml", "selected", true);
    let output = fixture.run(Some(selected.as_os_str()), None);
    fixture.assert_completed(&output, "selected", "plain");
}

#[test]
fn cli_config_precedes_valid_or_missing_environment_selection() {
    for valid_env in [false, true] {
        let fixture = Fixture::new("cli-precedence");
        fixture.config("config/update-all/config.toml", "fallback", true);
        let selected = if valid_env {
            fixture.config("selected/config.toml", "selected", true)
        } else {
            fixture.root.join("missing.toml")
        };
        let cli = fixture.config("cli/config.toml", "cli", true);
        let output = fixture.run(Some(selected.as_os_str()), Some(&cli));
        fixture.assert_completed(&output, "cli", "plain");
    }
    let fixture = Fixture::new("missing-cli");
    let selected = fixture.config("selected/config.toml", "selected", true);
    let output = fixture.run(
        Some(selected.as_os_str()),
        Some(&fixture.root.join("missing.toml")),
    );
    fixture.assert_rejected(&output, "config file not found");
}

#[test]
fn zero_argument_empty_or_unset_environment_preserves_xdg_and_home_discovery() {
    for env_config in [None, Some(OsStr::new(""))] {
        for xdg in [false, true] {
            let fixture = Fixture::new("ordinary-discovery");
            fixture.config("home/.config/update-all/config.toml", "fallback", true);
            let marker = if xdg {
                fixture.config("config/update-all/config.toml", "selected", true);
                "selected"
            } else {
                "fallback"
            };
            let output = fixture.run(env_config, None);
            fixture.assert_completed(&output, marker, "plain");
        }
    }
}

#[test]
fn zero_argument_default_dashboard_keeps_non_tty_detach_and_truthful_completion() {
    let fixture = Fixture::new("default-dashboard");
    fixture.config("config/update-all/config.toml", "fallback", false);
    let output = fixture.run(None, None);
    fixture.assert_completed(&output, "fallback", "dashboard");
}

#[test]
fn absent_configuration_keeps_read_only_runtime_default_validation() {
    let fixture = Fixture::new("no-config-defaults");
    let mut command = fixture.command(None);
    command.args(["config", "validate"]);
    let output = fixture.capture(command);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("no config file found"));
    assert!(!fixture.root.join("state/update-all/runs").exists());
}

#[test]
fn explicit_environment_paths_preserve_whitespace_relative_and_non_unicode_names() {
    use std::os::unix::ffi::OsStringExt;
    for (label, name) in [
        ("whitespace", OsString::from(" ")),
        ("relative", OsString::from("relative.toml")),
        (
            "non-unicode",
            OsString::from_vec(b"config-\xff.toml".to_vec()),
        ),
    ] {
        for exists in [false, true] {
            let fixture = Fixture::new(label);
            fixture.config("config/update-all/config.toml", "fallback", true);
            if exists {
                fixture.write_config(&fixture.root.join("cwd").join(&name), "selected", true);
            }
            let output = fixture.run(Some(&name), None);
            if exists {
                fixture.assert_completed(&output, "selected", "plain");
            } else {
                fixture.assert_rejected(&output, "config file not found");
            }
        }
    }
}

#[test]
#[allow(unsafe_code)] // The isolated native FIFO fixture has no safe standard-library constructor.
fn explicit_config_directories_and_fifos_are_rejected_before_reading() {
    for fifo in [false, true] {
        for source in ["environment", "cli", "validate"] {
            let fixture = Fixture::new("non-file-config");
            fixture.config("config/update-all/config.toml", "fallback", true);
            let target = fixture.root.join("not-a-regular-file");
            if fifo {
                let path = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
                // SAFETY: path is a live NUL-terminated string in the private fixture root.
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            } else {
                fs::create_dir(&target).unwrap();
            }
            if source == "validate" {
                let mut command = fixture.command(None);
                command.args(["config", "validate", "--path"]).arg(&target);
                let output = fixture.capture(command);
                assert_eq!(output.status.code(), Some(3));
                assert!(String::from_utf8_lossy(&output.stderr)
                    .contains("config path is not a regular file"));
            } else {
                let output = if source == "cli" {
                    fixture.run(None, Some(&target))
                } else {
                    fixture.run(Some(target.as_os_str()), None)
                };
                fixture.assert_rejected(&output, "config path is not a regular file");
            }
        }
    }
}

#[test]
fn explicit_config_symlink_to_regular_file_remains_supported() {
    let fixture = Fixture::new("symlink-config");
    fixture.config("config/update-all/config.toml", "fallback", true);
    let target = fixture.config("selected/target.toml", "selected", true);
    let link = fixture.root.join("selected/config.toml");
    std::os::unix::fs::symlink(target, &link).unwrap();
    let output = fixture.run(Some(link.as_os_str()), None);
    fixture.assert_completed(&output, "selected", "plain");
}

#[test]
fn malformed_explicit_environment_config_never_uses_valid_fallback() {
    for contents in ["this is not TOML", "[ui]\nmode=\"not-a-ui-mode\"\n"] {
        let fixture = Fixture::new("invalid-explicit");
        fixture.config("config/update-all/config.toml", "fallback", true);
        let target = fixture.root.join("invalid.toml");
        fs::write(&target, contents).unwrap();
        let output = fixture.run(Some(target.as_os_str()), None);
        fixture.assert_rejected(&output, "config");
    }
}

#[test]
fn configuration_creation_still_accepts_an_explicit_absent_target() {
    let fixture = Fixture::new("create-config");
    let target = fixture.root.join("new-config.toml");
    let missing_environment = fixture.root.join("unrelated-missing.toml");
    let mut command = fixture.command(Some(missing_environment.as_os_str()));
    command.args(["config", "init", "--path"]).arg(&target);
    let output = fixture.capture(command);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(target.is_file());
    assert!(!missing_environment.exists());
    assert!(!fixture.root.join("state/update-all/runs").exists());
}
