//! Real ordinary invocations prove selection without executing any real updater.
#![cfg(target_os = "linux")]

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::TempDir;
use wait_timeout::ChildExt;

const RELEASE_TASKS: [&str; 4] = [
    "builtin/dev-tools-dev-cache",
    "builtin/dev-tools-skills-sync",
    "builtin/dev-tools-sync-configs",
    "builtin/dev-tools-update-all",
];

fn temporary_directory(label: &str) -> TempDir {
    let mut builder = tempfile::Builder::new();
    builder.prefix(label);
    match std::env::var_os("UPDATE_ALL_ORDINARY_TEST_KEEP_DIR") {
        Some(root) => builder.tempdir_in(root).unwrap(),
        None => builder.tempdir().unwrap(),
    }
}

fn checked_recorder(path: &Path, expected_sha256: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("recorder override must be an absolute path".into());
    }
    if expected_sha256.len() != 64 || !expected_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("recorder override requires a SHA-256 identity".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err("recorder override must be a regular, non-symlink executable".into());
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let actual_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err("recorder override SHA-256 mismatch".into());
    }
    Ok(path.to_path_buf())
}

fn recorder() -> &'static Path {
    static RECORDER: OnceLock<(Option<TempDir>, PathBuf)> = OnceLock::new();
    &RECORDER
        .get_or_init(|| {
            if let Some(path) = std::env::var_os("UPDATE_ALL_ORDINARY_TEST_RECORDER") {
                let expected = std::env::var("UPDATE_ALL_ORDINARY_TEST_RECORDER_SHA256")
                    .expect("prebuilt recorder requires its independently verified SHA-256");
                let executable = checked_recorder(Path::new(&path), &expected)
                    .expect("prebuilt recorder identity must match before any test invocation");
                return (None, executable);
            }
            assert!(
                std::env::var_os("UPDATE_ALL_ORDINARY_TEST_RECORDER_SHA256").is_none(),
                "a prebuilt recorder SHA-256 also requires its recorder path"
            );
            let directory = temporary_directory("recorder-");
            let executable = directory.path().join("update-all-recorder");
            assert!(Command::new("rustc")
                .args(["--edition=2021", "-C", "debuginfo=0"])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/ordinary_run_recorder.rs"
                ))
                .arg("-o")
                .arg(&executable)
                .status()
                .unwrap()
                .success());
            (Some(directory), executable)
        })
        .1
}

struct Fixture {
    _temporary_directory: Option<TempDir>,
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str, auto_update: bool, selection: &str, detectable: bool) -> Self {
        let temporary_directory = temporary_directory(label);
        let root = temporary_directory.path().to_path_buf();
        let temporary_directory = if std::env::var_os("UPDATE_ALL_ORDINARY_TEST_KEEP_DIR").is_some()
        {
            temporary_directory.keep();
            None
        } else {
            Some(temporary_directory)
        };
        for directory in [
            "home", "config", "cache", "state", "data", "runtime", "tmp", "cwd", "bin",
        ] {
            fs::create_dir(root.join(directory)).unwrap();
        }
        if detectable {
            // Fixtures are immutable; hard links avoid copying the same executable.
            fs::hard_link(recorder(), root.join("bin/update-all")).unwrap_or_else(|_| {
                fs::copy(recorder(), root.join("bin/update-all")).unwrap();
            });
        }
        fs::create_dir(root.join("config/update-all")).unwrap();
        fs::write(
            root.join("config/update-all/config.toml"),
            format!(
                "[ui]\nmode=\"plain\"\n\
                 [install]\nauto_update={auto_update}\n\
                 [updaters]\n{selection}\n\
                 [tasks.tool_update]\ntimeout_secs=2\nretries=0\n"
            ),
        )
        .unwrap();
        Self {
            _temporary_directory: temporary_directory,
            root,
        }
    }

    fn run(&self, arguments: &[&str]) -> Output {
        let executable = std::env::var_os("UPDATE_ALL_ORDINARY_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")));
        let mut command = Command::new(executable);
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
            .env("ORDINARY_RUN_FIXTURE_ROOT", &self.root)
            .current_dir(self.root.join("cwd"))
            .stdin(Stdio::null())
            .process_group(0)
            .args(arguments);
        let environment: Vec<_> = command
            .get_envs()
            .map(|(key, value)| {
                json!({"key": key.to_string_lossy(), "value_bytes": value.map(OsStr::as_bytes)})
            })
            .collect();
        fs::write(
            self.root.join("invocation.json"),
            serde_json::to_vec_pretty(&json!({
                "program": command.get_program().to_string_lossy(),
                "arguments": arguments,
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
                "exit_code": status.code(),
                "timed_out": timed_out,
                "child_reaped": true,
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(!timed_out, "ordinary run hung: {}", self.root.display());
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        }
    }

    fn assert_run(&self, output: &Output, exit_code: i32, expected: &[&str]) -> Value {
        assert_eq!(
            output.status.code(),
            Some(exit_code),
            "{}\n{}\n{}",
            self.root.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
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
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        let mut selected: Vec<_> = run["selected_tasks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect();
        selected.sort_unstable();
        assert_eq!(selected, expected);
        assert_eq!(run["exit_code"], exit_code);
        assert_eq!(run["tasks"].as_array().unwrap().len(), expected.len());
        let status = if exit_code == 0 {
            "completed"
        } else {
            "failed"
        };
        assert_eq!(run["status"], status);
        assert_eq!(meta["status"], status);
        for task in run["tasks"].as_array().unwrap() {
            assert_eq!(task["status"], "completed");
        }
        let calls = match fs::read_to_string(self.root.join("calls.tsv")) {
            Ok(calls) => calls,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("read recorder calls: {error}"),
        };
        let mut actual_calls: Vec<_> = calls.lines().map(str::to_string).collect();
        actual_calls.sort_unstable();
        let mut expected_calls: Vec<_> = expected
            .iter()
            .map(|id| {
                let product = id.strip_prefix("builtin/dev-tools-").unwrap();
                format!("product\tupdate-if-installed\t{product}\t--json")
            })
            .collect();
        expected_calls.sort_unstable();
        assert_eq!(actual_calls, expected_calls);
        // Only the harmless recorder is executable through PATH. These checks
        // establish absent release/publication effects for this isolated run,
        // not network isolation or native managed-installation qualification.
        for path in [
            "state/dev-tools",
            "data/update-all/completions",
            "home/.local",
        ] {
            assert!(!self.root.join(path).exists(), "unexpected state at {path}");
        }
        assert_eq!(fs::read_dir(self.root.join("data")).unwrap().count(), 0);
        let events: Vec<Value> = fs::read_to_string(runs[0].join("events.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.last().unwrap()["kind"], "run_completed");
        assert_eq!(
            events
                .iter()
                .filter(|event| event["kind"] == "run_completed")
                .count(),
            1
        );
        run
    }
}

#[test]
fn legacy_auto_update_zero_argument_runs_select_the_same_visible_release_tasks() {
    let mut plans = Vec::new();
    for auto_update in [true, false] {
        let fixture = Fixture::new(&format!("legacy-{auto_update}-"), auto_update, "", true);
        let output = fixture.run(&[]);
        let run = fixture.assert_run(&output, 0, &RELEASE_TASKS);
        plans.push(run["selected_tasks"].clone());
    }
    assert_eq!(plans[0], plans[1]);
}

#[test]
fn ordinary_release_selection_controls_match_the_recorded_plan() {
    let exclusions = RELEASE_TASKS.join(",");
    let config_exclusions = format!("exclude={}", serde_json::to_string(&RELEASE_TASKS).unwrap());
    let cases: [(&str, &str, Vec<&str>, &[&str]); 8] = [
        ("config-exclude-", &config_exclusions, vec![], &[]),
        ("cli-exclude-", "", vec!["--exclude", &exclusions], &[]),
        (
            "only-one-",
            "",
            vec!["--only", RELEASE_TASKS[0]],
            &RELEASE_TASKS[..1],
        ),
        ("no-auto-selection-", "run_all_detected=false", vec![], &[]),
        (
            "explicit-include-",
            "run_all_detected=false\ninclude=[\"builtin/dev-tools-dev-cache\"]",
            vec![],
            &RELEASE_TASKS[..1],
        ),
        (
            "explicit-only-",
            "run_all_detected=false",
            vec!["--only", RELEASE_TASKS[0]],
            &RELEASE_TASKS[..1],
        ),
        (
            "exclude-wins-",
            &config_exclusions,
            vec!["--only", RELEASE_TASKS[0]],
            &[],
        ),
        (
            "dormant-completion-flags-",
            "run_all_detected=false",
            vec!["--completions", "refresh", "--completion-provider", "path"],
            &[],
        ),
    ];
    for (label, selection, arguments, expected) in cases {
        let fixture = Fixture::new(label, true, selection, true);
        let output = fixture.run(&arguments);
        fixture.assert_run(&output, 0, expected);
    }
}

#[test]
fn ordinary_run_without_detected_release_tasks_starts_no_release_command() {
    let fixture = Fixture::new("no-detected-updater-", true, "", false);
    let output = fixture.run(&[]);
    fixture.assert_run(&output, 0, &[]);
}

#[test]
fn ordinary_unknown_only_selector_rejects_before_any_release_task() {
    let fixture = Fixture::new("unknown-only-", true, "", true);
    let output = fixture.run(&["--only", "builtin/not-a-real-updater"]);
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown section in --only"));
    fixture.assert_run(&output, 3, &[]);
}

#[test]
fn ordinary_help_distinguishes_selected_updates_and_dormant_completions() {
    let fixture = Fixture::new("ordinary-help-", true, "", true);
    let output = fixture.run(&["--help"]);
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("Selected builtin/dev-tools-* tasks can check releases"));
    assert!(help.contains("legacy install.auto_update field does not control them"));
    assert!(help.contains("Ordinary task runs do not implicitly refresh completions"));
    assert!(help.contains("inactive in ordinary built-in runs"));
    assert!(help.contains("update-all completions sync"));
    assert!(!fixture.root.join("calls.tsv").exists());
    for directory in ["state", "cache", "data"] {
        assert_eq!(
            fs::read_dir(fixture.root.join(directory)).unwrap().count(),
            0
        );
    }
}

#[test]
fn prebuilt_recorder_rejects_invalid_identity_without_execution() {
    let directory = temporary_directory("invalid-recorder-");
    let path = directory.path().join("recorder");
    let bytes = b"identity fixture, never executed";
    fs::write(&path, bytes).unwrap();
    let digest = format!("{:x}", Sha256::digest(bytes));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(checked_recorder(&path, &digest).unwrap(), path);
    assert_eq!(
        checked_recorder(&path, &"0".repeat(64)).unwrap_err(),
        "recorder override SHA-256 mismatch"
    );
    assert_eq!(
        checked_recorder(&path, "").unwrap_err(),
        "recorder override requires a SHA-256 identity"
    );
    assert_eq!(
        checked_recorder(directory.path(), &digest).unwrap_err(),
        "recorder override must be a regular, non-symlink executable"
    );
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&path, &alias).unwrap();
    assert_eq!(
        checked_recorder(&alias, &digest).unwrap_err(),
        "recorder override must be a regular, non-symlink executable"
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        checked_recorder(&path, &digest).unwrap_err(),
        "recorder override must be a regular, non-symlink executable"
    );
}
