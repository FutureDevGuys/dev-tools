//! Executable regular-file admission with no installed providers or elevation tools.
#![cfg(unix)]

use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{symlink, MetadataExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use wait_timeout::ChildExt;

const CONFIG: &str = "[ui]\nmode=\"plain\"\n[updaters]\nexclude=[\"builtin/completions\"]\n";

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    mode: u32,
    modified: (i64, i64),
    contents: Vec<u8>,
}

fn inventory(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn visit(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Entry>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let contents = if metadata.is_file() {
            fs::read(path).unwrap()
        } else if metadata.file_type().is_symlink() {
            fs::read_link(path).unwrap().as_os_str().as_bytes().to_vec()
        } else {
            Vec::new()
        };
        entries.insert(
            path.strip_prefix(root).unwrap().to_owned(),
            Entry {
                mode: metadata.mode(),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
                contents,
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                visit(root, &entry.unwrap().path(), entries);
            }
        }
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries);
    entries
}

fn freeze_directory_times(path: &Path) {
    if !fs::symlink_metadata(path).unwrap().is_dir() {
        return;
    }
    for entry in fs::read_dir(path).unwrap() {
        freeze_directory_times(&entry.unwrap().path());
    }
    fs::File::open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(1_500_000_000))
        .unwrap();
}

struct Fixture {
    _temp: Option<TempDir>,
    evidence: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let temp = match std::env::var_os("UPDATE_ALL_READER_TEST_KEEP_DIR") {
            Some(root) => tempfile::Builder::new()
                .prefix(&format!("{label}-"))
                .tempdir_in(root)
                .unwrap(),
            None => TempDir::new().unwrap(),
        };
        let evidence = temp.path().to_owned();
        let temp = if std::env::var_os("UPDATE_ALL_READER_TEST_KEEP_DIR").is_some() {
            temp.keep();
            None
        } else {
            Some(temp)
        };
        let root = evidence.join("fixture");
        fs::create_dir(&root).unwrap();
        for name in [
            "home", "config", "cache", "state", "data", "runtime", "tmp", "cwd", "bin",
        ] {
            fs::create_dir(root.join(name)).unwrap();
        }
        Self {
            _temp: temp,
            evidence,
            root,
        }
    }

    fn main_path(&self) -> PathBuf {
        self.root.join("config/update-all/config.toml")
    }

    fn write(&self, path: &Path, contents: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn fallback(&self) {
        self.write(
            &self.root.join("home/.config/update-all/config.toml"),
            CONFIG,
        );
    }

    fn with_catalog(&self, path: &Path) {
        // JSON quoting is also valid for these ordinary TOML path strings.
        self.write(
            &self.main_path(),
            &format!(
                "{CONFIG}catalogs=[{}]\n",
                serde_json::to_string(path.to_str().unwrap()).unwrap()
            ),
        );
    }

    fn command(&self, validate: bool) -> Command {
        let binary = std::env::var_os("UPDATE_ALL_READER_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_update-all")));
        let mut command = Command::new(binary);
        command.env_clear();
        for (key, name) in [
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
            command.env(key, self.root.join(name));
        }
        command
            .env("LANG", "C.UTF-8")
            .current_dir(self.root.join("cwd"))
            .stdin(Stdio::null())
            .process_group(0);
        if validate {
            command.args(["config", "validate"]);
        }
        command
    }

    fn capture(&self, mut command: Command) -> Output {
        let before = inventory(&self.root);
        fs::write(self.evidence.join("before.txt"), format!("{before:#?}")).unwrap();
        let arguments: Vec<_> = command.get_args().map(OsStr::as_bytes).collect();
        let environment: Vec<_> = command.get_envs().map(|(key, value)| {
            json!({"key": key.to_string_lossy(), "value_bytes": value.map(OsStr::as_bytes)})
        }).collect();
        fs::write(
            self.evidence.join("invocation.json"),
            serde_json::to_vec_pretty(&json!({
                "program": command.get_program().to_string_lossy(), "arguments_bytes": arguments,
                "environment": environment, "environment_cleared": true,
                "cwd": command.get_current_dir(), "stdin": "null", "timeout_seconds": 3,
            }))
            .unwrap(),
        )
        .unwrap();
        let stdout = self.evidence.join("stdout.txt");
        let stderr = self.evidence.join("stderr.txt");
        command
            .stdout(fs::File::create(&stdout).unwrap())
            .stderr(fs::File::create(&stderr).unwrap());
        let mut child = command.spawn().unwrap();
        let waited = child.wait_timeout(Duration::from_secs(3)).unwrap();
        let timed_out = waited.is_none();
        let status = match waited {
            Some(status) => status,
            None => {
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(child.id() as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                child.wait().unwrap()
            }
        };
        let after = inventory(&self.root);
        fs::write(self.evidence.join("after.txt"), format!("{after:#?}")).unwrap();
        fs::write(
            self.evidence.join("result.json"),
            serde_json::to_vec_pretty(&json!({
                "exit_code": status.code(), "timed_out": timed_out, "child_reaped": true,
                "fixture_unchanged": before == after,
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(
            !timed_out,
            "configuration input hung: {}",
            self.evidence.display()
        );
        Output {
            status,
            stdout: fs::read(stdout).unwrap(),
            stderr: fs::read(stderr).unwrap(),
        }
    }

    fn reject(&self, command: Command, diagnostic: &str) {
        freeze_directory_times(&self.root);
        let before = inventory(&self.root);
        let output = self.capture(command);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(diagnostic),
            "{output:?}"
        );
        assert_eq!(
            inventory(&self.root),
            before,
            "rejected input changed fixture state"
        );
    }

    fn succeed(&self, command: Command, validate: bool) {
        freeze_directory_times(&self.root);
        let before = inventory(&self.root);
        let output = self.capture(command);
        assert!(output.status.success(), "{output:?}");
        if validate {
            assert_eq!(
                inventory(&self.root),
                before,
                "validation wrote fixture state"
            );
        } else {
            let runs: Vec<_> = fs::read_dir(self.root.join("state/update-all/runs"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.join("run.json").is_file())
                .collect();
            assert_eq!(runs.len(), 1);
            let run: Value =
                serde_json::from_slice(&fs::read(runs[0].join("run.json")).unwrap()).unwrap();
            assert_eq!(run["selected_tasks"], json!([]));
            assert_eq!(run["status"], "completed");
            assert_eq!(run["exit_code"], 0);
        }
    }
}

#[derive(Clone, Copy)]
enum Nonregular {
    Directory,
    Fifo,
    LinkToFifo,
}

#[allow(unsafe_code)] // No safe std constructor exists for a private native FIFO fixture.
fn nonregular(path: &Path, kind: Nonregular) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    if matches!(kind, Nonregular::Directory) {
        fs::create_dir(path).unwrap();
    } else {
        let target = if matches!(kind, Nonregular::LinkToFifo) {
            path.with_extension("fifo-target")
        } else {
            path.to_owned()
        };
        let native = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        // SAFETY: native is a live NUL-terminated path inside this private fixture root.
        assert_eq!(unsafe { libc::mkfifo(native.as_ptr(), 0o600) }, 0);
        if matches!(kind, Nonregular::LinkToFifo) {
            symlink(target, path).unwrap();
        }
    }
}

#[test]
fn discovered_main_nonregular_inputs_reject_without_fallback() {
    for kind in [
        Nonregular::Directory,
        Nonregular::Fifo,
        Nonregular::LinkToFifo,
    ] {
        for validate in [false, true] {
            for empty_environment in [false, true] {
                let fixture = Fixture::new("discovered-nonregular");
                fixture.fallback();
                nonregular(&fixture.main_path(), kind);
                let mut command = fixture.command(validate);
                if empty_environment {
                    command.env("UPDATE_ALL_CONFIG", "");
                }
                fixture.reject(command, "config path is not a regular file");
            }
        }
    }
}

#[test]
fn explicit_catalog_nonregular_inputs_reject_before_effects() {
    for kind in [
        Nonregular::Directory,
        Nonregular::Fifo,
        Nonregular::LinkToFifo,
    ] {
        for validate in [false, true] {
            let fixture = Fixture::new("catalog-nonregular");
            let path = fixture.root.join("catalog.toml");
            nonregular(&path, kind);
            fixture.with_catalog(&path);
            fixture.reject(
                fixture.command(validate),
                "updater catalog path is not a regular file",
            );
        }
    }
}

#[test]
fn discovered_main_and_explicit_catalog_regular_symlinks_remain_supported() {
    for main_symlink in [false, true] {
        for catalog_symlink in [false, true] {
            for validate in [false, true] {
                let fixture = Fixture::new("regular-inputs");
                fixture.fallback();
                let catalog = fixture.root.join("catalog.toml");
                if catalog_symlink {
                    fixture.write(&fixture.root.join("catalog-target.toml"), "");
                    symlink(fixture.root.join("catalog-target.toml"), &catalog).unwrap();
                } else {
                    fixture.write(&catalog, "");
                }
                fixture.with_catalog(&catalog);
                if main_symlink {
                    let target = fixture.root.join("main-target.toml");
                    fs::rename(fixture.main_path(), &target).unwrap();
                    symlink(target, fixture.main_path()).unwrap();
                }
                fixture.succeed(fixture.command(validate), validate);
            }
        }
    }
}

#[test]
fn explicit_selection_bypasses_nonregular_discovered_main() {
    for cli in [false, true] {
        for validate in [false, true] {
            let fixture = Fixture::new("explicit-precedence");
            nonregular(&fixture.main_path(), Nonregular::Fifo);
            let selected = fixture.root.join("selected.toml");
            fixture.write(&selected, CONFIG);
            let mut command = fixture.command(validate);
            if cli {
                command.env("UPDATE_ALL_CONFIG", fixture.root.join("missing.toml"));
                if validate {
                    command.arg("--path").arg(selected);
                } else {
                    command.arg("--config").arg(selected);
                }
            } else {
                command.env("UPDATE_ALL_CONFIG", selected);
            }
            fixture.succeed(command, validate);
        }
    }
}

#[test]
fn discovered_catalog_nonregular_filtering_and_symlink_rejection_are_preserved() {
    for symlink_entry in [false, true] {
        for validate in [false, true] {
            let fixture = Fixture::new("discovered-catalog-policy");
            fixture.write(&fixture.main_path(), CONFIG);
            let catalogs = fixture.main_path().parent().unwrap().join("catalog.d");
            nonregular(&catalogs.join("ignored-namespace"), Nonregular::Fifo);
            nonregular(&catalogs.join("local/ignored.toml"), Nonregular::Fifo);
            nonregular(
                &catalogs.join("local/directory.toml"),
                Nonregular::Directory,
            );
            fixture.write(&catalogs.join("local/regular.toml"), "");
            if symlink_entry {
                symlink(
                    catalogs.join("local/regular.toml"),
                    catalogs.join("local/link.toml"),
                )
                .unwrap();
                fixture.reject(
                    fixture.command(validate),
                    "updater catalog entries must not be symbolic links",
                );
            } else {
                fixture.succeed(fixture.command(validate), validate);
            }
        }
    }
}

#[test]
fn relative_catalog_paths_and_native_main_paths_remain_literal() {
    for validate in [false, true] {
        let fixture = Fixture::new("literal-catalog");
        let native = fixture
            .root
            .join(OsString::from_vec(b"config-\xff".to_vec()));
        let main = native.join("update-all/config.toml");
        fixture.write(&main, &format!("{CONFIG}catalogs=[\" catalog.toml \" ]\n"));
        fixture.write(&main.parent().unwrap().join(" catalog.toml "), "");
        let mut command = fixture.command(validate);
        command.env("UPDATE_ALL_CONFIG", main);
        fixture.succeed(command, validate);
    }
}
