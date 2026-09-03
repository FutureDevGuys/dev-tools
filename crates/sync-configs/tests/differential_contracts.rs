//! Black-box migration contracts for the Python 0.1.13 implementation and the native command.
//!
//! These tests deliberately compare only stable public behavior: exit status, the value-conscious
//! JSON envelope, and filesystem postconditions. Human wording and formatting are not a migration
//! interface. Tests named `native_*` document intentional correctness changes instead of forcing
//! the Rust implementation to reproduce known Python defects.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};
use tempfile::TempDir;

#[derive(Clone, Copy, Debug)]
enum Implementation {
    Python013,
    Native,
}

#[derive(Debug)]
struct Sandbox {
    root: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        let root = TempDir::new().expect("create isolated sync-configs sandbox");
        for name in ["home", "config", "state", "cache", "data", "tmp"] {
            fs::create_dir(root.path().join(name)).expect("create isolated platform directory");
        }
        Self { root }
    }

    fn path(&self) -> &Path {
        self.root.path()
    }

    fn write(&self, relative: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(&path, contents).expect("write fixture");
        path
    }

    fn manifest(&self, contents: &str) -> PathBuf {
        self.write("manifest.yaml", contents)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SnapshotNode {
    Directory,
    File(Vec<u8>),
    Symlink(String),
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonical repository root")
}

fn isolated_command(implementation: Implementation, sandbox: &Sandbox) -> Command {
    let repository = repository_root();
    let mut command = match implementation {
        Implementation::Python013 => {
            let mut command = Command::new("/usr/bin/python3");
            command.args(["-m", "syncconfigs.cli"]);
            command.env("PYTHONPATH", repository.join("sync-configs"));
            command.env("PYTHONDONTWRITEBYTECODE", "1");
            command
        }
        Implementation::Native => Command::new(env!("CARGO_BIN_EXE_sync-configs")),
    };
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", sandbox.path().join("home"))
        .env("XDG_CONFIG_HOME", sandbox.path().join("config"))
        .env("XDG_STATE_HOME", sandbox.path().join("state"))
        .env("XDG_CACHE_HOME", sandbox.path().join("cache"))
        .env("XDG_DATA_HOME", sandbox.path().join("data"))
        .env("TMPDIR", sandbox.path().join("tmp"))
        .env("SYNC_CONFIGS_LOG_ROOT", sandbox.path().join("logs"))
        .env("LC_ALL", "C.UTF-8")
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .current_dir(sandbox.path());
    if matches!(implementation, Implementation::Python013) {
        command
            .env("PYTHONPATH", repository.join("sync-configs"))
            .env("PYTHONDONTWRITEBYTECODE", "1");
    }
    command
}

fn run(
    implementation: Implementation,
    sandbox: &Sandbox,
    manifest: &Path,
    extra_arguments: &[&str],
) -> Output {
    let mut command = isolated_command(implementation, sandbox);
    command
        .args([
            "--no-color",
            "--log-style",
            "off",
            "--format",
            "json",
            "--config",
        ])
        .arg(manifest)
        .args(extra_arguments);
    command.output().expect("execute sync-configs candidate")
}

fn run_parse_case(implementation: Implementation, sandbox: &Sandbox, arguments: &[&str]) -> Output {
    isolated_command(implementation, sandbox)
        .args(arguments)
        .output()
        .expect("execute sync-configs parse case")
}

fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "expected exactly one JSON document ({error}); stdout={:?}; stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn stable_json_contract(output: &Output) -> Value {
    let value = json_output(output);
    json!({
        "schema_version": value.get("schema_version"),
        "outcome": value.get("outcome"),
        "exit_code": value.get("exit_code"),
        "dry_run": value.get("dry_run"),
        "profiles": value.get("profiles"),
    })
}

fn assert_successful_pair(python: &Output, native: &Output) {
    assert!(
        python.status.success(),
        "Python failed: {}",
        String::from_utf8_lossy(&python.stderr)
    );
    assert!(
        native.status.success(),
        "native failed: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(stable_json_contract(python), stable_json_contract(native));
}

fn snapshot(root: &Path) -> BTreeMap<String, SnapshotNode> {
    fn visit(base: &Path, path: &Path, result: &mut BTreeMap<String, SnapshotNode>) {
        let mut children = fs::read_dir(path)
            .expect("read snapshot directory")
            .map(|child| child.expect("read snapshot item").path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            let relative = child
                .strip_prefix(base)
                .expect("snapshot child under root")
                .to_string_lossy()
                .replace('\\', "/");
            let metadata = fs::symlink_metadata(&child).expect("snapshot metadata");
            if metadata.file_type().is_symlink() {
                let raw = fs::read_link(&child).expect("read snapshot symlink");
                let rendered = if raw.is_absolute() {
                    raw.strip_prefix(base)
                        .map(|relative| format!("<root>/{}", relative.display()))
                        .unwrap_or_else(|_| raw.display().to_string())
                } else {
                    raw.display().to_string()
                };
                result.insert(relative, SnapshotNode::Symlink(rendered));
            } else if metadata.is_dir() {
                result.insert(relative, SnapshotNode::Directory);
                visit(base, &child, result);
            } else if metadata.is_file() {
                result.insert(
                    relative,
                    SnapshotNode::File(fs::read(&child).expect("read snapshot file")),
                );
            } else {
                panic!("unexpected special file in snapshot: {}", child.display());
            }
        }
    }

    let mut result = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut result);
    }
    result
}

fn ordinary_file_identity(path: &Path) -> (u64, std::time::SystemTime) {
    let metadata = fs::metadata(path).expect("target metadata");
    (metadata.len(), metadata.modified().expect("target mtime"))
}

fn copy_fixture(sandbox: &Sandbox) -> PathBuf {
    sandbox.write("source.txt", "desired\n");
    sandbox.manifest(&format!(
        "default_mode: copy\nentries:\n  - name: copy-file\n    source: ./source.txt\n    target: {}\n",
        sandbox.path().join("output/target.txt").display()
    ))
}

#[test]
fn python_fixture_is_the_reviewed_013_source() {
    let sandbox = Sandbox::new();
    let output = isolated_command(Implementation::Python013, &sandbox)
        .arg("--version")
        .output()
        .expect("read Python fixture version");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "sync-configs 0.1.13"
    );
}

#[test]
fn copy_first_and_second_pass_match_and_are_idempotent() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = copy_fixture(&python);
    let native_manifest = copy_fixture(&native);

    let python_first = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_first = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_first, &native_first);
    assert_eq!(
        fs::read(python.path().join("output/target.txt")).unwrap(),
        fs::read(native.path().join("output/target.txt")).unwrap()
    );

    let python_before = ordinary_file_identity(&python.path().join("output/target.txt"));
    let native_before = ordinary_file_identity(&native.path().join("output/target.txt"));
    let python_second = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_second = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_second, &native_second);
    assert_eq!(
        ordinary_file_identity(&python.path().join("output/target.txt")),
        python_before,
        "Python reference rewrote an unchanged target"
    );
    assert_eq!(
        ordinary_file_identity(&native.path().join("output/target.txt")),
        native_before,
        "native implementation rewrote an unchanged target"
    );
}

#[cfg(unix)]
#[test]
fn symlink_creation_and_second_pass_match() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    python.write("source.txt", "source\n");
    native.write("source.txt", "source\n");
    let python_manifest = python.manifest(&format!(
        "entries:\n  - name: linked\n    source: ./source.txt\n    target: {}\n    mode: symlink\n",
        python.path().join("output/linked.txt").display()
    ));
    let native_manifest = native.manifest(&format!(
        "entries:\n  - name: linked\n    source: ./source.txt\n    target: {}\n    mode: symlink\n",
        native.path().join("output/linked.txt").display()
    ));

    let python_first = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_first = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_first, &native_first);
    let python_link = fs::read_link(python.path().join("output/linked.txt")).unwrap();
    let native_link = fs::read_link(native.path().join("output/linked.txt")).unwrap();
    assert_eq!(
        python_link.strip_prefix(python.path()).unwrap(),
        Path::new("source.txt")
    );
    assert_eq!(
        native_link.strip_prefix(native.path()).unwrap(),
        Path::new("source.txt")
    );

    let python_second = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_second = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_second, &native_second);
    assert_eq!(
        fs::read_link(python.path().join("output/linked.txt")).unwrap(),
        python_link
    );
    assert_eq!(
        fs::read_link(native.path().join("output/linked.txt")).unwrap(),
        native_link
    );
}

fn directory_fixture(sandbox: &Sandbox) -> PathBuf {
    sandbox.write("tree/keep.txt", "keep\n");
    sandbox.write("tree/drop.tmp", "drop\n");
    sandbox.write("tree/nested/also.txt", "nested\n");
    sandbox.write("literal.txt", "base\n");
    sandbox.write("literal.override.txt", "override\n");
    sandbox.manifest(&format!(
        "entries:\n  - name: recursive\n    source: ./tree\n    target: {}\n    mode: copy\n    directory_strategy: recursive\n    exclude: ['*.tmp']\n    discover_ignore_files: false\n    use_default_filters: false\n  - name: source-override\n    source: ./literal.txt\n    target: {}\n    mode: copy\n",
        sandbox.path().join("output/tree").display(),
        sandbox.path().join("output/overridden.txt").display(),
    ))
}

#[test]
fn directory_expansion_filters_and_source_overrides_match() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = directory_fixture(&python);
    let native_manifest = directory_fixture(&native);
    let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_output = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_output, &native_output);
    assert_eq!(
        snapshot(&python.path().join("output")),
        snapshot(&native.path().join("output"))
    );
    assert!(!native.path().join("output/tree/drop.tmp").exists());
    assert_eq!(
        fs::read_to_string(native.path().join("output/overridden.txt")).unwrap(),
        "override\n"
    );
}

fn overlay_fixture(sandbox: &Sandbox) -> PathBuf {
    sandbox.write(
        "desired.json",
        "{\"managed\":{\"enabled\":true},\"shape\":\"new\"}\n",
    );
    sandbox.write(
        "output/settings.json",
        "{\"managed\":{\"enabled\":false,\"keep\":7},\"shape\":{\"old\":1},\"user\":\"stay\"}\n",
    );
    sandbox.write(
        "desired.toml",
        "[managed]\nenabled = true\nname = \"native\"\n",
    );
    sandbox.write(
        "output/settings.toml",
        "user = \"stay\"\n\n[managed]\nenabled = false\nkeep = 7\n",
    );
    sandbox.manifest(&format!(
        "entries:\n  - name: json\n    source: ./desired.json\n    target: {}\n    mode: json_overlay\n  - name: toml\n    source: ./desired.toml\n    target: {}\n    mode: toml_overlay\n",
        sandbox.path().join("output/settings.json").display(),
        sandbox.path().join("output/settings.toml").display(),
    ))
}

fn assert_overlay_postconditions(sandbox: &Sandbox) {
    let json_value: Value = serde_json::from_slice(
        &fs::read(sandbox.path().join("output/settings.json")).expect("JSON target"),
    )
    .expect("valid JSON target");
    assert_eq!(json_value["managed"]["enabled"], true);
    assert_eq!(json_value["managed"]["keep"], 7);
    assert_eq!(json_value["shape"], "new");
    assert_eq!(json_value["user"], "stay");

    let toml = fs::read_to_string(sandbox.path().join("output/settings.toml")).unwrap();
    let document = toml
        .parse::<toml_edit::DocumentMut>()
        .expect("valid TOML target");
    assert_eq!(document["user"].as_str(), Some("stay"));
    assert_eq!(document["managed"]["enabled"].as_bool(), Some(true));
    assert_eq!(document["managed"]["name"].as_str(), Some("native"));
    assert_eq!(document["managed"]["keep"].as_integer(), Some(7));
}

#[test]
fn json_and_toml_overlays_match_semantically_and_converge() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = overlay_fixture(&python);
    let native_manifest = overlay_fixture(&native);

    let python_first = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_first = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_first, &native_first);
    assert_overlay_postconditions(&python);
    assert_overlay_postconditions(&native);

    let python_json_before = fs::read(python.path().join("output/settings.json")).unwrap();
    let native_json_before = fs::read(native.path().join("output/settings.json")).unwrap();
    let python_toml_before = fs::read(python.path().join("output/settings.toml")).unwrap();
    let native_toml_before = fs::read(native.path().join("output/settings.toml")).unwrap();
    let python_second = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_second = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_second, &native_second);
    assert_eq!(
        fs::read(python.path().join("output/settings.json")).unwrap(),
        python_json_before
    );
    assert_eq!(
        fs::read(native.path().join("output/settings.json")).unwrap(),
        native_json_before
    );
    assert_eq!(
        fs::read(python.path().join("output/settings.toml")).unwrap(),
        python_toml_before
    );
    assert_eq!(
        fs::read(native.path().join("output/settings.toml")).unwrap(),
        native_toml_before
    );
}

fn profile_fixture(sandbox: &Sandbox) -> (PathBuf, PathBuf) {
    sandbox.write("linux.txt", "linux\n");
    sandbox.write("desktop.txt", "desktop\n");
    sandbox.write("windows.txt", "windows\n");
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: linux\n    source: ./linux.txt\n    target: {}\n    mode: copy\n    profiles: [linux]\n  - name: desktop\n    source: ./desktop.txt\n    target: {}\n    mode: copy\n    profiles: [desktop]\n  - name: windows\n    source: ./windows.txt\n    target: {}\n    mode: copy\n    profiles: [windows]\n",
        sandbox.path().join("output/linux.txt").display(),
        sandbox.path().join("output/desktop.txt").display(),
        sandbox.path().join("output/windows.txt").display(),
    ));
    let profile_map = sandbox.write(
        "profiles.yaml",
        "schema_version: 1\nprofiles:\n  workstation: [linux, desktop, linux]\n",
    );
    (manifest, profile_map)
}

#[test]
fn profile_map_selection_and_order_match() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let (python_manifest, python_map) = profile_fixture(&python);
    let (native_manifest, native_map) = profile_fixture(&native);
    let python_map_arg = python_map.to_string_lossy().into_owned();
    let native_map_arg = native_map.to_string_lossy().into_owned();
    let python_output = run(
        Implementation::Python013,
        &python,
        &python_manifest,
        &[
            "--profile-map",
            &python_map_arg,
            "--host-profile",
            "workstation",
        ],
    );
    let native_output = run(
        Implementation::Native,
        &native,
        &native_manifest,
        &[
            "--profile-map",
            &native_map_arg,
            "--host-profile",
            "workstation",
        ],
    );
    assert_successful_pair(&python_output, &native_output);
    assert_eq!(
        json_output(&native_output)["profiles"],
        json!(["linux", "desktop"])
    );
    assert_eq!(
        snapshot(&python.path().join("output")),
        snapshot(&native.path().join("output"))
    );
    assert!(!native.path().join("output/windows.txt").exists());
}

fn precondition_fixture(sandbox: &Sandbox, state: &str, expected: &str) -> PathBuf {
    sandbox.write("state.json", state);
    sandbox.write("source.txt", "must-not-leak\n");
    sandbox.manifest(&format!(
        "state_preconditions:\n  - type: json_fields\n    path: {}\n    fields:\n      enabled: {}\n    remediation: repair caller state\nentries:\n  - name: gated\n    source: ./source.txt\n    target: {}\n    mode: copy\n",
        sandbox.path().join("state.json").display(),
        expected,
        sandbox.path().join("output/target.txt").display(),
    ))
}

#[test]
fn failed_state_preconditions_match_and_remain_read_only() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = precondition_fixture(&python, "{\"enabled\":false}\n", "true");
    let native_manifest = precondition_fixture(&native, "{\"enabled\":false}\n", "true");
    let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_output = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_eq!(python_output.status.code(), Some(1));
    assert_eq!(native_output.status.code(), Some(1));
    assert_eq!(
        stable_json_contract(&python_output),
        stable_json_contract(&native_output)
    );
    assert!(!python.path().join("output/target.txt").exists());
    assert!(!native.path().join("output/target.txt").exists());
    assert!(!String::from_utf8_lossy(&native_output.stdout).contains("must-not-leak"));
}

fn hook_fixture(sandbox: &Sandbox, fail: bool) -> PathBuf {
    sandbox.write(
        "hook.sh",
        "#!/bin/sh\nset -eu\ncase \"$1\" in\n  pre) printf 'generated\\n' > generated.txt ;;
  post) printf 'post\\n' > post.marker ;;
  fail) exit 23 ;;
esac\n",
    );
    let phase = if fail { "fail" } else { "pre" };
    sandbox.manifest(&format!(
        "entries:\n  - name: hooked\n    source: ./generated.txt\n    target: {}\n    mode: copy\n    pre_script: /usr/bin/sh hook.sh {}\n    pre_script_on_fail: abort\n    post_script: /usr/bin/sh hook.sh post\n    post_script_on_fail: abort\n",
        sandbox.path().join("output/target.txt").display(), phase,
    ))
}

#[test]
fn successful_hooks_and_aborting_pre_hook_match() {
    for fail in [false, true] {
        let python = Sandbox::new();
        let native = Sandbox::new();
        let python_manifest = hook_fixture(&python, fail);
        let native_manifest = hook_fixture(&native, fail);
        let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
        let native_output = run(Implementation::Native, &native, &native_manifest, &[]);
        assert_eq!(python_output.status.code(), native_output.status.code());
        assert_eq!(
            stable_json_contract(&python_output),
            stable_json_contract(&native_output)
        );
        assert_eq!(
            snapshot(&python.path().join("output")),
            snapshot(&native.path().join("output"))
        );
        assert_eq!(python.path().join("post.marker").exists(), !fail);
        assert_eq!(native.path().join("post.marker").exists(), !fail);
    }
}

#[test]
fn dry_run_is_read_only_in_both_implementations() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = hook_fixture(&python, false);
    let native_manifest = hook_fixture(&native, false);
    let python_output = run(
        Implementation::Python013,
        &python,
        &python_manifest,
        &["--dry-run"],
    );
    let native_output = run(
        Implementation::Native,
        &native,
        &native_manifest,
        &["--dry-run"],
    );
    assert_successful_pair(&python_output, &native_output);
    assert_eq!(json_output(&native_output)["dry_run"], true);
    for sandbox in [&python, &native] {
        assert!(!sandbox.path().join("generated.txt").exists());
        assert!(!sandbox.path().join("post.marker").exists());
        assert!(!sandbox.path().join("output/target.txt").exists());
    }
}

#[test]
fn cli_dependency_errors_share_exit_two_and_never_touch_host_state() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_map = python.write("profiles.yaml", "schema_version: 1\nprofiles: {}\n");
    let native_map = native.write("profiles.yaml", "schema_version: 1\nprofiles: {}\n");
    let python_output = run_parse_case(
        Implementation::Python013,
        &python,
        &[
            "--profile-map",
            python_map.to_str().unwrap(),
            "--log-style",
            "off",
        ],
    );
    let native_output = run_parse_case(
        Implementation::Native,
        &native,
        &[
            "--profile-map",
            native_map.to_str().unwrap(),
            "--log-style",
            "off",
        ],
    );
    assert_eq!(python_output.status.code(), Some(2));
    assert_eq!(native_output.status.code(), Some(2));
    assert!(python_output.stdout.is_empty());
    assert!(native_output.stdout.is_empty());
    assert!(!python.path().join("logs").exists());
    assert!(!native.path().join("logs").exists());
}

#[test]
fn native_distinguishes_a_missing_json_field_from_explicit_null() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = precondition_fixture(&python, "{}\n", "null");
    let native_manifest = precondition_fixture(&native, "{}\n", "null");
    let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_output = run(Implementation::Native, &native, &native_manifest, &[]);

    assert!(
        python_output.status.success(),
        "the reference defect changed unexpectedly"
    );
    assert!(python.path().join("output/target.txt").exists());
    assert_eq!(native_output.status.code(), Some(1));
    assert!(!native.path().join("output/target.txt").exists());
    assert_eq!(json_output(&native_output)["outcome"], "failed");
}

fn override_hook_fixture(sandbox: &Sandbox) -> PathBuf {
    sandbox.write("source.txt", "source\n");
    sandbox.write(
        "hook.sh",
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$1\" >> override-hooks.marker\n",
    );
    let manifest = sandbox.manifest(&format!(
        "entries:\n  - name: base\n    source: ./source.txt\n    target: {}\n    mode: copy\n",
        sandbox.path().join("output/target.txt").display()
    ));
    sandbox.write(
        "manifest.override.yaml",
        format!(
            "entries:\n  - name: replacement\n    source: ./source.txt\n    target: {}\n    mode: copy\n    pre_script: /usr/bin/sh hook.sh pre\n    post_script: /usr/bin/sh hook.sh post\n",
            sandbox.path().join("output/target.txt").display()
        ),
    );
    manifest
}

#[test]
fn native_runs_hooks_declared_by_manifest_overrides() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = override_hook_fixture(&python);
    let native_manifest = override_hook_fixture(&native);
    let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_output = run(Implementation::Native, &native, &native_manifest, &[]);
    assert!(python_output.status.success());
    assert!(native_output.status.success());
    assert!(
        !python.path().join("override-hooks.marker").exists(),
        "the Python reference defect changed; reassess this migration contract"
    );
    assert_eq!(
        fs::read_to_string(native.path().join("override-hooks.marker")).unwrap(),
        "pre\npost\n"
    );
}

#[test]
fn native_does_not_run_post_hooks_after_a_missing_source() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    for sandbox in [&python, &native] {
        sandbox.write(
            "hook.sh",
            "#!/bin/sh\nset -eu\nprintf 'ran\\n' > post.marker\n",
        );
    }
    let python_manifest = python.manifest(&format!(
        "entries:\n  - name: absent\n    source: ./missing.txt\n    target: {}\n    mode: copy\n    post_script: /usr/bin/sh hook.sh\n",
        python.path().join("output/target.txt").display()
    ));
    let native_manifest = native.manifest(&format!(
        "entries:\n  - name: absent\n    source: ./missing.txt\n    target: {}\n    mode: copy\n    post_script: /usr/bin/sh hook.sh\n",
        native.path().join("output/target.txt").display()
    ));
    let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_output = run(Implementation::Native, &native, &native_manifest, &[]);
    assert!(python_output.status.success());
    assert!(native_output.status.success());
    assert!(
        python.path().join("post.marker").exists(),
        "the Python reference defect changed; reassess this migration contract"
    );
    assert!(!native.path().join("post.marker").exists());
}

#[test]
fn native_forwards_the_toml_commented_target_policy() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    for sandbox in [&python, &native] {
        sandbox.write("desired.toml", "feature = true\n");
        sandbox.write(
            "output/settings.toml",
            "# feature = false\nuser = \"stay\"\n",
        );
    }
    let python_manifest = python.manifest(&format!(
        "entries:\n  - name: policy\n    source: ./desired.toml\n    target: {}\n    mode: toml_overlay\n    commented_target_policy: activate\n",
        python.path().join("output/settings.toml").display()
    ));
    let native_manifest = native.manifest(&format!(
        "entries:\n  - name: policy\n    source: ./desired.toml\n    target: {}\n    mode: toml_overlay\n    commented_target_policy: activate\n",
        native.path().join("output/settings.toml").display()
    ));
    let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_output = run(Implementation::Native, &native, &native_manifest, &[]);
    assert!(python_output.status.success());
    assert!(native_output.status.success());
    let python_target = fs::read_to_string(python.path().join("output/settings.toml")).unwrap();
    let native_target = fs::read_to_string(native.path().join("output/settings.toml")).unwrap();
    assert!(!python_target
        .lines()
        .any(|line| line.trim() == "feature = true"));
    assert!(native_target
        .lines()
        .any(|line| line.trim() == "feature = true"));
    assert!(native_target.contains("user = \"stay\""));
}

#[test]
fn native_rejects_unknown_manifest_fields_instead_of_silently_ignoring_them() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    for sandbox in [&python, &native] {
        sandbox.write("source.txt", "source\n");
    }
    let python_manifest = python.manifest(&format!(
        "entries:\n  - name: unknown\n    source: ./source.txt\n    target: {}\n    mode: copy\n    invented_semantics: true\n",
        python.path().join("output/target.txt").display()
    ));
    let native_manifest = native.manifest(&format!(
        "entries:\n  - name: unknown\n    source: ./source.txt\n    target: {}\n    mode: copy\n    invented_semantics: true\n",
        native.path().join("output/target.txt").display()
    ));
    let python_output = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_output = run(Implementation::Native, &native, &native_manifest, &[]);
    assert!(
        python_output.status.success(),
        "the Python reference defect changed unexpectedly"
    );
    assert!(python.path().join("output/target.txt").exists());
    assert_eq!(native_output.status.code(), Some(1));
    assert!(!native.path().join("output/target.txt").exists());
    let native_json = json_output(&native_output);
    assert_eq!(native_json["outcome"], "failed");
    assert_eq!(native_json["error_kind"], "convergence_failed");
    assert!(!String::from_utf8_lossy(&native_output.stdout).contains("source\n"));
}

fn directory_copy_fixture(sandbox: &Sandbox) -> PathBuf {
    sandbox.write("source/nested.txt", "one\n");
    sandbox.manifest(&format!(
        "entries:\n  - name: directory-copy\n    source: ./source\n    target: {}\n    mode: copy\n    directory_strategy: as_directory\n    reconcile_existing: true\n",
        sandbox.path().join("output/copied").display()
    ))
}

#[test]
fn native_detects_directory_content_drift_that_python_missed() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    let python_manifest = directory_copy_fixture(&python);
    let native_manifest = directory_copy_fixture(&native);
    let python_first = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_first = run(Implementation::Native, &native, &native_manifest, &[]);
    assert_successful_pair(&python_first, &native_first);

    python.write("source/nested.txt", "two\n");
    native.write("source/nested.txt", "two\n");
    let python_second = run(Implementation::Python013, &python, &python_manifest, &[]);
    let native_second = run(Implementation::Native, &native, &native_manifest, &[]);
    assert!(python_second.status.success());
    assert!(native_second.status.success());
    assert_eq!(
        fs::read_to_string(python.path().join("output/copied/nested.txt")).unwrap(),
        "one\n",
        "the Python reference defect changed; reassess this migration contract"
    );
    assert_eq!(
        fs::read_to_string(native.path().join("output/copied/nested.txt")).unwrap(),
        "two\n"
    );
}

#[cfg(unix)]
#[test]
fn native_strict_policy_never_adopts_an_identical_regular_file() {
    let python = Sandbox::new();
    let native = Sandbox::new();
    for sandbox in [&python, &native] {
        sandbox.write("source.txt", "same\n");
        sandbox.write("output/target.txt", "same\n");
    }
    let python_manifest = python.manifest(&format!(
        "entries:\n  - name: strict\n    source: ./source.txt\n    target: {}\n    mode: symlink\n",
        python.path().join("output/target.txt").display()
    ));
    let native_manifest = native.manifest(&format!(
        "entries:\n  - name: strict\n    source: ./source.txt\n    target: {}\n    mode: symlink\n",
        native.path().join("output/target.txt").display()
    ));
    let python_output = run(
        Implementation::Python013,
        &python,
        &python_manifest,
        &["--managed-path-policy", "strict"],
    );
    let native_output = run(
        Implementation::Native,
        &native,
        &native_manifest,
        &["--managed-path-policy", "strict"],
    );
    assert!(python_output.status.success());
    assert!(native_output.status.success());
    assert!(
        fs::symlink_metadata(python.path().join("output/target.txt"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the Python reference defect changed; reassess this migration contract"
    );
    assert!(
        fs::symlink_metadata(native.path().join("output/target.txt"))
            .unwrap()
            .is_file()
    );
}
